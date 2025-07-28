#!/bin/bash
# Auto Secrets Manager - Infisical Secret Manager Integration
# Handles fetching secrets from Infisical with authentication and error handling

# Source required modules
if [[ -f "$DEV_ENV_MANAGER_DIR/utils/logging.sh" ]]; then
    source "$DEV_ENV_MANAGER_DIR/utils/logging.sh"
fi

if [[ -f "$DEV_ENV_MANAGER_DIR/core/environment-mapping.sh" ]]; then
    source "$DEV_ENV_MANAGER_DIR/core/environment-mapping.sh"
fi

# Infisical configuration
readonly INFISICAL_API_VERSION="v3"
readonly INFISICAL_DEFAULT_BASE_URL="https://app.infisical.com"
readonly INFISICAL_CLI_CONFIG_PATH="$HOME/.infisical.json"

# Get Infisical base URL from configuration
_get_infisical_base_url() {
    echo "${DEV_ENV_MANAGER_SECRET_MANAGER_BASE_URL:-$INFISICAL_DEFAULT_BASE_URL}"
}

# Get Infisical project ID from configuration
_get_infisical_project_id() {
    local project_id="$DEV_ENV_MANAGER_SECRET_MANAGER_PROJECT_ID"

    # Expand environment variables in project ID
    if [[ "$project_id" =~ ^\$\{.*\}$ ]]; then
        local var_name="${project_id#\$\{}"
        var_name="${var_name%\}}"
        project_id="${!var_name}"
    fi

    echo "$project_id"
}

# Make authenticated API request to Infisical
_infisical_api_request() {
    local method="$1"
    local endpoint="$2"
    local data="${3:-}"

    local base_url
    base_url=$(_get_infisical_base_url)
    local full_url="${base_url}/api/${INFISICAL_API_VERSION}${endpoint}"

    local token="$INFISICAL_TOKEN"
    if [[ -z "$token" ]]; then
        log_error "Infisical token not available. Please authenticate first."
        return 1
    fi

    log_network "Making Infisical API request: $method $endpoint"

    local curl_args=(
        --silent
        --show-error
        --fail
        --max-time 30
        --retry 2
        --retry-delay 1
        -H "Accept: application/json"
        -H "Content-Type: application/json"
        -H "Authorization: Bearer $token"
    )

    # Add request body for POST/PUT requests
    if [[ -n "$data" ]]; then
        curl_args+=(-d "$data")
    fi

    # Make the request
    local response
    local exit_code

    response=$(curl "${curl_args[@]}" -X "$method" "$full_url" 2>&1)
    exit_code=$?

    if [[ $exit_code -eq 0 ]]; then
        echo "$response"
        return 0
    else
        log_error "Infisical API request failed (exit code: $exit_code)"
        log_debug "Response: $response"
        return 1
    fi
}

# Fetch secrets for environment using CLI
_fetch_secrets_with_cli() {
    local environment="$1"
    local project_id
    project_id=$(_get_infisical_project_id)

    if [[ -z "$project_id" ]]; then
        log_error "Infisical project ID not configured"
        return 1
    fi

    log_network "Fetching secrets from Infisical using CLI (env: $environment, project: $project_id)"

    # Use Infisical CLI to export secrets
    local secrets_output
    local exit_code

    secrets_output=$(infisical export         --projectId="$project_id"         --env="$environment"         --format=json         --include-imports 2>&1)
    exit_code=$?
    if [[ $exit_code -eq 0 ]]; then
        # Transform the JSON array into a key-value object
        echo "$secrets_output" | jq 'map({key: .key, value: .value}) | from_entries'
        log_debug "Successfully fetched secrets using CLI"
        return 0
    else
        log_error "Failed to fetch secrets using Infisical CLI"
        log_debug "CLI output: $secrets_output"

        # Check for common error patterns
        if [[ "$secrets_output" =~ "not found" ]]; then
            log_error "Environment '$environment' not found in project '$project_id'"
        elif [[ "$secrets_output" =~ "unauthorized" ]] || [[ "$secrets_output" =~ "forbidden" ]]; then
            log_error "Insufficient permissions for environment '$environment'"
            log_info "Ensure your Infisical user has access to the '$environment' environment"
        elif [[ "$secrets_output" =~ "network" ]] || [[ "$secrets_output" =~ "timeout" ]]; then
            log_error "Network error connecting to Infisical"
            log_info "Check your internet connection and Infisical service status"
        fi

        return 1
    fi
}

# Fetch secrets for environment using API
_fetch_secrets_with_api() {
    local environment="$1"
    local project_id
    project_id=$(_get_infisical_project_id)

    if [[ -z "$project_id" ]]; then
        log_error "Infisical project ID not configured"
        return 1
    fi

    log_network "Fetching secrets from Infisical API (env: $environment, project: $project_id)"

    # Make API request to get secrets
    local response
    response=$(_infisical_api_request "GET" "/secrets?environment=$environment&workspaceId=$project_id")
    local exit_code=$?

    if [[ $exit_code -eq 2 ]]; then
        # Fallback to CLI method
        _fetch_secrets_with_cli "$environment"
        return $?
    elif [[ $exit_code -ne 0 ]]; then
        log_error "Failed to fetch secrets from Infisical API"
        return 1
    fi

    # Parse JSON response and convert to env format
    local secrets_env
    secrets_json=$(echo "$response" | jq '
        [.secrets[]? // .data.secrets[]? // empty |
        select(.secretKey and .secretValue) |
        {key: .secretKey, value: .secretValue}] |
        from_entries
    ' 2>/dev/null)

    if [[ -n "$secrets_json" ]] && [[ "$secrets_json" != "null" ]]; then
        echo "$secrets_json"
        log_debug "Successfully parsed secrets from API response"
        return 0
    else
        log_error "No secrets found in API response"
        log_debug "API response: $response"
        return 1
    fi
}

# Authenticate with Infisical if universal auth is configured
_authenticate_infisical() {
    log_info "🔑 Attempting Infisical authentication..."

    # Source config.sh to get the variables set by _setup_configuration
    # This is needed because infisical.sh might be sourced directly or indirectly
    if [[ -f "$DEV_ENV_MANAGER_DIR/config.sh" ]]; then
        source "$DEV_ENV_MANAGER_DIR/config.sh"
    else
        log_error "DEV_ENV_MANAGER_DIR/config.sh not found. Cannot authenticate Infisical."
        return 1
    fi

    if [[ "$DEV_ENV_MANAGER_SECRET_MANAGER_AUTH_METHOD" == "universal-auth" ]]; then
        local infisical_client_id="$DEV_ENV_MANAGER_SECRET_MANAGER_CLIENT_ID"
        local infisical_client_secret="${INFISICAL_CLIENT_SECRET:-${TF_VAR_INFISICAL_CLIENT_SECRET:-}}"
        local infisical_base_url="$DEV_ENV_MANAGER_SECRET_MANAGER_BASE_URL"

        if [[ -z "$infisical_client_id" ]]; then
            log_error "Infisical universal authentication requires 'clientId' to be set in devcontainer-feature.json options."
            return 1
        fi

        if [[ -z "$infisical_client_secret" ]]; then
            log_error "Infisical universal authentication requires 'clientSecret' to be set via INFISICAL_CLIENT_SECRET or TF_VAR_INFISICAL_CLIENT_SECRET environment variable."
            return 1
        fi

        log_info "Attempting Infisical universal authentication with client ID: $infisical_client_id"
        local infisical_token_raw
        infisical_token_raw=$(infisical login --method=universal-auth --domain="$infisical_base_url" --client-id="$infisical_client_id" --client-secret="$infisical_client_secret" --silent --plain)
        local exit_code=$?

        if [[ $exit_code -eq 0 ]]; then
            export INFISICAL_TOKEN="$infisical_token_raw"
            log_success "Infisical universal authentication successful."
            return 0
        else
            local error_output
            error_output=$(infisical login --method=universal-auth --domain="$infisical_base_url" --client-id="$infisical_client_id" --client-secret="$infisical_client_secret" --silent --plain 2>&1 >/dev/null)
            log_error "Infisical universal authentication failed. Output: $error_output"
            return 1
        fi
    else
        log_info "Infisical universal authentication not configured or not selected as secret manager."
        return 0
    fi
}

# Main function to fetch secrets from Infisical
fetch_infisical_secrets() {
    local environment="$1"

    # Validate environment
    if [[ -z "$environment" ]]; then
        log_error "Environment not specified for Infisical secrets fetch"
        return 1
    fi

    if ! is_valid_environment "$environment"; then
        log_error "Invalid environment name: $environment"
        return 1
    fi

    log_info "Fetching secrets from Infisical for environment: $environment"

    # Ensure INFISICAL_TOKEN is set
    if [[ -z "$INFISICAL_TOKEN" ]]; then
        log_error "INFISICAL_TOKEN is not set. Please authenticate with Infisical first."
        error_with_context "AUTH" "Infisical authentication required"
        return 1
    fi

    # Attempt to fetch secrets (prefer CLI for reliability)
    local secrets_content
    local fetch_method="CLI"

    secrets_content=$(_fetch_secrets_with_cli "$environment")
    local exit_code=$?

    # Fallback to API if CLI fails
    if [[ $exit_code -ne 0 ]] && [[ "$DEV_ENV_MANAGER_SECRET_MANAGER_AUTH_METHOD" == "api" ]]; then
        log_debug "CLI method failed, trying API method"
        fetch_method="API"
        secrets_content=$(_fetch_secrets_with_api "$environment")
        exit_code=$?
    fi

    if [[ $exit_code -eq 0 ]] && [[ -n "$secrets_content" ]]; then
        log_success "Secrets fetched successfully using $fetch_method ($(echo "$secrets_content" | wc -l) secrets)"
        echo "$secrets_content"
        return 0
    else
        error_with_context "NETWORK" "Failed to fetch secrets from Infisical"
        return 1
    fi
}

# Test Infisical connection and authentication
test_infisical_connection() {
    echo "Testing Infisical Connection:"
    echo "============================"

    # Check CLI installation
    if command -v infisical >/dev/null 2>&1; then
        local version
        version=$(infisical --version 2>/dev/null | head -1)
        echo "✅ Infisical CLI installed: $version"
    else
        echo "❌ Infisical CLI not installed"
        return 1
    fi

    # Check authentication (INFISICAL_TOKEN should be set by _authenticate_infisical)
    if [[ -n "$INFISICAL_TOKEN" ]]; then
        echo "✅ Authentication: OK (INFISICAL_TOKEN is set)"
    else
        echo "❌ Authentication: Failed (INFISICAL_TOKEN is not set)"
        return 1
    fi

    # Test project access
    local project_id
    project_id=$(_get_infisical_project_id)
    if [[ -n "$project_id" ]]; then
        echo "✅ Project ID configured: $project_id"

        # Test environment access
        local current_environment
        current_environment=$(get_current_environment)
        echo "🔍 Testing environment access: $current_environment"

        if fetch_infisical_secrets "$current_environment" >/dev/null 2>&1; then
            echo "✅ Environment access: OK"
        else
            echo "❌ Environment access: Failed"
            return 1
        fi
    else
        echo "❌ Project ID not configured"
        return 1
    fi

    echo "🎉 Infisical connection test passed!"
    return 0
}

# Set up Infisical as the active secret manager interface
export -f fetch_infisical_secrets
export -f test_infisical_connection
