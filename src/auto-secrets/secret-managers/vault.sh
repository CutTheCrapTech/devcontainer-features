#!/bin/bash
# Auto Secrets Manager - HashiCorp Vault Secret Manager Integration
# Handles fetching secrets from Vault with authentication and error handling

# Source required modules
if [[ -f "$DEV_ENV_MANAGER_DIR/utils/logging.sh" ]]; then
    source "$DEV_ENV_MANAGER_DIR/utils/logging.sh"
fi

if [[ -f "$DEV_ENV_MANAGER_DIR/core/environment-mapping.sh" ]]; then
    source "$DEV_ENV_MANAGER_DIR/core/environment-mapping.sh"
fi

# Vault configuration
readonly VAULT_API_VERSION="v1"
readonly VAULT_DEFAULT_MOUNT="secret"
readonly VAULT_KV_VERSION="2"  # Default to KV v2

# Get Vault address from configuration
_get_vault_address() {
    local vault_addr="$DEV_ENV_MANAGER_SECRET_MANAGER_BASE_URL"

    # Expand environment variables
    if [[ "$vault_addr" =~ ^\$\{.*\}$ ]]; then
        local var_name="${vault_addr#\$\{}"
        var_name="${var_name%\}}"
        vault_addr="${!var_name}"
    fi

    # Default to VAULT_ADDR environment variable
    echo "${vault_addr:-$VAULT_ADDR}"
}

# Check if Vault CLI is available and authenticated
_check_vault_auth() {
    local vault_addr
    vault_addr=$(_get_vault_address)

    if [[ -z "$vault_addr" ]]; then
        log_error "Vault address not configured (set VAULT_ADDR or DEV_ENV_MANAGER_SECRET_MANAGER_BASE_URL)"
        return 1
    fi

    # Check if CLI is installed
    if ! command -v vault >/dev/null 2>&1; then
        log_warn "Vault CLI not found, using direct API calls"
        # Don't return error - we can use API directly
    fi

    # Check if we can get a token
    if ! get_vault_token >/dev/null 2>&1; then
        log_error "Vault authentication failed - no valid token found"
        log_info "Authenticate with: vault auth -method=<method> or set VAULT_TOKEN"
        return 1
    fi

    log_debug "Vault authentication check passed"
    return 0
}

# Make authenticated API request to Vault
_vault_api_request() {
    local method="$1"
    local path="$2"
    local data="${3:-}"

    local vault_addr
    vault_addr=$(_get_vault_address)
    if [[ -z "$vault_addr" ]]; then
        log_error "Vault address not configured"
        return 1
    fi

    local token
    token=$(get_vault_token)
    if [[ $? -ne 0 ]]; then
        return 1
    fi

    # Remove leading slash from path
    path="${path#/}"
    local full_url="${vault_addr}/${VAULT_API_VERSION}/${path}"

    log_network "Making Vault API request: $method /${path}"

    local curl_args=(
        --silent
        --show-error
        --fail
        --max-time 30
        --retry 2
        --retry-delay 1
        -H "X-Vault-Token: $token"
        -H "Accept: application/json"
        -H "Content-Type: application/json"
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
        log_error "Vault API request failed (exit code: $exit_code)"
        log_debug "Response: $response"

        # Check for specific error patterns
        if [[ "$response" =~ "403" ]] || [[ "$response" =~ "permission denied" ]]; then
            log_error "Access denied - check Vault policies and token permissions"
        elif [[ "$response" =~ "404" ]]; then
            log_error "Path not found - check secret path and mount point"
        elif [[ "$response" =~ "connection refused" ]]; then
            log_error "Cannot connect to Vault server at $vault_addr"
        fi

        return 1
    fi
}

# Get Vault KV version for a mount
_get_kv_version() {
    local mount="${1:-$VAULT_DEFAULT_MOUNT}"

    # Try to determine KV version from mount info
    local response
    response=$(_vault_api_request "GET" "sys/mounts")

    if [[ $? -eq 0 ]]; then
        local version
        version=$(echo "$response" | jq -r ".data.\"${mount}/\".options.version // \"1\"" 2>/dev/null)
        if [[ "$version" =~ ^[12]$ ]]; then
            echo "$version"
            return 0
        fi
    fi

    # Default to configured version
    echo "${DEV_ENV_MANAGER_SECRET_MANAGER_KV_VERSION:-$VAULT_KV_VERSION}"
}

# Fetch secret from Vault KV v1
_fetch_vault_kv1_secret() {
    local mount="$1"
    local path="$2"

    log_debug "Fetching KV v1 secret: $mount/$path"

    local response
    response=$(_vault_api_request "GET" "$mount/$path")

    if [[ $? -eq 0 ]]; then
        # Parse KV v1 response
        echo "$response" | jq '
            .data // {} |
            with_entries(.value = (.value | tostring))
        ' 2>/dev/null
    else
        return 1
    fi
}

# Fetch secret from Vault KV v2
_fetch_vault_kv2_secret() {
    local mount="$1"
    local path="$2"

    log_debug "Fetching KV v2 secret: $mount/data/$path"

    local response
    response=$(_vault_api_request "GET" "$mount/data/$path")

    if [[ $? -eq 0 ]]; then
        # Parse KV v2 response - ensure it's a proper JSON object
        echo "$response" | jq '.data.data // {}' 2>/dev/null
    else
        return 1
    fi
}

# Fetch secrets using Vault CLI
_fetch_secrets_with_cli() {
    local path="$1"
    local mount="${2:-$VAULT_DEFAULT_MOUNT}"

    if ! command -v vault >/dev/null 2>&1; then
        log_error "Vault CLI not available"
        return 1
    fi

    log_network "Fetching secrets from Vault using CLI: $mount/$path"

    # Set Vault address for CLI
    local vault_addr
    vault_addr=$(_get_vault_address)
    export VAULT_ADDR="$vault_addr"

    local secrets_output
    local exit_code

    # Try to read the secret
    secrets_output=$(vault kv get -format=json "$mount/$path" 2>&1)
    exit_code=$?

    if [[ $exit_code -eq 0 ]]; then
        # Parse CLI output - return as JSON object
        local secrets_json
        secrets_json=$(echo "$secrets_output" | jq '
            .data.data // .data // {} |
            with_entries(.value = (.value | tostring))
        ' 2>/dev/null)

        if [[ -n "$secrets_json" ]] && [[ "$secrets_json" != "null" ]]; then
            echo "$secrets_json"
            log_debug "Successfully fetched secrets using CLI"
            return 0
        fi
    fi

    log_error "Failed to fetch secrets using Vault CLI"
    log_debug "CLI output: $secrets_output"
    return 1
}

# Get secret path for environment
_get_vault_secret_path() {
    local environment="$1"
    local base_path="${DEV_ENV_MANAGER_SECRET_MANAGER_BASE_PATH:-}"

    if [[ -n "$base_path" ]]; then
        echo "$base_path/$environment"
    else
        echo "$environment"
    fi
}

# Get Vault token from various sources
get_vault_token() {
    # Check if vault CLI is available and authenticated
    if command -v vault >/dev/null 2>&1; then
        # Try to get token from vault CLI
        local token
        token=$(vault print token 2>/dev/null)
        if [[ -n "$token" ]] && [[ "$token" != "null" ]]; then
            echo "$token"
            return 0
        fi
    fi

    # Check environment variable
    if [[ -n "$VAULT_TOKEN" ]]; then
        echo "$VAULT_TOKEN"
        return 0
    fi

    # Check token file
    if [[ -f "$HOME/.vault-token" ]]; then
        local token
        token=$(cat "$HOME/.vault-token" 2>/dev/null)
        if [[ -n "$token" ]]; then
            echo "$token"
            return 0
        fi
    fi

    log_error "No Vault token found"
    return 1
}

# Main function to fetch secrets from Vault
fetch_vault_secrets() {
    local environment="$1"

    # Validate environment
    if [[ -z "$environment" ]]; then
        log_error "Environment not specified for Vault secrets fetch"
        return 1
    fi

    if ! is_valid_environment "$environment"; then
        log_error "Invalid environment name: $environment"
        return 1
    fi

    log_info "Fetching secrets from Vault for environment: $environment"

    # Check authentication first
    if ! _check_vault_auth; then
        error_with_context "AUTH" "Vault authentication failed"
        return 1
    fi

    # Get configuration
    local mount="${DEV_ENV_MANAGER_SECRET_MANAGER_MOUNT:-$VAULT_DEFAULT_MOUNT}"
    local secret_path
    secret_path=$(_get_vault_secret_path "$environment")

    # Determine KV version
    local kv_version
    kv_version=$(_get_kv_version "$mount")

    log_debug "Using Vault mount: $mount, path: $secret_path, KV version: $kv_version"

    # Attempt to fetch secrets
    local secrets_content
    local fetch_method="API"

    if [[ "$kv_version" == "2" ]]; then
        secrets_content=$(_fetch_vault_kv2_secret "$mount" "$secret_path")
    else
        secrets_content=$(_fetch_vault_kv1_secret "$mount" "$secret_path")
    fi

    local exit_code=$?

    # Fallback to CLI if API fails
    if [[ $exit_code -ne 0 ]] && command -v vault >/dev/null 2>&1; then
        log_debug "API method failed, trying CLI method"
        fetch_method="CLI"
        secrets_content=$(_fetch_secrets_with_cli "$secret_path" "$mount")
        exit_code=$?
    fi

    if [[ $exit_code -eq 0 ]] && [[ -n "$secrets_content" ]]; then
        log_success "Secrets fetched successfully using $fetch_method ($(echo "$secrets_content" | wc -l) secrets)"
        echo "$secrets_content"
        return 0
    else
        error_with_context "NETWORK" "Failed to fetch secrets from Vault"
        return 1
    fi
}

# Test Vault connection and authentication
test_vault_connection() {
    echo "Testing Vault Connection:"
    echo "========================"

    # Check Vault address
    local vault_addr
    vault_addr=$(_get_vault_address)
    if [[ -n "$vault_addr" ]]; then
        echo "✅ Vault address configured: $vault_addr"
    else
        echo "❌ Vault address not configured"
        return 1
    fi

    # Check CLI installation
    if command -v vault >/dev/null 2>&1; then
        local version
        version=$(vault version 2>/dev/null | head -1)
        echo "✅ Vault CLI installed: $version"
    else
        echo "⚠️  Vault CLI not installed (API-only mode)"
    fi

    # Check authentication
    if _check_vault_auth; then
        echo "✅ Authentication: OK"

        # Test token info
        if command -v vault >/dev/null 2>&1; then
            local token_info
            token_info=$(vault token lookup -format=json 2>/dev/null | jq -r '.data.display_name // "unknown"' 2>/dev/null)
            echo "   Token: $token_info"
        fi
    else
        echo "❌ Authentication: Failed"
        return 1
    fi

    # Test mount access
    local mount="${DEV_ENV_MANAGER_SECRET_MANAGER_MOUNT:-$VAULT_DEFAULT_MOUNT}"
    echo "🔍 Testing mount access: $mount"

    local response
    response=$(_vault_api_request "GET" "sys/mounts" 2>/dev/null)
    if [[ $? -eq 0 ]]; then
        local mount_exists
        mount_exists=$(echo "$response" | jq -r ".data.\"${mount}/\" // empty" 2>/dev/null)
        if [[ -n "$mount_exists" ]]; then
            echo "✅ Mount accessible: $mount"

            # Get KV version
            local kv_version
            kv_version=$(_get_kv_version "$mount")
            echo "   KV Version: $kv_version"
        else
            echo "❌ Mount not accessible: $mount"
            return 1
        fi
    else
        echo "⚠️  Could not verify mount access"
    fi

    # Test environment access
    local current_environment
    current_environment=$(get_current_environment)
    echo "🔍 Testing environment access: $current_environment"

    if fetch_vault_secrets "$current_environment" >/dev/null 2>&1; then
        echo "✅ Environment access: OK"
    else
        echo "❌ Environment access: Failed"
        return 1
    fi

    echo "🎉 Vault connection test passed!"
    return 0
}

# Set up Vault as the active secret manager interface
export -f fetch_vault_secrets test_vault_connection
