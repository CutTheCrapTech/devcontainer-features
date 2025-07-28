#!/bin/bash
# Auto Secrets Manager - Google Cloud Secret Manager Integration
# Handles fetching secrets from GCP Secret Manager with authentication and error handling

# Source required modules
if [[ -f "$DEV_ENV_MANAGER_DIR/utils/logging.sh" ]]; then
    source "$DEV_ENV_MANAGER_DIR/utils/logging.sh"
fi

if [[ -f "$DEV_ENV_MANAGER_DIR/core/environment-mapping.sh" ]]; then
    source "$DEV_ENV_MANAGER_DIR/core/environment-mapping.sh"
fi

# GCP configuration
readonly GCLOUD_CLI_MIN_VERSION="400.0.0"

# Get GCP project ID from configuration
_get_gcp_project_id() {
    local project_id="${DEV_ENV_MANAGER_SECRET_MANAGER_PROJECT_ID:-${GCP_PROJECT_ID:-${GOOGLE_CLOUD_PROJECT:-}}}"

    # Expand environment variables
    if [[ "$project_id" =~ ^\$\{.*\}$ ]]; then
        local var_name="${project_id#\$\{}"
        var_name="${var_name%\}}"
        project_id="${!var_name}"
    fi

    echo "$project_id"
}

# Get secret name prefix from configuration
_get_gcp_secret_prefix() {
    echo "${DEV_ENV_MANAGER_SECRET_MANAGER_SECRET_PREFIX:-dev-env-secrets}"
}

# Check if gcloud CLI is available and properly configured
_check_gcloud_cli() {
    if ! command -v gcloud >/dev/null 2>&1; then
        log_error "Google Cloud CLI not found. Please install gcloud CLI"
        return 1
    fi

    # Check gcloud CLI version
    local gcloud_version
    gcloud_version=$(gcloud version --format="value(Google Cloud SDK)" 2>/dev/null)
    if [[ -n "$gcloud_version" ]]; then
        log_debug "Google Cloud CLI version: $gcloud_version"
    fi

    # Check if user is authenticated
    if ! gcloud auth list --filter=status:ACTIVE --format="value(account)" 2>/dev/null | head -1 >/dev/null; then
        log_error "Not authenticated with Google Cloud"
        log_info "Authenticate using: gcloud auth login"
        return 1
    fi

    # Check if project is set
    local current_project
    current_project=$(gcloud config get-value project 2>/dev/null)
    if [[ -z "$current_project" ]]; then
        log_warn "No default project set in gcloud config"
    fi

    log_debug "Google Cloud CLI check passed"
    return 0
}

# Get GCP account information
_get_gcp_account_info() {
    local account
    account=$(gcloud auth list --filter=status:ACTIVE --format="value(account)" 2>/dev/null | head -1)

    if [[ -n "$account" ]]; then
        echo "Active account: $account"
        local project
        project=$(gcloud config get-value project 2>/dev/null)
        if [[ -n "$project" ]]; then
            echo "Default project: $project"
        fi
        return 0
    else
        echo "No active authentication found"
        return 1
    fi
}

# Construct secret name for environment
_get_gcp_secret_name() {
    local environment="$1"
    local prefix
    prefix=$(_get_gcp_secret_prefix)

    # GCP secret names must be lowercase letters, numbers, and hyphens
    local clean_prefix="${prefix,,}"
    clean_prefix="${clean_prefix//[^a-z0-9-]/}"
    local clean_env="${environment,,}"
    clean_env="${clean_env//[^a-z0-9-]/}"

    echo "${clean_prefix}-${clean_env}"
}

# List all secrets with the configured prefix
_list_gcp_secrets() {
    local project_id
    project_id=$(_get_gcp_project_id)
    local prefix
    prefix=$(_get_gcp_secret_prefix)

    if [[ -z "$project_id" ]]; then
        log_error "GCP project ID not configured"
        return 1
    fi

    log_debug "Listing GCP Secret Manager secrets with prefix: $prefix"

    gcloud secrets list \
        --project="$project_id" \
        --filter="name:${prefix}-*" \
        --format="value(name)" 2>/dev/null | sort
}

# Check if secret exists in GCP Secret Manager
_gcp_secret_exists() {
    local secret_name="$1"
    local project_id
    project_id=$(_get_gcp_project_id)

    if [[ -z "$project_id" ]]; then
        return 1
    fi

    gcloud secrets describe "$secret_name" \
        --project="$project_id" \
        >/dev/null 2>&1
}

# Get latest version of secret from GCP Secret Manager
_get_gcp_secret_value() {
    local secret_name="$1"
    local version="${2:-latest}"
    local project_id
    project_id=$(_get_gcp_project_id)

    if [[ -z "$project_id" ]]; then
        log_error "GCP project ID not configured"
        return 1
    fi

    log_network "Fetching secret from GCP Secret Manager: $secret_name"

    local secret_response
    secret_response=$(gcloud secrets versions access "$version" \
        --secret="$secret_name" \
        --project="$project_id" 2>&1)

    local exit_code=$?

    if [[ $exit_code -eq 0 ]]; then
        echo "$secret_response"
        return 0
    else
        log_error "Failed to retrieve secret: $secret_name"
        log_debug "GCP response: $secret_response"

        # Parse common error types
        if [[ "$secret_response" =~ "NOT_FOUND" ]]; then
            log_error "Secret not found: $secret_name"
        elif [[ "$secret_response" =~ "PERMISSION_DENIED" ]]; then
            log_error "Access denied - check IAM permissions for Secret Manager"
        elif [[ "$secret_response" =~ "FAILED_PRECONDITION" ]]; then
            log_error "Secret Manager API not enabled or project misconfigured"
        fi

        return 1
    fi
}

# Parse secret string based on format (JSON or key=value)
_parse_gcp_secret_string() {
    local secret_string="$1"

    if [[ -z "$secret_string" ]]; then
        log_error "Empty secret string"
        return 1
    fi

    # Check if it's JSON
    if echo "$secret_string" | jq . >/dev/null 2>&1; then
        log_debug "Parsing secret as JSON"
        echo "$secret_string" | jq -r '. | with_entries(.value = (.value | tostring))'
    else
        # Try to parse as key=value pairs
        log_debug "Parsing secret as key=value format"
        local json_object="{}"

        # Read line by line and build JSON object
        while IFS='=' read -r key value; do
            # Skip empty lines and comments
            [[ -z "$key" ]] || [[ "$key" =~ ^# ]] && continue

            # Remove leading/trailing whitespace
            key=$(echo "$key" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
            value=$(echo "$value" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')

            # Add to JSON object using jq
            json_object=$(echo "$json_object" | jq --arg k "$key" --arg v "$value" '. + {($k): $v}')
        done <<< "$secret_string"

        echo "$json_object"
    fi
}

# Enable Secret Manager API if not already enabled
_ensure_secret_manager_api() {
    local project_id
    project_id=$(_get_gcp_project_id)

    if [[ -z "$project_id" ]]; then
        log_error "GCP project ID not configured"
        return 1
    fi

    log_debug "Checking if Secret Manager API is enabled..."

    if ! gcloud services list --enabled --filter="name:secretmanager.googleapis.com" --project="$project_id" --format="value(name)" 2>/dev/null | grep -q secretmanager; then
        log_warn "Secret Manager API not enabled, attempting to enable..."

        if gcloud services enable secretmanager.googleapis.com --project="$project_id" >/dev/null 2>&1; then
            log_success "Secret Manager API enabled successfully"
            # Wait a moment for API to be fully available
            sleep 2
        else
            log_error "Failed to enable Secret Manager API"
            return 1
        fi
    fi

    return 0
}

# Authenticate with GCP (verify credentials)
_authenticate_gcp() {
    log_info "🔑 Verifying Google Cloud authentication..."

    if ! command -v gcloud >/dev/null 2>&1; then
        log_error "Google Cloud CLI not installed"
        return 1
    fi

    # Test credentials by listing active account
    local active_account
    active_account=$(gcloud auth list --filter=status:ACTIVE --format="value(account)" 2>/dev/null | head -1)

    if [[ -n "$active_account" ]]; then
        log_success "Google Cloud authentication successful (Account: $active_account)"

        # Check if project is configured
        local project_id
        project_id=$(_get_gcp_project_id)
        if [[ -n "$project_id" ]]; then
            log_debug "Using project: $project_id"
        else
            log_warn "No project configured - set DEV_ENV_MANAGER_SECRET_MANAGER_PROJECT_ID"
        fi

        return 0
    else
        log_error "Google Cloud authentication failed"
        log_info "Run 'gcloud auth login' to authenticate"
        return 1
    fi
}

# Main function to fetch secrets from GCP Secret Manager
fetch_gcp_secrets() {
    local environment="$1"

    # Validate environment
    if [[ -z "$environment" ]]; then
        log_error "Environment not specified for GCP Secret Manager secrets fetch"
        return 1
    fi

    if ! is_valid_environment "$environment"; then
        log_error "Invalid environment name: $environment"
        return 1
    fi

    log_info "Fetching secrets from GCP Secret Manager for environment: $environment"

    # Check gcloud CLI and authentication
    if ! _check_gcloud_cli; then
        error_with_context "AUTH" "Google Cloud CLI not available or not authenticated"
        return 1
    fi

    # Check project configuration
    local project_id
    project_id=$(_get_gcp_project_id)
    if [[ -z "$project_id" ]]; then
        log_error "GCP project ID not configured"
        log_info "Set DEV_ENV_MANAGER_SECRET_MANAGER_PROJECT_ID environment variable"
        return 1
    fi

    # Ensure Secret Manager API is enabled
    if ! _ensure_secret_manager_api; then
        error_with_context "AUTH" "Secret Manager API not available"
        return 1
    fi

    # Get secret name for environment
    local secret_name
    secret_name=$(_get_gcp_secret_name "$environment")

    log_debug "Using GCP project: $project_id, secret: $secret_name"

    # Check if secret exists
    if ! _gcp_secret_exists "$secret_name"; then
        log_error "Secret not found in GCP Secret Manager: $secret_name"
        log_info "Available secrets:"
        _list_gcp_secrets | while read -r secret; do
            log_info "  - $secret"
        done
        return 1
    fi

    # Fetch secret value
    local secret_string
    secret_string=$(_get_gcp_secret_value "$secret_name")

    if [[ $? -ne 0 ]] || [[ -z "$secret_string" ]]; then
        error_with_context "NETWORK" "Failed to fetch secret from GCP Secret Manager"
        return 1
    fi

    # Parse and return secret as JSON
    local parsed_secrets
    parsed_secrets=$(_parse_gcp_secret_string "$secret_string")

    if [[ $? -eq 0 ]] && [[ -n "$parsed_secrets" ]]; then
        local secret_count
        secret_count=$(echo "$parsed_secrets" | jq 'length' 2>/dev/null || echo "unknown")
        log_success "Secrets fetched successfully from GCP Secret Manager ($secret_count secrets)"
        echo "$parsed_secrets"
        return 0
    else
        log_error "Failed to parse secret string from GCP Secret Manager"
        return 1
    fi
}

# Test GCP Secret Manager connection and authentication
test_gcp_connection() {
    echo "Testing GCP Secret Manager Connection:"
    echo "====================================="

    # Check gcloud CLI installation
    if command -v gcloud >/dev/null 2>&1; then
        local version
        version=$(gcloud version --format="value(Google Cloud SDK)" 2>/dev/null)
        echo "✅ Google Cloud CLI installed: $version"
    else
        echo "❌ Google Cloud CLI not installed"
        echo "   Install from: https://cloud.google.com/sdk/docs/install"
        return 1
    fi

    # Check authentication
    local account_info
    account_info=$(_get_gcp_account_info 2>/dev/null)
    if [[ $? -eq 0 ]]; then
        echo "✅ Google Cloud Authentication: OK"
        echo "   $account_info"
    else
        echo "❌ Google Cloud Authentication: Failed"
        echo "   Login with: gcloud auth login"
        return 1
    fi

    # Check project configuration
    local project_id
    project_id=$(_get_gcp_project_id)

    if [[ -n "$project_id" ]]; then
        echo "✅ Project configured: $project_id"
    else
        echo "❌ Project not configured"
        echo "   Set DEV_ENV_MANAGER_SECRET_MANAGER_PROJECT_ID or run: gcloud config set project PROJECT_ID"
        return 1
    fi

    # Test Secret Manager API
    echo "🔍 Testing Secret Manager API..."

    if ! _ensure_secret_manager_api; then
        echo "❌ Secret Manager API not available"
        return 1
    fi

    if gcloud secrets list --project="$project_id" --limit=1 >/dev/null 2>&1; then
        echo "✅ Secret Manager API access: OK"
    else
        echo "❌ Secret Manager API access: Failed"
        echo "   Ensure API is enabled and you have required IAM permissions"
        return 1
    fi

    # Test environment access
    local current_environment
    current_environment=$(get_current_environment)
    local secret_name
    secret_name=$(_get_gcp_secret_name "$current_environment")

    echo "🔍 Testing environment access: $current_environment"
    echo "   Secret name: $secret_name"

    if _gcp_secret_exists "$secret_name"; then
        echo "✅ Environment secret exists"

        # Test read permission
        if _get_gcp_secret_value "$secret_name" >/dev/null 2>&1; then
            echo "✅ Read permission: OK"
        else
            echo "❌ Read permission: Failed"
            echo "   Ensure you have 'Secret Manager Secret Accessor' role"
            return 1
        fi
    else
        echo "⚠️  Environment secret not found: $secret_name"
        echo "   Available secrets:"
        _list_gcp_secrets | head -5 | while read -r secret; do
            echo "     - $secret"
        done
    fi

    echo "🎉 GCP Secret Manager connection test completed!"
    return 0
}

# Export functions for use in other modules
export -f fetch_gcp_secrets test_gcp_connection
