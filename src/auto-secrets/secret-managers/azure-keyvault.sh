#!/bin/bash
# Auto Secrets Manager - Azure Key Vault Integration
# Handles fetching secrets from Azure Key Vault with authentication and error handling

# Source required modules
if [[ -f "$DEV_ENV_MANAGER_DIR/utils/logging.sh" ]]; then
  # shellcheck source=utils/logging.sh
  source "$DEV_ENV_MANAGER_DIR/utils/logging.sh"
fi

if [[ -f "$DEV_ENV_MANAGER_DIR/core/environment-mapping.sh" ]]; then
  # shellcheck source=core/environment-mapping.sh
  source "$DEV_ENV_MANAGER_DIR/core/environment-mapping.sh"
fi

# Get Azure Key Vault URL from configuration
_get_azure_keyvault_url() {
  local vault_url="${DEV_ENV_MANAGER_SECRET_MANAGER_BASE_URL:-${AZURE_KEYVAULT_URL:-}}"

  # Expand environment variables
  if [[ "$vault_url" =~ ^\$\{.*\}$ ]]; then
    local var_name="${vault_url#\$\{}"
    var_name="${var_name%\}}"
    vault_url="${!var_name}"
  fi

  echo "$vault_url"
}

# Get Azure Key Vault name from URL
_get_azure_keyvault_name() {
  local vault_url
  vault_url=$(_get_azure_keyvault_url)

  if [[ -n "$vault_url" ]]; then
    # Extract vault name from URL (https://vault-name.vault.azure.net/)
    echo "$vault_url" | sed 's|https://||' | sed 's|\.vault\.azure\.net.*||'
  fi
}

# Get secret name prefix from configuration
_get_azure_secret_prefix() {
  echo "${DEV_ENV_MANAGER_SECRET_MANAGER_SECRET_PREFIX:-dev-env-secrets}"
}

# Check if Azure CLI is available and properly configured
_check_azure_cli() {
  if ! command -v az >/dev/null 2>&1; then
    log_error "Azure CLI not found. Please install Azure CLI"
    return 1
  fi

  # Check Azure CLI version
  local az_version
  az_version=$(az version --output tsv --query '"azure-cli"' 2>/dev/null)
  if [[ -n "$az_version" ]]; then
    log_debug "Azure CLI version: $az_version"
  fi

  # Check if user is logged in
  if ! az account show >/dev/null 2>&1; then
    log_error "Not logged in to Azure"
    log_info "Login using: az login"
    return 1
  fi

  log_debug "Azure CLI check passed"
  return 0
}

# Get Azure account information
_get_azure_account_info() {
  if ! az account show --output json 2>/dev/null; then
    echo "Unable to determine Azure account info"
    return 1
  fi
}

# Construct secret name for environment
_get_azure_secret_name() {
  local environment="$1"
  local prefix
  prefix=$(_get_azure_secret_prefix)

  # Azure Key Vault secret names must be alphanumeric and hyphens only
  local clean_prefix="${prefix//[^a-zA-Z0-9-]/}"
  local clean_env="${environment//[^a-zA-Z0-9-]/}"

  echo "${clean_prefix}-${clean_env}"
}

# List all secrets with the configured prefix
_list_azure_secrets() {
  local vault_name
  vault_name=$(_get_azure_keyvault_name)
  local prefix
  prefix=$(_get_azure_secret_prefix)

  if [[ -z "$vault_name" ]]; then
    log_error "Azure Key Vault name not configured"
    return 1
  fi

  log_debug "Listing Azure Key Vault secrets with prefix: $prefix"

  az keyvault secret list \
    --vault-name "$vault_name" \
    --query "[?starts_with(name, '${prefix}-')].name" \
    --output tsv 2>/dev/null | sort
}

# Check if secret exists in Azure Key Vault
_azure_secret_exists() {
  local secret_name="$1"
  local vault_name
  vault_name=$(_get_azure_keyvault_name)

  if [[ -z "$vault_name" ]]; then
    return 1
  fi

  az keyvault secret show \
    --vault-name "$vault_name" \
    --name "$secret_name" \
    >/dev/null 2>&1
}

# Get secret value from Azure Key Vault
_get_azure_secret_value() {
  local secret_name="$1"
  local vault_name
  vault_name=$(_get_azure_keyvault_name)

  if [[ -z "$vault_name" ]]; then
    log_error "Azure Key Vault name not configured"
    return 1
  fi

  log_network "Fetching secret from Azure Key Vault: $secret_name"

  local secret_response
  secret_response=$(az keyvault secret show \
    --vault-name "$vault_name" \
    --name "$secret_name" \
    --output json 2>&1)

  local exit_code=$?

  if [[ $exit_code -eq 0 ]]; then
    # Extract value from response
    echo "$secret_response" | jq -r '.value // empty'
    return 0
  else
    log_error "Failed to retrieve secret: $secret_name"
    log_debug "Azure response: $secret_response"

    # Parse common error types
    if [[ "$secret_response" =~ "SecretNotFound" ]]; then
      log_error "Secret not found: $secret_name"
    elif [[ "$secret_response" =~ "Forbidden" ]] || [[ "$secret_response" =~ "insufficient privileges" ]]; then
      log_error "Access denied - check Azure Key Vault permissions"
    elif [[ "$secret_response" =~ "VaultNotFound" ]]; then
      log_error "Key Vault not found: $vault_name"
    fi

    return 1
  fi
}

# Parse secret string based on format (JSON or key=value)
_parse_azure_secret_string() {
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
    done <<<"$secret_string"

    echo "$json_object"
  fi
}

# Main function to fetch secrets from Azure Key Vault
fetch_azure_secrets() {
  local environment="$1"

  # Validate environment
  if [[ -z "$environment" ]]; then
    log_error "Environment not specified for Azure Key Vault secrets fetch"
    return 1
  fi

  if ! is_valid_environment "$environment"; then
    log_error "Invalid environment name: $environment"
    return 1
  fi

  log_info "Fetching secrets from Azure Key Vault for environment: $environment"

  # Check Azure CLI and authentication
  if ! _check_azure_cli; then
    error_with_context "AUTH" "Azure CLI not available or not authenticated"
    return 1
  fi

  # Check Key Vault configuration
  local vault_name
  vault_name=$(_get_azure_keyvault_name)
  if [[ -z "$vault_name" ]]; then
    log_error "Azure Key Vault name not configured"
    log_info "Set DEV_ENV_MANAGER_SECRET_MANAGER_BASE_URL to your Key Vault URL"
    return 1
  fi

  # Get secret name for environment
  local secret_name
  secret_name=$(_get_azure_secret_name "$environment")

  log_debug "Using Azure Key Vault: $vault_name, secret: $secret_name"

  # Check if secret exists
  if ! _azure_secret_exists "$secret_name"; then
    log_error "Secret not found in Azure Key Vault: $secret_name"
    log_info "Available secrets:"
    _list_azure_secrets | while read -r secret; do
      log_info "  - $secret"
    done
    return 1
  fi

  # Fetch secret value
  local secret_string
  if secret_string=$(_get_azure_secret_value "$secret_name"); then
    error_with_context "NETWORK" "Failed to fetch secret from Azure Key Vault"
    return 1
  fi

  # Parse and return secret as JSON
  local parsed_secrets
  if parsed_secrets=$(_parse_azure_secret_string "$secret_string"); then
    local secret_count
    secret_count=$(echo "$parsed_secrets" | jq 'length' 2>/dev/null || echo "unknown")
    log_success "Secrets fetched successfully from Azure Key Vault ($secret_count secrets)"
    echo "$parsed_secrets"
    return 0
  else
    log_error "Failed to parse secret string from Azure Key Vault"
    return 1
  fi
}

# Test Azure Key Vault connection and authentication
test_azure_connection() {
  echo "Testing Azure Key Vault Connection:"
  echo "=================================="

  # Check Azure CLI installation
  if command -v az >/dev/null 2>&1; then
    local version
    version=$(az version --output tsv --query '"azure-cli"' 2>/dev/null)
    echo "✅ Azure CLI installed: $version"
  else
    echo "❌ Azure CLI not installed"
    echo "   Install from: https://docs.microsoft.com/en-us/cli/azure/install-azure-cli"
    return 1
  fi

  # Check Azure authentication
  local account_info
  if account_info=$(_get_azure_account_info 2>/dev/null); then
    echo "✅ Azure Authentication: OK"
    local user_name
    user_name=$(echo "$account_info" | jq -r '.user.name // "unknown"')
    local subscription_name
    subscription_name=$(echo "$account_info" | jq -r '.name // "unknown"')
    echo "   User: $user_name"
    echo "   Subscription: $subscription_name"
  else
    echo "❌ Azure Authentication: Failed"
    echo "   Login with: az login"
    return 1
  fi

  # Check Key Vault configuration
  local vault_name
  vault_name=$(_get_azure_keyvault_name)
  local vault_url
  vault_url=$(_get_azure_keyvault_url)

  if [[ -n "$vault_name" ]] && [[ -n "$vault_url" ]]; then
    echo "✅ Key Vault configured: $vault_name"
    echo "   URL: $vault_url"
  else
    echo "❌ Key Vault not configured"
    echo "   Set DEV_ENV_MANAGER_SECRET_MANAGER_BASE_URL to your Key Vault URL"
    return 1
  fi

  # Test Key Vault access
  echo "🔍 Testing Key Vault permissions..."

  if az keyvault secret list --vault-name "$vault_name" --max-results 1 >/dev/null 2>&1; then
    echo "✅ List secrets permission: OK"
  else
    echo "❌ List secrets permission: Failed"
    echo "   Ensure you have 'Key Vault Secrets User' or 'Key Vault Administrator' role"
    return 1
  fi

  # Test environment access
  local current_environment
  current_environment=$(get_current_environment)
  local secret_name
  secret_name=$(_get_azure_secret_name "$current_environment")

  echo "🔍 Testing environment access: $current_environment"
  echo "   Secret name: $secret_name"

  if _azure_secret_exists "$secret_name"; then
    echo "✅ Environment secret exists"

    # Test read permission
    if _get_azure_secret_value "$secret_name" >/dev/null 2>&1; then
      echo "✅ Read permission: OK"
    else
      echo "❌ Read permission: Failed"
      echo "   Ensure you have 'Key Vault Secrets User' role"
      return 1
    fi
  else
    echo "⚠️  Environment secret not found: $secret_name"
    echo "   Available secrets:"
    _list_azure_secrets | head -5 | while read -r secret; do
      echo "     - $secret"
    done
  fi

  echo "🎉 Azure Key Vault connection test completed!"
  return 0
}

# Export functions for use in other modules
export -f fetch_azure_secrets test_azure_connection
