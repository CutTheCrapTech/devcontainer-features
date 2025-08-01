#!/bin/bash
# Auto Secrets Manager - Bitwarden Integration
# Handles fetching secrets from Bitwarden with authentication and error handling

# Get Bitwarden server URL from configuration
_get_bitwarden_server_url() {
  local server_url="${DEV_ENV_MANAGER_SECRET_MANAGER_BASE_URL:-${BW_SERVER_URL:-https://vault.bitwarden.com}}"

  # Expand environment variables
  if [[ "$server_url" =~ ^\$\{.*\}$ ]]; then
    local var_name="${server_url#\$\{}"
    var_name="${var_name%\}}"
    server_url="${!var_name}"
  fi

  echo "$server_url"
}

# Get Bitwarden organization ID from configuration
_get_bitwarden_org_id() {
  echo "${DEV_ENV_MANAGER_SECRET_MANAGER_ORG_ID:-${BW_ORG_ID:-}}"
}

# Get secret item name prefix from configuration
_get_bitwarden_item_prefix() {
  echo "${DEV_ENV_MANAGER_SECRET_MANAGER_SECRET_PREFIX:-dev-env-secrets}"
}

# Check if Bitwarden CLI is available and properly configured
_check_bitwarden_cli() {
  if ! command -v bw >/dev/null 2>&1; then
    log_error "Bitwarden CLI not found. Please install Bitwarden CLI"
    return 1
  fi

  # Check Bitwarden CLI version
  local bw_version
  bw_version=$(bw --version 2>/dev/null)
  if [[ -n "$bw_version" ]]; then
    log_debug "Bitwarden CLI version: $bw_version"
  fi

  # Check if server is configured
  local server_url
  server_url=$(_get_bitwarden_server_url)
  if [[ "$server_url" != "https://vault.bitwarden.com" ]]; then
    bw config server "$server_url" >/dev/null 2>&1
    log_debug "Configured Bitwarden server: $server_url"
  fi

  log_debug "Bitwarden CLI check passed"
  return 0
}

# Check if user is authenticated with Bitwarden
_check_bitwarden_auth() {
  if [[ -z "$BW_SESSION" ]]; then
    log_debug "No BW_SESSION environment variable found"
    return 1
  fi

  # Test session by trying to list items
  if bw list items --session "$BW_SESSION" >/dev/null 2>&1; then
    log_debug "Bitwarden session is valid"
    return 0
  else
    log_debug "Bitwarden session is invalid or expired"
    return 1
  fi
}

# Get Bitwarden user status
_get_bitwarden_status() {
  bw status --session "${BW_SESSION:-}" 2>/dev/null | jq -r '.status // "unauthenticated"'
}

# Authenticate with Bitwarden and get session token
_authenticate_bitwarden_session() {
  local email="${BW_EMAIL:-}"
  local password="${BW_PASSWORD:-}"
  local client_id="${BW_CLIENT_ID:-}"
  local client_secret="${BW_CLIENT_SECRET:-}"

  log_info "Authenticating with Bitwarden..."

  # Check if already authenticated
  if _check_bitwarden_auth; then
    log_debug "Already authenticated with Bitwarden"
    return 0
  fi

  # Try API key authentication first (recommended for automation)
  if [[ -n "$client_id" ]] && [[ -n "$client_secret" ]]; then
    log_debug "Attempting API key authentication"

    local session_token
    if session_token=$(bw login --apikey --raw 2>/dev/null); then
      export BW_SESSION="$session_token"
      log_success "Bitwarden API key authentication successful"
      return 0
    fi
  fi

  # Try password authentication
  if [[ -n "$email" ]] && [[ -n "$password" ]]; then
    log_debug "Attempting password authentication"

    local session_token
    if session_token=$(echo "$password" | bw login "$email" --raw 2>/dev/null); then
      export BW_SESSION="$session_token"
      log_success "Bitwarden password authentication successful"
      return 0
    fi
  fi

  # Check if user is already logged in but needs to unlock
  local status
  status=$(_get_bitwarden_status)

  if [[ "$status" == "locked" ]]; then
    log_info "Bitwarden vault is locked, attempting to unlock..."

    if [[ -n "$password" ]]; then
      local session_token
      if session_token=$(echo "$password" | bw unlock --raw 2>/dev/null); then
        export BW_SESSION="$session_token"
        log_success "Bitwarden vault unlocked successfully"
        return 0
      fi
    fi
  fi

  log_error "Bitwarden authentication failed"
  return 1
}

# Construct item name for environment
_get_bitwarden_item_name() {
  local environment="$1"
  local prefix
  prefix=$(_get_bitwarden_item_prefix)

  echo "${prefix}-${environment}"
}

# Search for items with the configured prefix
_list_bitwarden_items() {
  local prefix
  prefix=$(_get_bitwarden_item_prefix)
  local org_id
  org_id=$(_get_bitwarden_org_id)

  log_debug "Listing Bitwarden items with prefix: $prefix"

  local bw_args=("list" "items" "--search" "$prefix" "--session" "$BW_SESSION")

  # Add organization filter if specified
  if [[ -n "$org_id" ]]; then
    bw_args+=("--organizationid" "$org_id")
  fi

  bw "${bw_args[@]}" 2>/dev/null | jq -r '.[].name // empty' | sort
}

# Check if item exists in Bitwarden
_bitwarden_item_exists() {
  local item_name="$1"
  local org_id
  org_id=$(_get_bitwarden_org_id)

  local bw_args=("get" "item" "$item_name" "--session" "$BW_SESSION")

  if [[ -n "$org_id" ]]; then
    bw_args+=("--organizationid" "$org_id")
  fi

  bw "${bw_args[@]}" >/dev/null 2>&1
}

# Get item from Bitwarden
_get_bitwarden_item() {
  local item_name="$1"
  local org_id
  org_id=$(_get_bitwarden_org_id)

  log_network "Fetching item from Bitwarden: $item_name"

  local bw_args=("get" "item" "$item_name" "--session" "$BW_SESSION")

  if [[ -n "$org_id" ]]; then
    bw_args+=("--organizationid" "$org_id")
  fi

  local item_response
  item_response=$(bw "${bw_args[@]}" 2>&1)

  local exit_code=$?

  if [[ $exit_code -eq 0 ]]; then
    echo "$item_response"
    return 0
  else
    log_error "Failed to retrieve item: $item_name"
    log_debug "Bitwarden response: $item_response"

    # Parse common error types
    if [[ "$item_response" =~ "Not found" ]]; then
      log_error "Item not found: $item_name"
    elif [[ "$item_response" =~ "You are not authorized" ]] || [[ "$item_response" =~ "Access denied" ]]; then
      log_error "Access denied - check Bitwarden permissions"
    elif [[ "$item_response" =~ "Vault is locked" ]]; then
      log_error "Bitwarden vault is locked"
    fi

    return 1
  fi
}

# Extract secrets from Bitwarden item
_extract_secrets_from_item() {
  local item_json="$1"

  if [[ -z "$item_json" ]]; then
    log_error "Empty item JSON"
    return 1
  fi

  local secrets_object="{}"

  # Extract from notes field (key=value format)
  local notes
  notes=$(echo "$item_json" | jq -r '.notes // ""')

  if [[ -n "$notes" ]]; then
    # Parse notes as key=value pairs
    while IFS='=' read -r key value; do
      # Skip empty lines and comments
      [[ -z "$key" ]] || [[ "$key" =~ ^# ]] && continue

      # Remove leading/trailing whitespace
      key=$(echo "$key" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
      value=$(echo "$value" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')

      # Add to secrets object
      if [[ -n "$key" ]] && [[ -n "$value" ]]; then
        secrets_object=$(echo "$secrets_object" | jq --arg k "$key" --arg v "$value" '. + {($k): $v}')
      fi
    done <<<"$notes"
  fi

  # Extract from custom fields
  local custom_fields
  custom_fields=$(echo "$item_json" | jq -r '.fields[]? // empty')

  if [[ -n "$custom_fields" ]]; then
    while read -r field; do
      local field_name
      field_name=$(echo "$field" | jq -r '.name // ""')
      local field_value
      field_value=$(echo "$field" | jq -r '.value // ""')

      if [[ -n "$field_name" ]] && [[ -n "$field_value" ]]; then
        secrets_object=$(echo "$secrets_object" | jq --arg k "$field_name" --arg v "$field_value" '. + {($k): $v}')
      fi
    done <<<"$(echo "$item_json" | jq -c '.fields[]? // empty')"
  fi

  # Extract username and password if they exist and are relevant
  local username
  username=$(echo "$item_json" | jq -r '.login.username // ""')
  local password
  password=$(echo "$item_json" | jq -r '.login.password // ""')

  if [[ -n "$username" ]]; then
    secrets_object=$(echo "$secrets_object" | jq --arg v "$username" '. + {"USERNAME": $v}')
  fi

  if [[ -n "$password" ]]; then
    secrets_object=$(echo "$secrets_object" | jq --arg v "$password" '. + {"PASSWORD": $v}')
  fi

  echo "$secrets_object"
}

# Authenticate with Bitwarden (wrapper function)
_authenticate_bitwarden() {
  log_info "🔑 Attempting Bitwarden authentication..."

  if ! command -v bw >/dev/null 2>&1; then
    log_error "Bitwarden CLI not installed"
    return 1
  fi

  if _authenticate_bitwarden_session; then
    log_success "Bitwarden authentication successful"
    return 0
  else
    log_error "Bitwarden authentication failed"
    return 1
  fi
}

# Main function to fetch secrets from Bitwarden
fetch_bitwarden_secrets() {
  local environment="$1"

  # Validate environment
  if [[ -z "$environment" ]]; then
    log_error "Environment not specified for Bitwarden secrets fetch"
    return 1
  fi

  if ! is_valid_environment "$environment"; then
    log_error "Invalid environment name: $environment"
    return 1
  fi

  log_info "Fetching secrets from Bitwarden for environment: $environment"

  # Check Bitwarden CLI
  if ! _check_bitwarden_cli; then
    error_with_context "AUTH" "Bitwarden CLI not available"
    return 1
  fi

  # Authenticate if needed
  if ! _check_bitwarden_auth; then
    if ! _authenticate_bitwarden_session; then
      error_with_context "AUTH" "Bitwarden authentication failed"
      return 1
    fi
  fi

  # Get item name for environment
  local item_name
  item_name=$(_get_bitwarden_item_name "$environment")

  log_debug "Using Bitwarden item name: $item_name"

  # Check if item exists
  if ! _bitwarden_item_exists "$item_name"; then
    log_error "Item not found in Bitwarden: $item_name"
    log_info "Available items:"
    _list_bitwarden_items | while read -r item; do
      log_info "  - $item"
    done
    return 1
  fi

  # Fetch item
  local item_json
  if item_json=$(_get_bitwarden_item "$item_name"); then
    error_with_context "NETWORK" "Failed to fetch item from Bitwarden"
    return 1
  fi

  # Extract secrets from item
  local parsed_secrets

  if parsed_secrets=$(_extract_secrets_from_item "$item_json"); then
    local secret_count
    secret_count=$(echo "$parsed_secrets" | jq 'length' 2>/dev/null || echo "unknown")
    log_success "Secrets fetched successfully from Bitwarden ($secret_count secrets)"
    echo "$parsed_secrets"
    return 0
  else
    log_error "Failed to extract secrets from Bitwarden item"
    return 1
  fi
}

# Test Bitwarden connection and authentication
test_bitwarden_connection() {
  echo "Testing Bitwarden Connection:"
  echo "============================="

  # Check Bitwarden CLI installation
  if command -v bw >/dev/null 2>&1; then
    local version
    version=$(bw --version 2>/dev/null)
    echo "✅ Bitwarden CLI installed: $version"
  else
    echo "❌ Bitwarden CLI not installed"
    echo "   Install from: https://bitwarden.com/help/cli/"
    return 1
  fi

  # Check server configuration
  local server_url
  server_url=$(_get_bitwarden_server_url)
  echo "✅ Server configured: $server_url"

  # Check authentication
  if _check_bitwarden_auth; then
    echo "✅ Bitwarden Authentication: OK"

    local status
    status=$(_get_bitwarden_status)
    echo "   Status: $status"
  else
    echo "❌ Bitwarden Authentication: Failed"

    # Try to authenticate
    if _authenticate_bitwarden_session; then
      echo "✅ Authentication successful after retry"
    else
      echo "   Configure authentication with environment variables:"
      echo "   - BW_EMAIL and BW_PASSWORD (interactive)"
      echo "   - BW_CLIENT_ID and BW_CLIENT_SECRET (API key, recommended)"
      return 1
    fi
  fi

  # Test organization access if configured
  local org_id
  org_id=$(_get_bitwarden_org_id)
  if [[ -n "$org_id" ]]; then
    echo "✅ Organization configured: $org_id"
  fi

  # Test item access
  echo "🔍 Testing item access..."

  if bw list items --session "$BW_SESSION" >/dev/null 2>&1; then
    echo "✅ List items permission: OK"
  else
    echo "❌ List items permission: Failed"
    return 1
  fi

  # Test environment access
  local current_environment
  current_environment=$(get_current_environment)
  local item_name
  item_name=$(_get_bitwarden_item_name "$current_environment")

  echo "🔍 Testing environment access: $current_environment"
  echo "   Item name: $item_name"

  if _bitwarden_item_exists "$item_name"; then
    echo "✅ Environment item exists"

    # Test read permission
    if _get_bitwarden_item "$item_name" >/dev/null 2>&1; then
      echo "✅ Read permission: OK"
    else
      echo "❌ Read permission: Failed"
      return 1
    fi
  else
    echo "⚠️  Environment item not found: $item_name"
    echo "   Available items:"
    _list_bitwarden_items | head -5 | while read -r item; do
      echo "     - $item"
    done
  fi

  echo "🎉 Bitwarden connection test completed!"
  return 0
}

# Export functions for use in other modules
export -f fetch_bitwarden_secrets authenticate_bitwarden test_bitwarden_connection
