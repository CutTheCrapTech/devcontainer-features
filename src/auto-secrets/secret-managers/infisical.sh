#!/bin/bash
# Auto Secrets Manager - Infisical Secret Manager Integration
# Handles fetching secrets from Infisical with authentication and error handling

# Fetch secrets for environment using CLI
_fetch_secrets_with_cli() {
  local environment="$1"
  local project_id="$DEV_ENV_MANAGER_SECRET_MANAGER_PROJECT_ID"

  if [[ -z "$project_id" ]]; then
    log_error "Infisical project ID not configured"
    return 1
  fi

  log_network "Fetching secrets from Infisical using CLI (env: $environment, project: $project_id)"

  # Use Infisical CLI to export secrets
  local secrets_output
  local exit_code

  secrets_output=$(infisical export --projectId="$project_id" --env="$environment" --format=json 2>&1)
  exit_code=$?
  if [[ $exit_code -eq 0 ]]; then
    # Transform the JSON array into a key-value object
    echo "$secrets_output" | jq 'map({key: (.secretPath + "/" + .key), value: .value}) | from_entries'
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

# Authenticate with Infisical if universal auth is configured
authenticate_infisical() {
  log_info "🔑 Attempting Infisical authentication..."

  local infisical_domain="$DEV_ENV_MANAGER_SECRET_MANAGER_DOMAIN"
  local infisical_client_id="$DEV_ENV_MANAGER_SECRET_MANAGER_CLIENT_ID"
  # shellcheck disable=SC2153
  local infisical_client_secret="${INFISICAL_CLIENT_SECRET}"

  if [[ "$DEV_ENV_MANAGER_SECRET_MANAGER_AUTH_METHOD" == "universal-auth" ]]; then
    if [[ -z "$infisical_domain" ]]; then
      log_error "Infisical universal authentication requires 'domain' to be set in devcontainer-feature.json options."
      return 1
    fi

    if [[ -z "$infisical_client_id" ]]; then
      log_error "Infisical universal authentication requires 'clientId' to be set in devcontainer-feature.json options."
      return 1
    fi

    if [[ -z "$infisical_client_secret" ]]; then
      log_error "Infisical universal authentication requires 'clientSecret' to be set via INFISICAL_CLIENT_SECRET environment variable."
      return 1
    fi

    log_info "Attempting Infisical universal authentication with client ID: $infisical_client_id"
    local infisical_token_raw
    if infisical_token_raw=$(infisical login --method=universal-auth --domain="$infisical_domain" --client-id="$infisical_client_id" --client-secret="$infisical_client_secret" --silent --plain 2>&1); then
      export INFISICAL_TOKEN="$infisical_token_raw"
      log_success "Infisical universal authentication successful."
      return 0
    else
      log_error "Infisical universal authentication failed. Output: $infisical_token_raw"
      return 1
    fi
  else
    log_info "Only universal authentication is implemented for infisical currently."
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
  if secrets_content=$(_fetch_secrets_with_cli "$environment"); then
    log_success "Secrets fetched successfully using CLI ($(echo "$secrets_content" | wc -l) secrets)"
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
  local project_id="$DEV_ENV_MANAGER_SECRET_MANAGER_PROJECT_ID"
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
export -f fetch_infisical_secrets authenticate_infisical test_infisical_connection
