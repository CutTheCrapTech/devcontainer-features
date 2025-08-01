#!/bin/bash
# Auto Secrets Manager - Secret Manager Interface
# Provides a common interface for all secret manager implementations

# Current secret manager
CURRENT_SECRET_MANAGER=""

# Load secret manager implementation
_load_secret_manager() {
  local manager="${1:-$DEV_ENV_MANAGER_SECRET_MANAGER}"

  if [[ "$manager" == "$CURRENT_SECRET_MANAGER" ]]; then
    log_debug "Secret manager already loaded: $manager"
    return 0
  fi

  log_debug "Loading secret manager: $manager"

  case "$manager" in
  "infisical")
    # All secret managers are already loaded by init.sh
    CURRENT_SECRET_MANAGER="infisical"
    log_debug "Infisical secret manager loaded"
    ;;
  "vault")
    # All secret managers are already loaded by init.sh
    CURRENT_SECRET_MANAGER="vault"
    log_debug "Vault secret manager loaded"
    ;;
  "aws")
    # All secret managers are already loaded by init.sh
    CURRENT_SECRET_MANAGER="aws"
    log_debug "AWS Secrets Manager loaded"
    ;;
  "azure")
    # All secret managers are already loaded by init.sh
    CURRENT_SECRET_MANAGER="azure"
    log_debug "Azure Key Vault loaded"
    ;;
  "gcp")
    # All secret managers are already loaded by init.sh
    CURRENT_SECRET_MANAGER="gcp"
    log_debug "GCP Secret Manager loaded"
    ;;
  "bitwarden")
    # All secret managers are already loaded by init.sh
    CURRENT_SECRET_MANAGER="bitwarden"
    log_debug "Bitwarden loaded"
    ;;
  *)
    log_error "Unknown secret manager: $manager"
    return 1
    ;;
  esac

  return 0
}

# Generic function to fetch secrets from current manager
fetch_secrets_from_manager() {
  local environment="$1"

  if [[ -z "$CURRENT_SECRET_MANAGER" ]]; then
    if ! _load_secret_manager; then
      log_error "No secret manager loaded"
      return 1
    fi
  fi

  log_debug "Fetching secrets using $CURRENT_SECRET_MANAGER manager"

  # Call the specific implementation
  case "$CURRENT_SECRET_MANAGER" in
  "infisical")
    fetch_infisical_secrets "$environment"
    ;;
  "vault")
    fetch_vault_secrets "$environment"
    ;;
  "aws")
    fetch_aws_secrets "$environment"
    ;;
  "azure")
    fetch_azure_secrets "$environment"
    ;;
  "gcp")
    fetch_gcp_secrets "$environment"
    ;;
  "bitwarden")
    fetch_bitwarden_secrets "$environment"
    ;;
  *)
    log_error "No fetch function available for manager: $CURRENT_SECRET_MANAGER"
    return 1
    ;;
  esac
}

# Generic function to test secret manager connection
test_secret_manager_connection() {
  if [[ -z "$CURRENT_SECRET_MANAGER" ]]; then
    if ! _load_secret_manager; then
      log_error "No secret manager loaded"
      return 1
    fi
  fi

  log_debug "Testing connection for $CURRENT_SECRET_MANAGER manager"

  # Call the specific implementation
  case "$CURRENT_SECRET_MANAGER" in
  "infisical")
    test_infisical_connection
    ;;
  "vault")
    test_vault_connection
    ;;
  "aws")
    test_aws_connection
    ;;
  "azure")
    test_azure_connection
    ;;
  "gcp")
    test_gcp_connection
    ;;
  "bitwarden")
    test_bitwarden_connection
    ;;
  *)
    log_error "No test function available for manager: $CURRENT_SECRET_MANAGER"
    return 1
    ;;
  esac
}

# Check if current manager supports a specific feature
manager_supports_feature() {
  local feature="$1"

  if [[ -z "$CURRENT_SECRET_MANAGER" ]]; then
    return 1
  fi

  case "$CURRENT_SECRET_MANAGER" in
  "infisical")
    case "$feature" in
    "path_filtering" | "environment_isolation" | "cli_support")
      return 0
      ;;
    *)
      return 1
      ;;
    esac
    ;;
  "vault")
    case "$feature" in
    "path_filtering" | "environment_isolation" | "cli_support" | "kv_versioning")
      return 0
      ;;
    *)
      return 1
      ;;
    esac
    ;;
  "aws")
    case "$feature" in
    "path_filtering" | "environment_isolation" | "versioning")
      return 0
      ;;
    *)
      return 1
      ;;
    esac
    ;;
  "azure")
    case "$feature" in
    "environment_isolation" | "versioning")
      return 0
      ;;
    *)
      return 1
      ;;
    esac
    ;;
  "gcp")
    case "$feature" in
    "path_filtering" | "environment_isolation" | "versioning")
      return 0
      ;;
    *)
      return 1
      ;;
    esac
    ;;
  "bitwarden")
    case "$feature" in
    "environment_isolation" | "organization_support")
      return 0
      ;;
    *)
      return 1
      ;;
    esac
    ;;
  *)
    return 1
    ;;
  esac
}

# Get manager-specific configuration
get_manager_config() {
  local config_key="$1"

  if [[ -z "$CURRENT_SECRET_MANAGER" ]]; then
    return 1
  fi

  case "$CURRENT_SECRET_MANAGER" in
  "infisical")
    case "$config_key" in
    "base_url")
      get_infisical_base_url
      ;;
    "project_id")
      get_infisical_project_id
      ;;
    *)
      return 1
      ;;
    esac
    ;;
  "vault")
    case "$config_key" in
    "address")
      get_vault_address
      ;;
    "mount")
      echo "${DEV_ENV_MANAGER_SECRET_MANAGER_MOUNT:-secret}"
      ;;
    *)
      return 1
      ;;
    esac
    ;;
  "aws")
    case "$config_key" in
    "region")
      echo "${AWS_REGION:-us-east-1}"
      ;;
    *)
      return 1
      ;;
    esac
    ;;
  "azure")
    case "$config_key" in
    "vault_url")
      echo "$DEV_ENV_MANAGER_SECRET_MANAGER_BASE_URL"
      ;;
    *)
      return 1
      ;;
    esac
    ;;
  "gcp")
    case "$config_key" in
    "project_id")
      echo "${GCP_PROJECT_ID:-$SECRET_MANAGER_PROJECT_ID}"
      ;;
    *)
      return 1
      ;;
    esac
    ;;
  "bitwarden")
    case "$config_key" in
    "server_url")
      echo "${BW_SERVER_URL:-$SECRET_MANAGER_BASE_URL}"
      ;;
    "org_id")
      echo "${BW_ORG_ID:-$SECRET_MANAGER_ORG_ID}"
      ;;
    *)
      return 1
      ;;
    esac
    ;;
  *)
    return 1
    ;;
  esac
}

# Show current manager status
show_manager_status() {
  echo "Secret Manager Status:"
  echo "====================="

  if [[ -n "$CURRENT_SECRET_MANAGER" ]]; then
    echo "  Active Manager: $CURRENT_SECRET_MANAGER"

    # Show manager-specific status
    case "$CURRENT_SECRET_MANAGER" in
    "infisical")
      echo "  Base URL: $(get_manager_config base_url)"
      echo "  Project ID: $(get_manager_config project_id)"
      ;;
    "vault")
      echo "  Address: $(get_manager_config address)"
      echo "  Mount: $(get_manager_config mount)"
      ;;
    "aws")
      echo "  Region: $(get_manager_config region)"
      ;;
    "azure")
      echo "  Vault URL: $(get_manager_config vault_url)"
      ;;
    "gcp")
      echo "  Project ID: $(get_manager_config project_id)"
      ;;
    "bitwarden")
      echo "  Server URL: $(get_manager_config server_url)"
      echo "  Organization ID: $(get_manager_config org_id)"
      ;;
    esac

    # Show supported features
    echo "  Features:"
    local features=("path_filtering" "environment_isolation" "cli_support" "versioning" "kv_versioning")
    for feature in "${features[@]}"; do
      if manager_supports_feature "$feature"; then
        echo "    ✅ $feature"
      else
        echo "    ❌ $feature"
      fi
    done
  else
    echo "  No manager loaded"
    echo "  Configured: ${DEV_ENV_MANAGER_SECRET_MANAGER:-not set}"
  fi
}

# Initialize manager interface
init_manager_interface() {
  local manager="${DEV_ENV_MANAGER_SECRET_MANAGER:-infisical}"

  log_debug "Initializing secret manager interface with: $manager"

  if _load_secret_manager "$manager"; then
    log_debug "Secret manager interface initialized successfully"
    return 0
  else
    log_error "Failed to initialize secret manager interface"
    return 1
  fi
}

# Auto-initialize if not already done
if [[ -z "$CURRENT_SECRET_MANAGER" ]] && [[ -n "$DEV_ENV_MANAGER_SECRET_MANAGER" ]]; then
  init_manager_interface
fi

# Generic function to authenticate with the current secret manager
authenticate_current_secret_manager() {
  if [[ -z "$CURRENT_SECRET_MANAGER" ]]; then
    if ! _load_secret_manager; then
      log_error "No secret manager loaded for authentication"
      return 1
    fi
  fi

  log_debug "Attempting authentication for $CURRENT_SECRET_MANAGER"

  case "$CURRENT_SECRET_MANAGER" in
  "infisical")
    authenticate_infisical
    ;;
  "vault")
    authenticate_vault
    ;;
  "aws")
    log_error "AWS authentication not implemented"
    return 1
    ;;
  "azure")
    log_error "Azure authentication not implemented"
    return 1
    ;;
  "gcp")
    authenticate_gcp
    ;;
  "bitwarden")
    authenticate_bitwarden
    ;;
  *)
    log_warn "No authentication method available for manager: $CURRENT_SECRET_MANAGER"
    return 0
    ;;
  esac
}

# Export functions for use in other modules
export -f fetch_secrets_from_manager test_secret_manager_connection
export -f manager_supports_feature
export -f get_manager_config show_manager_status init_manager_interface
export -f authenticate_current_secret_manager
