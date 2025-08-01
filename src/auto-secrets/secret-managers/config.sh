#!/bin/bash
# Auto Secrets Manager - Secret Manager Specific Configuration
# This template uses the parsed configuration values from config.sh

# The SECRET_MANAGER_* variables are already set by the config parser in config.sh
# This file provides backwards compatibility and additional secret manager specific setup

case "$DEV_ENV_MANAGER_SECRET_MANAGER" in
"infisical")
  # Use parsed configuration values or fall back to environment variables
  export DEV_ENV_MANAGER_SECRET_MANAGER_PROJECT_ID="${DEV_ENV_MANAGER_SECRET_MANAGER_PROJECT_ID:-${INFISICAL_PROJECT_ID:-}}"
  export DEV_ENV_MANAGER_SECRET_MANAGER_BASE_URL="${DEV_ENV_MANAGER_SECRET_MANAGER_BASE_URL:-https://app.infisical.com}"
  export DEV_ENV_MANAGER_SECRET_MANAGER_AUTH_METHOD="${DEV_ENV_MANAGER_SECRET_MANAGER_AUTH_METHOD:-universal-auth}"
  export DEV_ENV_MANAGER_SECRET_MANAGER_CLIENT_ID="${DEV_ENV_MANAGER_SECRET_MANAGER_CLIENT_ID:-${INFISICAL_CLIENT_ID:-}}"
  ;;
"vault")
  # Set Vault-specific variables and use parsed config
  export DEV_ENV_MANAGER_SECRET_MANAGER_MOUNT="${DEV_ENV_MANAGER_SECRET_MANAGER_MOUNT:-${VAULT_KV_PATH:-secret}}"
  export DEV_ENV_MANAGER_SECRET_MANAGER_KV_VERSION="${DEV_ENV_MANAGER_SECRET_MANAGER_KV_VERSION:-${VAULT_KV_VERSION:-2}}"
  ;;
"aws")
  # Use parsed config for AWS
  export DEV_ENV_MANAGER_AWS_REGION="${DEV_ENV_MANAGER_SECRET_MANAGER_REGION:-${AWS_REGION:-us-east-1}}"
  export DEV_ENV_MANAGER_SECRET_MANAGER_REGION="${DEV_ENV_MANAGER_SECRET_MANAGER_REGION:-${AWS_REGION:-us-east-1}}"
  export DEV_ENV_MANAGER_SECRET_MANAGER_SECRET_PREFIX="${DEV_ENV_MANAGER_SECRET_MANAGER_SECRET_PREFIX:-dev-env-secrets}"
  ;;
"azure")
  # Use parsed config for Azure
  export DEV_ENV_MANAGER_SECRET_MANAGER_BASE_URL="${DEV_ENV_MANAGER_SECRET_MANAGER_BASE_URL:-${AZURE_KEYVAULT_URL:-}}"
  export DEV_ENV_MANAGER_SECRET_MANAGER_SECRET_PREFIX="${DEV_ENV_MANAGER_SECRET_MANAGER_SECRET_PREFIX:-dev-env-secrets}"
  ;;
"gcp")
  # Use parsed config for GCP
  export DEV_ENV_MANAGER_SECRET_MANAGER_PROJECT_ID="${DEV_ENV_MANAGER_SECRET_MANAGER_PROJECT_ID:-${GCP_PROJECT_ID:-${GOOGLE_CLOUD_PROJECT:-}}}"
  export DEV_ENV_MANAGER_SECRET_MANAGER_SECRET_PREFIX="${DEV_ENV_MANAGER_SECRET_MANAGER_SECRET_PREFIX:-dev-env-secrets}"
  ;;
"bitwarden")
  # Use parsed config for Bitwarden
  export DEV_ENV_MANAGER_SECRET_MANAGER_BASE_URL="${DEV_ENV_MANAGER_SECRET_MANAGER_BASE_URL:-${BW_SERVER_URL:-https://vault.bitwarden.com}}"
  export DEV_ENV_MANAGER_SECRET_MANAGER_ORG_ID="${DEV_ENV_MANAGER_SECRET_MANAGER_ORG_ID:-${BW_ORG_ID:-}}"
  export DEV_ENV_MANAGER_SECRET_MANAGER_SECRET_PREFIX="${DEV_ENV_MANAGER_SECRET_MANAGER_SECRET_PREFIX:-dev-env-secrets}"
  ;;
*)
  # Default or unsupported secret manager
  if command -v log_warn >/dev/null 2>&1; then
    log_warn "Unknown secret manager: $DEV_ENV_MANAGER_SECRET_MANAGER"
  else
    echo "Warning: Unknown secret manager: $DEV_ENV_MANAGER_SECRET_MANAGER" >&2
  fi
  ;;
esac

# Validate that required variables are set
case "$DEV_ENV_MANAGER_SECRET_MANAGER" in
"infisical")
  if [[ -z "$DEV_ENV_MANAGER_SECRET_MANAGER_PROJECT_ID" ]]; then
    echo "Error: DEV_ENV_MANAGER_SECRET_MANAGER_PROJECT_ID not configured for Infisical" >&2
  fi
  ;;
"gcp")
  if [[ -z "$SECRET_MANAGER_PROJECT_ID" ]]; then
    echo "Error: DEV_ENV_MANAGER_SECRET_MANAGER_PROJECT_ID not configured for GCP" >&2
  fi
  ;;
"azure")
  if [[ -z "$SECRET_MANAGER_BASE_URL" ]]; then
    echo "Error: DEV_ENV_MANAGER_SECRET_MANAGER_BASE_URL not configured for Azure Key Vault" >&2
  fi
  ;;
esac
