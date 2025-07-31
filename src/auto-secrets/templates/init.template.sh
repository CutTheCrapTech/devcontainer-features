#!/bin/bash
# Auto Secrets Manager Shell Integration Loader

FEATURE_DIR="{{FEATURE_DIR}}"

# Only initialize if we're in a git repository or if explicitly enabled
if [[ -d .git ]] || [[ "$DEV_ENV_MANAGER_FORCE" == "true" ]]; then
  # Load configuration first
  if [[ -f "$FEATURE_DIR/config.sh" ]]; then
    # shellcheck source=/dev/null
    source "$FEATURE_DIR/config.sh"
  else
    echo "Error: Auto Secrets Manager configuration not found at $FEATURE_DIR/config.sh" >&2
    return 1
  fi

  # Source config parser utilities for runtime use
  if [[ -f "$FEATURE_DIR/utils/config-parser.sh" ]]; then
    # shellcheck source=utils/config-parser.sh
    source "$FEATURE_DIR/utils/config-parser.sh"
  fi

  # Load core modules with error checking
  core_modules=(
    "utils/logging.sh"
    "core/branch-detection.sh"
    "core/environment-mapping.sh"
    "core/permissions.sh"
    "core/cache.sh"
  )

  for module in "${core_modules[@]}"; do
    if [[ -f "$FEATURE_DIR/$module" ]]; then
      # shellcheck source=/dev/null
      source "$FEATURE_DIR/$module"
    else
      echo "Error: Required module not found: $FEATURE_DIR/$module" >&2
      return 1
    fi
  done

  # Load secret manager interface and implementation
  if [[ -f "$FEATURE_DIR/secret-managers/manager-interface.sh" ]]; then
    # shellcheck source=secret-managers/manager-interface.sh
    source "$FEATURE_DIR/secret-managers/manager-interface.sh"
  else
    echo "Error: Secret manager interface not found" >&2
    return 1
  fi

  # Initialize the specific secret manager
  if ! init_manager_interface; then
    echo "Error: Failed to initialize secret manager: $DEV_ENV_MANAGER_SECRET_MANAGER" >&2
    return 1
  fi

  # Load shell-specific integration
  if [[ -n "$ZSH_VERSION" ]] && [[ "$DEV_ENV_MANAGER_SHELLS" =~ (zsh|both) ]]; then
    # shellcheck source=shells/zsh-integration.sh
    source "$FEATURE_DIR/shells/zsh-integration.sh"
  elif [[ -n "$BASH_VERSION" ]] && [[ "$DEV_ENV_MANAGER_SHELLS" =~ (bash|both) ]]; then
    # shellcheck source=shells/bash-integration.sh
    source "$FEATURE_DIR/shells/bash-integration.sh"
  fi

  # Initialize environment detection
  if command -v init_environment_detection >/dev/null 2>&1; then
    init_environment_detection
  fi

  # Set up command aliases if configured
  if command -v setup_auto_commands >/dev/null 2>&1; then
    setup_auto_commands
  fi

  # Log successful initialization
  if command -v log_debug >/dev/null 2>&1; then
    current_env=""
    if command -v get_current_environment >/dev/null 2>&1; then
      current_env=$(get_current_environment)
    else
      current_env="unknown"
    fi
    log_debug "Auto Secrets Manager initialized for environment: $current_env"
  fi
fi
