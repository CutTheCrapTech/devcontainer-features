#!/bin/bash
# Auto Secrets Manager - Simple Dynamic Initialization
# Sources all modules automatically from directory structure

FEATURE_DIR="{{FEATURE_DIR}}"

# Only initialize if we're in a git repository or if explicitly enabled
if [[ -d .git ]] || [[ "$DEV_ENV_MANAGER_FORCE" == "true" ]]; then
  # Load base configuration first
  if [[ -f "$FEATURE_DIR/config.sh" ]]; then
    # shellcheck source=/dev/null
    source "$FEATURE_DIR/config.sh"
  else
    echo "Error: Auto Secrets Manager configuration not found at $FEATURE_DIR/config.sh" >&2
    return 1
  fi

  # Phase 1: Load utilities (no dependencies)
  if [[ -d "$FEATURE_DIR/utils" ]]; then
    for util_file in "$FEATURE_DIR/utils"/*.sh; do
      # shellcheck source=/dev/null
      [[ -f "$util_file" ]] && source "$util_file"
    done
  fi

  # Phase 2: Load core modules (depend on utils)
  if [[ -d "$FEATURE_DIR/core" ]]; then
    for core_file in "$FEATURE_DIR/core"/*.sh; do
      # shellcheck source=/dev/null
      [[ -f "$core_file" ]] && source "$core_file"
    done
  fi

  # Phase 3: Load secret managers (depend on utils + core)
  if [[ -d "$FEATURE_DIR/secret-managers" ]]; then
    for manager_file in "$FEATURE_DIR/secret-managers"/*.sh; do
      # shellcheck source=/dev/null
      [[ -f "$manager_file" ]] && source "$manager_file"
    done
  fi

  # Phase 4: Load shell integration (depends on everything above)
  if [[ -d "$FEATURE_DIR/shells" ]]; then
    for shell_file in "$FEATURE_DIR/shells"/*.sh; do
      # shellcheck source=/dev/null
      [[ -f "$shell_file" ]] && source "$shell_file"
    done
  fi

  # Initialize the secret manager
  if command -v init_manager_interface >/dev/null 2>&1; then
    if ! init_manager_interface; then
      echo "Error: Failed to initialize secret manager: $DEV_ENV_MANAGER_SECRET_MANAGER" >&2
      return 1
    fi
  fi

  # Initialize environment detection
  if command -v init_environment_detection >/dev/null 2>&1; then
    init_environment_detection
  fi

  # Set up command aliases if configured
  if command -v setup_auto_commands >/dev/null 2>&1; then
    setup_auto_commands
  fi

  # Success indicator
  export DEV_ENV_MANAGER_INITIALIZED=true

  # Validate configuration
  if [[ -f "$FEATURE_DIR/validate-config.sh" ]] && [[ "$DEV_ENV_MANAGER_DEBUG" == "true" ]]; then
    # shellcheck source=/dev/null
    source "$FEATURE_DIR/validate-config.sh"
    if ! validate_runtime_config; then
      echo "Warning: Configuration validation failed" >&2
    fi
  fi

  # Log successful initialization
  if command -v log_debug >/dev/null 2>&1; then
    current_env="unknown"
    if command -v get_current_environment >/dev/null 2>&1; then
      current_env=$(get_current_environment)
    fi
    log_debug "Auto Secrets Manager initialized successfully for environment: $current_env"
  fi

fi
