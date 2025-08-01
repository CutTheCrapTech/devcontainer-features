#!/bin/bash
# Auto Secrets Manager - Bash Shell Integration
# Provides bash-specific hooks and prompt integration for branch change detection

# Bash-specific configuration
BASH_INTEGRATION_INITIALIZED=false

# Original prompt command backup
ORIGINAL_PROMPT_COMMAND="$PROMPT_COMMAND"

# Branch change detection function for bash
_bash_check_environment_change() {
  # Only run if we're in a git repository
  if ! is_in_git_repo; then
    return 0
  fi

  # Check if branch has changed
  local current_branch
  current_branch=$(get_current_branch)

  if [[ "$current_branch" != "$LAST_KNOWN_BRANCH" ]]; then
    log_debug "Branch change detected in bash: $LAST_KNOWN_BRANCH -> $current_branch"

    # Update cached branch
    export LAST_KNOWN_BRANCH="$current_branch"

    # Update environment
    local new_environment
    new_environment=$(get_current_environment_with_override)

    if [[ "$new_environment" != "$CURRENT_ENVIRONMENT" ]]; then
      export CURRENT_ENVIRONMENT="$new_environment"
      log_info "Environment changed: $CURRENT_ENVIRONMENT -> $new_environment"

      # Clear branch cache to force refresh
      clear_branch_cache
      clear_environment_cache

      # Auto-refresh secrets if configured
      if [[ "$DEV_ENV_MANAGER_CACHE_BACKGROUND_REFRESH" == "true" ]]; then
        (refresh_secrets >/dev/null 2>&1 &)
      else
        log_info "Run 'refresh_secrets' to update secrets for new environment"
      fi
    fi
  fi

  # Check if cache needs refresh based on time
  if [[ "$DEV_ENV_MANAGER_CACHE_STRATEGY" == "time_based" ]]; then
    local cache_dir
    cache_dir=$(get_cache_dir)

    if should_refresh_cache "$cache_dir"; then
      if [[ "$DEV_ENV_MANAGER_CACHE_BACKGROUND_REFRESH" == "true" ]]; then
        (refresh_secrets >/dev/null 2>&1 &)
      fi
    fi
  fi
}

# Enhanced prompt command that includes environment change detection
_bash_prompt_command() {
  # Run original prompt command first
  if [[ -n "$ORIGINAL_PROMPT_COMMAND" ]]; then
    eval "$ORIGINAL_PROMPT_COMMAND"
  fi

  # Check for environment changes
  _bash_check_environment_change
}

# Set up bash prompt integration
_setup_bash_prompt_integration() {
  if [[ "$BASH_INTEGRATION_INITIALIZED" == "true" ]]; then
    return 0
  fi

  log_debug "Setting up bash prompt integration"

  # Set up PROMPT_COMMAND
  if [[ -n "$PROMPT_COMMAND" ]]; then
    # Avoid duplicate setup
    if [[ "$PROMPT_COMMAND" != *"_bash_prompt_command"* ]]; then
      PROMPT_COMMAND="_bash_prompt_command"
    fi
  else
    PROMPT_COMMAND="_bash_prompt_command"
  fi

  # Initialize branch tracking
  local temp_branch
  temp_branch=$(get_current_branch)
  export LAST_KNOWN_BRANCH="$temp_branch"

  log_debug "Bash prompt integration initialized"
  BASH_INTEGRATION_INITIALIZED=true
}

# Clean up bash integration
_cleanup_bash_integration() {
  if [[ "$BASH_INTEGRATION_INITIALIZED" == "false" ]]; then
    return 0
  fi

  log_debug "Cleaning up bash integration"

  # Restore original prompt command
  PROMPT_COMMAND="$ORIGINAL_PROMPT_COMMAND"

  BASH_INTEGRATION_INITIALIZED=false
}

# Bash-specific environment display for prompt (optional)
_bash_env_indicator() {
  if [[ "$DEV_ENV_MANAGER_SHOW_ENV_IN_PROMPT" == "true" ]]; then
    local current_env
    current_env=$(get_current_environment_with_override)

    case "$current_env" in
    "production" | "prod")
      echo -e "\033[0;31m[$current_env]\033[0m " # Red for production
      ;;
    "staging" | "stage")
      echo -e "\033[0;33m[$current_env]\033[0m " # Yellow for staging
      ;;
    "development" | "dev" | "develop")
      echo -e "\033[0;32m[$current_env]\033[0m " # Green for development
      ;;
    *)
      echo -e "\033[0;36m[$current_env]\033[0m " # Cyan for others
      ;;
    esac
  fi
}

# Bash completion for secrets commands
_bash_completion_secrets() {
  local cur prev opts
  COMPREPLY=()
  cur="${COMP_WORDS[COMP_CWORD]}"
  prev="${COMP_WORDS[COMP_CWORD - 1]}"

  case "${COMP_WORDS[0]}" in
  "inspect_secrets")
    opts="--values --json --help"
    # shellcheck disable=SC2207
    COMPREPLY=($(compgen -W "${opts}" -- "${cur}"))
    ;;
  "load_secrets")
    if [[ ${cur} == -* ]]; then
      opts="--all --pattern --help"
      # shellcheck disable=SC2207
      COMPREPLY=($(compgen -W "${opts}" -- "${cur}"))
    elif [[ ${prev} == "--pattern" ]]; then
      # Could provide pattern suggestions here
      COMPREPLY=()
    else
      # Complete with available secret keys
      local cache_dir
      cache_dir=$(get_cache_dir)
      if is_cache_valid "$cache_dir"; then
        local secrets
        secrets=$(jq -r '.secrets | keys[]' "$cache_dir/secrets.json" 2>/dev/null)
        # shellcheck disable=SC2207
        COMPREPLY=($(compgen -W "${secrets}" -- "${cur}"))
      fi
    fi
    ;;
  "debug_env" | "refresh_secrets" | "cleanup_cache")
    opts="--help"
    # shellcheck disable=SC2207
    COMPREPLY=($(compgen -W "${opts}" -- "${cur}"))
    ;;
  esac
}

# Set up bash completion
_setup_bash_completion() {
  if command -v complete >/dev/null 2>&1; then
    complete -F _bash_completion_secrets inspect_secrets
    complete -F _bash_completion_secrets load_secrets
    complete -F _bash_completion_secrets debug_env
    complete -F _bash_completion_secrets refresh_secrets
    complete -F _bash_completion_secrets cleanup_cache

    log_debug "Bash completion set up for secrets commands"
  fi
}

# Bash-specific keybindings
_setup_bash_keybindings() {
  # Bind Ctrl+R for refresh_secrets (if user wants it)
  if [[ "$DEV_ENV_MANAGER_BIND_REFRESH_KEY" == "true" ]]; then
    bind '"\C-r": "refresh_secrets\n"'
    log_debug "Bound Ctrl+R to refresh_secrets"
  fi

  # Bind Ctrl+E for debug_env
  if [[ "$DEV_ENV_MANAGER_BIND_DEBUG_KEY" == "true" ]]; then
    bind '"\C-e": "debug_env\n"'
    log_debug "Bound Ctrl+E to debug_env"
  fi
}

# Handle bash history integration
_setup_bash_history_integration() {
  # Optionally add secret-related commands to history with special marking
  if [[ "$DEV_ENV_MANAGER_MARK_HISTORY" == "true" ]]; then
    # This is a placeholder for future enhancement
    # Could mark commands that use secrets in history
    log_debug "History integration not yet implemented"
  fi
}

# Bash-specific error handling
_bash_error_handler() {
  local exit_code=$?
  local line_number=${BASH_LINENO[0]}
  local command="${BASH_COMMAND}"

  # Only handle our errors
  if [[ "$command" =~ (refresh_secrets|inspect_secrets|load_secrets|debug_env) ]]; then
    log_error "Command failed on line $line_number: $command (exit code: $exit_code)"

    # Provide context-specific help
    case "$command" in
    *refresh_secrets*)
      log_info "Check your secret manager authentication and network connection"
      ;;
    *inspect_secrets* | *load_secrets*)
      log_info "Try running 'refresh_secrets' first"
      ;;
    esac
  fi

  return $exit_code
}

# Set up bash error handling
_setup_bash_error_handling() {
  if [[ "$DEV_ENV_MANAGER_DEBUG" == "true" ]]; then
    set -E # Enable ERR trap inheritance
    trap '_bash_error_handler' ERR
    log_debug "Bash error handling enabled"
  fi
}

# Main bash initialization function
_init_bash_integration() {
  if [[ "$BASH_INTEGRATION_INITIALIZED" == "true" ]]; then
    return 0
  fi

  log_debug "Initializing bash integration"

  # Check if we're actually in bash
  if [[ -z "$BASH_VERSION" ]]; then
    log_error "Bash integration loaded but not running in bash"
    return 1
  fi

  # Initialize components based on detection mode
  case "$DEV_ENV_MANAGER_DETECTION" in
  "auto" | "prompt")
    _setup_bash_prompt_integration
    ;;
  "manual")
    log_debug "Manual detection mode - prompt integration disabled"
    ;;
  *)
    log_warn "Unknown detection mode: $DEV_ENV_MANAGER_DETECTION"
    _setup_bash_prompt_integration # Default to prompt integration
    ;;
  esac

  # Set up additional features
  _setup_bash_completion
  _setup_bash_keybindings
  _setup_bash_history_integration
  _setup_bash_error_handling

  log_debug "Bash integration initialized successfully"
}

# Clean up function for bash
_cleanup_bash() {
  _cleanup_bash_integration

  # Remove trap if set
  if [[ "$DEV_ENV_MANAGER_DEBUG" == "true" ]]; then
    trap - ERR
  fi

  # Remove keybindings
  if [[ "$DEV_ENV_MANAGER_BIND_REFRESH_KEY" == "true" ]]; then
    bind -r '\C-r' 2>/dev/null || true
  fi

  if [[ "$DEV_ENV_MANAGER_BIND_DEBUG_KEY" == "true" ]]; then
    bind -r '\C-e' 2>/dev/null || true
  fi

  log_debug "Bash integration cleaned up"
}

# Initialize bash integration if we're in an interactive bash shell
if [[ -n "$PS1" ]] && [[ -n "$BASH_VERSION" ]]; then
  _init_bash_integration
fi

# Add cleanup to bash exit
trap '_cleanup_bash' EXIT

log_debug "Bash integration module loaded"
