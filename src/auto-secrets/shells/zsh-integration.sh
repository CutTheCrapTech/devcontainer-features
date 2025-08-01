#!/bin/bash
# Auto Secrets Manager - Zsh Shell Integration
# Provides zsh-specific hooks and prompt integration for branch change detection

# Zsh-specific configuration
ZSH_INTEGRATION_INITIALIZED=false

# Branch change detection function for zsh
_zsh_check_environment_change() {
    # Only run if we're in a git repository
    if ! is_in_git_repo; then
        return 0
    fi

    # Check if branch has changed
    local current_branch
    current_branch=$(get_current_branch)

    if [[ "$current_branch" != "$LAST_KNOWN_BRANCH" ]]; then
        log_debug "Branch change detected in zsh: $LAST_KNOWN_BRANCH -> $current_branch"

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

# Zsh precmd hook function
_zsh_precmd_hook() {
    _zsh_check_environment_change
}

# Set up zsh prompt integration using precmd hooks
_setup_zsh_prompt_integration() {
    if [[ "$ZSH_INTEGRATION_INITIALIZED" == "true" ]]; then
        return 0
    fi

    log_debug "Setting up zsh prompt integration"

    # Add our hook to precmd_functions array
    if [[ -z "${precmd_functions[(r)_zsh_precmd_hook]}" ]]; then
        precmd_functions+=(_zsh_precmd_hook)
    fi

    # Initialize branch tracking
    local temp_branch
    temp_branch=$(get_current_branch)
    export LAST_KNOWN_BRANCH="$temp_branch"

    log_debug "Zsh prompt integration initialized"
    ZSH_INTEGRATION_INITIALIZED=true
}

# Clean up zsh integration
_cleanup_zsh_integration() {
    if [[ "$ZSH_INTEGRATION_INITIALIZED" == "false" ]]; then
        return 0
    fi

    log_debug "Cleaning up zsh integration"

    # Remove our hook from precmd_functions using the index method.
    # This is more IDE-friendly than the original pattern removal syntax.
    local index=${precmd_functions[(I)_zsh_precmd_hook]}
    if (( index <= ${#precmd_functions} )); then
        precmd_functions[index]=()
    fi

    ZSH_INTEGRATION_INITIALIZED=false
}

# Zsh-specific environment display for prompt (optional)
_zsh_env_indicator() {
    if [[ "$DEV_ENV_MANAGER_SHOW_ENV_IN_PROMPT" == "true" ]]; then
        local current_env
        current_env=$(get_current_environment_with_override)

        case "$current_env" in
            "production"|"prod")
                echo "%F{red}[$current_env]%f "  # Red for production
                ;;
            "staging"|"stage")
                echo "%F{yellow}[$current_env]%f "  # Yellow for staging
                ;;
            "development"|"dev"|"develop")
                echo "%F{green}[$current_env]%f "  # Green for development
                ;;
            *)
                echo "%F{cyan}[$current_env]%f "  # Cyan for others
                ;;
        esac
    fi
}

# Zsh completion system integration
_zsh_completion_secrets() {
  # shellcheck disable=SC2034  # These variables are used by zsh completion system
  local context state line
  # shellcheck disable=SC2034
  typeset -A opt_args

  # shellcheck disable=SC2154  # service is set by zsh completion system
  case "$service" in
      "inspect_secrets")
          _arguments \
              '--values[Show secret values (truncated)]' \
              '--json[Output in JSON format]' \
              '--help[Show help message]'
          ;;
      "load_secrets")
          _arguments \
              '--all[Load all available secrets]' \
              '--pattern=[Load secrets matching pattern]:pattern:' \
              '--help[Show help message]' \
              '*:secret key:_zsh_complete_secret_keys' \
              '--:command:_command_names'
          ;;
      "debug_env"|"refresh_secrets"|"cleanup_cache")
          _arguments \
              '--help[Show help message]'
          ;;
  esac
}

# Complete available secret keys
_zsh_complete_secret_keys() {
    local cache_dir
    cache_dir=$(get_cache_dir)
    if is_cache_valid "$cache_dir"; then
      local secrets_output secrets
      # shellcheck disable=SC2034  # Used in zsh array splitting on next line
      secrets_output=$(grep -o '^[A-Z_][A-Z0-9_]*' "$cache_dir/secrets.env" 2>/dev/null)
      # shellcheck disable=SC2296,SC2034  # Valid zsh syntax, used by _describe
      secrets=("${(@f)secrets_output}")
      _describe 'secret keys' secrets
    fi
}

# Set up zsh completion
_setup_zsh_completion() {
    # Check if zsh completion system is available
    if [[ -n "$_comp_setup" ]] || autoload -U compinit; then
        # Set up completion functions
        compdef _zsh_completion_secrets inspect_secrets
        compdef _zsh_completion_secrets load_secrets
        compdef _zsh_completion_secrets debug_env
        compdef _zsh_completion_secrets refresh_secrets
        compdef _zsh_completion_secrets cleanup_cache

        log_debug "Zsh completion set up for secrets commands"
    else
        log_debug "Zsh completion system not available"
    fi
}

# Zsh-specific keybindings using zle
_setup_zsh_keybindings() {
    # Define zle widgets for our functions
    _zsh_refresh_secrets_widget() {
        BUFFER="refresh_secrets"
        zle accept-line
    }

    _zsh_debug_env_widget() {
        BUFFER="debug_env"
        zle accept-line
    }

    _zsh_inspect_secrets_widget() {
      # shellcheck disable=SC2034  # BUFFER is used by zsh line editor
      BUFFER="inspect_secrets"
      zle accept-line
    }

    # Register widgets
    zle -N _zsh_refresh_secrets_widget
    zle -N _zsh_debug_env_widget
    zle -N _zsh_inspect_secrets_widget

    # Bind keys if requested
    if [[ "$DEV_ENV_MANAGER_BIND_REFRESH_KEY" == "true" ]]; then
        bindkey '^R' _zsh_refresh_secrets_widget
        log_debug "Bound Ctrl+R to refresh_secrets"
    fi

    if [[ "$DEV_ENV_MANAGER_BIND_DEBUG_KEY" == "true" ]]; then
        bindkey '^E' _zsh_debug_env_widget
        log_debug "Bound Ctrl+E to debug_env"
    fi

    if [[ "$DEV_ENV_MANAGER_BIND_INSPECT_KEY" == "true" ]]; then
        bindkey '^I' _zsh_inspect_secrets_widget
        log_debug "Bound Ctrl+I to inspect_secrets"
    fi
}

# Zsh history integration
_setup_zsh_history_integration() {
    if [[ "$DEV_ENV_MANAGER_MARK_HISTORY" == "true" ]]; then
        # Hook into zsh history to mark commands that use secrets
        _zsh_history_hook() {
            local command="$1"

            # Mark secret-related commands in history
            if [[ "$command" =~ (refresh_secrets|inspect_secrets|load_secrets) ]]; then
                # Add a comment marker for secret commands
                print -s "# [SECRETS] $command"
            fi
        }

        # Add to zshaddhistory hook (if available)
        # shellcheck disable=SC2154  # functions is a zsh built-in associative array
        if (( $+functions[add-zsh-hook] )); then
            add-zsh-hook zshaddhistory _zsh_history_hook
            log_debug "Zsh history integration enabled"
        fi
    fi
}

# Zsh-specific error handling using TRAPZERR
_setup_zsh_error_handling() {
    if [[ "$DEV_ENV_MANAGER_DEBUG" == "true" ]]; then
        TRAPZERR() {
            local exit_code=$?
            local line_number=$LINENO

            # Get the failing command from history
            local command
            command=$(fc -ln -1)

            # Only handle our errors
            if [[ "$command" =~ (refresh_secrets|inspect_secrets|load_secrets|debug_env) ]]; then
                log_error "Command failed on line $line_number: $command (exit code: $exit_code)"

                # Provide context-specific help
                case "$command" in
                    *refresh_secrets*)
                        log_info "Check your secret manager authentication and network connection"
                        ;;
                    *inspect_secrets*|*load_secrets*)
                        log_info "Try running 'refresh_secrets' first"
                        ;;
                esac
            fi

            return $exit_code
        }

        log_debug "Zsh error handling enabled"
    fi
}

# Zsh-specific prompt customization
_setup_zsh_prompt_customization() {
    if [[ "$DEV_ENV_MANAGER_SHOW_ENV_IN_PROMPT" == "true" ]]; then
        # Add environment indicator to RPROMPT if not already present
        if [[ -z "${RPROMPT}" ]] || [[ "${RPROMPT}" != *"_zsh_env_indicator"* ]]; then
          # shellcheck disable=SC2016
          RPROMPT='$(_zsh_env_indicator)'$RPROMPT
          log_debug "Environment indicator added to zsh prompt"
        fi
    fi
}

# Main zsh initialization function
_init_zsh_integration() {
    if [[ "$ZSH_INTEGRATION_INITIALIZED" == "true" ]]; then
        return 0
    fi

    log_debug "Initializing zsh integration"

    # Check if we're actually in zsh
    if [[ -z "$ZSH_VERSION" ]]; then
        log_error "Zsh integration loaded but not running in zsh"
        return 1
    fi

    # Initialize components based on detection mode
    case "$DEV_ENV_MANAGER_DETECTION" in
        "prompt")
            _setup_zsh_prompt_integration
            ;;
        "manual")
            log_debug "Manual detection mode - prompt integration disabled"
            ;;
        *)
            log_warn "Unknown detection mode: $DEV_ENV_MANAGER_DETECTION"
            _setup_zsh_prompt_integration  # Default to prompt integration
            ;;
    esac

    # Set up additional features
    _setup_zsh_completion
    _setup_zsh_keybindings
    _setup_zsh_history_integration
    _setup_zsh_error_handling
    _setup_zsh_prompt_customization

    log_debug "Zsh integration initialized successfully"
}

# Clean up function for zsh
_cleanup_zsh() {
    _cleanup_zsh_integration

    # Remove hooks if they were added
    if (( $+functions[add-zsh-hook] )); then
        add-zsh-hook -d zshaddhistory _zsh_history_hook 2>/dev/null || true
    fi

    # Remove keybindings
    if [[ "$DEV_ENV_MANAGER_BIND_REFRESH_KEY" == "true" ]]; then
        bindkey -r '^R' 2>/dev/null || true
    fi

    if [[ "$DEV_ENV_MANAGER_BIND_DEBUG_KEY" == "true" ]]; then
        bindkey -r '^E' 2>/dev/null || true
    fi

    if [[ "$DEV_ENV_MANAGER_BIND_INSPECT_KEY" == "true" ]]; then
        bindkey -r '^I' 2>/dev/null || true
    fi

    # Remove zle widgets
    zle -D _zsh_refresh_secrets_widget 2>/dev/null || true
    zle -D _zsh_debug_env_widget 2>/dev/null || true
    zle -D _zsh_inspect_secrets_widget 2>/dev_null || true

    # Remove TRAPZERR
    unfunction TRAPZERR 2>/dev/null || true

    log_debug "Zsh integration cleaned up"
}

# Initialize zsh integration if we're in an interactive zsh shell
if [[ -n "$PS1" ]] && [[ -n "$ZSH_VERSION" ]]; then
    _init_zsh_integration
fi

# Add cleanup to zsh exit
zshexit_functions+=(_cleanup_zsh)

log_debug "Zsh integration module loaded"
