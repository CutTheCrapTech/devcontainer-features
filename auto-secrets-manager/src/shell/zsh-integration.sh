#!/usr/bin/env zsh
# Auto Secrets Manager - Zsh Integration
#
# Minimal zsh integration that leverages branch-detection.sh and Python backend.
# Provides optional features like prompt display and history marking.

# Ensure we have the core branch detection logic
if [[ ! -f "${AUTO_SECRETS_FEATURE_DIR:-/usr/local/share/auto-secrets}/branch-detection.sh" ]]; then
    echo "Error: branch-detection.sh not found" >&2
    return 1
fi

# Source the core branch detection logic
source "${AUTO_SECRETS_FEATURE_DIR:-/usr/local/share/auto-secrets}/branch-detection.sh"

# Set up precmd hook for branch change detection
if [[ "$AUTO_SECRETS_BRANCH_DETECTION" != "false" ]]; then
    # Add our function to precmd_functions array
    if [[ -z "${precmd_functions[(r)_auto_secrets_check_branch_change]}" ]]; then
        precmd_functions+=(_auto_secrets_check_branch_change)
    fi
fi

# Optional: Environment indicator in prompt
if [[ "$AUTO_SECRETS_SHOW_ENV_IN_PROMPT" == "true" ]]; then
    # Add environment to right prompt
    if [[ -z "$RPROMPT" ]]; then
        RPROMPT='$(_auto_secrets_get_current_env)'
    else
        RPROMPT='$(_auto_secrets_get_current_env)'$RPROMPT
    fi
fi

# Optional: Mark secret commands in history
if [[ "$AUTO_SECRETS_MARK_HISTORY" == "true" ]]; then
    _auto_secrets_mark_secret_commands() {
        local cmd="$1"
        # Mark commands that deal with secrets
        if [[ "$cmd" =~ (auto-secrets) ]]; then
            print -s "# [SECRETS] $cmd"
            return 1  # Don't add the original command to history
        fi
        return 0
    }

    # Add to zshaddhistory hook
    if [[ -z "${zshaddhistory_functions[(r)_auto_secrets_mark_secret_commands]}" ]]; then
        zshaddhistory_functions+=(_auto_secrets_mark_secret_commands)
    fi
fi

# Error handling for secret commands
if [[ "$AUTO_SECRETS_DEBUG" == "true" ]]; then
    TRAPZERR() {
        local cmd=$(fc -ln -1)
        if [[ "$cmd" =~ (auto-secrets) ]]; then
            echo "💡 Secret command failed. Run 'auto-secrets debug' for diagnostics" >&2
        fi
        return $?
    }
fi

# Cleanup on shell exit
_auto_secrets_zsh_cleanup() {
    # Remove from precmd_functions
    precmd_functions=(${precmd_functions[@]/_auto_secrets_check_branch_change})

    # Remove from zshaddhistory_functions if present
    if [[ "$AUTO_SECRETS_MARK_HISTORY" == "true" ]]; then
        zshaddhistory_functions=(${zshaddhistory_functions[@]/_auto_secrets_mark_secret_commands})
    fi

    # Remove error trap
    if [[ "$AUTO_SECRETS_DEBUG" == "true" ]]; then
        unfunction TRAPZERR 2>/dev/null || true
    fi
}

# Add cleanup to zshexit_functions
if [[ -z "${zshexit_functions[(r)_auto_secrets_zsh_cleanup]}" ]]; then
    zshexit_functions+=(_auto_secrets_zsh_cleanup)
fi

# Health check function for debugging
auto-secrets-zsh-health() {
    echo "=== Auto Secrets Zsh Integration Health ==="
    echo "Integration loaded: Yes"
    echo "Branch detection active: $(if [[ "${precmd_functions[(r)_auto_secrets_check_branch_change]}" ]]; then echo "Yes"; else echo "No"; fi)"
    echo "Environment in prompt: $AUTO_SECRETS_SHOW_ENV_IN_PROMPT"
    echo "History marking: $AUTO_SECRETS_MARK_HISTORY"
    echo "Debug mode: $AUTO_SECRETS_DEBUG"
    echo "Cleanup registered: $(if [[ "${zshexit_functions[(r)_auto_secrets_zsh_cleanup]}" ]]; then echo "Yes"; else echo "No"; fi)"

    # Call core health check
    _auto_secrets_branch_detection_health
}

# Export the health check function
autoload -U auto-secrets-zsh-health
