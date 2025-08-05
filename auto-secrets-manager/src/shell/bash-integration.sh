#!/usr/bin/env bash
# Auto Secrets Manager - Bash Integration
#
# Minimal bash integration that leverages branch-detection.sh and Python backend.
# Provides optional features like prompt display and history marking.

# Ensure we have the core branch detection logic
if [[ ! -f "${AUTO_SECRETS_FEATURE_DIR:-/usr/local/share/auto-secrets}/branch-detection.sh" ]]; then
  echo "Error: branch-detection.sh not found" >&2
  return 1
fi

# Source the core branch detection logic
source "${AUTO_SECRETS_FEATURE_DIR:-/usr/local/share/auto-secrets}/branch-detection.sh"

# Set up PROMPT_COMMAND for branch change detection
if [[ "$AUTO_SECRETS_ENABLE" != "false" ]]; then
  # Add our function to PROMPT_COMMAND
  if [[ "$PROMPT_COMMAND" != *"_auto_secrets_check_branch_change"* ]]; then
    if [[ -n "$PROMPT_COMMAND" ]]; then
      PROMPT_COMMAND="$PROMPT_COMMAND; _auto_secrets_check_branch_change"
    else
      PROMPT_COMMAND="_auto_secrets_check_branch_change"
    fi
  fi
fi

# Optional: Environment indicator in prompt
if [[ "$AUTO_SECRETS_SHOW_ENV_IN_PROMPT" == "true" ]]; then
  # Add environment to PS1 if not already present
  if [[ "$PS1" != *'$(_auto_secrets_get_current_env)'* ]]; then
    PS1='$(_auto_secrets_get_current_env)'"$PS1"
  fi
fi

# Optional: Mark secret commands in history
if [[ "$AUTO_SECRETS_MARK_HISTORY" == "true" ]]; then
  _auto_secrets_mark_secret_commands() {
    local cmd="$1"
    # Mark commands that deal with secrets
    if [[ "$cmd" =~ (auto-secrets) ]]; then
      # Add to history with [SECRETS] marker
      history -s "# [SECRETS] $cmd"
      return 1 # Don't add the original command to history
    fi
    return 0
  }

  # Set up history control (this is more complex in bash than zsh)
  _auto_secrets_original_histcontrol="$HISTCONTROL"
  export HISTCONTROL="$HISTCONTROL:ignorespace"

  # Hook into command execution (this is a simplified approach)
  _auto_secrets_preexec() {
    [[ -n "$COMP_LINE" ]] && return                     # Don't trigger on tab completion
    [[ "$BASH_COMMAND" = "$PROMPT_COMMAND" ]] && return # Don't trigger on prompt command

    _auto_secrets_mark_secret_commands "$BASH_COMMAND"
  }

  # Enable preexec functionality
  if [[ -z "$_auto_secrets_preexec_installed" ]]; then
    trap '_auto_secrets_preexec' DEBUG
    _auto_secrets_preexec_installed=1
  fi
fi

# Error handling for secret commands
if [[ "$AUTO_SECRETS_DEBUG" == "true" ]]; then
  _auto_secrets_error_handler() {
    local exit_code=$?
    local cmd="${BASH_COMMAND}"

    if [[ "$cmd" =~ (auto-secrets) ]]; then
      echo "💡 Secret command failed. Run 'auto-secrets debug' for diagnostics" >&2
    fi

    return $exit_code
  }

  # Set up error trap
  if [[ -z "$_auto_secrets_error_trap_installed" ]]; then
    trap '_auto_secrets_error_handler' ERR
    _auto_secrets_error_trap_installed=1
  fi
fi

# Cleanup function for shell exit
_auto_secrets_bash_cleanup() {
  # Remove from PROMPT_COMMAND
  if [[ "$PROMPT_COMMAND" == *"_auto_secrets_check_branch_change"* ]]; then
    PROMPT_COMMAND="${PROMPT_COMMAND//_auto_secrets_check_branch_change/}"
    PROMPT_COMMAND="${PROMPT_COMMAND//;;/;}" # Clean up double semicolons
    PROMPT_COMMAND="${PROMPT_COMMAND#;}"     # Remove leading semicolon
    PROMPT_COMMAND="${PROMPT_COMMAND%;}"     # Remove trailing semicolon
  fi

  # Restore history control
  if [[ "$AUTO_SECRETS_MARK_HISTORY" == "true" ]]; then
    export HISTCONTROL="$_auto_secrets_original_histcontrol"
    trap - DEBUG # Remove DEBUG trap
    unset _auto_secrets_preexec_installed
  fi

  # Remove error trap
  if [[ "$AUTO_SECRETS_DEBUG" == "true" ]]; then
    trap - ERR # Remove ERR trap
    unset _auto_secrets_error_trap_installed
  fi

  # Call core cleanup
  _auto_secrets_cleanup_branch_detection

  # Clean up bash-specific variables
  unset _auto_secrets_original_histcontrol
}

# Set up EXIT trap for cleanup
if [[ -z "$_auto_secrets_exit_trap_installed" ]]; then
  # Preserve existing EXIT trap if any
  _auto_secrets_original_exit_trap="$(trap -p EXIT | sed "s/trap -- '\(.*\)' EXIT/\1/")"

  if [[ -n "$_auto_secrets_original_exit_trap" ]]; then
    trap "_auto_secrets_bash_cleanup; $_auto_secrets_original_exit_trap" EXIT
  else
    trap "_auto_secrets_bash_cleanup" EXIT
  fi

  _auto_secrets_exit_trap_installed=1
fi

# Health check function for debugging
auto-secrets-bash-health() {
  echo "=== Auto Secrets Bash Integration Health ==="
  echo "Integration loaded: Yes"
  echo "PROMPT_COMMAND active: $(if [[ "$PROMPT_COMMAND" == *"_auto_secrets_check_branch_change"* ]]; then echo "Yes"; else echo "No"; fi)"
  echo "Environment in prompt: $AUTO_SECRETS_SHOW_ENV_IN_PROMPT"
  echo "History marking: $AUTO_SECRETS_MARK_HISTORY"
  echo "Debug mode: $AUTO_SECRETS_DEBUG"
  echo "DEBUG trap installed: $(if [[ -n "$_auto_secrets_preexec_installed" ]]; then echo "Yes"; else echo "No"; fi)"
  echo "ERR trap installed: $(if [[ -n "$_auto_secrets_error_trap_installed" ]]; then echo "Yes"; else echo "No"; fi)"
  echo "EXIT trap installed: $(if [[ -n "$_auto_secrets_exit_trap_installed" ]]; then echo "Yes"; else echo "No"; fi)"

  # Call core health check
  _auto_secrets_branch_detection_health
}

# Make health check function available
export -f auto-secrets-bash-health 2>/dev/null || true
