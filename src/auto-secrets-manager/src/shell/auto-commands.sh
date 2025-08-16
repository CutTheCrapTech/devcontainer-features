#!/bin/bash
# Auto Secrets Manager - Common Shell Functions
# Shared functions for auto commands integration

# Function to call auto-secrets Python module
_call_auto_secrets() {
  # Try console script first, fallback to direct module call
  if command -v auto-secrets >/dev/null 2>&1; then
    auto-secrets "$@"
  else
    echo "ERROR: auto-secrets not found" >&2
    return 1
  fi
}

# Set up automatic command aliases
_setup_auto_commands() {
  # Check if jq is available
  if ! command -v jq >/dev/null 2>&1; then
    if [[ "${AUTO_SECRETS_DEBUG}" == "true" ]]; then
      echo "jq not available, skipping auto commands setup"
    fi
    return 0
  fi

  # Get AUTO_COMMANDS configuration
  local auto_commands_json=$AUTO_SECRETS_AUTO_COMMANDS

  if [[ "$auto_commands_json" == "{}" ]] || [[ -z "$auto_commands_json" ]]; then
    return 0 # No auto commands configured
  fi

  # Parse command names from JSON using jq
  local commands
  commands=$(echo "$auto_commands_json" | jq -r 'keys[]' 2>/dev/null)

  # Set up aliases for commands that exist on the system
  for cmd in $commands; do
    if command -v "$cmd" >/dev/null 2>&1; then
      # Create wrapper function
      eval "${cmd}_with_secrets() { _load_secrets_for_command '$cmd' \"\$@\"; }"
      # Create alias
      # shellcheck disable=SC2139
      alias "$cmd"="${cmd}_with_secrets"
      if [[ "${AUTO_SECRETS_DEBUG}" == "true" ]]; then
        echo "Auto-loading enabled for: $cmd"
      fi
    fi
  done
}

# Load secrets for specific command based on configuration
_load_secrets_for_command() {
  local command="$1"
  shift

  # Remove the _with_secrets suffix if present
  local command_to_run="${command%_with_secrets}"

  # Create a temporary file for secrets
  local secrets_env_file
  secrets_env_file=$(mktemp)

  # CRITICAL: Set a trap to ensure the secrets file is deleted when the function exits,
  # for any reason (success, error, or interrupt).
  # shellcheck disable=SC2064
  trap "rm -f '$secrets_env_file'" RETURN EXIT INT TERM

  cached_branch=$(_auto_secrets_get_cached_data "${AUTO_SECRETS_CACHE_DIR}/state/current_branch.branch")
  cached_repo=$(_auto_secrets_get_cached_data "${AUTO_SECRETS_CACHE_DIR}/state/current_branch.repo")

  # Call Python to handle all the logic and write secrets to temp file
  if _call_auto_secrets output-env --command="$command_to_run" --branch="$cached_branch" --repo="$cached_repo" >"$secrets_env_file" 2>/dev/null; then
    # Check if the secrets file was actually populated with content.
    if [[ -s "$secrets_env_file" ]]; then
      if [[ "${AUTO_SECRETS_DEBUG}" == "true" ]]; then
        echo "Secrets found for '$command_to_run'. Executing in a subshell with secrets."
      fi
      # Execute the command in a subshell.
      # This isolates the environment variables to only this command.
      (
        # Source the file inside the subshell
        # shellcheck disable=SC1090
        . "$secrets_env_file"
        # Replace the subshell process with the user's command
        exec "$command_to_run" "$@"
      )
      return $? # Return the exit code of the subshell/command
    fi
  fi

  # If the Python script failed or produced no secrets, run the original command as is.
  if [[ "${AUTO_SECRETS_DEBUG}" == "true" ]]; then
    echo "No secrets found or an error occurred. Executing '$command_to_run' normally."
  fi
  exec "$command_to_run" "$@"
}

_setup_auto_commands
