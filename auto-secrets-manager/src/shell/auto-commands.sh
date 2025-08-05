#!/bin/bash
# Auto Secrets Manager - Common Shell Functions
# Shared functions for auto commands integration

# Function to call auto-secrets Python module
_call_auto_secrets() {
  # Try console script first, fallback to direct module call
  if command -v auto-secrets-py >/dev/null 2>&1; then
    auto-secrets-py "$@"
  elif command -v python3 >/dev/null 2>&1; then
    # Try to find the module in common locations
    local module_paths=(
      "/usr/local/lib/python*/site-packages"
      "/usr/lib/python*/site-packages"
      "$HOME/.local/lib/python*/site-packages"
      "/opt/auto-secrets/src"
      "/usr/local/share/auto-secrets/src"
    )

    for path_pattern in "${module_paths[@]}"; do
      for path in $path_pattern; do
        if [[ -d "$path/auto_secrets" ]]; then
          PYTHONPATH="$path:$PYTHONPATH" python3 -m auto_secrets.cli "$@"
          return $?
        fi
      done
    done

    echo "ERROR: auto_secrets module not found" >&2
    return 1
  else
    echo "ERROR: Neither auto-secrets-py nor python3 found" >&2
    return 1
  fi
}

# Set up automatic command aliases
_setup_auto_commands() {
  # Check if jq is available
  if ! command -v jq >/dev/null 2>&1; then
    if [[ "${DEBUG:-false}" == "true" ]]; then
      echo "jq not available, skipping auto commands setup"
    fi
    return 0
  fi

  # Get AUTO_COMMANDS configuration
  local auto_commands_json="${ AUTO_COMMANDS:-{} }"

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
      alias "$cmd"="${cmd}_with_secrets"
      if [[ "${DEBUG:-false}" == "true" ]]; then
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
  command="${command%_with_secrets}"

  # Create a temporary file for secrets
  local secrets_env_file
  secrets_env_file=$(mktemp)

  # Ensure cleanup on exit
  trap "rm -f '$secrets_env_file'" EXIT

  # Call Python to handle all the logic and write secrets to temp file
  if _call_auto_secrets exec --command="$command" --output-env="$secrets_env_file" 2>/dev/null; then
    # Source the secrets file if it exists and has content
    if [[ -s "$secrets_env_file" ]]; then
      source "$secrets_env_file"
      if [[ "${DEBUG:-false}" == "true" ]]; then
        echo "Secrets loaded for command: $command"
      fi
    fi
  fi

  # Clean up temp file
  rm -f "$secrets_env_file"
  trap - EXIT

  # Execute the original command with secrets loaded
  exec "$command" "$@"
}

_setup_auto_commands
