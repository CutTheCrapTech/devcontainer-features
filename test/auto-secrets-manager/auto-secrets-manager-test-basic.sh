#!/bin/bash

# test.sh: Post-installation verification for Auto Secrets Manager

set -euo pipefail

AUTO_SECRETS_PROFILE_FILE="/etc/profile.d/auto-secrets.sh"

echo "=== Auto Secrets Manager Post-Installation Test ==="

# 1. Verify and source /etc/profile.d/auto-secrets.sh
echo -e "\n--- Step 1: Verify and source profile file ---"

if [[ ! -f "$AUTO_SECRETS_PROFILE_FILE" ]]; then
  echo "❌ Error: '$AUTO_SECRETS_PROFILE_FILE' not found."
  exit 1
fi
echo "✅ '$AUTO_SECRETS_PROFILE_FILE' found."

echo "Sourcing '$AUTO_SECRETS_PROFILE_FILE'..."
# Source the file in a subshell to avoid polluting the main script's environment unnecessarily
# and capture its output (if any)
if ! output=$(source "$AUTO_SECRETS_PROFILE_FILE" 2>&1); then
  echo "❌ Error sourcing '$AUTO_SECRETS_PROFILE_FILE':"
  echo "$output"
  exit 1
fi
echo "✅ '$AUTO_SECRETS_PROFILE_FILE' sourced successfully."

# Define variables expected to be set by the profile script
# These are examples based on previous conversation, adjust as needed.
EXPECTED_ENV_VARS=(
  "AUTO_SECRETS_FEATURE_DIR"
  "AUTO_SECRETS_CACHE_DIR"
  "AUTO_SECRETS_BRANCH_DETECTION"
  "AUTO_SECRETS_SHOW_ENV_IN_PROMPT"
  "AUTO_SECRETS_MARK_HISTORY"
  "AUTO_SECRETS_DEBUG"
)

# Define variables expected to be JSON (from devcontainer-feature.json options)
EXPECTED_JSON_VARS=(
  "AUTO_SECRETS_BRANCH_MAPPING"
  "AUTO_SECRETS_SECRET_MANAGER_CONFIG"
  "AUTO_SECRETS_AUTO_COMMANDS"
  "AUTO_SECRETS_CACHE_CONFIG"
)

# Check for non-empty string variables
echo -e "\n--- Step 1.1: Check for non-empty string variables ---"
for var in "${EXPECTED_ENV_VARS[@]}"; do
  if [[ -z "${!var}" ]]; then
    echo "❌ Error: Environment variable '$var' is empty or not set."
    exit 1
  else
    echo "✅ Variable '$var' is set: '${!var}'"
  fi
done

# Check for valid JSON variables using jq
echo -e "\n--- Step 1.2: Check for valid JSON variables ---"
if ! command -v jq &>/dev/null; then
  echo "🟡 Warning: 'jq' is not installed. Skipping JSON validation for environment variables."
else
  for var in "${EXPECTED_JSON_VARS[@]}"; do
    if [[ -z "${!var}" ]]; then
      echo "❌ Error: JSON variable '$var' is empty or not set."
      exit 1
    fi
    if ! echo "${!var}" | jq . &>/dev/null; then
      echo "❌ Error: Environment variable '$var' does not contain valid JSON."
      echo "Value: '${!var}'"
      exit 1
    else
      echo "✅ JSON variable '$var' is valid."
    fi
  done
fi

# 2. Check auto-secrets CLI works
echo -e "\n--- Step 2: Check 'auto-secrets' CLI ---"

if ! command -v auto-secrets &>/dev/null; then
  echo "❌ Error: 'auto-secrets' CLI command not found."
  exit 1
fi
echo "✅ 'auto-secrets' CLI command found."

echo "Running 'auto-secrets debug'..."
if ! debug_output=$(auto-secrets debug 2>&1); then
  echo "❌ Error: 'auto-secrets debug' command failed."
  echo "Output:"
  echo "$debug_output"
  exit 1
fi
echo "✅ 'auto-secrets debug' ran successfully."
echo "Output Snippet (first 10 lines):"
echo "$debug_output" | head -n 10
echo "..."

# 3. Check that the auto-secrets-daemon is running
echo -e "\n--- Step 3: Check for running 'auto-secrets-daemon' ---"

# Use pgrep to check if a process matching "auto-secrets-daemon" exists.
# The -f flag matches against the full command line for better reliability.
if ! pgrep -f "auto-secrets-daemon" >/dev/null; then
  echo "❌ Error: The 'auto-secrets-daemon' process is not running."
  echo "This background process is required for certain features. Check service logs for details."
  exit 1
fi

echo "✅ 'auto-secrets-daemon' process is running."
ps -f -p "$(pgrep -f "auto-secrets-daemon")" | tail -n +2 # Show the process details

# 4. Check shell integration sourcing in rc files
echo -e "\n--- Step 4: Check shell integration sourcing ---"

# Get the value of AUTO_SECRETS_SHELLS, defaulting to 'both' for the check
# Sourcing AUTO_SECRETS_PROFILE_FILE to ensure we get the value set during installation
CURRENT_SHELLS=$(source "$AUTO_SECRETS_PROFILE_FILE" >/dev/null 2>&1 && echo "$AUTO_SECRETS_SHELLS")

echo "AUTO_SECRETS_SHELLS is set to: $CURRENT_SHELLS"

AUTO_SECRETS_FEATURE_DIR_FROM_PROFILE=$(source "$AUTO_SECRETS_PROFILE_FILE" >/dev/null 2>&1 && echo "$AUTO_SECRETS_FEATURE_DIR")
if [[ -z "$AUTO_SECRETS_FEATURE_DIR_FROM_PROFILE" ]]; then
  echo "❌ Error: AUTO_SECRETS_FEATURE_DIR not set in profile. Cannot verify sourcing paths."
  exit 1
fi

ZSH_INTEGRATION_FILE="${AUTO_SECRETS_FEATURE_DIR_FROM_PROFILE}/zsh-integration.sh"
BASH_INTEGRATION_FILE="${AUTO_SECRETS_FEATURE_DIR_FROM_PROFILE}/bash-integration.sh"
AUTO_COMMANDS_FILE="${AUTO_SECRETS_FEATURE_DIR_FROM_PROFILE}/auto-commands.sh"

check_sourcing_in_file() {
  local rc_file="$1"
  local shell_type="$2"
  local expected_files=("${@:3}")
  local sourced_ok=true

  echo "Checking '$rc_file' for $shell_type integration..."

  if [[ ! -f "$rc_file" ]]; then
    echo "🟡 Warning: '$rc_file' not found. Skipping check for this shell."
    return 0
  fi

  local rc_content=$(cat "$rc_file")

  for file in "${expected_files[@]}"; do
    # We're looking for a line that sources the file, optionally preceded by a conditional
    # This regex is a bit more robust
    if ! grep -qE "(^|[^a-zA-Z0-9_])source\\s+['\"]?$(echo "$file" | sed 's/\./\\./g' | sed 's/\//\\\//g')['\"]?" <<<"$rc_content"; then
      echo "❌ Error: '$file' is NOT sourced in '$rc_file'."
      sourced_ok=false
    else
      echo "✅ '$file' is sourced in '$rc_file'."
    fi
  done
  if ! $sourced_ok; then
    return 1
  fi
  return 0
}

if [[ "$CURRENT_SHELLS" == "zsh" || "$CURRENT_SHELLS" == "both" ]]; then
  if ! check_sourcing_in_file "$ZSHRC_FILE" "zsh" "$ZSH_INTEGRATION_FILE" "$AUTO_COMMANDS_FILE"; then
    echo "❌ Zsh integration check failed."
    exit 1
  fi
fi

if [[ "$CURRENT_SHELLS" == "bash" || "$CURRENT_SHELLS" == "both" ]]; then
  if ! check_sourcing_in_file "$BASHRC_FILE" "bash" "$BASH_INTEGRATION_FILE" "$AUTO_COMMANDS_FILE"; then
    echo "❌ Bash integration check failed."
    exit 1
  fi
fi

echo "✅ Shell integration sourcing checks passed."

echo -e "\n=== All post-installation tests passed! ==="
exit 0
