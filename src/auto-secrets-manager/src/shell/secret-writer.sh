#!/usr/bin/env bash
#
# secret-writer.sh
#
# A simple launcher script that executes the 'auto-secrets' tool to allow
# a user to interactively set a secret manager secret.
#
# This script is idempotent: it will only run the setup if a configuration
# file is not already present. It delegates all logic and user interaction
# to the underlying Python application.
#

# Exit immediately if a command exits with a non-zero status.
set -e

# --- Pre-flight Checks ---

# 1. Verify that the 'auto-secrets' command is available in the PATH.
if ! command -v auto-secrets &>/dev/null; then
  echo "Error: 'auto-secrets' command not found." >&2
  echo "Please ensure the auto-secrets-manager feature is installed and your PATH is configured correctly." >&2
  exit 127
fi

# 2. Verify that the required environment variable is set.
if [ -z "$AUTO_SECRETS_SM_SECRET_LOC" ]; then
  echo "Error: AUTO_SECRETS_SM_SECRET_LOC environment variable is not set." >&2
  echo "This variable is required to locate the secret configuration directory." >&2
  exit 1
fi

# --- Main Execution ---

CONFIG_FILE_PLAIN="$AUTO_SECRETS_SM_SECRET_LOC/sm-config.json"
CONFIG_FILE_ENCRYPTED="$AUTO_SECRETS_SM_SECRET_LOC/sm-config.enc.json"

# This is the core logic you requested.
# Only proceed if NEITHER the plain nor the encrypted config file exists.
if [ ! -f "$CONFIG_FILE_PLAIN" ] && [ ! -f "$CONFIG_FILE_ENCRYPTED" ]; then
  echo "Secret manager configuration not found. Launching setup..."
  # Execute the command with no arguments. The Python application will
  # handle prompting the user for all necessary information.
  auto-secrets set-sm-secret
  echo "Setup process completed."
else
  echo "Secret manager configuration already exists. Skipping setup."
fi
