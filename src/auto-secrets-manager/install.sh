#!/bin/bash
set -e

# Auto Secrets Manager - DevContainer Feature Install Script
# Installs Python backend, shell integration, and sets up configuration

echo "🔐 Installing Auto Secrets Manager..."

# Feature source directory (where this script is located)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOURCE_DIR="$SCRIPT_DIR/src"

# Installation directories
INSTALL_DIR="/usr/local/share/auto-secrets"

# Parse options (provided as environment variables by DevContainer)
# Note: DevContainer feature options use different casing, so we map them
# Default values for optional configurations
SECRET_MANAGER="${SECRETMANAGER:-infisical}"
SHELLS="${SHELLS:-both}"
SECRET_MANAGER_CONFIG="${SECRETMANAGERCONFIG:-'{"host":"https://app.infisical.com"}'}"
CACHE_CONFIG=${CACHECONFIG:-'{"refresh_interval":"15m","cleanup_interval":"7d"}'}
SHOW_ENV_IN_PROMPT="${SHOWENVINPROMPT:-false}"
MARK_HISTORY="${MARKHISTORY:-false}"
DEBUG="${DEBUG:-false}"
BRANCH_DETECTION="${BRANCHDETECTION:-true}"
# No Defaults here
BRANCH_MAPPING="${BRANCHMAPPING:-'{}'}"
AUTO_COMMANDS="${AUTOCOMMANDS:-'{}'}"

# Validate required options
if [[ -z "$SECRET_MANAGER" ]]; then
  echo "❌ SECRET_MANAGER is required"
  exit 1
fi

if [[ -z "$SHELLS" ]]; then
  echo "❌ SHELLS is required"
  exit 1
fi

if [[ -z "$BRANCH_MAPPING" || "$BRANCH_MAPPING" == "{}" ]]; then
  echo "❌ BRANCH_MAPPING is required and cannot be empty"
  echo "💡 For security, you must explicitly map branches to environments"
  exit 1
fi

echo "📋 Configuration:"
echo "  Secret Manager: $SECRET_MANAGER"
echo "  Shells: $SHELLS"
echo "  Branch Mapping: $BRANCH_MAPPING"
echo "  Debug Mode: ${DEBUG:-false}"

# Detect package manager and install dependencies
echo "📦 Installing system dependencies..."

if command -v apt-get >/dev/null 2>&1; then
  # Debian/Ubuntu
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  apt-get install -y python3 python3-pip python3-venv git jq curl
elif command -v apk >/dev/null 2>&1; then
  # Alpine
  apk add --no-cache python3 py3-pip git jq curl
elif command -v yum >/dev/null 2>&1; then
  # RHEL/CentOS
  yum install -y python3 python3-pip git jq curl
elif command -v dnf >/dev/null 2>&1; then
  # Fedora
  dnf install -y python3 python3-pip git jq curl
else
  echo "⚠️  Unknown package manager. Please ensure python3, pip, git, jq, and curl are installed."
fi

# Verify jq installation
if ! command -v jq >/dev/null 2>&1; then
  echo "❌ jq installation failed"
  exit 1
fi

echo "✅ System dependencies installed"

#
# Transforms a single-quoted string into a standard, double-quoted JSON string.
# Validates the result is valid JSON. Returns the clean JSON string.
# Exits with an error and non-zero status code if validation fails.
#
# Usage:
#   CLEAN_VAR=$(transform_to_json "${RAW_VAR}")
#
transform_to_json() {
  local raw_string="$1"
  local var_name="$2"
  local json_string

  # Log the input value to stdout for debugging
  echo "    > Input:  ${var_name}: ${raw_string}" >&2

  # Transform single quotes to double quotes
  json_string=$(echo "${raw_string}" | sed "s/'/\"/g")

  # Log the output value to stdout for debugging
  echo "    > Output: ${var_name}: ${json_string}" >&2

  # Validate that the result is valid JSON
  if ! echo "${json_string}" | jq -e . >/dev/null 2>&1; then
    echo "❌ ERROR: Input string could not be transformed into valid JSON." >&2
    return 1
  fi

  # Echo the clean JSON string to stdout so it can be captured
  echo "${json_string}"
}

# --- Transform and Validate Configuration ---
# Use the function to safely process each user-provided string.
echo "🔧 Transforming configuration from single-quote format to standard JSON..."

JSON_BRANCH_MAPPING=$(transform_to_json "${BRANCH_MAPPING}" "BRANCH_MAPPING")
JSON_SECRET_MANAGER_CONFIG=$(transform_to_json "${SECRET_MANAGER_CONFIG}" "SECRET_MANAGER_CONFIG")
JSON_CACHE_CONFIG=$(transform_to_json "${CACHE_CONFIG}" "CACHE_CONFIG")
JSON_AUTO_COMMANDS=$(transform_to_json "${AUTO_COMMANDS}" "AUTO_COMMANDS")

echo "✅ All configurations transformed and validated successfully."

# Verify Python version meets requirements
if ! python3 -c "import sys; sys.exit(0 if sys.version_info >= (3,9) else 1)" 2>/dev/null; then
  python_version=$(python3 --version 2>/dev/null | cut -d' ' -f2 || echo "unknown")
  echo "❌ Python 3.9+ required, found Python $python_version"
  echo "💡 Please use a base image with Python 3.9 or later"
  exit 1
fi

echo "✅ Python version check passed"

# Install Python package
echo "🐍 Installing Python package..."

if [[ ! -d "$SOURCE_DIR" ]]; then
  echo "❌ Source directory not found: $SOURCE_DIR"
  exit 1
fi

# Install the auto_secrets Python package
cd "$SOURCE_DIR"

# Force modern setuptools that properly handles PEP 621
echo "🚀 Upgrading build tools..."
if ! pip3 install --upgrade --quiet "setuptools>=67.0" "wheel>=0.40" "pip>=23.0" 2>/dev/null; then
  echo "❌ Container environment insufficient: cannot upgrade build tools"
  echo ""
  echo "🔧 Your base image is too old or has packaging conflicts."

  # Verify the upgrade
  echo "🔍 Build tools versions:"
  python3 -c "import setuptools, pip; print(f'setuptools: {setuptools.__version__}'), print(f'pip: {pip.__version__}')"
  echo ""

  exit 1
fi

pip3 install . || {
  echo "❌ Failed to install Python package"
  exit 1
}

# Verify installation
if ! python3 -c "import auto_secrets" 2>/dev/null; then
  echo "❌ Python package verification failed"
  exit 1
fi

echo "✅ Python package installed"

# Create installation directory
echo "📁 Setting up installation directory..."
mkdir -p "$INSTALL_DIR"
chmod 755 "$INSTALL_DIR"

# Copy shell integration files
cp -r "$SOURCE_DIR/shell/"* "$INSTALL_DIR/"
chmod 755 "$INSTALL_DIR"/*.sh

echo "✅ Shell integration files installed"

# Copy git hooks files
cp -r "$SOURCE_DIR/hooks/"* "$INSTALL_DIR/"
chmod 755 "$INSTALL_DIR"/*

echo "✅ Git hooks copied"

# Set up shell integration based on SHELLS option
echo "🐚 Setting up shell integration..."

# Create profile script that exports environment variables
cat >"/etc/profile.d/auto-secrets.sh" <<EOF
# Auto Secrets Manager - Environment Configuration
# Generated by DevContainer feature installation

# Core configuration (using proper UPPER_SNAKE_CASE)
export AUTO_SECRETS_SECRET_MANAGER="$SECRET_MANAGER"
export AUTO_SECRETS_SHELLS="$SHELLS"

# Json configurations
export AUTO_SECRETS_BRANCH_MAPPINGS='$JSON_BRANCH_MAPPING'
export AUTO_SECRETS_SECRET_MANAGER_CONFIG='${JSON_SECRET_MANAGER_CONFIG}'
export AUTO_SECRETS_AUTO_COMMANDS='${JSON_AUTO_COMMANDS}'
export AUTO_SECRETS_CACHE_CONFIG='${JSON_CACHE_CONFIG}'

# Feature settings
export AUTO_SECRETS_SHOW_ENV_IN_PROMPT="${SHOW_ENV_IN_PROMPT}"
export AUTO_SECRETS_MARK_HISTORY="${MARK_HISTORY}"
export AUTO_SECRETS_DEBUG="${DEBUG}"
export AUTO_SECRETS_BRANCH_DETECTION="${BRANCH_DETECTION}"

# Paths and directories
export AUTO_SECRETS_FEATURE_DIR="$INSTALL_DIR"
export AUTO_SECRETS_CACHE_DIR="/dev/shm/auto-secrets"
export AUTO_SECRETS_LOG_DIR="/var/log/auto-secrets"
export AUTO_SECRETS_LOG_LEVEL="INFO"

# Create log directory with proper permissions
if [[ -w /var/log ]]; then
    mkdir -p /var/log/auto-secrets
    chmod 755 /var/log/auto-secrets
fi
EOF

chmod 644 "/etc/profile.d/auto-secrets.sh"

# Set up shell-specific integration
if [[ "$SHELLS" == "zsh" ]] || [[ "$SHELLS" == "both" ]]; then
  echo "Setting up Zsh integration..."

  # Add to system zshrc
  if [[ -f /etc/zsh/zshrc ]]; then
    # shellcheck disable=SC2129
    echo "" >>/etc/zsh/zshrc
    echo "# Auto Secrets Manager - Zsh Integration" >>/etc/zsh/zshrc
    echo "if [[ -f '$INSTALL_DIR/zsh-integration.sh' ]]; then" >>/etc/zsh/zshrc
    echo "    source '$INSTALL_DIR/zsh-integration.sh'" >>/etc/zsh/zshrc
    echo "fi" >>/etc/zsh/zshrc
    echo "if [[ -f '$INSTALL_DIR/auto-commands.sh' ]]; then" >>/etc/zsh/zshrc
    echo "    source '$INSTALL_DIR/auto-commands.sh'" >>/etc/zsh/zshrc
    echo "fi" >>/etc/zsh/zshrc
  fi

  # Also add to global zshrc location
  mkdir -p /usr/local/share/zsh/site-functions
  echo "source '$INSTALL_DIR/zsh-integration.sh'" >/usr/local/share/zsh/site-functions/_auto-secrets
  echo "source '$INSTALL_DIR/auto-commands.sh'" >>/usr/local/share/zsh/site-functions/_auto-secrets
fi

if [[ "$SHELLS" == "bash" ]] || [[ "$SHELLS" == "both" ]]; then
  echo "Setting up Bash integration..."

  # Add to system bashrc
  if [[ -f /etc/bash.bashrc ]]; then
    # shellcheck disable=SC2129
    echo "" >>/etc/bash.bashrc
    echo "# Auto Secrets Manager - Bash Integration" >>/etc/bash.bashrc
    echo "if [[ -f '$INSTALL_DIR/bash-integration.sh' ]]; then" >>/etc/bash.bashrc
    echo "    source '$INSTALL_DIR/bash-integration.sh'" >>/etc/bash.bashrc
    echo "fi" >>/etc/bash.bashrc
    echo "if [[ -f '$INSTALL_DIR/auto-commands.sh' ]]; then" >>/etc/bash.bashrc
    echo "    source '$INSTALL_DIR/auto-commands.sh'" >>/etc/bash.bashrc
    echo "fi" >>/etc/bash.bashrc
  fi

  # Also add to /etc/profile.d for wider compatibility
  cat >"/etc/profile.d/auto-secrets-bash.sh" <<EOF
# Auto Secrets Manager - Bash Integration Loader
if [[ -n "\$BASH_VERSION" ]] && [[ -f '$INSTALL_DIR/bash-integration.sh' ]]; then
    source '$INSTALL_DIR/bash-integration.sh'
fi
if [[ -n "\$BASH_VERSION" ]] && [[ -f '$INSTALL_DIR/auto-commands.sh' ]]; then
    source '$INSTALL_DIR/auto-commands.sh'
fi
EOF
  chmod 644 "/etc/profile.d/auto-secrets-bash.sh"
fi

echo "✅ Shell integration configured"

# Create cache directory structure
echo "💾 Setting up cache directories..."

# Create cache base directory
mkdir -p /dev/shm/auto-secrets
chmod 1777 /dev/shm/auto-secrets

# Create and set permissions for the log directory
mkdir -p /var/log/auto-secrets
chmod 1777 /var/log/auto-secrets

echo "✅ Cache directories created"

# Validate installation
echo "🔍 Validating installation..."

# Test Python package
if python3 -c "import auto_secrets; print('Python package OK')" 2>/dev/null; then
  echo "✅ Python package validation passed"
else
  echo "❌ Python package validation failed"
  exit 1
fi

# Test CLI command
if auto-secrets --help >/dev/null 2>&1; then
  echo "✅ CLI command validation passed"
else
  echo "❌ CLI command validation failed"
  exit 1
fi

# Test JSON parsing (jq)
if echo '{"test": "value"}' | jq -r '.test' >/dev/null 2>&1; then
  echo "✅ jq validation passed"
else
  echo "❌ jq validation failed"
  exit 1
fi

echo ""
echo "🎉 Auto Secrets Manager installation completed successfully!"
echo ""
echo "📚 Available commands:"
echo "  auto-secrets refresh          - Refresh secrets cache"
echo "  auto-secrets inspect          - Inspect cached secrets"
echo "  auto-secrets debug            - Debug environment and configuration"
echo "  auto-secrets                  - Full CLI interface"
echo ""
echo "🔧 Integration status:"
echo "  Shell integration: $SHELLS"
echo "  Environment in prompt: ${SHOW_ENV_IN_PROMPT}"
echo "  History marking: ${MARK_HISTORY}"
echo "  Debug mode: ${DEBUG}"
echo "  BRANCH_DETECTION: ${BRANCH_DETECTION}"
echo ""
echo "💡 Next steps:"
echo "  1. Restart your shell or run: source /etc/profile.d/auto-secrets.sh"
echo "  2. Navigate to a git repository"
echo "  3. Run: auto-secrets debug (to verify configuration)"
echo "  4. Run: auto-secrets refresh (to cache secrets for current environment)"
echo ""
echo "📖 For more information, see the documentation or run: auto-secrets --help"
