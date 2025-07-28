#!/bin/bash
# DevContainer Feature: Auto Secrets Manager
# Installation script that sets up branch-based secret management

set -e

# Feature options - these are passed as environment variables by the Dev Containers spec.
# Option names from devcontainer-feature.json are converted to uppercase, e.g., 'secretManager' becomes 'SECRETMANAGER'.
# We assign them to local variables for clarity and provide default values as a fallback, synced with devcontainer-feature.json.
DETECTION=${DETECTION:-"prompt"}
SHELLS=${SHELLS:-"both"}
SECRET_MANAGER=${SECRETMANAGER:-"infisical"}
DEBUG=${DEBUG:-"false"}

# Additional options that need to be handled
BRANCH_MAPPING_JSON=${BRANCHMAPPING:-'{"main":"production","prod":"production","master":"production","staging":"staging","stage":"staging","develop":"development","development":"development","default":"development"}'}
AUTO_COMMANDS_JSON=${AUTOCOMMANDS:-'{"terraform":["/infrastructure/","/shared/"],"kubectl":["/kubernetes/","/shared/"],"helm":["/kubernetes/","/shared/"],"aws":["/infrastructure/","/shared/"],"tofu":["/infrastructure/","/shared/"],"npm":["/frontend/","/shared/"],"python":["/backend/","/shared/"],"default":["/shared/"]}'}
ON_DEMAND_COMMANDS_JSON=${ONDEMANDCOMMANDS:-'{"load_secrets":true,"inspect_secrets":true,"refresh_secrets":true,"debug_env":true}'}
SECRET_MANAGER_CONFIG_JSON=${SECRETMANAGERCONFIG:-'{"projectId":"${INFISICAL_PROJECT_ID}","baseUrl":"https://app.infisical.com","authMethod":"universal-auth","clientId":""}'}
CACHE_CONFIG_JSON=${CACHE:-'{"refreshInterval":"15m","strategy":"time_based","backgroundRefresh":false,"cleanupInterval":"1h"}'}
OFFLINE_MODE_JSON=${OFFLINEMODE:-'{"allowStaleCache":true,"maxStaleAge":"2h","gracefulFailure":true,"retryInterval":"5m"}'}
BIND_JSON=${BIND:-'{"debugKey":false,"refreshKey":false,"inspectKey":false,"markHistory":false}'}

# Installation paths
FEATURE_DIR="/usr/local/share/auto-secrets"
BIN_DIR="/usr/local/bin"

echo "🔐 Installing Auto Secrets Manager..."

# Ensure GNU coreutils for compatibility
_ensure_gnu_coreutils() {
    if [ -f /bin/busybox ] && ! stat --version >/dev/null 2>&1; then
        echo "📦 Installing GNU coreutils for compatibility..."
        if command -v apk >/dev/null 2>&1; then
            apk add --no-cache coreutils
        elif command -v apt-get >/dev/null 2>&1; then
            apt-get update && apt-get install -y coreutils
        elif command -v yum >/dev/null 2>&1; then
            yum install -y coreutils
        fi
    fi
}

# Install required system dependencies
_install_dependencies() {
    echo "📦 Installing system dependencies..."

    # Detect package manager and install jq, curl, git
    if command -v apt-get >/dev/null 2>&1; then
        apt-get update
        apt-get install -y jq curl git ca-certificates
    elif command -v apk >/dev/null 2>&1; then
        apk add --no-cache jq curl git ca-certificates
    elif command -v yum >/dev/null 2>&1; then
        yum install -y jq curl git ca-certificates
    elif command -v dnf >/dev/null 2>&1; then
        dnf install -y jq curl git ca-certificates
    else
        echo "⚠️  Could not detect package manager. Please ensure jq, curl, and git are available."
    fi
}

# Create feature directory structure
_create_directories() {
    echo "📁 Creating directory structure..."
    mkdir -p "$FEATURE_DIR"/{core,shells,secret-managers,utils,templates}
    mkdir -p "$BIN_DIR"
}

# Copy feature files to installation directory
_install_feature_files() {
    echo "📋 Installing feature files..."

    # Get the directory where this script is located
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

    # Copy all feature files
    cp -r "$SCRIPT_DIR"/core/* "$FEATURE_DIR/core/"
    cp -r "$SCRIPT_DIR"/shells/* "$FEATURE_DIR/shells/"
    cp -r "$SCRIPT_DIR"/secret-managers/* "$FEATURE_DIR/secret-managers/"
    cp -r "$SCRIPT_DIR"/utils/* "$FEATURE_DIR/utils/"
    cp -r "$SCRIPT_DIR"/templates/* "$FEATURE_DIR/templates/"

    # Make all scripts executable
    find "$FEATURE_DIR" -name "*.sh" -exec chmod +x {} \;

    # Copy config parser utility
    cp "$SCRIPT_DIR/utils/config-parser.sh" "$FEATURE_DIR/utils/"
    chmod +x "$FEATURE_DIR/utils/config-parser.sh"
}

# Parse JSON configuration and set up environment
_setup_configuration() {
    echo "⚙️  Setting up configuration..."

    # Source the config parser
    source "$SCRIPT_DIR/utils/config-parser.sh"

    # Validate JSON options
    validate_json_option "$BRANCH_MAPPING_JSON" "branchMapping"
    validate_json_option "$SECURITY_JSON" "security"

    validate_json_option "$AUTO_COMMANDS_JSON" "autoCommands"
    validate_json_option "$SECRET_MANAGER_CONFIG_JSON" "secretManagerConfig"
    validate_json_option "$CACHE_CONFIG_JSON" "cache"
    validate_json_option "$OFFLINE_MODE_JSON" "offlineMode"
    validate_json_option "$BIND_JSON" "bind"

    # Get version from devcontainer-feature.json
    local feature_version
    feature_version=$(get_feature_version "$SCRIPT_DIR")

    # Create main configuration file from environment variables
    cat > "$FEATURE_DIR/config.sh" << EOF
#!/bin/bash
# Auto Secrets Manager Configuration

# Feature settings
export DEV_ENV_MANAGER_DETECTION="$DETECTION"
export DEV_ENV_MANAGER_SHELLS="$SHELLS"
export DEV_ENV_MANAGER_SECRET_MANAGER="$SECRET_MANAGER"
export DEV_ENV_MANAGER_DEBUG="$DEBUG"
export DEV_ENV_MANAGER_VERSION="$feature_version"

# Feature paths
export DEV_ENV_MANAGER_DIR="$FEATURE_DIR"

# Store original JSON for runtime pattern matching
export DEV_ENV_MANAGER_BRANCH_MAPPING_JSON='$BRANCH_MAPPING_JSON'

$(generate_full_config "$SECRET_MANAGER_CONFIG_JSON" "$CACHE_CONFIG_JSON" "$OFFLINE_MODE_JSON" "$BIND_JSON" "$AUTO_COMMANDS_JSON" "$ON_DEMAND_COMMANDS_JSON")

# Source secret manager specific configuration
source "$FEATURE_DIR/secret-manager-config.sh"
EOF

    # Copy secret manager config template
    cp "$SCRIPT_DIR/templates/secret-manager-config.template.sh" "$FEATURE_DIR/secret-manager-config.sh"
    chmod +x "$FEATURE_DIR/secret-manager-config.sh"

    chmod +x "$FEATURE_DIR/config.sh"

    # Also create a runtime config validator
    cat > "$FEATURE_DIR/validate-config.sh" << 'EOF'
#!/bin/bash
# Runtime configuration validator

source "$DEV_ENV_MANAGER_DIR/utils/config-parser.sh"
source "$DEV_ENV_MANAGER_DIR/utils/validation.sh"

validate_runtime_config() {
    echo "🔍 Validating runtime configuration..."

    # Validate all critical configurations
    if validate_all_config; then
        echo "✅ Configuration validation passed"
        return 0
    else
        echo "❌ Configuration validation failed"
        return 1
    fi
}

# Export for use in other scripts
export -f validate_runtime_config
EOF
    chmod +x "$FEATURE_DIR/validate-config.sh"
}

# Install command-line utilities
_install_cli_tools() {
    echo "🔧 Installing CLI tools..."

    # Create main CLI wrapper
    cat > "$BIN_DIR/dev-env-manager" << 'EOF'
#!/bin/bash
# Auto Secrets Manager CLI

FEATURE_DIR="/usr/local/share/auto-secrets"
source "$FEATURE_DIR/config.sh"
source "$FEATURE_DIR/core/cache.sh"
source "$FEATURE_DIR/utils/logging.sh"

show_help() {
    echo "Auto Secrets Manager CLI"
    echo ""
    echo "Commands:"
    echo "  refresh-secrets    Refresh cached secrets from secret manager"
    echo "  inspect-secrets    List available secret keys"
    echo "  load-secrets       Load specific secrets for a command"
    echo "  debug-env          Show current environment and cache status"
    echo "  cleanup-cache      Clean up old cache directories"
    echo "  help               Show this help message"
    echo ""
    echo "Examples:"
    echo "  dev-env-manager refresh-secrets"
    echo "  dev-env-manager inspect-secrets"
    echo "  dev-env-manager load-secrets DATABASE_URL -- node migrate.js"
}

case "$1" in
    refresh-secrets|refresh)
        refresh_secrets
        ;;
    inspect-secrets|inspect|list)
        inspect_secrets "$@"
        ;;
    load-secrets|load)
        shift
        load_secrets "$@"
        ;;
    debug-env|debug|status)
        debug_env
        ;;
    cleanup-cache|cleanup)
        cleanup_cache
        ;;
    help|--help|-h)
        show_help
        ;;
    *)
        echo "Unknown command: $1"
        echo ""
        show_help
        exit 1
        ;;
esac
EOF

    chmod +x "$BIN_DIR/dev-env-manager"

    # Create convenience symlinks
    ln -sf "$BIN_DIR/dev-env-manager" "$BIN_DIR/refresh_secrets"
    ln -sf "$BIN_DIR/dev-env-manager" "$BIN_DIR/inspect_secrets"
    ln -sf "$BIN_DIR/dev-env-manager" "$BIN_DIR/load_secrets"
}

# Set up shell integration
_setup_shell_integration() {
    echo "🐚 Setting up shell integration for '$SHELLS'..."

    # Create shell initialization script from template
    sed "s|{{FEATURE_DIR}}|$FEATURE_DIR|g" "$FEATURE_DIR/templates/init.template.sh" > "$FEATURE_DIR/init.sh"
    chmod +x "$FEATURE_DIR/init.sh"

    # Add to shell initialization files - CORRECTED to use | delimiter
    INIT_SNIPPET=$(sed "s|{{FEATURE_DIR}}|$FEATURE_DIR|g" "$FEATURE_DIR/templates/shell-config.template.sh")

    _install_for_bash() {
        if command -v bash >/dev/null 2>&1; then
            echo "  -> Installing for bash..."
            mkdir -p /etc
            echo "$INIT_SNIPPET" >> /etc/bash.bashrc
        else
            echo "⚠️  'bash' selected but command not found. Skipping bash integration."
        fi
    }

    _install_for_zsh() {
        if command -v zsh >/dev/null 2>&1; then
            echo "  -> Installing for zsh..."
            mkdir -p /etc/zsh
            touch /etc/zsh/zshrc
            echo "$INIT_SNIPPET" >> /etc/zsh/zshrc
        else
            echo "⚠️  'zsh' selected but command not found. Skipping zsh integration."
        fi
    }

    case "$SHELLS" in
        bash)
            _install_for_bash
            ;;
        zsh)
            _install_for_zsh
            ;;
        both)
            _install_for_bash
            _install_for_zsh
            ;;
        *)
            echo "❌ Invalid shell option: '$SHELLS'. Please use 'bash', 'zsh', or 'both'." >&2
            exit 1
            ;;
    esac
}

# Create tmpfs mount point for cache
_setup_cache_directory() {
    echo "💾 Setting up cache directory..."

    # Ensure /dev/shm is available (should be by default in containers)
    if [[ ! -d /dev/shm ]]; then
        echo "⚠️  /dev/shm not available, cache will use /tmp (less secure)"
        mkdir -p /tmp/dev-env-manager-cache
        chmod 1777 /tmp/dev-env-manager-cache  # Sticky bit for multi-user safety
    fi
}

# Main installation function
main() {
    echo "🚀 Starting Auto Secrets Manager installation..."

    _ensure_gnu_coreutils
    _install_dependencies
    _create_directories
    _install_feature_files
    _setup_configuration
    # Source manager-interface.sh to make authenticate_current_secret_manager available
    source "$FEATURE_DIR/secret-managers/manager-interface.sh"
    # authenticate_current_secret_manager  # Commented out during installation to avoid errors
    _install_cli_tools
    _setup_shell_integration
    _setup_cache_directory

    echo "✅ Auto Secrets Manager installed successfully!"
    echo ""
    echo "🔧 Configuration:"
    echo "  Detection: $DETECTION"
    echo "  Shells: $SHELLS"
    echo "  Secret Manager: $SECRET_MANAGER"
    echo "  Cache Expiry: $CACHE_EXPIRY"
    echo "  Version: $(get_feature_version "$SCRIPT_DIR")"
    echo ""
    echo "📖 Usage:"
    echo "  Open a new shell or run: source /usr/local/share/auto-secrets/init.sh"
    echo "  Commands: refresh_secrets, inspect_secrets, load_secrets"
    echo ""
    echo "🔍 Debug: Set DEV_ENV_MANAGER_DEBUG=true for verbose logging"
}

# Run main installation
main "$@"
