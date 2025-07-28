#!/bin/bash
# Auto Secrets Manager - Logging Utilities
# Provides consistent logging and error handling across the feature

# Color codes for terminal output
readonly RED='\033[0;31m'
readonly YELLOW='\033[1;33m'
readonly GREEN='\033[0;32m'
readonly BLUE='\033[0;34m'
readonly PURPLE='\033[0;35m'
readonly CYAN='\033[0;36m'
readonly NC='\033[0m' # No Color

# Log levels
readonly LOG_ERROR=1
readonly LOG_WARN=2
readonly LOG_INFO=3
readonly LOG_DEBUG=4

# Get current log level from environment
get_log_level() {
    if [[ "$DEV_ENV_MANAGER_DEBUG" == "true" ]]; then
        echo $LOG_DEBUG
    else
        echo $LOG_INFO
    fi
}

# Core logging function
_log() {
    local level="$1"
    local color="$2"
    local prefix="$3"
    shift 3
    local message="$*"

    local current_level=$(get_log_level)

    # Only log if message level is <= current level
    if [[ $level -le $current_level ]]; then
        echo -e "${color}${prefix}${NC} ${message}" >&2
    fi
}

# Logging functions
log_error() {
    _log $LOG_ERROR "$RED" "🚨 ERROR:" "$@"
}

log_warn() {
    _log $LOG_WARN "$YELLOW" "⚠️  WARN:" "$@"
}

log_info() {
    _log $LOG_INFO "$GREEN" "ℹ️  INFO:" "$@"
}

log_debug() {
    _log $LOG_DEBUG "$CYAN" "🔍 DEBUG:" "$@"
}

log_success() {
    _log $LOG_INFO "$GREEN" "✅ SUCCESS:" "$@"
}

# Special logging for cache operations
log_cache() {
    _log $LOG_DEBUG "$PURPLE" "💾 CACHE:" "$@"
}

# Special logging for network operations
log_network() {
    _log $LOG_DEBUG "$BLUE" "🌐 NETWORK:" "$@"
}

# Log with timestamp (for debugging race conditions)
log_timestamp() {
    local timestamp=$(date '+%H:%M:%S.%3N')
    log_debug "[${timestamp}] $*"
}

# Error handling with context
error_with_context() {
    local context="$1"
    shift
    local message="$*"

    log_error "[$context] $message"

    # Provide debugging hints based on context
    case "$context" in
        "CACHE")
            log_info "Try: refresh_secrets or check /dev/shm permissions"
            ;;
        "NETWORK")
            log_info "Check internet connection and secret manager status"
            ;;
        "AUTH")
            log_info "Re-authenticate with your secret manager"
            ;;
        "GIT")
            log_info "Ensure you're in a git repository with valid branch"
            ;;
        "PERMISSIONS")
            log_info "Check file permissions and user ownership"
            ;;
    esac
}

# Progress indicator for long operations
show_progress() {
    local message="$1"
    local duration="${2:-3}"

    echo -n "$message"
    for ((i=0; i<duration; i++)); do
        echo -n "."
        sleep 1
    done
    echo " done!"
}

# Format duration for human readability
format_duration() {
    local seconds="$1"

    if [[ $seconds -lt 60 ]]; then
        echo "${seconds}s"
    elif [[ $seconds -lt 3600 ]]; then
        echo "$((seconds / 60))m $((seconds % 60))s"
    else
        echo "$((seconds / 3600))h $(((seconds % 3600) / 60))m"
    fi
}

# Parse duration string to seconds
parse_duration() {
    local duration="$1"

    # Remove any spaces
    duration="${duration// /}"

    # Extract number and unit
    local number="${duration%[a-zA-Z]*}"
    local unit="${duration#$number}"

    # Default to seconds if no unit specified
    if [[ -z "$unit" ]]; then
        unit="s"
    fi

    case "${unit,,}" in
        "s"|"sec"|"seconds")
            echo "$number"
            ;;
        "m"|"min"|"minutes")
            echo $((number * 60))
            ;;
        "h"|"hour"|"hours")
            echo $((number * 3600))
            ;;
        "d"|"day"|"days")
            echo $((number * 86400))
            ;;
        *)
            log_error "Invalid duration unit: $unit (use s, m, h, d)"
            echo 900  # Default to 15 minutes
            ;;
    esac
}

# Check if we should show verbose output
is_verbose() {
    [[ "$DEV_ENV_MANAGER_DEBUG" == "true" ]]
}

# Conditional execution with logging
run_with_log() {
    local description="$1"
    shift
    local command=("$@")

    log_debug "Running: $description"
    log_timestamp "Command: ${command[*]}"

    if "${command[@]}"; then
        log_debug "✅ $description completed successfully"
        return 0
    else
        local exit_code=$?
        log_error "❌ $description failed with exit code: $exit_code"
        return $exit_code
    fi
}

# Safe command execution with error capture
safe_run() {
    local output
    local exit_code

    # Capture both stdout and stderr
    output=$("$@" 2>&1)
    exit_code=$?

    if [[ $exit_code -eq 0 ]]; then
        echo "$output"
        return 0
    else
        log_error "Command failed: $*"
        log_error "Output: $output"
        return $exit_code
    fi
}

# Log environment information for debugging
log_environment_info() {
    if is_verbose; then
        log_debug "Environment Information:"
        log_debug "  Shell: ${SHELL:-unknown}"
        log_debug "  User: $(whoami) ($(id -u):$(id -g))"
        log_debug "  PWD: $PWD"
        log_debug "  Git branch: $(git branch --show-current 2>/dev/null || echo 'not in git repo')"
        log_debug "  Cache dir: $(_get_cache_dir 2>/dev/null || echo 'not initialized')"
        log_debug "  Feature version: ${DEV_ENV_MANAGER_VERSION:-unknown}"
    fi
}

# Pretty print JSON with error handling
pretty_json() {
    local json="$1"

    echo "$json" | jq .
}

# Validate required environment variables
validate_required_vars() {
    local missing_vars=()

    for var in "$@"; do
        if [[ -z "${!var}" ]]; then
            missing_vars+=("$var")
        fi
    done

    if [[ ${#missing_vars[@]} -gt 0 ]]; then
        log_error "Missing required environment variables:"
        for var in "${missing_vars[@]}"; do
            log_error "  - $var"
        done
        return 1
    fi

    return 0
}

# Print banner with feature information
print_banner() {
    if is_verbose; then
        local version="${DEV_ENV_MANAGER_VERSION:-unknown}"
        echo -e "${CYAN}"
        echo "╔══════════════════════════════════════════════════════════════╗"
        echo "║                   Auto Secrets Manager                      ║"
        printf "║                     Version %-7s                       ║\n" "$version"
        echo "╚══════════════════════════════════════════════════════════════╝"
        echo -e "${NC}"
    fi
}

# Export functions for use in other modules
export -f log_error log_warn log_info log_debug log_success
export -f log_cache log_network log_timestamp
export -f error_with_context show_progress format_duration parse_duration
export -f is_verbose run_with_log safe_run log_environment_info
export -f pretty_json validate_required_vars print_banner
