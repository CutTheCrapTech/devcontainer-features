#!/bin/bash
# Auto Secrets Manager - Cache Management Module
# Handles secure caching of secrets in tmpfs with atomic operations

# Source required modules
if [[ -f "$DEV_ENV_MANAGER_DIR/utils/logging.sh" ]]; then
    source "$DEV_ENV_MANAGER_DIR/utils/logging.sh"
fi

if [[ -f "$DEV_ENV_MANAGER_DIR/core/environment-mapping.sh" ]]; then
    source "$DEV_ENV_MANAGER_DIR/core/environment-mapping.sh"
fi

if [[ -f "$DEV_ENV_MANAGER_DIR/core/permissions.sh" ]]; then
    source "$DEV_ENV_MANAGER_DIR/core/permissions.sh"
fi

# Cache configuration
readonly CACHE_BASE_DIR="/dev/shm/dev-env-manager"
readonly CACHE_FALLBACK_DIR="/tmp/dev-env-manager"
readonly CACHE_VERSION="v1"

# Get the base cache directory (prefer tmpfs, fallback to /tmp)
_get_cache_base_dir() {
    if [[ -d /dev/shm ]] && [[ -w /dev/shm ]]; then
        echo "$CACHE_BASE_DIR"
    else
        log_warn "/dev/shm not available, using less secure fallback: $CACHE_FALLBACK_DIR"
        echo "$CACHE_FALLBACK_DIR"
    fi
}

# Generate cache directory path for current user and environment
get_cache_dir() {
    local user_id=$(id -u)
    local environment
    environment=$(get_current_environment_with_override)
    local env_hash
    env_hash=$(get_environment_hash "$environment")
    local base_dir
    base_dir=$(_get_cache_base_dir)

    echo "${base_dir}-${user_id}-${env_hash}"
}

# Get cache directory for specific environment
get_cache_dir_for_environment() {
    local environment="$1"
    local user_id=$(id -u)
    local env_hash
    env_hash=$(get_environment_hash "$environment")
    local base_dir
    base_dir=$(_get_cache_base_dir)

    echo "${base_dir}-${user_id}-${env_hash}"
}

# Create cache directory with proper security
_create_cache_dir() {
    local cache_dir="$1"
    local lock_file="${cache_dir}.lock"

    log_cache "Creating cache directory: $cache_dir"

    # Use atomic directory creation from permissions module
    if ! create_secure_directory "$cache_dir"; then
        log_error "Failed to create cache directory: $cache_dir"
        return 1
    fi

    # Create control files
    local control_files=(
        ".version"
        ".timestamp"
        ".last_accessed"
        ".environment"
        ".branch"
    )

    for file in "${control_files[@]}"; do
        if ! create_secure_file "$cache_dir/$file"; then
            log_error "Failed to create control file: $cache_dir/$file"
            remove_path_secure "$cache_dir"
            return 1
        fi
    done

    # Write initial metadata
    local current_time=$(date +%s)
    local current_environment
    current_environment=$(get_current_environment_with_override)
    local current_branch
    current_branch=$(get_current_branch)

    write_file_atomic "$cache_dir/.version" "$CACHE_VERSION"
    write_file_atomic "$cache_dir/.timestamp" "$current_time"
    write_file_atomic "$cache_dir/.last_accessed" "$current_time"
    write_file_atomic "$cache_dir/.environment" "$current_environment"
    write_file_atomic "$cache_dir/.branch" "$current_branch"

    # Create main secrets file
    if ! create_secure_file "$cache_dir/secrets.json"; then
        log_error "Failed to create secrets file"
        remove_path_secure "$cache_dir"
        return 1
    fi

    log_cache "Cache directory created successfully: $cache_dir"
    return 0
}

# Check if cache directory exists and is valid
is_cache_valid() {
    local cache_dir="$1"

    # Check if directory exists
    if [[ ! -d "$cache_dir" ]]; then
        log_debug "Cache directory does not exist: $cache_dir"
        return 1
    fi

    # Verify permissions and ownership
    if ! is_path_secure "$cache_dir"; then
        log_warn "Cache directory security compromised: $cache_dir"
        return 1
    fi

    # Check for required files
    local required_files=(
        "secrets.json"
        ".timestamp"
        ".last_accessed"
        ".environment"
    )

    for file in "${required_files[@]}"; do
        if [[ ! -f "$cache_dir/$file" ]]; then
            log_debug "Missing cache file: $cache_dir/$file"
            return 1
        fi

        if ! is_path_secure "$cache_dir/$file"; then
            log_warn "Cache file security compromised: $cache_dir/$file"
            return 1
        fi
    done

    log_debug "Cache is valid: $cache_dir"
    return 0
}

# Get cache age in seconds
get_cache_age() {
    local cache_dir="$1"
    local timestamp_file="$cache_dir/.timestamp"

    if [[ ! -f "$timestamp_file" ]]; then
        echo "0"
        return 1
    fi

    local cache_timestamp
    cache_timestamp=$(cat "$timestamp_file" 2>/dev/null || echo "0")
    local current_time=$(date +%s)
    local age=$((current_time - cache_timestamp))

    echo "$age"
}

# Check if cache should be refreshed
should_refresh_cache() {
    local cache_dir="$1"
    local max_age="${2:-}"

    if [[ -z "$max_age" ]]; then
        # Ensure DEV_ENV_MANAGER_CACHE_REFRESH_INTERVAL is available or use default
        local refresh_interval="${DEV_ENV_MANAGER_CACHE_REFRESH_INTERVAL:-${DEV_ENV_MANAGER_CACHE_EXPIRY:-15m}}"
        max_age=$(parse_duration "$refresh_interval")
    fi

    if ! is_cache_valid "$cache_dir"; then
        log_debug "Cache invalid, needs refresh"
        return 0
    fi

    local cache_age
    cache_age=$(get_cache_age "$cache_dir")

    if [[ $cache_age -gt $max_age ]]; then
        log_debug "Cache expired (age: ${cache_age}s, max: ${max_age}s)"
        return 0
    fi

    log_debug "Cache is fresh (age: ${cache_age}s, max: ${max_age}s)"
    return 1
}

# Touch cache access timestamp
touch_cache_access() {
    local cache_dir="$1"
    local access_file="$cache_dir/.last_accessed"

    if [[ -f "$access_file" ]]; then
        local current_time=$(date +%s)
        write_file_atomic "$access_file" "$current_time"
        log_cache "Cache access recorded: $cache_dir"
    fi
}

# Write secrets to cache atomically
write_secrets_to_cache() {
    local cache_dir="$1"
    local secrets_content="$2"

    log_cache "Writing secrets to cache: $cache_dir"

    # Ensure cache directory exists
    if [[ ! -d "$cache_dir" ]]; then
        if ! _create_cache_dir "$cache_dir"; then
            log_error "Failed to create cache directory for writing"
            return 1
        fi
    fi

    # Verify cache is secure before writing
    if ! is_cache_valid "$cache_dir"; then
        log_error "Cache directory invalid, cannot write secrets"
        return 1
    fi

    # Prepare secrets content as JSON with metadata
    local full_content
    full_content=$(cat << EOF
{
  "_metadata": {
    "generated_at": "$(date -Iseconds)",
    "environment": "$(get_current_environment_with_override)",
    "branch": "$(get_current_branch)",
    "version": "$CACHE_VERSION"
  },
  "secrets": $secrets_content
}
EOF
)

    # Write secrets atomically
    if ! write_file_atomic "$cache_dir/secrets.json" "$full_content"; then
        log_error "Failed to write secrets to cache"
        return 1
    fi

    # Update timestamp
    local current_time=$(date +%s)
    write_file_atomic "$cache_dir/.timestamp" "$current_time"
    touch_cache_access "$cache_dir"

    log_cache "Secrets written to cache successfully"
    return 0
}

# Get cache status information
get_cache_status() {
    local cache_dir
    cache_dir=$(get_cache_dir)

    echo "Cache Status:"
    echo "  Directory: $cache_dir"

    if is_cache_valid "$cache_dir"; then
        local cache_age
        cache_age=$(get_cache_age "$cache_dir")
        local age_formatted
        age_formatted=$(format_duration "$cache_age")

        local environment
        environment=$(cat "$cache_dir/.environment" 2>/dev/null || echo "unknown")

        local branch
        branch=$(cat "$cache_dir/.branch" 2>/dev/null || echo "unknown")

        echo "  Status: Valid"
        echo "  Age: $age_formatted"
        echo "  Environment: $environment"
        echo "  Branch: $branch"
        echo "  Secrets file: $(jq '.secrets | length' < "$cache_dir/secrets.json" 2>/dev/null || echo "0") secrets"
    else
        echo "  Status: Invalid or missing"
    fi
}

# Clean up old cache directories
cleanup_old_caches() {
    local base_dir
    base_dir=$(_get_cache_base_dir)
    local user_id=$(id -u)
    local cleanup_threshold_seconds
    cleanup_threshold_seconds=$(parse_duration "${DEV_ENV_MANAGER_OFFLINE_MODE_MAX_STALE_AGE:-${DEV_ENV_MANAGER_CACHE_CLEANUP_INTERVAL:-7d}}")
    local current_time=$(date +%s)
    local cleaned_count=0

    log_info "Cleaning up old cache directories..."

    # Find all cache directories for current user
    for cache_dir in "${base_dir}"-"${user_id}"-*; do
        [[ -d "$cache_dir" ]] || continue

        # Skip if not owned by current user (safety check)
        if ! is_path_secure "$cache_dir"; then
            log_warn "Skipping cache directory with incorrect ownership: $cache_dir"
            continue
        fi

        local last_accessed_file="$cache_dir/.last_accessed"

        # Skip if no access timestamp (newly created cache)
        [[ -f "$last_accessed_file" ]] || continue

        local last_accessed
        last_accessed=$(cat "$last_accessed_file" 2>/dev/null || echo "0")
        local age=$((current_time - last_accessed))

        if [[ $age -gt $cleanup_threshold_seconds ]]; then
            local environment
            environment=$(cat "$cache_dir/.environment" 2>/dev/null || echo "unknown")

            log_info "Removing stale cache: $environment (unused for $(format_duration $age))"

            if remove_path_secure "$cache_dir"; then
                ((cleaned_count++))
            else
                log_error "Failed to remove stale cache: $cache_dir"
            fi
        fi
    done

    log_info "Cache cleanup completed: $cleaned_count directories removed"
}

# Initialize cache system
_init_cache_system() {
    local base_dir
    base_dir=$(_get_cache_base_dir)

    # Ensure base directory exists with proper permissions
    if [[ ! -d "$(dirname "$base_dir")" ]]; then
        log_error "Cache base directory not available: $(dirname "$base_dir")"
        return 1
    fi

    # Log cache configuration
    if [[ "$DEV_ENV_MANAGER_DEBUG" == "true" ]]; then
        log_debug "Cache system initialized (base: $base_dir)"
        log_debug "Cache refresh interval: ${DEV_ENV_MANAGER_CACHE_REFRESH_INTERVAL:-15m}"
        log_debug "Cache strategy: ${DEV_ENV_MANAGER_CACHE_STRATEGY:-time_based}"
        log_debug "Background refresh: ${DEV_ENV_MANAGER_CACHE_BACKGROUND_REFRESH:-false}"
    fi

    return 0
}

# Get or create cache directory for current environment
ensure_cache_dir() {
    local cache_dir
    cache_dir=$(get_cache_dir)

    if is_cache_valid "$cache_dir"; then
        touch_cache_access "$cache_dir"
        echo "$cache_dir"
        return 0
    fi

    log_info "Creating cache directory for environment: $(get_current_environment_with_override)"

    if _create_cache_dir "$cache_dir"; then
        echo "$cache_dir"
        return 0
    else
        log_error "Failed to create cache directory"
        return 1
    fi
}

# Export functions for use in other modules
export -f get_cache_dir get_cache_dir_for_environment
export -f is_cache_valid get_cache_age should_refresh_cache touch_cache_access
export -f write_secrets_to_cache get_cache_status cleanup_old_caches ensure_cache_dir

# Initialize cache system when module is loaded
_init_cache_system
