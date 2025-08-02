#!/bin/bash
# Auto Secrets Manager - Cache Management Module
# Handles secure caching of secrets in tmpfs with atomic operations

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
  local user_id
  user_id=$(id -u)
  local environment
  environment=$(get_current_environment_with_override)
  local env_hash
  env_hash=$(get_environment_hash "$environment")
  local base_dir
  base_dir=$(_get_cache_base_dir)

  echo "${base_dir}-${user_id}-${env_hash}"
}

# Create cache directory with proper security
_create_cache_dir() {
  local cache_dir="$1"

  log_cache "Creating cache directory: $cache_dir"

  # Use atomic directory creation from permissions module
  if ! create_secure_directory "$cache_dir"; then
    log_error "Failed to create cache directory: $cache_dir"
    return 1
  fi

  # Create version file and initial empty metadata file
  if ! create_secure_file "$cache_dir/.version" || ! create_secure_file "$cache_dir/cache.metadata.json"; then
    log_error "Failed to create control files in $cache_dir"
    remove_path_secure "$cache_dir"
    return 1
  fi

  # Write initial data
  write_file_atomic "$cache_dir/.version" "$CACHE_VERSION"
  jq -n '{status: "uninitialized"}' >"$cache_dir/cache.metadata.json"

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

  # Check for essential files
  if [[ ! -f "$cache_dir/secrets.json" ]] || [[ ! -f "$cache_dir/cache.metadata.json" ]]; then
    log_debug "Missing essential cache files in $cache_dir"
    return 1
  fi

  log_debug "Cache is valid: $cache_dir"
  return 0
}

# Get cache age in seconds from metadata
get_cache_age() {
  local cache_dir="$1"
  local metadata_file="$cache_dir/cache.metadata.json"

  if [[ ! -f "$metadata_file" ]]; then
    echo "-1"
    return
  fi

  local last_refresh_str
  last_refresh_str=$(jq -r '.last_successful_refresh // "0"' "$metadata_file")

  # Handle ISO 8601 date format
  local last_refresh_ts
  if [[ "$last_refresh_str" == "0" ]]; then
    last_refresh_ts=0
  else
    last_refresh_ts=$(date -d "$last_refresh_str" +%s)
  fi

  local current_time
  current_time=$(date +%s)
  local age=$((current_time - last_refresh_ts))

  echo "$age"
}

# Check if cache should be refreshed based on metadata
should_refresh_cache() {
  local cache_dir="$1"
  local metadata_file="$cache_dir/cache.metadata.json"

  if ! is_cache_valid "$cache_dir"; then
    log_debug "Cache invalid, needs refresh"
    return 0 # Needs refresh
  fi

  local status
  status=$(jq -r '.status // "error"' "$metadata_file")

  if [[ "$status" != "ok" ]]; then
    log_debug "Cache status is '$status', needs refresh"
    return 0 # Needs refresh
  fi

  local max_age
  local refresh_interval="${DEV_ENV_MANAGER_CACHE_REFRESH_INTERVAL:-15m}"
  max_age=$(parse_duration "$refresh_interval")

  local cache_age
  cache_age=$(get_cache_age "$cache_dir")

  if [[ $cache_age -gt $max_age ]]; then
    log_debug "Cache expired (age: ${cache_age}s, max: ${max_age}s)"
    return 0 # Needs refresh
  fi

  log_debug "Cache is fresh (age: ${cache_age}s, max: ${max_age}s)"
  return 1 # Does not need refresh
}

# Touch cache access timestamp in metadata
touch_cache_access() {
  local cache_dir="$1"
  local metadata_file="$cache_dir/cache.metadata.json"

  if [[ -f "$metadata_file" ]]; then
    local current_metadata
    current_metadata=$(cat "$metadata_file")
    local new_metadata
    new_metadata=$(echo "$current_metadata" | jq --arg date "$(date -Iseconds)" '.last_accessed = $date')
    write_file_atomic "$metadata_file" "$new_metadata"
    log_cache "Cache access recorded: $cache_dir"
  fi
}

# Write secrets to cache atomically and update metadata
write_secrets_to_cache() {
  local cache_dir="$1"
  local secrets_content="$2"

  log_cache "Writing secrets to cache: $cache_dir"

  if ! ensure_cache_dir >/dev/null; then
    log_error "Failed to ensure cache directory exists for writing"
    return 1
  fi

  # Prepare secrets content as JSON with metadata
  local full_content
  full_content=$(jq -n --argjson secrets "$secrets_content" \
    --arg env "$(get_current_environment_with_override)" \
    --arg branch "$(get_current_branch)" \
    --arg version "$CACHE_VERSION" \
    '{ "_metadata": { "generated_at": "$(now | todate)", "environment": $env, "branch": $branch, "version": $version }, "secrets": $secrets }')

  # Write secrets atomically
  if ! write_file_atomic "$cache_dir/secrets.json" "$full_content"; then
    log_error "Failed to write secrets to cache"
    return 1
  fi

  # Update metadata file to status: ok
  local metadata_file="$cache_dir/cache.metadata.json"
  local current_metadata
  current_metadata=$(cat "$metadata_file")
  local new_metadata
  new_metadata=$(echo "$current_metadata" | jq \
    --arg status "ok" \
    --arg date "$(date -Iseconds)" \
    --arg env "$(get_current_environment_with_override)" \
    --arg branch "$(get_current_branch)" \
    '.status = $status | .last_successful_refresh = $date | .environment = $env | .branch = $branch')

  if ! write_file_atomic "$metadata_file" "$new_metadata"; then
    log_error "Failed to update cache metadata"
    return 1
  fi

  log_cache "Secrets written to cache successfully"
  return 0
}

# Get cache status information from metadata
get_cache_status() {
  local cache_dir
  cache_dir=$(get_cache_dir)

  echo "Cache Status:"
  echo "  Directory: $cache_dir"

  local metadata_file="$cache_dir/cache.metadata.json"
  if [[ ! -f "$metadata_file" ]]; then
    echo "  Status: Not initialized"
    return
  fi

  local status
  status=$(jq -r '.status // "unknown"' "$metadata_file")
  echo "  Status: $status"

  if [[ "$status" == "ok" ]]; then
    local cache_age
    cache_age=$(get_cache_age "$cache_dir")
    local age_formatted
    age_formatted=$(format_duration "$cache_age")

    local environment
    environment=$(jq -r '.environment // "unknown"' "$metadata_file")
    local branch
    branch=$(jq -r '.branch // "unknown"' "$metadata_file")

    echo "  Age: $age_formatted"
    echo "  Environment: $environment"
    echo "  Branch: $branch"
    echo "  Secrets file: $(jq '.secrets | length' <"$cache_dir/secrets.json" 2>/dev/null || echo "0") secrets"
  elif [[ "$status" == "error" ]]; then
    local last_attempt
    last_attempt=$(jq -r '.last_attempted_refresh // "unknown"' "$metadata_file")
    local error_message
    error_message=$(jq -r '.error_message // "-"' "$metadata_file")
    echo "  Last Attempt: $last_attempt"
    echo "  Error: $error_message"
  fi
}

# Clean up old cache directories based on metadata
cleanup_old_caches() {
  local base_dir
  base_dir=$(_get_cache_base_dir)
  local user_id
  user_id=$(id -u)
  local cleanup_threshold_seconds
  cleanup_threshold_seconds=$(parse_duration "${DEV_ENV_MANAGER_CACHE_CLEANUP_INTERVAL:-7d}")
  local current_time
  current_time=$(date +%s)
  local cleaned_count=0

  log_info "Cleaning up old cache directories..."

  for cache_dir in "${base_dir}"-"${user_id}"-*; do
    [[ -d "$cache_dir" ]] || continue

    if ! is_path_secure "$cache_dir"; then
      log_warn "Skipping cache directory with incorrect ownership: $cache_dir"
      continue
    fi

    local metadata_file="$cache_dir/cache.metadata.json"
    [[ -f "$metadata_file" ]] || continue

    local last_accessed_str
    last_accessed_str=$(jq -r '.last_accessed // "0"' "$metadata_file")

    local last_accessed_ts
    if [[ "$last_accessed_str" == "0" ]]; then
      last_accessed_ts=0
    else
      last_accessed_ts=$(date -d "$last_accessed_str" +%s)
    fi

    local age=$((current_time - last_accessed_ts))

    if [[ $age -gt $cleanup_threshold_seconds ]]; then
      local environment
      environment=$(jq -r '.environment // "unknown"' "$metadata_file")

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

  if [[ -d "$cache_dir" ]]; then
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
