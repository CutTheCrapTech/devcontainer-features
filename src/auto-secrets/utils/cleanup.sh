#!/bin/bash
# Auto Secrets Manager - Cleanup Utilities
# Handles cache maintenance, resource cleanup, and system maintenance

# Source required modules
if [[ -f "$DEV_ENV_MANAGER_DIR/utils/logging.sh" ]]; then
  # shellcheck source=utils/logging.sh
  source "$DEV_ENV_MANAGER_DIR/utils/logging.sh"
fi

if [[ -f "$DEV_ENV_MANAGER_DIR/core/permissions.sh" ]]; then
  # shellcheck source=core/permissions.sh
  source "$DEV_ENV_MANAGER_DIR/core/permissions.sh"
fi

if [[ -f "$DEV_ENV_MANAGER_DIR/core/cache.sh" ]]; then
  # shellcheck source=core/cache.sh
  source "$DEV_ENV_MANAGER_DIR/core/cache.sh"
fi

# Cleanup configuration
readonly DEFAULT_CLEANUP_AGE="7d"
readonly DEFAULT_CLEANUP_INTERVAL="1h"
readonly EMERGENCY_CLEANUP_THRESHOLD="90" # Percentage

# Get cleanup age threshold in seconds
get_cleanup_age_seconds() {
  # Use parsed configuration values with fallbacks
  local age="${DEV_ENV_MANAGER_MAX_STALE_AGE:-${DEV_ENV_MANAGER_CACHE_CLEANUP_INTERVAL:-$DEFAULT_CLEANUP_AGE}}"
  parse_duration "$age"
}

# Get all cache directories for current user
get_user_cache_dirs() {
  local base_dir
  base_dir=$(get_cache_base_dir)
  local user_id
  user_id=$(id -u)

  find "$(dirname "$base_dir")" -maxdepth 1 -type d -name "${base_dir##*/}-${user_id}-*" 2>/dev/null | sort
}

# Get all cache directories for all users (root only)
get_all_cache_dirs() {
  local base_dir
  base_dir=$(get_cache_base_dir)

  if [[ $(id -u) -eq 0 ]]; then
    find "$(dirname "$base_dir")" -maxdepth 1 -type d -name "${base_dir##*/}-*" 2>/dev/null | sort
  else
    log_warn "Cannot list all user cache directories (not root)"
    get_user_cache_dirs
  fi
}

# Check if cache directory is stale
is_cache_stale() {
  local cache_dir="$1"
  local max_age_seconds="$2"
  local current_time
  current_time=$(date +%s)

  # Check last access time
  local last_accessed_file="$cache_dir/.last_accessed"
  if [[ -f "$last_accessed_file" ]]; then
    local last_accessed
    last_accessed=$(cat "$last_accessed_file" 2>/dev/null || echo "0")
    local age=$((current_time - last_accessed))

    if [[ $age -gt $max_age_seconds ]]; then
      return 0 # Stale
    fi
  else
    # No access file - check directory modification time
    local dir_mtime
    dir_mtime=$(stat -c %Y "$cache_dir" 2>/dev/null || echo "0")
    local age=$((current_time - dir_mtime))

    if [[ $age -gt $max_age_seconds ]]; then
      return 0 # Stale
    fi
  fi

  return 1 # Not stale
}

# Get cache directory information
get_cache_info() {
  local cache_dir="$1"

  # Basic info
  local owner
  owner=$(stat -c %U "$cache_dir" 2>/dev/null || echo "unknown")
  local size
  size=$(du -sh "$cache_dir" 2>/dev/null | cut -f1 || echo "unknown")

  # Environment info
  local environment
  environment=$(cat "$cache_dir/.environment" 2>/dev/null || echo "unknown")

  # Last accessed
  local last_accessed
  last_accessed=$(cat "$cache_dir/.last_accessed" 2>/dev/null || echo "0")
  local last_accessed_formatted
  if [[ "$last_accessed" != "0" ]]; then
    last_accessed_formatted=$(date -d "@$last_accessed" 2>/dev/null || echo "unknown")
  else
    last_accessed_formatted="never"
  fi

  # Age calculation
  local current_time
  current_time=$(date +%s)
  local age=$((current_time - last_accessed))
  local age_formatted
  age_formatted=$(format_duration "$age")

  echo "  Directory: $(basename "$cache_dir")"
  echo "  Owner: $owner"
  echo "  Environment: $environment"
  echo "  Size: $size"
  echo "  Last Accessed: $last_accessed_formatted"
  echo "  Age: $age_formatted"
  echo "  Valid: $(if is_cache_valid "$cache_dir"; then echo "Yes"; else echo "No"; fi)"
}

# Clean up stale cache directories
cleanup_stale_caches() {
  local max_age_seconds
  max_age_seconds=$(get_cleanup_age_seconds)
  local cleaned_count=0
  local total_size_cleaned=0

  # Use parsed configuration
  local cleanup_interval="${DEV_ENV_MANAGER_CACHE_CLEANUP_INTERVAL:-$DEFAULT_CLEANUP_AGE}"
  log_info "Cleaning up stale cache directories (older than $cleanup_interval)"

  # Get cache directories to check
  local cache_dirs
  if [[ "$1" == "--all-users" ]] && [[ $(id -u) -eq 0 ]]; then
    mapfile -t cache_dirs < <(get_all_cache_dirs)
    log_info "Cleaning cache for all users (running as root)"
  else
    mapfile -t cache_dirs < <(get_user_cache_dirs)
    log_info "Cleaning cache for current user: $(whoami)"
  fi

  if [[ ${#cache_dirs[@]} -eq 0 ]]; then
    log_info "No cache directories found"
    return 0
  fi

  for cache_dir in "${cache_dirs[@]}"; do
    [[ -d "$cache_dir" ]] || continue

    # Skip if not owned by current user (unless root cleaning all)
    if [[ $(id -u) -ne 0 ]] && ! is_path_secure "$cache_dir"; then
      log_debug "Skipping cache directory with incorrect ownership: $cache_dir"
      continue
    fi

    # Check if cache is stale
    if is_cache_stale "$cache_dir" "$max_age_seconds"; then
      local environment
      environment=$(cat "$cache_dir/.environment" 2>/dev/null || echo "unknown")

      # Get size before deletion
      local size_bytes
      size_bytes=$(du -sb "$cache_dir" 2>/dev/null | cut -f1 || echo "0")

      log_info "Removing stale cache: $environment ($(basename "$cache_dir"))"

      if remove_path_secure "$cache_dir"; then
        ((cleaned_count++))
        total_size_cleaned=$((total_size_cleaned + size_bytes))
      else
        log_error "Failed to remove stale cache: $cache_dir"
      fi
    else
      log_debug "Cache still fresh: $(basename "$cache_dir")"
    fi
  done

  local size_cleaned_formatted
  if [[ $total_size_cleaned -gt 0 ]]; then
    if [[ $total_size_cleaned -gt 1048576 ]]; then
      size_cleaned_formatted="$((total_size_cleaned / 1048576))MB"
    elif [[ $total_size_cleaned -gt 1024 ]]; then
      size_cleaned_formatted="$((total_size_cleaned / 1024))KB"
    else
      size_cleaned_formatted="${total_size_cleaned}B"
    fi
  else
    size_cleaned_formatted="0B"
  fi

  log_success "Cache cleanup completed: $cleaned_count directories removed, $size_cleaned_formatted freed"
  return 0
}

# Clean up invalid/corrupted cache directories
cleanup_invalid_caches() {
  local cleaned_count=0

  log_info "Cleaning up invalid/corrupted cache directories"

  local cache_dirs
  mapfile -t cache_dirs < <(get_user_cache_dirs)

  for cache_dir in "${cache_dirs[@]}"; do
    [[ -d "$cache_dir" ]] || continue

    # Skip if not owned by current user
    if ! is_path_secure "$cache_dir"; then
      continue
    fi

    # Check if cache is valid
    if ! is_cache_valid "$cache_dir"; then
      local environment
      environment=$(cat "$cache_dir/.environment" 2>/dev/null || echo "unknown")

      log_info "Removing invalid cache: $environment ($(basename "$cache_dir"))"

      if remove_path_secure "$cache_dir"; then
        ((cleaned_count++))
      else
        log_error "Failed to remove invalid cache: $cache_dir"
      fi
    fi
  done

  log_success "Invalid cache cleanup completed: $cleaned_count directories removed"
  return 0
}

# Emergency cleanup when disk space is low
emergency_cleanup() {
  local threshold="${1:-$EMERGENCY_CLEANUP_THRESHOLD}"

  log_warn "Running emergency cleanup (threshold: ${threshold}%)"

  # Check disk usage
  local base_dir
  base_dir=$(get_cache_base_dir)
  local disk_usage
  disk_usage=$(df "$(dirname "$base_dir")" | awk 'NR==2 {print $5}' | sed 's/%//')

  if [[ -z "$disk_usage" ]] || [[ ! "$disk_usage" =~ ^[0-9]+$ ]]; then
    log_error "Could not determine disk usage"
    return 1
  fi

  log_info "Current disk usage: ${disk_usage}%"

  if [[ $disk_usage -lt $threshold ]]; then
    log_info "Disk usage below threshold, no emergency cleanup needed"
    return 0
  fi

  # Aggressive cleanup strategy
  log_warn "Disk usage above threshold, performing aggressive cleanup"

  # 1. Clean all invalid caches first
  cleanup_invalid_caches

  # 2. Clean stale caches with reduced threshold (1 day instead of 7)
  log_info "Cleaning caches older than 1 day"
  local one_day_seconds=86400
  local cache_dirs
  mapfile -t cache_dirs < <(get_user_cache_dirs)

  for cache_dir in "${cache_dirs[@]}"; do
    [[ -d "$cache_dir" ]] || continue

    if ! is_path_secure "$cache_dir"; then
      continue
    fi

    if is_cache_stale "$cache_dir" "$one_day_seconds"; then
      local environment
      environment=$(cat "$cache_dir/.environment" 2>/dev/null || echo "unknown")
      log_info "Emergency cleanup: removing cache for $environment"
      remove_path_secure "$cache_dir"
    fi
  done

  # 3. Check disk usage again
  disk_usage=$(df "$(dirname "$base_dir")" | awk 'NR==2 {print $5}' | sed 's/%//')
  log_info "Disk usage after emergency cleanup: ${disk_usage}%"

  if [[ $disk_usage -ge $threshold ]]; then
    log_error "Emergency cleanup completed but disk usage still high"
    return 1
  else
    log_success "Emergency cleanup successful"
    return 0
  fi
}

# List all cache directories with details
list_all_caches() {
  local show_all_users="${1:-false}"

  echo "Cache Directory Report:"
  echo "======================"

  local cache_dirs
  if [[ "$show_all_users" == "true" ]] && [[ $(id -u) -eq 0 ]]; then
    mapfile -t cache_dirs < <(get_all_cache_dirs)
    echo "Showing cache for all users (running as root)"
  else
    mapfile -t cache_dirs < <(get_user_cache_dirs)
    echo "Showing cache for current user: $(whoami)"
  fi

  if [[ ${#cache_dirs[@]} -eq 0 ]]; then
    echo "No cache directories found"
    return 0
  fi

  local total_size=0
  local valid_count=0
  local invalid_count=0
  local stale_count=0

  local max_age_seconds
  max_age_seconds=$(get_cleanup_age_seconds)

  for cache_dir in "${cache_dirs[@]}"; do
    [[ -d "$cache_dir" ]] || continue

    echo ""
    get_cache_info "$cache_dir"

    # Update counters
    local size_bytes
    size_bytes=$(du -sb "$cache_dir" 2>/dev/null | cut -f1 || echo "0")
    total_size=$((total_size + size_bytes))

    if is_cache_valid "$cache_dir"; then
      ((valid_count++))
    else
      ((invalid_count++))
    fi

    if is_cache_stale "$cache_dir" "$max_age_seconds"; then
      ((stale_count++))
    fi
  done

  echo ""
  echo "Summary:"
  echo "  Total directories: ${#cache_dirs[@]}"
  echo "  Valid: $valid_count"
  echo "  Invalid: $invalid_count"
  echo "  Stale: $stale_count"

  # Format total size
  local total_size_formatted
  if [[ $total_size -gt 1073741824 ]]; then
    total_size_formatted="$((total_size / 1073741824))GB"
  elif [[ $total_size -gt 1048576 ]]; then
    total_size_formatted="$((total_size / 1048576))MB"
  elif [[ $total_size -gt 1024 ]]; then
    total_size_formatted="$((total_size / 1024))KB"
  else
    total_size_formatted="${total_size}B"
  fi

  echo "  Total size: $total_size_formatted"
}

# Schedule periodic cleanup (if supported by system)
schedule_cleanup() {
  # Use parsed configuration values
  local interval="${DEV_ENV_MANAGER_CACHE_CLEANUP_INTERVAL:-$DEFAULT_CLEANUP_INTERVAL}"

  log_info "Setting up periodic cleanup (interval: $interval)"

  # Check if we can schedule cleanup
  if command -v crontab >/dev/null 2>&1; then
    # Convert interval to cron format (simplified)
    local cron_schedule
    case "$interval" in
    *h)
      local hours="${interval%h}"
      cron_schedule="0 */$hours * * *"
      ;;
    *d)
      local days="${interval%d}"
      cron_schedule="0 0 */$days * *"
      ;;
    *)
      # Default to daily
      cron_schedule="0 2 * * *" # 2 AM daily
      ;;
    esac

    log_info "Would add cron job: $cron_schedule dev-env-manager cleanup-cache"
    log_warn "Automatic cron scheduling not implemented - add manually if needed"
  else
    log_warn "Crontab not available - cannot schedule automatic cleanup"
  fi
}

# Cleanup function for shell exit
cleanup_on_exit() {
  local exit_code="${1:-0}"

  log_debug "Performing exit cleanup (exit code: $exit_code)"

  # Quick cleanup of current session artifacts
  local temp_files=()

  # Find any temporary files we might have created for this specific shell process
  if [[ -n "$TMPDIR" ]]; then
    mapfile -t -O "${#temp_files[@]}" temp_files < <(find "$TMPDIR" -name "dev-env-manager.$.*" -user "$(whoami)" 2>/dev/null || true)
  fi
  mapfile -t -O "${#temp_files[@]}" temp_files < <(find /tmp -name "dev-env-manager.$.*" -user "$(whoami)" 2>/dev/null || true)

  for temp_file in "${temp_files[@]}"; do
    if [[ -e "$temp_file" ]]; then
      log_debug "Cleaning up temporary file: $temp_file"
      rm -rf "$temp_file" 2>/dev/null || true
    fi
  done

  # Update access timestamp on active cache
  local cache_dir
  cache_dir=$(get_cache_dir 2>/dev/null || echo "")
  if [[ -n "$cache_dir" ]] && [[ -d "$cache_dir" ]]; then
    touch_cache_access "$cache_dir" 2>/dev/null || true
  fi

  log_debug "Exit cleanup completed"
}

# Clean up specific environment cache
cleanup_environment_cache() {
  local environment="$1"

  if [[ -z "$environment" ]]; then
    log_error "Environment not specified for cleanup"
    return 1
  fi

  local cache_dir
  cache_dir=$(get_cache_dir_for_environment "$environment")

  if [[ -d "$cache_dir" ]]; then
    log_info "Cleaning up cache for environment: $environment"
    remove_path_secure "$cache_dir"
  else
    log_info "No cache found for environment: $environment"
  fi
}

# Comprehensive cleanup function
full_cleanup() {
  local force="${1:-false}"

  if [[ "$force" != "true" ]]; then
    echo "This will clean up all cache directories and temporary files."
    echo -n "Are you sure? (y/N): "
    read -r response
    if [[ ! "$response" =~ ^[Yy]$ ]]; then
      log_info "Cleanup cancelled"
      return 0
    fi
  fi

  log_info "Performing full cleanup"

  # Clean up invalid caches
  cleanup_invalid_caches "$@"

  # Clean up stale caches
  cleanup_stale_caches "$@"

  # Clean up temporary files
  cleanup_on_exit "$@"

  # Clean up empty directories
  local base_dir
  base_dir=$(get_cache_base_dir)
  find "$(dirname "$base_dir")" -type d -empty -name "${base_dir##*/}-*" -delete 2>/dev/null || true

  log_success "Full cleanup completed"
  return 0
}

# Set up exit cleanup trap if in interactive shell
if [[ -n "$PS1" ]]; then
  trap 'cleanup_on_exit $?' EXIT
fi

# Ensure configuration is loaded when module is sourced
if [[ -z "$DEV_ENV_MANAGER_VERSION" ]] && [[ -n "$DEV_ENV_MANAGER_DIR" ]] && [[ -f "$DEV_ENV_MANAGER_DIR/config.sh" ]]; then
  # shellcheck source=/dev/null
  source "$DEV_ENV_MANAGER_DIR/config.sh"
fi
