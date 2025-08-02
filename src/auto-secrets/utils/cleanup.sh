#!/bin/bash
# Auto Secrets Manager - Cleanup Utilities
# This file now acts as a simple wrapper around the centralized cache cleanup logic.

# This function is the main entry point for cleaning stale caches.
# It calls the centralized `cleanup_old_caches` function from `core/cache.sh`
# which contains the authoritative logic based on `cache.metadata.json`.
cleanup_stale_caches() {
    log_info "Initiating stale cache cleanup..."
    cleanup_old_caches
}

# This function is now deprecated and simply calls the new central function.
# It is kept for backward compatibility in case it is called from other scripts.
cleanup_invalid_caches() {
    log_warn "cleanup_invalid_caches is deprecated. The logic is now part of cleanup_old_caches."
    cleanup_old_caches
}

# A simple function to list caches. This can be expanded later if needed.
list_all_caches() {
    log_info "Listing all cache directories..."
    get_cache_status
}

# Comprehensive cleanup function
full_cleanup() {
  local force="${1:-false}"

  if [[ "$force" != "true" ]]; then
    echo "This will clean up all cache directories and temporary files."
    read -p "Are you sure? (y/N) " -r
    if [[ ! "$response" =~ ^[Yy]$ ]]; then
      log_info "Cleanup cancelled"
      return 0
    fi
  fi

  log_info "Performing full cleanup..."
  cleanup_old_caches
  log_success "Full cleanup completed"
}