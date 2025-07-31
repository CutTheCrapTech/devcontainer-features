#!/bin/bash
# Auto Secrets Manager - Branch Detection Module
# Handles git branch detection with robust detached HEAD support

# Source logging utilities
if [[ -f "$DEV_ENV_MANAGER_DIR/utils/logging.sh" ]]; then
  source "$DEV_ENV_MANAGER_DIR/utils/logging.sh"
fi

# Global variables for caching current branch state
CACHED_BRANCH=""
CACHED_BRANCH_TIMESTAMP=0
BRANCH_CACHE_TTL=5 # Cache branch for 5 seconds to avoid excessive git calls

# Core branch detection with detached HEAD handling
_get_current_branch() {
  local current_time
  current_time=$(date +%s)

  # Return cached result if still valid
  if [[ -n "$CACHED_BRANCH" ]] && [[ $((current_time - CACHED_BRANCH_TIMESTAMP)) -lt $BRANCH_CACHE_TTL ]]; then
    echo "$CACHED_BRANCH"
    return 0
  fi

  # Check if we're in a git repository
  if ! git rev-parse --git-dir 2>/dev/null; then
    log_debug "Not in a git repository"
    echo "no-git"
    return 0
  fi

  # Try to get current branch name
  local current_branch
  current_branch=$(git branch --show-current 2>/dev/null)

  # Handle detached HEAD state
  if [[ -z "$current_branch" ]]; then
    log_debug "Detached HEAD detected, checking for reference"

    # Try to get a meaningful reference in detached HEAD
    local head_ref
    head_ref=$(git symbolic-ref HEAD 2>/dev/null || git describe --tags --exact-match 2>/dev/null || git rev-parse --short HEAD 2>/dev/null)

    if [[ -n "$head_ref" ]]; then
      # Clean up ref name (remove refs/heads/ prefix if present)
      current_branch="${head_ref#refs/heads/}"
      log_debug "Detached HEAD on: $current_branch"
    else
      current_branch="detached"
      log_debug "True detached HEAD state"
    fi
  fi

  # Cache the result
  CACHED_BRANCH="$current_branch"
  CACHED_BRANCH_TIMESTAMP=$current_time

  log_debug "Current branch: $current_branch"
  echo "$current_branch"
}

# Get branch with fallback to environment variable
get_current_branch() {
  local branch

  # Allow manual override via environment variable
  if [[ -n "$DEV_ENV_MANAGER_OVERRIDE_BRANCH" ]]; then
    log_debug "Using branch override: $DEV_ENV_MANAGER_OVERRIDE_BRANCH"
    echo "$DEV_ENV_MANAGER_OVERRIDE_BRANCH"
    return 0
  fi

  branch=$(_get_current_branch)

  # Handle special cases
  case "$branch" in
  "no-git")
    log_warn "Not in a git repository, using default environment"
    echo "default"
    ;;
  "detached")
    log_warn "Detached HEAD state, using default environment"
    echo "detached"
    ;;
  "")
    log_warn "Could not determine git branch, using default"
    echo "default"
    ;;
  *)
    echo "$branch"
    ;;
  esac
}

# Check if current directory is in a git repository
is_in_git_repo() {
  git rev-parse --is-inside-work-tree >/dev/null 2>&1
}

# Branch change detection for prompt integration
_setup_branch_change_detection() {
  # Store current branch for comparison
  local temp_branch
  temp_branch=$(get_current_branch)
  export LAST_KNOWN_BRANCH="$temp_branch"
  log_debug "Branch change detection initialized: $LAST_KNOWN_BRANCH"
}

# Clear branch cache (useful after git operations)
clear_branch_cache() {
  CACHED_BRANCH=""
  CACHED_BRANCH_TIMESTAMP=0
  log_debug "Branch cache cleared"
}

# Initialize branch change detection if we're in a shell
if [[ -n "$PS1" ]] && is_in_git_repo; then
  _setup_branch_change_detection
fi

# Export functions for use in other modules
export -f get_current_branch is_in_git_repo
export -f clear_branch_cache
