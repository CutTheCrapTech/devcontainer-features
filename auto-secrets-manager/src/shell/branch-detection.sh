#!/bin/bash
# Auto Secrets Manager - Branch Detection Logic
#
# Optimized branch change detection for shell integration.
# This file contains the core logic shared between bash and zsh.
# Designed to be fast (~2-5ms with caching) and reliable.

# Cache directory for branch state
AUTO_SECRETS_CACHE_DIR="${AUTO_SECRETS_CACHE_DIR:-/dev/shm/auto-secrets-${USER}}"
AUTO_SECRETS_BRANCH_CACHE="${AUTO_SECRETS_CACHE_DIR}/state/current_branch"

# Initialize branch cache directory
_auto_secrets_init_branch_cache() {
  if [[ ! -d "${AUTO_SECRETS_CACHE_DIR}/state" ]]; then
    mkdir -p "${AUTO_SECRETS_CACHE_DIR}/state" 2>/dev/null || {
      # Fallback to home directory if /dev/shm is not available
      AUTO_SECRETS_CACHE_DIR="${HOME}/.cache/auto-secrets"
      AUTO_SECRETS_BRANCH_CACHE="${AUTO_SECRETS_CACHE_DIR}/state/current_branch"
      mkdir -p "${AUTO_SECRETS_CACHE_DIR}/state" 2>/dev/null
    }
  fi
}

# Fast branch detection with caching
_auto_secrets_get_current_branch() {
  # Fast path: check if we're in a git repository
  if [[ ! -d .git ]] && ! git rev-parse --git-dir >/dev/null 2>&1; then
    echo ""
    return 0
  fi

  # Get current branch name
  local branch
  branch=$(git branch --show-current 2>/dev/null)

  # Fallback for detached HEAD or older git versions
  if [[ -z "$branch" ]]; then
    branch=$(git symbolic-ref --short HEAD 2>/dev/null || echo "")
  fi

  echo "$branch"
}

# Get the last known branch from cache
_auto_secrets_get_cached_branch() {
  if [[ -f "$AUTO_SECRETS_BRANCH_CACHE" ]]; then
    cat "$AUTO_SECRETS_BRANCH_CACHE" 2>/dev/null || echo ""
  else
    echo ""
  fi
}

# Update the cached branch
_auto_secrets_update_cached_branch() {
  local branch="$1"
  local repo_path="$2"

  _auto_secrets_init_branch_cache

  # Store branch and repo path
  echo "$branch" >"$AUTO_SECRETS_BRANCH_CACHE" 2>/dev/null
  echo "$repo_path" >"${AUTO_SECRETS_BRANCH_CACHE}.repo" 2>/dev/null
}

# Main branch change detection function
# This is called from precmd hooks in both bash and zsh
_auto_secrets_check_branch_change() {
  # Skip if disabled
  if [[ "$AUTO_SECRETS_ENABLE" == "false" ]]; then
    return 0
  fi

  # Get current branch and repository path
  local current_branch
  current_branch=$(_auto_secrets_get_current_branch)
  local current_repo
  current_repo=$(git rev-parse --show-toplevel 2>/dev/null)

  # Get cached branch and repo
  local cached_branch
  cached_branch=$(_auto_secrets_get_cached_branch)
  local cached_repo=""
  if [[ -f "${AUTO_SECRETS_BRANCH_CACHE}.repo" ]]; then
    cached_repo=$(cat "${AUTO_SECRETS_BRANCH_CACHE}.repo" 2>/dev/null || echo "")
  fi

  # Check if branch or repository changed
  if [[ "$current_branch" != "$cached_branch" ]] || [[ "$current_repo" != "$cached_repo" ]]; then
    # Update cache first (fast operation)
    _auto_secrets_update_cached_branch "$current_branch" "$current_repo"

    # Only notify if we have a valid branch and the change is meaningful
    if [[ -n "$current_branch" ]] && [[ "$current_branch" != "$cached_branch" ]]; then
      # Notify Python daemon in background (non-blocking)
      if command -v auto-secrets >/dev/null 2>&1; then
        {
          auto-secrets branch-changed "$current_branch" "$current_repo" 2>/dev/null || true
        } &
        # Don't wait for the background process
        disown 2>/dev/null || true
      fi

      # Optional: Update environment variable for shell prompt
      if [[ "$AUTO_SECRETS_SHOW_ENV_IN_PROMPT" == "true" ]]; then
        export AUTO_SECRETS_CURRENT_BRANCH="$current_branch"
      fi

      # Optional: Debug output
      if [[ "$AUTO_SECRETS_DEBUG" == "true" ]]; then
        echo "[auto-secrets] Branch changed: $cached_branch -> $current_branch" >&2
      fi
    fi
  fi
}

# Force refresh of branch detection
_auto_secrets_force_branch_refresh() {
  # Clear cache to force detection
  rm -f "$AUTO_SECRETS_BRANCH_CACHE" "${AUTO_SECRETS_BRANCH_CACHE}.repo" 2>/dev/null
  _auto_secrets_check_branch_change
}

# Get current environment (for prompt display)
_auto_secrets_get_current_env() {
  local branch
  branch=$(_auto_secrets_get_current_branch)

  if [[ -n "$branch" ]] && command -v auto-secrets >/dev/null 2>&1; then
    auto-secrets current-env --prompt-format 2>/dev/null || echo ""
  else
    echo ""
  fi
}

# Health check function
_auto_secrets_branch_detection_health() {
  echo "=== Auto Secrets Branch Detection Health Check ==="
  echo "Cache Directory: $AUTO_SECRETS_CACHE_DIR"
  echo "Branch Cache File: $AUTO_SECRETS_BRANCH_CACHE"
  echo "Cache Directory Exists: $(if [[ -d "$AUTO_SECRETS_CACHE_DIR" ]]; then echo "Yes"; else echo "No"; fi)"
  echo "Branch Cache Exists: $(if [[ -f "$AUTO_SECRETS_BRANCH_CACHE" ]]; then echo "Yes"; else echo "No"; fi)"
  echo "Current Branch: $(_auto_secrets_get_current_branch)"
  echo "Cached Branch: $(_auto_secrets_get_cached_branch)"
  echo "Git Repository: $(if git rev-parse --git-dir >/dev/null 2>&1; then echo "Yes"; else echo "No"; fi)"
  echo "auto-secrets Available: $(if command -v auto-secrets >/dev/null 2>&1; then echo "Yes"; else echo "No"; fi)"
  echo "=================================================="
}

# Export functions for use in shell integrations
# These will be available in bash and zsh integration files
