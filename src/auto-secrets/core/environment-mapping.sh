#!/bin/bash
# Auto Secrets Manager - Environment Mapping Module
# Maps git branches to secret manager environments

# Source logging utilities
if [[ -f "$DEV_ENV_MANAGER_DIR/utils/logging.sh" ]]; then
  source "$DEV_ENV_MANAGER_DIR/utils/logging.sh"
fi

# Source branch detection
if [[ -f "$DEV_ENV_MANAGER_DIR/core/branch-detection.sh" ]]; then
  source "$DEV_ENV_MANAGER_DIR/core/branch-detection.sh"
fi

# Global environment cache
CACHED_ENVIRONMENT=""
CACHED_ENVIRONMENT_BRANCH=""

_check_branch_patterns() {
  local branch="$1"

  echo "$DEV_ENV_MANAGER_BRANCH_MAPPING_JSON" | jq -r 'to_entries[] | select(.key | test("[*?]")) | "\(.key) \(.value)"' | while read -r pattern env; do
    local regex_pattern="${pattern//\*/.*}"
    if [[ "$branch" =~ ^${regex_pattern}$ ]]; then
      echo "$env"
      return 0
    fi
  done
}

# Core environment mapping function
_get_environment_from_branch() {
  local branch="$1"
  local original_branch="$branch"

  # Return cached result if branch hasn't changed
  if [[ "$branch" == "$CACHED_ENVIRONMENT_BRANCH" ]] && [[ -n "$CACHED_ENVIRONMENT" ]]; then
    echo "$CACHED_ENVIRONMENT"
    return 0
  fi

  local environment

  # Check if we have branch mapping JSON
  if [[ -z "$DEV_ENV_MANAGER_BRANCH_MAPPING_JSON" ]]; then
    log_error "No branch mapping configuration found"
    return 1
  fi

  # Handle special cases - fetch default directly
  case "$branch" in
  "detached" | "no-git" | "" | "default")
    environment=$(echo "$DEV_ENV_MANAGER_BRANCH_MAPPING_JSON" | jq -r '.default // ""')
    if [[ -n "$environment" ]]; then
      # Cache the result
      CACHED_ENVIRONMENT="$environment"
      CACHED_ENVIRONMENT_BRANCH="$original_branch"
      log_debug "Using default environment '$environment' for special branch '$branch'"
      echo "$environment"
      return 0
    else
      log_error "No default configured for special branch '$branch'"
      return 1
    fi
    ;;
  esac

  # First check for exact branch match (fast path)
  environment=$(echo "$DEV_ENV_MANAGER_BRANCH_MAPPING_JSON" | jq -r --arg b "$branch" '.[$b] // ""')

  if [[ -n "$environment" ]]; then
    # Cache the result
    CACHED_ENVIRONMENT="$environment"
    CACHED_ENVIRONMENT_BRANCH="$original_branch"

    log_debug "Exact match: branch '$branch' to environment '$environment'"
    echo "$environment"
    return 0
  fi

  # Then check for pattern matches (slower path)
  environment=$(_check_branch_patterns "$branch")

  if [[ -n "$environment" ]]; then
    # Cache the result
    CACHED_ENVIRONMENT="$environment"
    CACHED_ENVIRONMENT_BRANCH="$original_branch"

    log_debug "Pattern match: branch '$branch' to environment '$environment'"
    echo "$environment"
    return 0
  fi

  # This should not happen if user configured "default" properly
  log_error "No mapping found for branch '$branch'"
  return 1
}

# Get current environment (convenience function)
get_current_environment() {
  local current_branch
  current_branch=$(get_current_branch)
  _get_environment_from_branch "$current_branch"
}

# Validate environment name
is_valid_environment() {
  local environment="$1"

  # Basic validation - alphanumeric, dashes, underscores
  if [[ "$environment" =~ ^[a-zA-Z0-9_-]+$ ]]; then
    return 0
  else
    return 1
  fi
}

# Show current environment mapping
show_environment_mapping() {
  local current_branch
  local current_environment

  current_branch=$(get_current_branch)
  current_environment=$(get_current_environment)

  echo "Environment Mapping:"
  echo "  Current Branch: $current_branch"
  echo "  Current Environment: $current_environment"
  echo ""

  # Check if we have JSON config
  if [[ -z "$DEV_ENV_MANAGER_BRANCH_MAPPING_JSON" ]]; then
    echo "No branch mapping configuration found"
    return 1
  fi

  echo "Configured Branch Mappings:"

  # Show all user-configured mappings from JSON
  echo "$DEV_ENV_MANAGER_BRANCH_MAPPING_JSON" | jq -r 'to_entries[] | "  \(.key) -> \(.value)"'

  echo ""
  echo "Special branches (detached, no-git, empty) -> default"
}

# Create hash for environment (used in cache directory naming)
get_environment_hash() {
  local environment="$1"

  if command -v sha256sum >/dev/null 2>&1; then
    echo -n "$environment" | sha256sum | cut -c1-12
  elif command -v shasum >/dev/null 2>&1; then
    echo -n "$environment" | shasum -a 256 | cut -c1-12
  else
    # Fallback to simple hash
    local hash=0
    for ((i = 0; i < ${#environment}; i++)); do
      char="${environment:$i:1}"
      hash=$(((hash * 31 + $(printf '%d' "'$char")) % 1000000))
    done
    printf "%012d" $hash
  fi
}

# Set up environment change detection
_setup_environment_change_detection() {
  local temp_env
  temp_env=$(get_current_environment)
  export LAST_KNOWN_ENVIRONMENT="$temp_env"
  log_debug "Environment change detection initialized: $LAST_KNOWN_ENVIRONMENT"
}

# Check for environment changes and trigger refresh if needed
check_environment_change() {
  local current_environment
  current_environment=$(get_current_environment)

  if [[ "$current_environment" != "$LAST_KNOWN_ENVIRONMENT" ]]; then
    log_info "Environment changed: $LAST_KNOWN_ENVIRONMENT → $current_environment"

    # Update the stored environment
    export LAST_KNOWN_ENVIRONMENT="$current_environment"

    # Clear environment cache
    clear_environment_cache

    # Trigger cache refresh if function exists
    if command -v refresh_secrets >/dev/null 2>&1; then
      log_info "Refreshing secrets for new environment..."
      refresh_secrets
    fi

    return 0 # Environment changed
  fi

  return 1 # No change
}

# Clear environment cache
clear_environment_cache() {
  CACHED_ENVIRONMENT=""
  CACHED_ENVIRONMENT_BRANCH=""
  log_debug "Environment cache cleared"
}

# Override environment temporarily
override_environment() {
  local environment="$1"

  if ! is_valid_environment "$environment"; then
    log_error "Invalid environment name: $environment"
    return 1
  fi

  export DEV_ENV_MANAGER_OVERRIDE_ENVIRONMENT="$environment"
  clear_environment_cache
  log_info "Environment overridden to: $environment"
}

# Get environment with override support
get_current_environment_with_override() {
  if [[ -n "$DEV_ENV_MANAGER_OVERRIDE_ENVIRONMENT" ]]; then
    echo "$DEV_ENV_MANAGER_OVERRIDE_ENVIRONMENT"
  else
    get_current_environment
  fi
}

# Test environment mapping (for debugging)
test_environment_mapping() {
  echo "Testing Environment Mapping:"
  echo "=========================="

  # Check if we have JSON config
  if [[ -z "$DEV_ENV_MANAGER_BRANCH_MAPPING_JSON" ]]; then
    echo "No branch mapping configuration found"
    return 1
  fi

  # Get all configured branches from JSON plus some test cases
  local configured_branches
  mapfile -t configured_branches < <(jq -r 'keys[]' <<<"$DEV_ENV_MANAGER_BRANCH_MAPPING_JSON")

  # Add common test branches that might not be configured
  local test_branches=(
    "main" "master" "develop" "staging"
    "feature/auth" "bugfix/login" "hotfix/security"
    "release/v1.2.0" "experiment/new-ui"
    "detached" "no-git" "" "random-branch"
  )

  # Combine configured branches with test branches (remove duplicates)
  local all_branches
  mapfile -t all_branches < <(printf '%s\n' "${configured_branches[@]}" "${test_branches[@]}" | sort -u)

  # Test each branch
  for branch in "${all_branches[@]}"; do
    local environment
    environment=$(_get_environment_from_branch "$branch" 2>/dev/null)
    local status=$?

    if [[ $status -eq 0 ]]; then
      printf "%-20s -> %s\n" "$branch" "$environment"
    else
      printf "%-20s -> ERROR (no mapping)\n" "$branch"
    fi
  done
}

# Initialize environment change detection if we're in a shell
if [[ -n "$PS1" ]] && is_in_git_repo; then
  _setup_environment_change_detection
fi

# Export functions for use in other modules
export -f get_current_environment is_valid_environment
export -f show_environment_mapping get_environment_hash
export -f check_environment_change clear_environment_cache override_environment
export -f get_current_environment_with_override test_environment_mapping
