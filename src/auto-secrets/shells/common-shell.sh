#!/bin/bash
# Auto Secrets Manager - Common Shell Utilities
# Shared functions for bash and zsh shell integrations

# Internal function to prompt the user for confirmation.
_prompt_user_to_continue() {
  local warning_message="$1"
  echo "$warning_message"
  read -p "Do you want to run the command anyway? (y/N) " -r
  echo # for newline
  if [[ "$REPLY" =~ ^[Yy]$ ]]; then
    return 0 # Success (user chose to continue)
  else
    return 1 # Failure (user chose to abort)
  fi
}

# Internal function to display formatted metadata and prompt the user.
_display_cache_metadata_and_prompt() {
  local header_msg="$1"
  local status="$2"
  local environment="$3"
  local branch="$4"
  local timestamp_label="$5"
  local timestamp_value="$6"
  local error_label="$7"
  local error_value="$8"
  local warning_msg="$9"
  echo "$header_msg"
  echo "------------------------------------"
  printf "%-15s %s\n" "Status:" "$status"
  printf "%-15s %s\n" "Environment:" "$environment"
  printf "%-15s %s\n" "Branch:" "$branch"
  printf "%-15s %s\n" "$timestamp_label:" "$timestamp_value"
  if [[ -n "$error_value" ]]; then
    printf "%-15s %s\n" "$error_label:" "$error_value"
  fi
  echo "------------------------------------"
  _prompt_user_to_continue "$warning_msg"
  return $?
}

# Guard function to check cache health before running commands.
_check_cache_health_and_prompt() {
  local metadata_file
  metadata_file="$(get_cache_dir)/cache.metadata.json"

  if [[ ! -f "$metadata_file" ]]; then
    _prompt_user_to_continue "Secrets cache is not initialized. Please run 'refresh_secrets' first."
    return $?
  fi

  local metadata_content
  metadata_content=$(cat "$metadata_file")
  local status
  status=$(echo "$metadata_content" | jq -r '.status // "error"')

  case "$status" in
  "ok")
    return 0
    ;;
  "error")
    _display_cache_metadata_and_prompt \
      "⚠️ Auto-secrets refresh failed." \
      "$status" \
      "$(echo "$metadata_content" | jq -r '.environment // "-"')" \
      "$(echo "$metadata_content" | jq -r '.branch // "-"')" \
      "Attempted at" \
      "$(echo "$metadata_content" | jq -r '.last_attempted_refresh // "-"')" \
      "Error" \
      "$(echo "$metadata_content" | jq -r '.error_message // "-"')" \
      "Your secrets are likely missing or stale."
    return $?
    ;;
  "in_progress")
    local prev_error
    prev_error=""
    if [[ $(echo "$metadata_content" | jq 'has("previous_error")') == "true" ]]; then
      prev_error=$(echo "$metadata_content" | jq -r '.previous_error')
    fi
    _display_cache_metadata_and_prompt \
      "⏳ Auto-secrets refresh is in progress." \
      "$status" \
      "$(echo "$metadata_content" | jq -r '.environment // "-"')" \
      "$(echo "$metadata_content" | jq -r '.branch // "-"')" \
      "Started at" \
      "$(echo "$metadata_content" | jq -r '.last_attempted_refresh // "-"')" \
      "(Previous Error)" \
      "$prev_error" \
      "The cache is currently being updated. Running a command now may result in errors or the use of using stale data."
    return $?
    ;;
  esac
}

# Initialize environment detection for current shell
init_environment_detection() {
  # Ensure all configuration is loaded
  if [[ -z "$DEV_ENV_MANAGER_DIR" ]]; then
    log_error "DEV_ENV_MANAGER_DIR not set"
    return 1
  fi

  # Set up current environment variables
  local temp_branch
  temp_branch=$(get_current_branch)
  export CURRENT_BRANCH="$temp_branch"
  local temp_env
  temp_env=$(get_current_environment_with_override)
  export CURRENT_ENVIRONMENT="$temp_env"

  log_debug "Environment detection initialized: $CURRENT_BRANCH -> $CURRENT_ENVIRONMENT"

  # Ensure cache directory exists
  local cache_dir
  if cache_dir=$(ensure_cache_dir); then
    log_debug "Cache directory ready: $cache_dir"
  else
    log_warn "Failed to initialize cache directory"
  fi
}

# Refresh secrets from secret manager
refresh_secrets() {
  _check_cache_health_and_prompt || return 1
  # Ensure configuration is loaded
  # Config is already loaded by init.sh

  local environment
  environment=$(get_current_environment_with_override)
  local cache_dir
  cache_dir=$(get_cache_dir)

  log_info "Refreshing secrets for environment: $environment"

  # Show progress for long operations
  if is_verbose; then
    show_progress "Fetching secrets" 2 &
    local progress_pid=$!
  fi

  # Fetch secrets from the configured secret manager
  local secrets_content
  if secrets_content=$(fetch_secrets_from_manager "$environment"); then
    # Stop progress indicator
    if [[ -n "$progress_pid" ]]; then
      kill "$progress_pid" 2>/dev/null
      wait "$progress_pid" 2>/dev/null
    fi

    # Write to cache
    if write_secrets_to_cache "$cache_dir" "$secrets_content"; then
      log_success "Secrets refreshed successfully"
      return 0
    else
      log_error "Failed to write secrets to cache"
      return 1
    fi
  else
    # Stop progress indicator
    if [[ -n "$progress_pid" ]]; then
      kill "$progress_pid" 2>/dev/null
      wait "$progress_pid" 2>/dev/null
    fi

    # Try to use stale cache if available (use parsed config)
    local allow_stale="${DEV_ENV_MANAGER_OFFLINE_MODE_ALLOW_STALE_CACHE:-${DEV_ENV_MANAGER_OFFLINE_MODE_GRACEFUL_FAILURE:-true}}"
    if [[ "$allow_stale" == "true" ]] && is_cache_valid "$cache_dir"; then
      local cache_age
      cache_age=$(get_cache_age "$cache_dir")
      local age_formatted
      age_formatted=$(format_duration "$cache_age")

      log_warn "Using stale cache (age: $age_formatted)"
      log_info "Run 'refresh_secrets' again when network connectivity is restored"
      return 0
    else
      error_with_context "NETWORK" "Failed to fetch secrets and no stale cache available"
      return 1
    fi
  fi
}

# Inspect available secrets (keys only by default)
inspect_secrets() {
  _check_cache_health_and_prompt || return 1
  local show_values=false
  local output_format="list"

  # Parse arguments
  while [[ $# -gt 0 ]]; do
    case "$1" in
    --values | -v)
      show_values=true
      shift
      ;;
    --json | -j)
      output_format="json"
      shift
      ;;
    --help | -h)
      echo "Usage: inspect_secrets [--values] [--json]"
      echo "  --values, -v    Show secret values (truncated for security)"
      echo "  --json, -j      Output in JSON format"
      return 0
      ;;
    *)
      log_error "Unknown option: $1"
      return 1
      ;;
    esac
  done

  local cache_dir
  cache_dir=$(get_cache_dir)

  if ! is_cache_valid "$cache_dir"; then
    log_error "No valid cache found. Run 'refresh_secrets' first."
    return 1
  fi

  local secrets_file="$cache_dir/secrets.json"
  local environment
  environment=$(get_current_environment_with_override)

  if [[ "$output_format" == "json" ]]; then
    jq -c ". | {environment: \"$environment\", secrets: .secrets}" "$secrets_file"
  else
    echo "🔍 Secrets for environment: $environment"
    echo "========================================"

    local secrets_json
    secrets_json=$(jq -r '.secrets // {}' "$secrets_file")
    local secret_keys
    secret_keys=$(echo "$secrets_json" | jq -r 'keys[]')

    local count=0
    for key in $secret_keys; do
      ((count++))
      if [[ "$show_values" == "true" ]]; then
        local value
        value=$(echo "$secrets_json" | jq -r --arg k "$key" '.[$k]')
        # Show partial value for security
        local display_value="$value"
        if [[ ${#value} -gt 20 ]]; then
          display_value="${value:0:8}...${value: -4}"
        fi
        printf "  %-25s = %s (%d chars)\n" "$key" "$display_value" "${#value}"
      else
        local value_length
        value_length=$(echo "$secrets_json" | jq -r --arg k "$key" '.[$k] | length')
        printf "  %-25s (%d chars)\n" "$key" "$value_length"
      fi
    done < <(echo "$secrets_json" | jq -r 'keys[]')

    echo ""
    echo "📊 Total secrets: $count"

    if [[ "$show_values" == "false" ]]; then
      echo ""
      echo "💡 Use 'inspect_secrets --values' to see truncated values"
      echo "   Use 'load_secrets KEY1 KEY2 -- command' to use specific secrets"
    fi
  fi

  # Update access timestamp
  touch_cache_access "$cache_dir"
}

# Load specific secrets and execute command
load_secrets() {
  _check_cache_health_and_prompt || return 1
  local secrets_to_load=()
  local command_args=()
  local parsing_command=false
  local load_all=false
  local pattern=""

  # Parse arguments
  while [[ $# -gt 0 ]]; do
    if [[ "$1" == "--" ]]; then
      parsing_command=true
      shift
      continue
    fi

    if [[ "$parsing_command" == "true" ]]; then
      command_args+=("$1")
    else
      case "$1" in
      --all)
        load_all=true
        ;;
      --pattern=*)
        pattern="${1#--pattern=}"
        ;;
      --help | -h)
        echo "Usage: load_secrets [OPTIONS] [KEY1 KEY2 ...] -- COMMAND"
        echo "Options:"
        echo "  --all               Load all available secrets"
        echo "  --pattern=PATTERN   Load secrets matching pattern"
        echo "Examples:"
        echo "  load_secrets DATABASE_URL -- node migrate.js"
        echo "  load_secrets API_KEY REDIS_URL -- npm start"
        echo "  load_secrets --pattern='FRONTEND_*' -- npm run build"
        echo "  load_secrets --all -- debug-command"
        return 0
        ;;
      *)
        secrets_to_load+=("$1")
        ;;
      esac
    fi
    shift
  done

  # Validate command was provided
  if [[ ${#command_args[@]} -eq 0 ]]; then
    log_error "No command specified"
    echo "Usage: load_secrets [KEY1 KEY2 ...] -- COMMAND"
    return 1
  fi

  local cache_dir
  cache_dir=$(get_cache_dir)

  if ! is_cache_valid "$cache_dir"; then
    log_error "No valid cache found. Run 'refresh_secrets' first."
    return 1
  fi

  local secrets_file="$cache_dir/secrets.json"
  local secrets_json
  secrets_json=$(jq -r '.secrets // {}' "$secrets_file")

  # Create a JSON array of the keys the user wants
  local jq_keys_array
  jq_keys_array=$(printf '%s\n' "${secrets_to_load[@]}" | jq -R . | jq -s .)

  # Use jq to filter the secrets JSON and get only the key-value pairs we need.
  # The output is formatted as KEY\0VALUE\0 for safe parsing.
  local filtered_secrets
  if [[ "$load_all" == "true" ]]; then
    log_debug "Loading all secrets"
    filtered_secrets=$(echo "$secrets_json" | jq -r 'to_entries[] | "\(.key)\u0000\(.value)\u0000"')
  elif [[ -n "$pattern" ]]; then
    log_debug "Loading secrets matching pattern: $pattern"
    filtered_secrets=$(echo "$secrets_json" | jq -r --arg p "$pattern" 'to_entries[] | select(.key | test($p)) | "\(.key)\u0000\(.value)\u0000"')
  else
    log_debug "Loading specific secrets: ${secrets_to_load[*]}"
    filtered_secrets=$(echo "$secrets_json" | jq -r --argjson keys "$jq_keys_array" '
            to_entries[] | select(.key as $k | $keys | index($k)) | "\(.key)\u0000\(.value)\u0000"
        ')
  fi

  # Check if any secrets were found
  if [[ -z "$filtered_secrets" ]]; then
    log_error "No matching secrets found"
    return 1
  fi

  # Execute command with secrets in environment
  (
    # Loop through the null-delimited output from jq and export variables
    while IFS= read -r -d '' key && IFS= read -r -d '' value; do
      export "$key"="$value"
    done <<<"$filtered_secrets"

    log_debug "Executing command with secrets..."
    exec "${command_args[@]}"
  )
}

# Debug environment and cache status
debug_env() {
  _check_cache_health_and_prompt || return 1
  echo "🔍 Auto Secrets Manager Debug Information"
  echo "========================================"

  # Environment information
  echo ""
  echo "📍 Environment:"
  echo "  Current Branch: $(get_current_branch)"
  echo "  Current Environment: $(get_current_environment_with_override)"
  echo "  Git Repository: $(if is_in_git_repo; then echo "Yes"; else echo "No"; fi)"
  echo "  Working Directory: $PWD"

  # Configuration
  echo ""
  echo "⚙️  Configuration:"
  echo "  Secret Manager: ${DEV_ENV_MANAGER_SECRET_MANAGER:-not set}"
  echo "  Detection Mode: ${DEV_ENV_MANAGER_DETECTION:-not set}"
  echo "  Cache Expiry: ${DEV_ENV_MANAGER_CACHE_REFRESH_INTERVAL:-15m}"
  echo "  Cache Strategy: ${DEV_ENV_MANAGER_CACHE_STRATEGY:-not set}"
  echo "  Background Refresh: ${DEV_ENV_MANAGER_CACHE_BACKGROUND_REFRESH:-not set}"
  echo "  Debug Mode: ${DEV_ENV_MANAGER_DEBUG:-false}"
  echo "  Version: ${DEV_ENV_MANAGER_VERSION:-unknown}"

  # Cache status
  echo ""
  get_cache_status

  # Branch mapping
  echo ""
  show_environment_mapping

  # Test secret manager connection
  echo ""
  echo "🔐 Secret Manager Connection:"
  if command -v test_secret_manager_connection >/dev/null 2>&1; then
    test_secret_manager_connection
  else
    echo "  Test function not available"
  fi

  # System information
  echo ""
  echo "💻 System Information:"
  echo "  User: $(whoami) ($(id -u):$(id -g))"
  echo "  Shell: ${SHELL:-unknown}"
  echo "  Cache Base: $(get_cache_base_dir)"
  echo "  Tmpfs Available: $(if [[ -d /dev/shm ]] && [[ -w /dev/shm ]]; then echo "Yes"; else echo "No"; fi)"

  # Feature status
  echo ""
  echo "🚀 Feature Status:"
  echo "  Version: ${DEV_ENV_MANAGER_VERSION:-unknown}"
  echo "  Install Directory: ${DEV_ENV_MANAGER_DIR:-not set}"
  echo "  Initialized: $(if [[ -n "$CURRENT_ENVIRONMENT" ]]; then echo "Yes"; else echo "No"; fi)"
}

# Set up automatic command aliases
setup_auto_commands() {
  # Get list of commands that should auto-load secrets
  local auto_commands=()

  if [[ -n "$AUTO_COMMANDS_JSON" ]]; then
    # Parse from JSON configuration
    while IFS= read -r cmd; do
      [[ -n "$cmd" ]] && auto_commands+=("$cmd")
    done < <(echo "$AUTO_COMMANDS_JSON" | jq -r 'keys[]')
  fi

  # Set up aliases for commands that exist on the system
  for cmd in "${auto_commands[@]}"; do
    if command -v "$cmd" >/dev/null 2>&1; then
      # Create a wrapper function instead of alias for better control
      eval "${cmd}_with_secrets() { _load_secrets_for_command '$cmd' \"\$@\"; }"
      # shellcheck disable=SC2139
      alias "$cmd"="${cmd}_with_secrets"
      log_debug "Auto-loading enabled for: $cmd"
    fi
  done
}

# Load secrets for specific command based on configuration
_load_secrets_for_command() {
  local command="$1"
  shift
  local original_cmd="$command"

  # Remove the _with_secrets suffix if present
  command="${command%_with_secrets}"

  local cache_dir
  cache_dir=$(get_cache_dir)

  if ! is_cache_valid "$cache_dir"; then
    log_warn "No cached secrets available for command: $command"
    # Still execute the command without secrets
    exec "$original_cmd" "$@"
    return $?
  fi

  # Get auto command paths for this command
  local auto_cmd_paths
  if [[ -n "$AUTO_COMMANDS_JSON" ]]; then
    auto_cmd_paths=$(echo "$AUTO_COMMANDS_JSON" | jq -r --arg cmd "$command" '.[$cmd][]? // .default[]? // "/shared/"')
  else
    auto_cmd_paths="/shared/"
  fi

  # Load secrets from JSON into current environment
  local secrets_file="$cache_dir/secrets.json"
  if [[ -f "$secrets_file" ]]; then
    local secrets_json
    secrets_json=$(jq -r '.secrets // {}' "$secrets_file")

    # Filter secrets based on patterns if configured
    if [[ "$auto_cmd_paths" != "/shared/" ]]; then
      # Create pattern matching for secret keys
      local filtered_secrets="{}"
      while IFS= read -r pattern; do
        [[ -z "$pattern" ]] && continue

        # Convert pattern to appropriate regex
        local regex_pattern
        case "$pattern" in
        *"/**")
          # Recursive: /infrastructure/** → /infrastructure/.*
          regex_pattern="${pattern%/**}/.*"
          ;;
        *"/*")
          # Non-recursive: /infrastructure/* → /infrastructure/[^/]*
          regex_pattern="${pattern%/*}/[^/]*"
          ;;
        *)
          # Exact secret match: /tofu/exact_secret → /tofu/exact_secret
          regex_pattern="^${pattern}$"
          ;;
        esac

        local matching_secrets
        matching_secrets=$(echo "$secrets_json" | jq --arg pattern "$regex_pattern" '
                    with_entries(select(.key | test($pattern)))
                ')
        filtered_secrets=$(echo "$filtered_secrets $matching_secrets" | jq -s 'add')
      done <<<"$auto_cmd_paths"
      secrets_json="$filtered_secrets"
    fi

    # Export each key-value pair with sanitized variable names
    while IFS= read -r line; do
      if [[ -n "$line" ]]; then
        local key="${line%%=*}"
        local value="${line#*=}"
        # Sanitize key: remove leading slash, replace slashes with underscores
        local clean_key="${key#/}"
        clean_key="${clean_key//\//_}"

        # Add TF_VAR_ prefix for Terraform/Tofu commands
        if [[ "$command" == "terraform" || "$command" == "tofu" ]]; then
          export "TF_VAR_${clean_key}=${value}"
          export "TF_VAR_${clean_key}"="$value"
          log_debug "Exported TF_VAR_${clean_key} for ${command}"
        else
          export "${clean_key}=${value}"
          export "${clean_key}"="$value"
        fi

        export "${clean_key}=${value}"
        export "${clean_key}"="$value"
      fi
    done < <(echo "$secrets_json" | jq -r 'to_entries[] | "\(.key)=\(.value)"')

    touch_cache_access "$cache_dir"
    log_debug "Secrets loaded for command: $command"

    # Execute the original command with secrets
    exec "$original_cmd" "$@"
  else
    log_warn "Secrets file not found: $secrets_file"
    # Still execute the command without secrets
    exec "$original_cmd" "$@"
  fi
}

# Clean up cache
cleanup_cache() {
  _check_cache_health_and_prompt || return 1
  cleanup_old_caches
}

# Show help for the shell integration
show_help() {
  echo "🔐 Auto Secrets Manager - Available Commands"
  echo "==========================================="
  echo ""
  echo "Core Commands:"
  echo "  refresh_secrets       Fetch fresh secrets from secret manager"
  echo "  inspect_secrets       List available secret keys"
  echo "  load_secrets         Load specific secrets for a command"
  echo "  debug_env            Show environment and cache status"
  echo "  cleanup_cache        Clean up old cache directories"
  echo ""
  echo "Examples:"
  echo "  refresh_secrets"
  echo "  inspect_secrets --values"
  echo "  load_secrets DATABASE_URL API_KEY -- node server.js"
  echo "  load_secrets --pattern='FRONTEND_*' -- npm run build"
  echo "  load_secrets --all -- debug-script.sh"
  echo ""
  echo "Environment Overrides:"
  echo "  DEV_ENV_MANAGER_OVERRIDE_ENVIRONMENT=staging refresh_secrets"
  echo "  DEV_ENV_MANAGER_DEBUG=true inspect_secrets"
  echo ""
  echo "🔧 Configuration is loaded from devcontainer.json feature options"
}

# Handle environment changes (called from prompt integration)
refresh_environment() {
  local current_environment
  current_environment=$(get_current_environment_with_override)

  if [[ "$current_environment" != "$CURRENT_ENVIRONMENT" ]]; then
    log_info "Environment changed: $CURRENT_ENVIRONMENT → $current_environment"
    export CURRENT_ENVIRONMENT="$current_environment"

    # Refresh secrets for new environment if auto-refresh is enabled
    local background_refresh="${CACHE_BACKGROUND_REFRESH:-false}"
    if [[ "$background_refresh" == "true" ]]; then
      refresh_secrets &
    else
      log_info "Run 'refresh_secrets' to load secrets for new environment"
    fi
  fi
}

# Export functions for shell use
export -f refresh_secrets inspect_secrets load_secrets debug_env cleanup_cache
export -f show_help refresh_environment
export -f init_environment_detection setup_auto_commands

# Make CLI commands available
alias refresh_secrets='refresh_secrets'
alias inspect_secrets='inspect_secrets'
alias load_secrets='load_secrets'
alias debug_env='debug_env'
alias cleanup_cache='cleanup_cache'
alias secrets_help='show_help'
