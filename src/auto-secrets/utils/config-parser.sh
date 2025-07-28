#!/bin/bash
# Auto Secrets Manager - Configuration Parser Utilities
# Handles parsing of complex JSON configurations from devcontainer-feature.json options

# Generic parser for JSON objects into environment variables.
# Converts keys to a shell-safe, SCREAMING_SNAKE_CASE format.
# 1. Inserts underscores for camelCase.
# 2. Replaces any non-alphanumeric characters (like '/') with underscores.
# 3. Converts the result to uppercase.
# 4. Prepends a given prefix.
#
# Arguments:
#   $1: JSON string to parse.
#   $2: Prefix for the environment variable names (e.g., "DEV_ENV_MANAGER_CACHE").
_parse_json_config() {
    local json="$1"
    local prefix="$2"
    local jq_filter
    local key_prefix

    if [[ -n "$prefix" ]]; then
        key_prefix="${prefix}_"
    else
        key_prefix=""
    fi

    # This single filter handles both camelCase and special characters in keys.
    jq_filter='to_entries[] | "export \($p)\($(.key | gsub("(?<a>[a-z])(?<b>[A-Z])"; "\(.a)_\\(.b)") | gsub("[^a-zA-Z0-9_]"; "_") | ascii_upcase))=\\"\\(.value)\\\""'

    echo "$json" | jq -r --arg p "${key_prefix}" "$jq_filter"
}

# Store JSON configurations as environment variables for runtime use
_store_json_configs() {
    local auto_commands_json="$1"
    local on_demand_commands_json="$2"

    cat << EOF
# Store JSON configurations for runtime parsing
export AUTO_COMMANDS_JSON='$auto_commands_json'
export ON_DEMAND_COMMANDS_JSON='$on_demand_commands_json'
EOF
}

# Get feature version from JSON or environment
get_feature_version() {
    local script_dir="$1"

    if [[ -f "$script_dir/devcontainer-feature.json" ]]; then
        jq -r '.version // "1.0.0"' "$script_dir/devcontainer-feature.json"
    else
        echo "${DEV_ENV_MANAGER_VERSION:-1.0.0}"
    fi
}

# Validate JSON structure
validate_json_option() {
    local json="$1"
    local option_name="$2"

    if [[ -z "$json" ]]; then
        echo "Warning: $option_name is empty, using defaults" >&2
        return 1
    fi

    if ! echo "$json" | jq . >/dev/null 2>&1; then
        echo "Error: Invalid JSON in $option_name option" >&2
        return 1
    fi

    return 0
}

# Generate complete configuration from all JSON options
generate_full_config() {
    local secret_manager_config="$1"
    local cache_config="$2"
    local offline_mode="$3"
    local bind_json="$4"
    local auto_commands="$5"
    local on_demand_commands="$6"

    echo "# Generated configuration from devcontainer-feature.json options"
    echo ""

    echo "# Cache configuration"
    _parse_json_config "$cache_config" "DEV_ENV_MANAGER_CACHE"
    echo ""

    echo "# Offline mode configuration"
    _parse_json_config "$offline_mode" "DEV_ENV_MANAGER_OFFLINE_MODE"
    echo ""

    echo "# Secret manager configuration"
    _parse_json_config "$secret_manager_config" "DEV_ENV_MANAGER_SECRET_MANAGER"
    echo ""

    echo "# Key binding configuration"
    _parse_json_config "$bind_json" "DEV_ENV_MANAGER_BIND"
    echo ""

    echo "# JSON configurations for runtime use"
    _store_json_configs "$auto_commands" "$on_demand_commands"
}

# Export functions for use in other scripts
export -f get_feature_version validate_json_option generate_full_config
