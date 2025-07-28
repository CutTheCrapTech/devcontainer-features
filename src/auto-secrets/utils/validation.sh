#!/bin/bash
# Auto Secrets Manager - Validation Utilities
# Provides input validation and configuration checks

# Source logging utilities
if [[ -f "$DEV_ENV_MANAGER_DIR/utils/logging.sh" ]]; then
    source "$DEV_ENV_MANAGER_DIR/utils/logging.sh"
fi

# Validate environment name format
_validate_environment_name() {
    local environment="$1"

    if [[ -z "$environment" ]]; then
        log_error "Environment name cannot be empty"
        return 1
    fi

    # Check length (reasonable limit)
    if [[ ${#environment} -gt 64 ]]; then
        log_error "Environment name too long (max 64 characters): $environment"
        return 1
    fi

    # Check for valid characters (alphanumeric, hyphens, underscores)
    if [[ ! "$environment" =~ ^[a-zA-Z0-9_-]+$ ]]; then
        log_error "Environment name contains invalid characters: $environment"
        log_info "Only alphanumeric characters, hyphens, and underscores are allowed"
        return 1
    fi

    # Cannot start with hyphen or underscore
    if [[ "$environment" =~ ^[-_] ]]; then
        log_error "Environment name cannot start with hyphen or underscore: $environment"
        return 1
    fi

    # Cannot end with hyphen or underscore
    if [[ "$environment" =~ [-_]$ ]]; then
        log_error "Environment name cannot end with hyphen or underscore: $environment"
        return 1
    fi

    log_debug "Environment name validation passed: $environment"
    return 0
}

# Validate URL format
_validate_url() {
    local url="$1"
    local allow_empty="${2:-false}"

    if [[ -z "$url" ]]; then
        if [[ "$allow_empty" == "true" ]]; then
            return 0
        else
            log_error "URL cannot be empty"
            return 1
        fi
    fi

    # Basic URL format check
    if [[ ! "$url" =~ ^https?:// ]]; then
        log_error "URL must start with http:// or https://: $url"
        return 1
    fi

    # Check for obvious malformed URLs
    if [[ "$url" =~ [[:space:]] ]]; then
        log_error "URL cannot contain spaces: $url"
        return 1
    fi

    # Check length
    if [[ ${#url} -gt 2048 ]]; then
        log_error "URL too long (max 2048 characters): $url"
        return 1
    fi

    log_debug "URL validation passed: $url"
    return 0
}

# Validate duration format (e.g., "5m", "1h", "30s")
_validate_duration() {
    local duration="$1"

    if [[ -z "$duration" ]]; then
        log_error "Duration cannot be empty"
        return 1
    fi

    # Remove any spaces
    duration="${duration// /}"

    # Check format: number followed by unit
    if [[ ! "$duration" =~ ^[0-9]+[smhd]?$ ]]; then
        log_error "Invalid duration format: $duration"
        log_info "Use format like: 30s, 5m, 1h, 2d"
        return 1
    fi

    # Extract number and unit
    local number="${duration%[a-zA-Z]*}"
    local unit="${duration#$number}"

    # Validate number is positive
    if [[ $number -le 0 ]]; then
        log_error "Duration must be positive: $duration"
        return 1
    fi

    # Validate reasonable limits
    case "${unit,,}" in
        ""|"s"|"sec"|"seconds")
            if [[ $number -gt 86400 ]]; then  # 1 day in seconds
                log_warn "Duration unusually long: $duration"
            fi
            ;;
        "m"|"min"|"minutes")
            if [[ $number -gt 1440 ]]; then  # 1 day in minutes
                log_warn "Duration unusually long: $duration"
            fi
            ;;
        "h"|"hour"|"hours")
            if [[ $number -gt 168 ]]; then  # 1 week in hours
                log_warn "Duration unusually long: $duration"
            fi
            ;;
        "d"|"day"|"days")
            if [[ $number -gt 30 ]]; then  # 1 month in days
                log_warn "Duration unusually long: $duration"
            fi
            ;;
        *)
            log_error "Invalid duration unit: $unit"
            log_info "Valid units: s, m, h, d"
            return 1
            ;;
    esac

    log_debug "Duration validation passed: $duration"
    return 0
}

# Validate configuration value based on type
_validate_config_value() {
    local key="$1"
    local value="$2"
    local type="$3"

    case "$type" in
        "string")
            if [[ -z "$value" ]]; then
                log_error "Configuration value cannot be empty: $key"
                return 1
            fi
            ;;
        "boolean")
            if [[ ! "$value" =~ ^(true|false)$ ]]; then
                log_error "Configuration value must be true or false: $key=$value"
                return 1
            fi
            ;;
        "integer")
            if [[ ! "$value" =~ ^[0-9]+$ ]]; then
                log_error "Configuration value must be an integer: $key=$value"
                return 1
            fi
            ;;
        "duration")
            if ! _validate_duration "$value"; then
                log_error "Invalid duration configuration: $key=$value"
                return 1
            fi
            ;;
        "url")
            if ! _validate_url "$value" true; then
                log_error "Invalid URL configuration: $key=$value"
                return 1
            fi
            ;;
        "enum")
            shift 3  # Remove key, value, type to get allowed values
            local allowed_values=("$@")
            local valid=false
            for allowed in "${allowed_values[@]}"; do
                if [[ "$value" == "$allowed" ]]; then
                    valid=true
                    break
                fi
            done
            if [[ "$valid" == "false" ]]; then
                log_error "Configuration value not allowed: $key=$value"
                log_info "Allowed values: ${allowed_values[*]}"
                return 1
            fi
            ;;
        *)
            log_warn "Unknown validation type: $type"
            ;;
    esac

    log_debug "Configuration validation passed: $key=$value"
    return 0
}

# Validate JSON string
validate_json() {
    local json_string="$1"

    if [[ -z "$json_string" ]]; then
        log_error "JSON string cannot be empty"
        return 1
    fi

    if echo "$json_string" | jq . >/dev/null 2>&1; then
        log_debug "JSON validation passed"
        return 0
    else
        log_error "Invalid JSON format"
        return 1
    fi
}

# Comprehensive validation for secret manager configuration
_validate_secret_manager_config() {
    local manager="$1"

    case "$manager" in
        "infisical")
            _validate_config_value "SECRET_MANAGER_BASE_URL" "$SECRET_MANAGER_BASE_URL" "url" &&
            _validate_config_value "SECRET_MANAGER_PROJECT_ID" "$SECRET_MANAGER_PROJECT_ID" "string"
            ;;
        "vault")
            _validate_config_value "VAULT_ADDR" "$(get_vault_address 2>/dev/null)" "url"
            ;;
        "aws")
            _validate_config_value "AWS_REGION" "${AWS_REGION:-us-east-1}" "string" &&
            _validate_config_value "SECRET_MANAGER_SECRET_PREFIX" "${SECRET_MANAGER_SECRET_PREFIX:-dev-env-secrets}" "string"
            ;;
        "azure")
            _validate_config_value "SECRET_MANAGER_BASE_URL" "$SECRET_MANAGER_BASE_URL" "url" &&
            _validate_config_value "SECRET_MANAGER_SECRET_PREFIX" "${SECRET_MANAGER_SECRET_PREFIX:-dev-env-secrets}" "string"
            ;;
        "gcp")
            _validate_config_value "SECRET_MANAGER_PROJECT_ID" "$SECRET_MANAGER_PROJECT_ID" "string" &&
            _validate_config_value "SECRET_MANAGER_SECRET_PREFIX" "${SECRET_MANAGER_SECRET_PREFIX:-dev-env-secrets}" "string"
            ;;
        "bitwarden")
            _validate_config_value "SECRET_MANAGER_BASE_URL" "${SECRET_MANAGER_BASE_URL:-https://vault.bitwarden.com}" "url" &&
            _validate_config_value "SECRET_MANAGER_SECRET_PREFIX" "${SECRET_MANAGER_SECRET_PREFIX:-dev-env-secrets}" "string"
            ;;
        *)
            log_error "Unknown secret manager for validation: $manager"
            return 1
            ;;
    esac
}

# Validate all critical configurations
validate_all_config() {
    local errors=0

    echo "🔍 Validating Configuration..."
    echo "============================="

    # Basic feature configuration
    if ! _validate_config_value "DEV_ENV_MANAGER_DETECTION" "$DEV_ENV_MANAGER_DETECTION" "enum" "prompt" "manual"; then
        ((errors++))
    fi

    if ! _validate_config_value "DEV_ENV_MANAGER_SHELLS" "$DEV_ENV_MANAGER_SHELLS" "enum" "bash" "zsh" "both"; then
        ((errors++))
    fi

    if ! _validate_config_value "DEV_ENV_MANAGER_SECRET_MANAGER" "$DEV_ENV_MANAGER_SECRET_MANAGER" "enum" "infisical" "vault" "aws" "azure" "gcp" "bitwarden"; then
        ((errors++))
    fi

    # Cache configuration
    if ! _validate_duration "$DEV_ENV_MANAGER_CACHE_REFRESH_INTERVAL"; then
        ((errors++))
    fi

    if ! _validate_config_value "DEV_ENV_MANAGER_CACHE_STRATEGY" "$DEV_ENV_MANAGER_CACHE_STRATEGY" "enum" "time_based" "manual_only" "hybrid"; then
        ((errors++))
    fi

    # Secret manager specific validation
    if ! _validate_secret_manager_config "$DEV_ENV_MANAGER_SECRET_MANAGER"; then
        ((errors++))
    fi

    # Environment mapping validation
    local environments=("$BRANCH_MAPPING_MAIN" "$BRANCH_MAPPING_STAGING" "$BRANCH_MAPPING_DEVELOP" "$BRANCH_MAPPING_DEFAULT")
    for env in "${environments[@]}"; do
        if [[ -n "$env" ]] && ! _validate_environment_name "$env"; then
            ((errors++))
        fi
    done

    if [[ $errors -eq 0 ]]; then
        echo "✅ All configuration validation passed"
        return 0
    else
        echo "❌ Configuration validation failed with $errors errors"
        return 1
    fi
}

# Export functions for use in other modules
export -f validate_json validate_all_config
