#!/bin/bash
# Auto Secrets Manager - AWS Secrets Manager Integration
# Handles fetching secrets from AWS Secrets Manager with authentication and error handling

# Source required modules
if [[ -f "$DEV_ENV_MANAGER_DIR/utils/logging.sh" ]]; then
    source "$DEV_ENV_MANAGER_DIR/utils/logging.sh"
fi

if [[ -f "$DEV_ENV_MANAGER_DIR/core/environment-mapping.sh" ]]; then
    source "$DEV_ENV_MANAGER_DIR/core/environment-mapping.sh"
fi

# AWS configuration
readonly AWS_DEFAULT_REGION="us-east-1"
readonly AWS_CLI_VERSION_MIN="2.0.0"

# Get AWS region from configuration
_get_aws_region() {
    local region="${DEV_ENV_MANAGER_SECRET_MANAGER_REGION:-${DEV_ENV_MANAGER_AWS_REGION:-$AWS_DEFAULT_REGION}}"

    # Expand environment variables
    if [[ "$region" =~ ^\$\{.*\}$ ]]; then
        local var_name="${region#\$\{}"
        var_name="${var_name%\}}"
        region="${!var_name}"
    fi

    echo "$region"
}

# Get AWS secret name prefix from configuration
_get_aws_secret_prefix() {
    echo "${DEV_ENV_MANAGER_SECRET_MANAGER_SECRET_PREFIX:-dev-env-secrets}"
}

# Check if AWS CLI is available and properly configured
_check_aws_cli() {
    if ! command -v aws >/dev/null 2>&1; then
        log_error "AWS CLI not found. Please install AWS CLI v2"
        return 1
    fi

    # Check AWS CLI version
    local aws_version
    aws_version=$(aws --version 2>&1 | head -1 | grep -o 'aws-cli/[0-9.]*' | cut -d'/' -f2)
    if [[ -n "$aws_version" ]]; then
        log_debug "AWS CLI version: $aws_version"
    fi

    # Check if AWS credentials are configured
    if ! aws sts get-caller-identity >/dev/null 2>&1; then
        log_error "AWS credentials not configured or expired"
        log_info "Configure credentials using: aws configure or IAM roles"
        return 1
    fi

    log_debug "AWS CLI check passed"
    return 0
}

# Get AWS caller identity for debugging
_get_aws_identity() {
    if ! aws sts get-caller-identity --output json 2>/dev/null; then
        echo "Unable to determine AWS identity"
        return 1
    fi
}

# Construct secret name for environment
_get_aws_secret_name() {
    local environment="$1"
    local prefix
    prefix=$(_get_aws_secret_prefix)

    echo "${prefix}/${environment}"
}

# List all secrets with the configured prefix
_list_aws_secrets() {
    local prefix
    prefix=$(_get_aws_secret_prefix)
    local region
    region=$(_get_aws_region)

    log_debug "Listing AWS secrets with prefix: $prefix"

    aws secretsmanager list-secrets \
        --region "$region" \
        --filters Name=name,Values="${prefix}/" \
        --query 'SecretList[].Name' \
        --output text 2>/dev/null | tr '\t' '\n'
}

# Check if secret exists in AWS Secrets Manager
_aws_secret_exists() {
    local secret_name="$1"
    local region
    region=$(_get_aws_region)

    aws secretsmanager describe-secret \
        --secret-id "$secret_name" \
        --region "$region" \
        >/dev/null 2>&1
}

# Get secret value from AWS Secrets Manager
_get_aws_secret_value() {
    local secret_name="$1"
    local region
    region=$(_get_aws_region)

    log_network "Fetching secret from AWS: $secret_name"

    local secret_response
    secret_response=$(aws secretsmanager get-secret-value \
        --secret-id "$secret_name" \
        --region "$region" \
        --output json 2>&1)

    local exit_code=$?

    if [[ $exit_code -eq 0 ]]; then
        # Extract SecretString from response
        echo "$secret_response" | jq -r '.SecretString // empty'
        return 0
    else
        log_error "Failed to retrieve secret: $secret_name"
        log_debug "AWS response: $secret_response"

        # Parse common error types
        if [[ "$secret_response" =~ "ResourceNotFoundException" ]]; then
            log_error "Secret not found: $secret_name"
        elif [[ "$secret_response" =~ "UnauthorizedOperation" ]] || [[ "$secret_response" =~ "AccessDenied" ]]; then
            log_error "Access denied - check IAM permissions for secrets manager"
        elif [[ "$secret_response" =~ "InvalidRequestException" ]]; then
            log_error "Invalid request - check secret name format"
        fi

        return 1
    fi
}

# Parse secret string based on format (JSON or key=value)
_parse_secret_string() {
    local secret_string="$1"

    if [[ -z "$secret_string" ]]; then
        log_error "Empty secret string"
        return 1
    fi

    # Check if it's JSON
    if echo "$secret_string" | jq . >/dev/null 2>&1; then
        log_debug "Parsing secret as JSON"
        echo "$secret_string" | jq -r '. | with_entries(.value = (.value | tostring))'
    else
        # Try to parse as key=value pairs
        log_debug "Parsing secret as key=value format"
        local json_object="{}"

        # Read line by line and build JSON object
        while IFS='=' read -r key value; do
            # Skip empty lines and comments
            [[ -z "$key" ]] || [[ "$key" =~ ^# ]] && continue

            # Remove leading/trailing whitespace
            key=$(echo "$key" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
            value=$(echo "$value" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')

            # Add to JSON object using jq
            json_object=$(echo "$json_object" | jq --arg k "$key" --arg v "$value" '. + {($k): $v}')
        done <<< "$secret_string"

        echo "$json_object"
    fi
}

# Main function to fetch secrets from AWS Secrets Manager
fetch_aws_secrets() {
    local environment="$1"

    # Validate environment
    if [[ -z "$environment" ]]; then
        log_error "Environment not specified for AWS secrets fetch"
        return 1
    fi

    if ! is_valid_environment "$environment"; then
        log_error "Invalid environment name: $environment"
        return 1
    fi

    log_info "Fetching secrets from AWS Secrets Manager for environment: $environment"

    # Check AWS CLI and credentials
    if ! _check_aws_cli; then
        error_with_context "AUTH" "AWS CLI not available or credentials not configured"
        return 1
    fi

    # Get secret name for environment
    local secret_name
    secret_name=$(_get_aws_secret_name "$environment")

    log_debug "Using AWS secret name: $secret_name"

    # Check if secret exists
    if ! _aws_secret_exists "$secret_name"; then
        log_error "Secret not found in AWS Secrets Manager: $secret_name"
        log_info "Available secrets:"
        _list_aws_secrets | while read -r secret; do
            log_info "  - $secret"
        done
        return 1
    fi

    # Fetch secret value
    local secret_string
    secret_string=$(_get_aws_secret_value "$secret_name")

    if [[ $? -ne 0 ]] || [[ -z "$secret_string" ]]; then
        error_with_context "NETWORK" "Failed to fetch secret from AWS Secrets Manager"
        return 1
    fi

    # Parse and return secret as JSON
    local parsed_secrets
    parsed_secrets=$(_parse_secret_string "$secret_string")

    if [[ $? -eq 0 ]] && [[ -n "$parsed_secrets" ]]; then
        local secret_count
        secret_count=$(echo "$parsed_secrets" | jq 'length' 2>/dev/null || echo "unknown")
        log_success "Secrets fetched successfully from AWS ($secret_count secrets)"
        echo "$parsed_secrets"
        return 0
    else
        log_error "Failed to parse secret string from AWS"
        return 1
    fi
}

# Test AWS Secrets Manager connection and authentication
test_aws_connection() {
    echo "Testing AWS Secrets Manager Connection:"
    echo "====================================="

    # Check AWS CLI installation
    if command -v aws >/dev/null 2>&1; then
        local version
        version=$(aws --version 2>&1 | head -1)
        echo "✅ AWS CLI installed: $version"
    else
        echo "❌ AWS CLI not installed"
        echo "   Install from: https://aws.amazon.com/cli/"
        return 1
    fi

    # Check AWS credentials
    local identity
    identity=$(_get_aws_identity 2>/dev/null)
    if [[ $? -eq 0 ]]; then
        echo "✅ AWS Authentication: OK"
        local user_arn
        user_arn=$(echo "$identity" | jq -r '.Arn // "unknown"')
        echo "   Identity: $user_arn"
    else
        echo "❌ AWS Authentication: Failed"
        echo "   Configure with: aws configure"
        return 1
    fi

    # Check region configuration
    local region
    region=$(_get_aws_region)
    echo "✅ Region configured: $region"

    # Test permissions
    echo "🔍 Testing Secrets Manager permissions..."

    if aws secretsmanager list-secrets --max-items 1 >/dev/null 2>&1; then
        echo "✅ List secrets permission: OK"
    else
        echo "❌ List secrets permission: Failed"
        log_info "Ensure IAM policy includes: secretsmanager:ListSecrets"
        return 1
    fi

    # Test environment access
    local current_environment
    current_environment=$(get_current_environment)
    local secret_name
    secret_name=$(_get_aws_secret_name "$current_environment")

    echo "🔍 Testing environment access: $current_environment"
    echo "   Secret name: $secret_name"

    if _aws_secret_exists "$secret_name"; then
        echo "✅ Environment secret exists"

        # Test read permission
        if _get_aws_secret_value "$secret_name" >/dev/null 2>&1; then
            echo "✅ Read permission: OK"
        else
            echo "❌ Read permission: Failed"
            log_info "Ensure IAM policy includes: secretsmanager:GetSecretValue"
            return 1
        fi
    else
        echo "⚠️  Environment secret not found: $secret_name"
        echo "   Available secrets:"
        _list_aws_secrets | head -5 | while read -r secret; do
            echo "     - $secret"
        done
    fi

    echo "🎉 AWS Secrets Manager connection test completed!"
    return 0
}

# Export functions for use in other modules
export -f fetch_aws_secrets test_aws_connection
