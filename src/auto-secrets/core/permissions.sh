#!/bin/bash
# Auto Secrets Manager - Permissions Module
# Handles secure file permissions and atomic operations for cache management

# Source logging utilities
if [[ -f "$DEV_ENV_MANAGER_DIR/utils/logging.sh" ]]; then
    source "$DEV_ENV_MANAGER_DIR/utils/logging.sh"
fi

# Security constants
readonly CACHE_DIR_PERMS="700"    # rwx------ (owner only)
readonly CACHE_FILE_PERMS="600"   # rw------- (owner only)
readonly LOCK_DIR_PERMS="700"     # rwx------ (owner only)
readonly TEMP_FILE_PERMS="600"    # rw------- (owner only)

# Get current user information
_get_current_user_info() {
    echo "$(id -u):$(id -g)"
}

# Get current username
_get_current_username() {
    whoami
}

# Create secure directory with proper permissions and race condition protection
create_secure_directory() {
    local dir_path="$1"
    local lock_file="${dir_path}.lock"
    local max_wait_time=30
    local wait_count=0

    log_debug "Creating secure directory: $dir_path"

    # Atomic lock creation to prevent race conditions
    while ! mkdir "$lock_file" 2>/dev/null; do
        if [[ $wait_count -ge $max_wait_time ]]; then
            log_error "Timeout waiting for directory lock: $dir_path"
            return 1
        fi

        log_debug "Another process is creating directory, waiting... ($wait_count/$max_wait_time)"
        sleep 0.1
        ((wait_count++))
    done

    # Ensure lock cleanup on any exit
    trap "rmdir '$lock_file' 2>/dev/null || true" RETURN EXIT

    # Check if directory already exists and is valid
    if [[ -d "$dir_path" ]]; then
        if _verify_directory_permissions "$dir_path"; then
            log_debug "Directory already exists with correct permissions: $dir_path"
            return 0
        else
            log_warn "Directory exists but has incorrect permissions, recreating: $dir_path"
            rm -rf "$dir_path"
        fi
    fi

    # Create directory with most restrictive permissions first
    if ! mkdir -p "$dir_path"; then
        log_error "Failed to create directory: $dir_path"
        return 1
    fi

    # Set strict permissions
    chmod "$CACHE_DIR_PERMS" "$dir_path" || {
        log_error "Failed to set directory permissions: $dir_path"
        rm -rf "$dir_path"
        return 1
    }

    # Set explicit ownership
    local user_info
    user_info=$(_get_current_user_info)
    chown "$user_info" "$dir_path" || {
        log_error "Failed to set directory ownership: $dir_path"
        rm -rf "$dir_path"
        return 1
    }

    log_debug "Secure directory created successfully: $dir_path"
    return 0
}

# Create secure file with proper permissions
create_secure_file() {
    local file_path="$1"
    local content="${2:-}"

    log_debug "Creating secure file: $file_path"

    # Ensure parent directory exists
    local parent_dir
    parent_dir=$(dirname "$file_path")
    if [[ ! -d "$parent_dir" ]]; then
        if ! create_secure_directory "$parent_dir"; then
            log_error "Failed to create parent directory: $parent_dir"
            return 1
        fi
    fi

    # Create file with restrictive permissions
    if ! touch "$file_path"; then
        log_error "Failed to create file: $file_path"
        return 1
    fi

    # Set strict permissions immediately
    chmod "$CACHE_FILE_PERMS" "$file_path" || {
        log_error "Failed to set file permissions: $file_path"
        rm -f "$file_path"
        return 1
    }

    # Set explicit ownership
    local user_info
    user_info=$(_get_current_user_info)
    chown "$user_info" "$file_path" || {
        log_error "Failed to set file ownership: $file_path"
        rm -f "$file_path"
        return 1
    }

    # Write content if provided
    if [[ -n "$content" ]]; then
        if ! echo "$content" > "$file_path"; then
            log_error "Failed to write content to file: $file_path"
            rm -f "$file_path"
            return 1
        fi
    fi

    log_debug "Secure file created successfully: $file_path"
    return 0
}

# Atomic file write with proper permissions
write_file_atomic() {
    local file_path="$1"
    local content="$2"
    local temp_file="${file_path}.tmp.$$"

    log_debug "Writing file atomically: $file_path"

    # Ensure parent directory exists
    local parent_dir
    parent_dir=$(dirname "$file_path")
    if [[ ! -d "$parent_dir" ]]; then
        if ! create_secure_directory "$parent_dir"; then
            log_error "Failed to create parent directory: $parent_dir"
            return 1
        fi
    fi

    # Write to temporary file first
    if ! echo "$content" > "$temp_file"; then
        log_error "Failed to write to temporary file: $temp_file"
        return 1
    fi

    # Set secure permissions on temp file
    chmod "$TEMP_FILE_PERMS" "$temp_file" || {
        log_error "Failed to set temp file permissions: $temp_file"
        rm -f "$temp_file"
        return 1
    }

    # Set ownership on temp file
    local user_info
    user_info=$(_get_current_user_info)
    chown "$user_info" "$temp_file" || {
        log_error "Failed to set temp file ownership: $temp_file"
        rm -f "$temp_file"
        return 1
    }

    # Atomic move to final location
    if ! mv "$temp_file" "$file_path"; then
        log_error "Failed to move temp file to final location: $temp_file -> $file_path"
        rm -f "$temp_file"
        return 1
    fi

    log_debug "File written atomically: $file_path"
    return 0
}

# Verify directory permissions and ownership
_verify_directory_permissions() {
    local dir_path="$1"

    if [[ ! -d "$dir_path" ]]; then
        log_debug "Directory does not exist: $dir_path"
        return 1
    fi

    # Check permissions
    local actual_perms
    actual_perms=$(stat -c %a "$dir_path" 2>/dev/null)
    if [[ "$actual_perms" != "$CACHE_DIR_PERMS" ]]; then
        log_warn "Directory permissions incorrect: expected $CACHE_DIR_PERMS, got $actual_perms ($dir_path)"
        return 1
    fi

    # Check ownership
    local actual_owner
    actual_owner=$(stat -c %U "$dir_path" 2>/dev/null)
    local expected_owner
    expected_owner=$(_get_current_username)
    if [[ "$actual_owner" != "$expected_owner" ]]; then
        log_warn "Directory ownership incorrect: expected $expected_owner, got $actual_owner ($dir_path)"
        return 1
    fi

    log_debug "Directory permissions verified: $dir_path"
    return 0
}

# Verify file permissions and ownership
_verify_file_permissions() {
    local file_path="$1"

    if [[ ! -f "$file_path" ]]; then
        log_debug "File does not exist: $file_path"
        return 1
    fi

    # Check permissions
    local actual_perms
    actual_perms=$(stat -c %a "$file_path" 2>/dev/null)
    if [[ "$actual_perms" != "$CACHE_FILE_PERMS" ]]; then
        log_warn "File permissions incorrect: expected $CACHE_FILE_PERMS, got $actual_perms ($file_path)"
        return 1
    fi

    # Check ownership
    local actual_owner
    actual_owner=$(stat -c %U "$file_path" 2>/dev/null)
    local expected_owner
    expected_owner=$(_get_current_username)
    if [[ "$actual_owner" != "$expected_owner" ]]; then
        log_warn "File ownership incorrect: expected $expected_owner, got $actual_owner ($file_path)"
        return 1
    fi

    log_debug "File permissions verified: $file_path"
    return 0
}

# Check if path is accessible and secure
is_path_secure() {
    local path="$1"

    # Check if path exists
    if [[ ! -e "$path" ]]; then
        log_debug "Path does not exist: $path"
        return 1
    fi

    # Verify it's owned by current user
    local actual_owner
    actual_owner=$(stat -c %U "$path" 2>/dev/null)
    local expected_owner
    expected_owner=$(_get_current_username)
    if [[ "$actual_owner" != "$expected_owner" ]]; then
        log_warn "Path not owned by current user: $path (owner: $actual_owner)"
        return 1
    fi

    # Check if it's a directory or file and verify appropriate permissions
    if [[ -d "$path" ]]; then
        return _verify_directory_permissions "$path"
    elif [[ -f "$path" ]]; then
        return _verify_file_permissions "$path"
    else
        log_warn "Path is neither file nor directory: $path"
        return 1
    fi
}

# Remove path securely (only if owned by current user)
remove_path_secure() {
    local path="$1"

    if [[ ! -e "$path" ]]; then
        log_debug "Path does not exist, nothing to remove: $path"
        return 0
    fi

    # Verify ownership before deletion
    local actual_owner
    actual_owner=$(stat -c %U "$path" 2>/dev/null)
    local expected_owner
    expected_owner=$(_get_current_username)
    if [[ "$actual_owner" != "$expected_owner" ]]; then
        log_error "Refusing to remove path not owned by current user: $path (owner: $actual_owner)"
        return 1
    fi

    log_debug "Securely removing path: $path"

    # Remove the path
    if [[ -d "$path" ]]; then
        rm -rf "$path" || {
            log_error "Failed to remove directory: $path"
            return 1
        }
    else
        rm -f "$path" || {
            log_error "Failed to remove file: $path"
            return 1
        }
    fi

    log_debug "Path removed securely: $path"
    return 0
}

# Export functions for use in other modules
export -f create_secure_directory create_secure_file write_file_atomic
export -f is_path_secure remove_path_secure
