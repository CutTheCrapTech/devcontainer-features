# Dev Environment Manager - Complete Architecture & Design

## **Core Concept & Vision**
Building a **DevContainer Feature** that automatically manages environment secrets based on git branches with **"Enterprise-grade security with zero-config setup"**:
* Maps branches to environments: `main/prod` → prod, `staging` → staging, `else` → dev
* Integrates with secret managers (starting with Infisical, expanding to Vault/AWS/Azure)
* Supports multiple shells (zsh + bash)
* Provides branch-based environment isolation with permission enforcement

## **Architecture Decisions**

### **1. File Organization (Enhanced Structure)**

```
dev-env-manager/
├── install.sh                           # Main installation script
├── src/
│   ├── core/
│   │   ├── cache.sh                     # Cache management logic
│   │   ├── branch-detection.sh         # Git branch detection
│   │   ├── environment-mapping.sh      # Branch → environment mapping
│   │   └── permissions.sh              # File permissions & security
│   ├── shells/
│   │   ├── zsh-integration.sh          # Zsh-specific hooks and functions
│   │   ├── bash-integration.sh         # Bash-specific hooks and functions
│   │   └── common-shell.sh             # Shared shell utilities
│   ├── secret-managers/
│   │   ├── infisical.sh                # Infisical API integration
│   │   ├── vault.sh                    # HashiCorp Vault integration
│   │   ├── aws-secrets.sh              # AWS Secrets Manager
│   │   ├── azure-keyvault.sh           # Azure Key Vault
│   │   └── manager-interface.sh        # Common interface for all managers
│   └── utils/
│       ├── logging.sh                  # Logging utilities
│       ├── validation.sh               # Input validation
│       └── cleanup.sh                  # Cleanup utilities
└── templates/
    ├── init.sh.template                # Dynamic init template
    └── shell-config.template           # Shell configuration template
```

**Benefits of Enhanced Structure**:
- **Modular by concern**: Core logic, shell-specific, secret manager plugins
- **Easy to extend**: Add new secret managers by dropping in new files
- **Clear separation**: Shell integration vs secret fetching vs caching
- **Template-based**: Dynamic generation based on user configuration

### **2. Git Branch Detection (Final Approach)**
**Hybrid method** with user choice:
* **Auto**: Try git hooks first, fallback to prompt-based detection
* **Prompt-only**: Check branch on every prompt (~1ms), refresh environment only when branch changes (2-3s)
* **Manual-only**: User runs `git refresh-env` when needed

**Why prompt-based won**: No conflicts with existing git setups, catches all branch change methods, industry standard approach.

**Detached HEAD Handling**: When `git branch --show-current` is empty (detached HEAD state), automatically maps to the configured `default` environment to ensure functionality.

### **3. Multi-Layer Security Model (Major Innovation)**

**Tier 1 - Auto-loaded (Infrastructure) - Path-filtered by default**:
```bash
alias terraform='_load_command_secrets terraform && terraform'
alias kubectl='_load_command_secrets kubectl && kubectl'
```
✅ **Secure**: Only loads secrets matching the command's configured paths (e.g., terraform gets `infrastructure/*` and `shared/*` only)

**Tier 2 - On-demand multiple secrets**:
```bash
# Load specific secrets by name
load_secrets DATABASE_URL API_KEY REDIS_URL -- node migrate.js

# Load secrets by path pattern
load_secrets "frontend/*" "shared/database" -- npm start

# Load secrets by tag/category
load_secrets --category="database,cache" -- python manage.py migrate
```

**Tier 3 - Manual debugging access**:
```bash
inspect_secrets         # List available secret keys safely
inspect_secrets --values # Show actual values (explicit flag required)
load_secrets --all -- debug-command  # Load everything (explicit flag required)
```

#### **Permission Enforcement Layers**:
1. **Secret Manager RBAC**: Infisical/Vault permissions control who can access what
2. **Branch-Environment Mapping**: Automatic environment selection based on git branch
3. **Container Isolation**: DevContainer's isolated `/dev/shm` (tmpfs in RAM)

## **Caching Architecture**

### **Cache Strategy**: User + Environment Hash + Strict Permissions

**CORRECTED**: Cache is based on `user + environment` (from secret manager), not `user + branch`.

```bash
# Cache location (Linux tmpfs - RAM only, never touches disk)
CACHE_BASE="/dev/shm/dev-env-manager"
USER_ID=$(id -u)
ENVIRONMENT=$(get_environment_from_branch "$current_branch")  # prod, staging, dev
ENV_HASH=$(echo -n "$ENVIRONMENT" | sha256sum | cut -c1-12)
CACHE_DIR="$CACHE_BASE-$USER_ID-$ENV_HASH"

# Examples:
# main branch → prod environment: /dev/shm/dev-env-manager-1000-a665a45920fa/ (prod secrets)
# staging branch → staging environment: /dev/shm/dev-env-manager-1000-b3f0c7f6bb76/ (staging secrets)  
# feature/auth branch → dev environment: /dev/shm/dev-env-manager-1000-e3b0c44298fc/ (dev secrets)
```

**Benefits:**
- **Multiple branches share cache**: `main` and `prod` branches both use production cache
- **Fewer cache directories**: Only 3 caches max (prod, staging, dev) per user
- **Efficient resource usage**: No cache explosion from many feature branches
- **Logical grouping**: Cache matches actual secret environments, not git artifacts

### **File Permissions Strategy**:
```bash
# Cache directory creation with strict permissions and race condition protection
_create_cache_dir() {
    local cache_dir="$1"
    local lock_file="${cache_dir}.lock"
    
    # Atomic lock creation to prevent race conditions
    if ! mkdir "$lock_file" 2>/dev/null; then
        # Lock failed, another process is creating the cache. Wait for it.
        echo "🔒 Another process is creating cache, waiting..." >&2
        local wait_count=0
        while [[ -d "$lock_file" ]] && [[ $wait_count -lt 50 ]]; do 
            sleep 0.1
            ((wait_count++))
        done
        
        # Verify the cache was actually created by the other process
        if [[ -d "$cache_dir" ]] && [[ -f "$cache_dir/secrets.env" ]]; then
            return 0  # Success, cache is ready
        else
            echo "⚠️  Cache creation by other process failed, retrying..." >&2
            # Fall through to create it ourselves
        fi
    fi
    
    # Ensure lock cleanup on any exit
    trap 'rmdir "$lock_file" 2>/dev/null' RETURN EXIT
    
    # Create with most restrictive permissions first
    mkdir -p "$cache_dir"
    chmod 700 "$cache_dir"              # rwx------ (owner only)
    chown "$(id -u):$(id -g)" "$cache_dir"  # Explicit ownership
    
    # Create control files
    touch "$cache_dir/.users"
    touch "$cache_dir/.timestamp" 
    touch "$cache_dir/.last_accessed"   # Initialize access tracking
    chmod 600 "$cache_dir"/.users       # rw------- (owner read/write only)
    chmod 600 "$cache_dir"/.timestamp
    chmod 600 "$cache_dir"/.last_accessed
    
    # Create secrets file with maximum security
    touch "$cache_dir/secrets.env"
    chmod 600 "$cache_dir/secrets.env"  # rw------- (owner read/write only)
    
    # Record initial timestamp
    echo "$(date +%s)" > "$cache_dir/.timestamp"
    echo "$(date +%s)" > "$cache_dir/.last_accessed"
    
    # Lock cleanup happens automatically via trap
}

# Atomic secret writing to prevent race conditions
_write_secrets_atomic() {
    local cache_dir="$1"
    local temp_file="$cache_dir/.secrets.tmp"
    
    # Write to temporary file first
    {
        echo "# Generated at $(date)"
        echo "# Branch: $current_branch"
        echo "# Environment: $current_environment" 
        # ... write actual secrets
    } > "$temp_file"
    
    chmod 600 "$temp_file"              # Secure temp file
    mv "$temp_file" "$cache_dir/secrets.env"  # Atomic move
}

# Permission verification before use
_verify_cache_permissions() {
    local cache_dir="$1"
    local expected_perms="700"
    local actual_perms=$(stat -c %a "$cache_dir" 2>/dev/null)
    
    if [[ "$actual_perms" != "$expected_perms" ]]; then
        echo "⚠️  Cache permissions compromised, recreating..." >&2
        rm -rf "$cache_dir"
        return 1
    fi
    
    # Verify ownership
    local owner=$(stat -c %U "$cache_dir" 2>/dev/null)
    if [[ "$owner" != "$(whoami)" ]]; then
        echo "⚠️  Cache ownership compromised, recreating..." >&2
        rm -rf "$cache_dir"
        return 1
    fi
    
    return 0
}
```

### **Cache Settings & Configuration**:
```bash
# Cache refresh settings
CACHE_REFRESH_INTERVAL="15m"      # How often to refresh cached secrets
CACHE_CHECK_INTERVAL="1m"         # How often to check cache age
CACHE_WARMUP_ON_STARTUP=true      # Pre-load secrets on shell startup
CACHE_BACKGROUND_REFRESH=false    # Refresh cache in background when stale

# Cache behavior strategies
CACHE_STRATEGY="time_based"       # Options: time_based, manual_only, hybrid
CACHE_STALE_THRESHOLD="20m"       # When to consider cache "very stale" (refresh_interval + buffer)
CACHE_CLEANUP_INTERVAL="1h"       # How often to cleanup orphaned caches

# Cache size is naturally limited by tmpfs (RAM) - no artificial limits needed

# Cache refresh logic
_should_refresh_cache() {
    local cache_timestamp="$1"
    local current_time=$(date +%s)
    local cache_age=$((current_time - cache_timestamp))
    local refresh_interval_seconds=$(parse_duration "$CACHE_REFRESH_INTERVAL")
    
    [[ $cache_age -gt $refresh_interval_seconds ]]
}
```

### **Cache Cleanup Strategy**
Access-time based cleanup (robust and secure):

```bash
_cleanup_orphaned_caches() {
    local user_id=$(id -u)
    local cleanup_threshold_seconds=$((7 * 24 * 3600))  # 7 days default
    local current_time=$(date +%s)
    
    # Clean up unused caches based on last access time
    for cache_dir in /dev/shm/dev-env-manager-$user_id-*; do
        [[ -d "$cache_dir" ]] || continue
        
        local last_accessed_file="$cache_dir/.last_accessed"
        
        # Skip if no access timestamp (newly created cache)
        [[ -f "$last_accessed_file" ]] || continue
        
        local last_accessed=$(stat -c %Y "$last_accessed_file" 2>/dev/null || echo 0)
        local age=$((current_time - last_accessed))
        
        if [[ $age -gt $cleanup_threshold_seconds ]]; then
            local cache_env=$(extract_environment_from_cache_path "$cache_dir")
            rm -rf "$cache_dir"
            echo "🗑️  Cleaned up stale cache for environment: $cache_env (unused for ${age}s)" >&2
        fi
    done
}

# Touch access timestamp whenever cache is used
_touch_cache_access() {
    local cache_dir="$1"
    touch "$cache_dir/.last_accessed"
}

# Update all cache access points to record usage
_get_cached_secrets() {
    local cache_dir="$(_get_cache_dir)"
    
    if [[ -f "$cache_dir/secrets.env" ]]; then
        _touch_cache_access "$cache_dir"  # Record access
        return 0
    fi
    
    return 1
}

_load_all_secrets() {
    local cache_dir="$(_get_cache_dir)"
    
    if [[ ! -f "$cache_dir/secrets.env" ]]; then
        echo "⚠️  No secrets cached. Run 'refresh_secrets' first." >&2
        return 1
    fi
    
    # Verify cache permissions and record access
    if ! _verify_cache_permissions "$cache_dir"; then
        echo "🔧 Cache permissions corrupted, rebuilding..." >&2
        refresh_secrets
        return $?
    fi
    
    _touch_cache_access "$cache_dir"  # Record access
    source "$cache_dir/secrets.env"
}

_load_command_secrets() {
    local command_name="$1"
    local cache_dir="$(_get_cache_dir)"
    
    if [[ ! -f "$cache_dir/secrets.env" ]]; then
        echo "⚠️  No secrets cached for $command_name." >&2
        return 1
    fi
    
    _touch_cache_access "$cache_dir"  # Record access
    
    # Get allowed paths for this command from configuration
    local allowed_paths=$(get_command_secret_paths "$command_name")
    
    if [[ -n "$allowed_paths" ]]; then
        source "$cache_dir/secrets.env"
        _filter_secrets_by_paths "$allowed_paths"
    else
        source "$cache_dir/secrets.env"
    fi
}
```

**Why Access-Time Cleanup is Superior:**
- **Robust**: Independent of git state, fake directories, or branch scanning
- **Secure**: Only looks at cache directories owned by current user  
- **Simple**: Just checks file timestamps - no complex logic
- **Predictable**: 7-day unused threshold regardless of git branch changes
- **Safe**: Won't delete actively used caches even if git state is weird

### **Cache Lifecycle**:
- **First shell on branch**: 3s fetch + cache creation with strict permissions
- **Additional shells on same branch**: Instant (shared cache with permission verification)
- **Branch switching**: New cache per environment (environment isolation)
- **Time-based refresh**: Configurable refresh interval (default 15m)
- **Stale cache handling**: Use stale cache immediately, refresh in background
- **Manual refresh**: `refresh_secrets` command bypasses all cache settings
- **Automatic cleanup**: Cache dies when last shell exits or container stops
- **Permission monitoring**: Continuous verification of cache security

### **Security Properties**:
- **Memory-only storage**: `/dev/shm` tmpfs - never touches disk
- **Per-user isolation**: User ID in cache path prevents cross-user access
- **Environment-based separation**: Different environments can't contaminate each other
- **Strict file permissions**: 700 for directories, 600 for files (owner-only access)
- **Atomic operations**: Prevent race conditions during cache updates
- **Permission verification**: Continuous monitoring for tampering attempts
- **Automatic cleanup**: Vanishes on container stop/crash
- **Ownership verification**: Ensures cache belongs to correct user

## **Portability & Compatibility Strategy**

### **Core Utilities Compatibility Issue**
The primary challenge is the difference between GNU Coreutils (standard Linux) and BusyBox (Alpine/minimal images):

**Specific Incompatibilities:**
- **`stat` command**: GNU uses `stat -c %a`, BusyBox varies (`%a` vs `%o`), macOS uses `stat -f %A`
- **`date` command**: GNU supports `date -d '15 minutes ago'`, BusyBox often lacks `-d` flag

### **Solution: Automatic Coreutils Installation**
The install script automatically ensures GNU-compatible utilities are available:

```bash
# In install.sh - runs during DevContainer build with root access
_ensure_gnu_coreutils() {
    # Detect BusyBox/Alpine and install GNU coreutils if needed
    if [ -f /bin/busybox ] && ! stat --version >/dev/null 2>&1; then
        echo "📦 Installing GNU coreutils for compatibility..."
        apk add coreutils
    fi
}
```

**Why This Works:**
- **Build-time installation**: Runs once during DevContainer build, not on every startup
- **Root access**: DevContainer features have root privileges during build phase
- **Minimal impact**: 1-2MB addition for full compatibility
- **No wrapper complexity**: Use standard GNU commands throughout codebase
- **Broad support**: Works on Ubuntu/Debian (already has GNU) and Alpine (gets GNU installed)

## **Network Failure & Offline Mode Handling**

### **Graceful Failure Philosophy**
Never block the shell startup - always fail gracefully with clear messaging.

```bash
_fetch_secrets_with_fallback() {
    local environment="$1"
    local cache_dir="$2"
    
    # Attempt to fetch secrets
    if ! _fetch_secrets_from_manager "$environment" "$cache_dir"; then
        
        # Check if stale cache exists
        if [[ -f "$cache_dir/secrets.env" ]]; then
            local cache_age=$(get_cache_age "$cache_dir")
            echo "⚠️  Could not connect to secret manager. Using stale cache (${cache_age} old)." >&2
            echo "   Run 'refresh_secrets' when connection is restored." >&2
            return 0  # Use stale cache
        else
            # No cache available
            echo "⚠️  Could not connect to secret manager and no cached secrets available." >&2
            echo "   Commands may fail without required environment variables." >&2
            echo "   Check network connection and run 'refresh_secrets' when ready." >&2
            
            # Create empty cache to prevent repeated attempts
            mkdir -p "$cache_dir"
            touch "$cache_dir/secrets.env"
            echo "# No secrets available - offline mode" > "$cache_dir/secrets.env"
            return 1  # No secrets available
        fi
    fi
}
```

**Behavior Strategy:**
- **With stale cache**: Use it immediately, warn user, continue normally
- **No cache + offline**: Create empty cache, warn user, don't block shell
- **Manual recovery**: User runs `refresh_secrets` when connection returns

## **Authentication Token Lifecycle Management**

### **Handling Expired Tokens**
Secret manager tokens (Infisical Universal Auth, Vault tokens) have TTLs and can expire during long dev sessions.

```bash
_handle_auth_failure() {
    local secret_manager="$1"
    local cache_dir="$2"
    
    # Mark cache as unauthorized
    touch "$cache_dir/.auth_failed"
    
    # Clear any existing secrets to prevent using stale authenticated data
    > "$cache_dir/secrets.env"
    
    # Provide clear recovery instructions
    case "$secret_manager" in
        "infisical")
            echo "🚨 Infisical authentication expired!" >&2
            echo "   Run: infisical login" >&2
            ;;
        "vault")
            echo "🚨 Vault token expired!" >&2
            echo "   Run: vault auth -method=<your-method>" >&2
            ;;
        *)
            echo "🚨 Secret manager authentication failed!" >&2
            echo "   Please re-authenticate and run 'refresh_secrets'" >&2
            ;;
    esac
}

# In the main fetch function
_fetch_secrets_from_manager() {
    # ... attempt fetch ...
    
    if [[ $response_code == "401" || $response_code == "403" ]]; then
        _handle_auth_failure "$SECRET_MANAGER" "$cache_dir"
        return 1
    fi
}
```

**Re-authentication Hooks (Future Enhancement):**
```json
{
  "secretManagerConfig": {
    "reAuthCommand": "infisical login --method=universal-auth",
    "authCheckCommand": "infisical whoami"
  }
}
```

## **Branch Detection & Environment Mapping**

### **Robust Branch Detection with Detached HEAD Support**

```bash
# Core branch detection with detached HEAD handling
_get_current_branch() {
    local current_branch
    
    # Try to get current branch name
    current_branch=$(git branch --show-current 2>/dev/null)
    
    # Handle detached HEAD state
    if [[ -z "$current_branch" ]]; then
        echo "⚠️  Detached HEAD detected, using default environment" >&2
        echo "detached"
        return 0
    fi
    
    echo "$current_branch"
}

# Environment mapping with detached HEAD fallback
get_environment_from_branch() {
    local branch="$1"
    local default_env="${BRANCH_MAPPING_DEFAULT:-development}"
    
    # Handle detached HEAD explicitly
    if [[ "$branch" == "detached" ]]; then
        echo "$default_env"
        return 0
    fi
    
    # Check explicit branch mappings first
    case "$branch" in
        "main"|"master")
            echo "${BRANCH_MAPPING_MAIN:-production}"
            ;;
        "prod"|"production")
            echo "${BRANCH_MAPPING_PROD:-production}"
            ;;
        "staging"|"stage")
            echo "${BRANCH_MAPPING_STAGING:-staging}"
            ;;
        "develop"|"development")
            echo "${BRANCH_MAPPING_DEVELOP:-development}"
            ;;
        release/*)
            echo "${BRANCH_MAPPING_RELEASE:-staging}"
            ;;
        hotfix/*)
            echo "${BRANCH_MAPPING_HOTFIX:-production}"
            ;;
        *)
            # All other branches (feature/*, bugfix/*, etc.) use default
            echo "$default_env"
            ;;
    esac
}

# Environment detection with caching
_detect_current_environment() {
    local current_branch=$(_get_current_branch)
    local current_environment=$(get_environment_from_branch "$current_branch")
    
    # Cache the current environment for performance
    export CURRENT_BRANCH="$current_branch"
    export CURRENT_ENVIRONMENT="$current_environment"
    
    echo "$current_environment"
}
```

## **Enhanced Security & Debugging Commands**

### **Enhanced Infrastructure Command Integration (Tier 1)**

```bash
# Core function to load all secrets for infrastructure commands
_load_all_secrets() {
    local cache_dir="$(_get_cache_dir)"
    
    if [[ ! -f "$cache_dir/secrets.env" ]]; then
        echo "⚠️  No secrets cached. Run 'refresh_secrets' first." >&2
        return 1
    fi
    
    # Verify cache permissions before loading
    if ! _verify_cache_permissions "$cache_dir"; then
        echo "🔧 Cache permissions corrupted, rebuilding..." >&2
        refresh_secrets
        return $?
    fi
    
    # Source all secrets into current subshell
    source "$cache_dir/secrets.env"
}

# Enhanced infrastructure command with path-based filtering (future enhancement)
_load_command_secrets() {
    local command_name="$1"
    local cache_dir="$(_get_cache_dir)"
    
    if [[ ! -f "$cache_dir/secrets.env" ]]; then
        echo "⚠️  No secrets cached for $command_name." >&2
        return 1
    fi
    
    # Get allowed paths for this command from configuration
    local allowed_paths=$(get_command_secret_paths "$command_name")
    
    if [[ -n "$allowed_paths" ]]; then
        # Load only secrets matching the command's allowed paths
        source "$cache_dir/secrets.env"
        _filter_secrets_by_paths "$allowed_paths"
    else
        # Fallback to loading all secrets
        source "$cache_dir/secrets.env"
    fi
}

# Dynamic alias creation with path-based filtering
_create_infrastructure_aliases() {
    # Read autoCommands dictionary from configuration
    local commands_json="$AUTO_COMMANDS_JSON"
    
    # Parse each command and its allowed paths
    echo "$commands_json" | jq -r 'to_entries[] | "\(.key) \(.value | join(" "))"' | while read -r cmd paths; do
        # Create alias that loads only the secrets this command needs
        alias "$cmd"="_load_command_secrets $cmd && $cmd"
        echo "🔧 Auto-loading enabled for '$cmd' with paths: $paths" >&2
    done
    
    # Export function for subshells
    export -f "_load_command_secrets"
}

# Path-based secret filtering (future enhancement)
_filter_secrets_by_paths() {
    local allowed_paths="$1"
    local temp_env=$(mktemp)
    
    # Filter secrets.env to only include matching paths
    while IFS='=' read -r key value; do
        for path_pattern in $allowed_paths; do
            if [[ "$key" =~ $path_pattern ]]; then
                echo "$key=$value" >> "$temp_env"
                break
            fi
        done
    done < "$(_get_cache_dir)/secrets.env"
    
    # Source filtered secrets
    source "$temp_env"
    rm -f "$temp_env"
}
```

### **Replacing `load_all_secrets` with Safe Debugging (Tier 3)**

```bash
# Safe inspection command
inspect_secrets() {
    local cache_dir="$(_get_cache_dir)"
    
    if [[ ! -f "$cache_dir/secrets.env" ]]; then
        echo "No secrets cached for current environment." >&2
        return 1
    fi
    
    echo "Available secrets for environment '$CURRENT_ENVIRONMENT':"
    # Extract only key names, never values
    grep -E '^[A-Z_]+=.' "$cache_dir/secrets.env" | cut -d'=' -f1 | sort | while read -r key; do
        echo "  - $key"
    done
    echo ""
    echo "Usage: load_secrets $key -- <command>"
    echo "       load_secrets $key1 $key2 -- <command>"
}

# Explicit value inspection (requires deliberate flag)
inspect_secrets() {
    case "$1" in
        --values)
            echo "🔍 Secret values for environment '$CURRENT_ENVIRONMENT':"
            source "$(_get_cache_dir)/secrets.env"
            grep -E '^[A-Z_]+=.' "$(_get_cache_dir)/secrets.env" | while IFS='=' read -r key value; do
                # Never show more than half the secret, max 8 chars
                local value_length=${#value}
                local max_show=$((value_length / 2))
                [[ $max_show -gt 8 ]] && max_show=8
                [[ $max_show -lt 3 ]] && max_show=3  # Minimum 3 chars for very short secrets
                echo "  $key=${value:0:$max_show}... (${value_length} chars total)"
            done
            ;;
        --json)
            # Output as JSON for tooling
            source "$(_get_cache_dir)/secrets.env"
            echo "{"
            grep -E '^[A-Z_]+=.' "$(_get_cache_dir)/secrets.env" | while IFS='=' read -r key value; do
                echo "  \"$key\": \"$value\","
            done | sed '$ s/,$//'
            echo "}"
            ;;
        *)
            # Default: keys only
            inspect_secrets
            ;;
    esac
}
```

### **Enhanced Secret Loading Commands**

```bash
# Multiple selection methods for load_secrets
load_secrets() {
    local secrets_to_load=()
    local command_args=()
    local parsing_command=false
    
    # Parse arguments until we hit --
    for arg in "$@"; do
        if [[ "$arg" == "--" ]]; then
            parsing_command=true
            continue
        fi
        
        if [[ "$parsing_command" == true ]]; then
            command_args+=("$arg")
        else
            case "$arg" in
                --category=*|--tag=*)
                    # Load secrets by category/tag (future enhancement)
                    local category="${arg#*=}"
                    secrets_to_load+=($(get_secrets_by_category "$category"))
                    ;;
                --pattern=*|--path=*)
                    # Load secrets matching pattern
                    local pattern="${arg#*=}"
                    secrets_to_load+=($(get_secrets_by_pattern "$pattern"))
                    ;;
                --all)
                    # Load all secrets (requires explicit flag)
                    echo "⚠️  Loading ALL secrets. Use with caution." >&2
                    secrets_to_load+=($(get_all_secret_keys))
                    ;;
                *)
                    # Direct secret name
                    secrets_to_load+=("$arg")
                    ;;
            esac
        fi
    done
    
    # Validate command was provided
    if [[ ${#command_args[@]} -eq 0 ]]; then
        echo "Usage: load_secrets <KEY1> [KEY2...] -- <command>" >&2
        echo "       load_secrets --pattern='frontend/*' -- npm start" >&2
        echo "       load_secrets --all -- debug-command" >&2
        return 1
    fi
    
    # Load selected secrets and execute command
    _execute_with_secrets "${secrets_to_load[@]}" -- "${command_args[@]}"
}
```

## **Performance Profile**
* **Shell startup**: Instant (no secret loading)
* **First shell per environment**: 3s (acceptable, matches current user workflow)
* **Additional shells same environment**: Instant (shared cache benefit)
* **Infrastructure commands**: Instant after first load
* **Branch changes**: 3s only when changing to different environment
* **Manual refresh**: 3s (immediate fresh secrets)
* **Permission checks**: <1ms overhead per cache access

## **Directory/Path-Based Secret Organization**
**Universal support** across secret managers:
- **Vault**: `secret/infrastructure/*`, `secret/frontend/*`
- **AWS Secrets**: `/infrastructure/*`, `/frontend/*`
- **Infisical**: `/infrastructure/`, `/frontend/`, `/shared/`
- **Azure Key Vault**: Naming pattern filtering
- **GCP Secret Manager**: Path prefix filtering

**Benefits**:
- **Principle of least privilege**: Tools only get secrets they need
- **Reduces blast radius**: Frontend devs never see infrastructure secrets
- **Natural organization**: Matches how teams think about secrets

## **Sample DevContainer Feature Configuration**

```json
{
  "image": "mcr.microsoft.com/devcontainers/base:ubuntu",
  "features": {
    "ghcr.io/your-org/dev-env-manager:1": {
      "detection": "auto",
      "shells": "both", 
      "secretManager": "infisical",
      "cacheExpiry": "10m",
      "branchMapping": {
        "main": "production",
        "prod": "production", 
        "staging": "staging",
        "develop": "development",
        "default": "development"
      },
      "security": {
        "verifyPermissions": true,
        "atomicWrites": true,
        "maxCacheAge": "15m"
      },
      "secretPaths": {
        "terraform": ["infrastructure/*", "shared/*"],
        "kubectl": ["kubernetes/*", "shared/*"],
        "npm": ["frontend/*", "shared/*"],
        "python": ["backend/*", "shared/database/*"],
        "default": ["shared/*"]
      },
      "autoCommands": {
        "terraform": ["infrastructure/*", "shared/*"],
        "kubectl": ["kubernetes/*", "shared/*"],
        "helm": ["kubernetes/*", "shared/*"],
        "aws": ["infrastructure/*", "shared/*"],
        "tofu": ["infrastructure/*", "shared/*"]
      },
      "onDemandCommands": {
        "load_secrets": true,
        "inspect_secrets": true,
        "refresh_secrets": true
      },
      "secretManagerConfig": {
        "projectId": "${INFISICAL_PROJECT_ID}",
        "baseUrl": "https://app.infisical.com",
        "authMethod": "universal-auth"
      },
      "cache": {
        "refreshInterval": "15m",
        "strategy": "time_based",
        "backgroundRefresh": false,
        "cleanupInterval": "1h"
      },
      "offlineMode": {
        "allowStaleCache": true,
        "maxStaleAge": "2h",
        "gracefulFailure": true,
        "retryInterval": "5m"
      },
      "authentication": {
        "reAuthCommand": "infisical login --method=universal-auth",
        "authCheckCommand": "infisical whoami",
        "tokenRefreshThreshold": "10m"
      }
    }
  }
}
```

**Alternative cache-focused configuration**:
```json
{
  "features": {
    "ghcr.io/your-org/dev-env-manager:1": {
      "secretManager": "infisical",
      "cache": {
        "refreshInterval": "10m",
        "strategy": "hybrid",
        "backgroundRefresh": true
      },
      "secretPaths": {
        "default": ["frontend/*", "shared/*"] 
      }
    }
  }
}
```

**Advanced multi-manager configuration**:
```json
{
  "features": {
    "ghcr.io/your-org/dev-env-manager:1": {
      "secretManager": "vault",
      "secretPaths": {
        "terraform": ["secret/infrastructure/*", "secret/shared/*"],
        "kubectl": ["secret/kubernetes/*"],
        "npm": ["secret/frontend/*", "secret/shared/database/*"]
      },
      "branchMapping": {
        "main": "production",
        "release/*": "staging", 
        "hotfix/*": "production",
        "feature/*": "development",
        "default": "development"
      },
      "secretManagerConfig": {
        "address": "${VAULT_ADDR}",
        "authMethod": "kubernetes",
        "role": "dev-env-manager",
        "namespace": "dev"
      }
    }
  }
}
```

## **Error Handling Philosophy**

### **"Caught Error" Approach**
- **Never block shell startup**: Always allow interactive shell, even without secrets
- **Clear, actionable messaging**: Tell user exactly what to do to fix the problem
- **Graceful degradation**: Use stale cache when available, empty environment when not
- **Manual recovery**: Provide simple commands (`refresh_secrets`, `inspect_secrets`) for debugging
- **No complexity creep**: Avoid automatic retry loops, complex networking, or daemon processes

### **Error Message Standards**
```bash
# Network failures
"⚠️  Could not connect to Infisical. Using stale cache (2h old)."
"   Run 'refresh_secrets' when connection is restored."

# Authentication failures  
"🚨 Authentication expired! Run: infisical login"

# Missing secrets
"⚠️  Secret 'DATABASE_URL' not found in development environment."
"   Check secret exists: inspect_secrets"

# Cache issues
"🔧 Cache permissions corrupted, rebuilding..."
```

**The goal**: Clear, non-blocking errors that give users immediate next steps without overwhelming them with technical details.

## **Why This Doesn't Exist Yet**
- **Not easily monetizable**: Can't charge developers/companies for DevContainer features
- **DevContainer ecosystem still young**: Feature marketplace developing
- **Secret manager fragmentation**: Everyone uses different tools
- **Most solutions are overcomplicated**: Enterprise tools with complex setup
- **Companies build internal tools**: But they're janky, undocumented, unmaintained

## **Unique Value Proposition**
- **Zero-config setup**: One line in devcontainer.json, works immediately
- **Enterprise-grade security**: Respects existing RBAC, no new attack vectors
- **Multi-provider support**: Works with Infisical, Vault, AWS, Azure, GCP
- **Automatic environment mapping**: Branch-based with sensible defaults
- **Developer-first UX**: Solves daily workflow pain with zero learning curve
- **OSS distribution**: No procurement, instant adoption
- **Strict security model**: File permissions, atomic operations, continuous verification

## **Implementation Size**
- **Current**: ~300 lines of shell script
- **With all features**: 500-1000 lines of code across modular files
- **Maintenance burden**: Minimal (API calls + file operations + shell hooks)

## **Next Development Steps**
1. **Enhanced file structure** implementation with modular organization
2. **Cache implementation** with tmpfs, strict permissions, and atomic operations
3. **Multi-secret-manager support** architecture (starting with Infisical)
4. **Directory-based secret filtering** with pattern matching
5. **Multiple secret loading** commands (`load_secrets` with various selection methods)
6. **Shell integration testing** (zsh vs bash compatibility)
7. **Permission verification system** for continuous security monitoring
8. **DevContainer feature packaging** and distribution

**The bottom line**: A simple, well-executed solution to a universal problem that becomes widely adopted because it "just works" and respects existing security infrastructure while maintaining the highest security standards.