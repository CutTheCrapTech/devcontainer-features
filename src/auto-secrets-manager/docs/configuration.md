# Configuration Guide

This document provides detailed configuration options for the Auto Secrets Manager DevContainer feature.

## Table of Contents

- [Secret Managers](#secret-managers)
- [Shell Integration](#shell-integration)
- [Branch Mapping](#branch-mapping)
- [Secret Manager Configuration](#secret-manager-configuration)
- [Auto Commands](#auto-commands)
- [Cache Configuration](#cache-configuration)
- [Environment Configuration](#environment-configuration)
- [Security Best Practices](#security-best-practices)

## Secret Managers

The `secretManager` option specifies which secret management service to use.

### Supported Values

- `"infisical"` - Infisical Cloud/Self-hosted (default and currently supported)
- `"vault"` - HashiCorp Vault (planned)
- `"aws"` - AWS Secrets Manager (planned)
- `"azure"` - Azure Key Vault (planned)
- `"gcp"` - Google Secret Manager (planned)

### Example

```json
{
  "secretManager": "infisical"
}
```

For detailed setup instructions, authentication methods, and troubleshooting for each secret manager, see the [Secret Managers Guide](secret-managers.md).

## Shell Integration

The `shells` option determines which shell environments receive integration.

### Supported Values

- `"bash"` - Bash shell only
- `"zsh"` - Zsh shell only
- `"both"` - Both bash and zsh (default)

### What Gets Integrated

Shell integration provides:

1. **Automatic branch detection** - Detects git branch changes via `precmd`/`PROMPT_COMMAND`
2. **Environment loading** - Automatically loads secrets when branch changes
3. **Command hooks** - Intercepts configured commands to load secrets
4. **Optional prompt enhancement** - Shows current environment in shell prompt
5. **Optional history marking** - Marks commands that used secrets in shell history

### Example

```json
{
  "shells": "both",
  "showEnvInPrompt": true,
  "markHistory": false
}
```

### Shell Health Check

Verify shell integration is working:

```bash
# For bash
auto-secrets-bash-health

# For zsh
auto-secrets-zsh-health
```

## Branch Mapping

The `branchMapping` option defines how git branches map to environments. This is provided as a JSON string due to DevContainer feature limitations.

### Basic Mapping

```json
{
  "branchMapping": "{'main':'production','develop':'staging','default':'development'}"
}
```

### Pattern Matching

Branch mappings support glob patterns for flexible matching:

```json
{
  "branchMapping": "{'main':'production','master':'production','staging':'staging','develop':'development','dev':'development','feature/*':'development','feature/**':'development','release/*':'staging','hotfix/*':'production','default':'development'}"
}
```

### Pattern Syntax

- `*` - Matches any characters except `/`
- `**` - Matches any characters including `/`
- `?` - Matches single character
- No wildcards - Exact match only

### Pattern Examples

| Branch Name             | Pattern      | Environment   | Match |
| ----------------------- | ------------ | ------------- | ----- |
| `feature/auth`          | `feature/*`  | `development` | ✅    |
| `feature/ui/components` | `feature/**` | `development` | ✅    |
| `feature/ui/components` | `feature/*`  | `development` | ❌    |
| `release/v1.0`          | `release/*`  | `staging`     | ✅    |
| `hotfix/security-patch` | `hotfix/*`   | `production`  | ✅    |

### Required Default

The `default` mapping is **required** and handles any branches that don't match other patterns:

```json
{
  "branchMapping": "{'main':'production','default':'development'}"
}
```

### Security Notes

🔒 **No default branch mappings are provided for security reasons.** You must explicitly define all mappings to prevent accidental exposure of production secrets.

## Secret Manager Configuration

The `secretManagerConfig` option provides service-specific configuration as a JSON string.

For detailed configuration options, authentication setup, and examples for each secret manager, see the [Secret Managers Guide](secret-managers.md).

### Basic Example

```json
{
  "secretManagerConfig": "{'project_id':'your-project-id','client_id':'your-client-id','site_url':'https://app.infisical.com'}"
}
```

### Security Note

**Never include sensitive credentials like `client_secret` in `secretManagerConfig`**. Always provide them through environment variables or configuration files for security.

## Auto Commands

The `autoCommands` option configures which commands automatically load secrets and optionally filters by file paths.

### Basic Configuration

```json
{
  "autoCommands": "{'terraform':[],'kubectl':[],'docker':[],'ansible':[]}"
}
```

### Path Filtering

Restrict secret loading to specific file paths for security and performance:

```json
{
  "autoCommands": "{'terraform':['/infrastructure/**'],'kubectl':['/kubernetes/**','/k8s/**'],'docker':['/docker/**','/containers/**'],'ansible':['/playbooks/**']}"
}
```

### Path Pattern Examples

| Pattern                    | Path                          | Matches |
| -------------------------- | ----------------------------- | ------- |
| `/infrastructure/**`       | `/infrastructure/secret1`     | ✅      |
| `/infrastructure/**`       | `/infrastructure/aws/secret1` | ✅      |
| `/infrastructure/*`        | `/infrastructure/secret1`     | ✅      |
| `/infrastructure/*`        | `/infrastructure/aws/secret1` | ❌      |
| `/infrastructure/secret_1` | `/infrastructure/secret1`     | ✅      |
| `/infrastructure/secret_1` | `/infrastructure/secret2`     | ❌      |

### Organizing Secrets by Paths

Organize your secrets using path structures in your secret manager:

```
/infrastructure/
├── database/
│   ├── DATABASE_URL
│   └── DB_PASSWORD
├── redis/
│   └── REDIS_URL
└── monitoring/
    └── DATADOG_API_KEY

/application/
├── auth/
│   ├── JWT_SECRET
│   └── OAUTH_CLIENT_ID
└── external-apis/
    ├── STRIPE_API_KEY
    └── SENDGRID_API_KEY
```

Filter commands to load only relevant secrets:

```json
{
  "autoCommands": "{'terraform':['/infrastructure/**'],'kubectl':['/application/**']}"
}
```

### Command Behavior

When an auto command is triggered:

1. **Path check** - If paths are specified, current directory must match
2. **Environment detection** - Current git branch determines environment
3. **Secret loading** - Secrets are loaded and exported to environment
4. **Command execution** - Original command runs with secrets available

### Troubleshooting Auto Commands

```bash
# Check if command is configured
auto-secrets debug | grep -A5 "Auto Commands"

# Test path matching
cd /infrastructure && auto-secrets current-env --paths

# Verify command detection
which terraform  # Ensure command exists
```

## Cache Configuration

The `cacheConfig` option controls caching behavior for performance and security.

### Default Configuration

```json
{
  "cacheConfig": "{'refresh_interval':'15m','cleanup_interval':'7d'}"
}
```

### Available Options

| Option             | Description                  | Format          | Default |
| ------------------ | ---------------------------- | --------------- | ------- |
| `refresh_interval` | How often to refresh secrets | Duration string | `15m`   |
| `cleanup_interval` | How often to clean old cache | Duration string | `7d`    |

### Duration Format

Use Go-style duration strings:

- `s` - seconds (e.g., `30s`)
- `m` - minutes (e.g., `15m`)
- `h` - hours (e.g., `2h`)
- `d` - days (e.g., `7d`)

### Performance Tuning

#### High-Frequency Development

For rapid development with frequent secret changes:

```json
{
  "cacheConfig": "{'refresh_interval':'5m','cleanup_interval':'1d'}"
}
```

#### Production Stability

For stable production environments:

```json
{
  "cacheConfig": "{'refresh_interval':'1h','cleanup_interval':'30d'}"
}
```

#### Resource-Constrained Environments

For containers with limited resources:

```json
{
  "cacheConfig": "{'refresh_interval':'30m','cleanup_interval':'3d'}"
}
```

### Cache Management Commands

```bash
# View cache status
auto-secrets inspect

# Force refresh
auto-secrets refresh

# Clean stale cache
auto-secrets cleanup

# Clean all cache
auto-secrets cleanup --all
```

### Cache Storage

- **Location**: `/dev/shm/auto-secrets/` (RAM filesystem)
- **Permissions**: `600` (user read/write only)
- **Format**: JSON metadata + shell-friendly env files
- **Size**: ~1-10KB per environment

## Environment Configuration

Configure environment-specific behavior and security options.

### Show Environment in Prompt

Display current environment in your shell prompt:

```json
{
  "showEnvInPrompt": true
}
```

**Result:**

```bash
[dev] user@container:~/project$ terraform plan
[staging] user@container:~/project$ git checkout staging
```

### Mark History

Mark commands that used auto-loaded secrets in shell history:

```json
{
  "markHistory": true
}
```

**Result:**

```bash
$ history
  1001  [auto-secrets:production] terraform apply
  1002  ls -la
  1003  [auto-secrets:staging] kubectl get pods
```

### Branch Detection

Control automatic branch change detection:

```json
{
  "branchDetection": true
}
```

**Default: `true`** - Automatically detects branch changes via shell prompt integration.

When disabled (`false`), secrets must be manually refreshed. However, **git hooks are the preferred method** for automatic branch detection as they're significantly more performant than shell-based detection.

#### Why Git Hooks Are Better

- **Performance**: Triggers only on actual branch changes, not every shell prompt
- **Reliability**: Guaranteed execution when switching branches
- **Efficiency**: No overhead (even if minimal) during regular shell operations

#### Manual Refresh (when branchDetection: false)

```bash
# Manual environment switching
auto-secrets refresh
eval "$(auto-secrets output-env)"
```

#### Recommended Setup: Git Hooks

For the best performance, disable shell-based detection and use git hooks instead:

```json
{
  "branchDetection": false
}
```

Then set up git hooks: **[Git Hook Setup](git-hooks.md)**

> **Note:** Shell-based detection is enabled by default to avoid interfering with existing git hooks, but git hooks provide superior performance when properly configured.

### Debug Mode

Enable comprehensive debugging and logging:

```json
{
  "debug": true
}
```

**Debug Information Includes:**

- Branch detection events
- Environment mapping decisions
- Cache hit/miss statistics
- Secret manager API calls
- Performance timing data
- Error stack traces

**Log Locations:**

- `/var/log/auto-secrets/cli.log` - CLI operations
- `/var/log/auto-secrets/shell.log` - Shell integration
- `/var/log/auto-secrets/daemon.log` - Background processes

## Security Best Practices

### Credential Storage

✅ **DO:**

```bash
# Environment variables (ephemeral)
export INFISICAL_CLIENT_SECRET="secret"

# Secure config file (RAM filesystem)
echo '{"INFISICAL_CLIENT_SECRET":"secret"}' > /dev/shm/auto-secrets/config.json
chmod 600 /dev/shm/auto-secrets/config.json
```

❌ **DON'T:**

```json
{
  "secretManagerConfig": "{'client_secret':'hardcoded-secret'}"
}
```

### Branch Mapping Security

✅ **DO:**

```json
{
  "branchMapping": "{'main':'production','staging':'staging','default':'development'}"
}
```

❌ **DON'T:**

```json
{
  "branchMapping": "{'default':'production'}"
}
```

### Path Filtering

✅ **DO:**

```json
{
  "autoCommands": "{'terraform':['/infrastructure/**'],'kubectl':['/k8s/**']}"
}
```

❌ **DON'T:**

```json
{
  "autoCommands": "{'terraform':['/**'],'kubectl':['/**']}"
}
```

### Regular Maintenance

```bash
# Rotate credentials regularly
auto-secrets refresh

# Monitor access
auto-secrets inspect

# Review logs
sudo tail -f /var/log/auto-secrets/cli.log

# Clean old cache
auto-secrets cleanup
```

### Incident Response

If credentials are compromised:

1. **Revoke credentials** in secret manager
2. **Clear cache**: `auto-secrets cleanup --all`
3. **Update configuration** with new credentials
4. **Refresh secrets**: `auto-secrets refresh`
5. **Verify access**: `auto-secrets debug`

---

For additional help, see the main [README](../README.md) or open an issue in the project repository.
