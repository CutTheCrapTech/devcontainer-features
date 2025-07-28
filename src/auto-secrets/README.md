# Auto Secrets Manager

A DevContainer Feature that automatically manages environment secrets based on git branches with enterprise-grade security.

## Overview

The Auto Secrets Manager provides:

- **Branch-based environment mapping**: Automatically maps git branches to environments (main → production, staging → staging, etc.)
- **Multi-provider support**: Works with Infisical, HashiCorp Vault, AWS Secrets Manager, Azure Key Vault, and more
- **Enterprise-grade security**: Secure caching in tmpfs with strict file permissions and atomic operations
- **Zero-config setup**: Works out of the box with sensible defaults
- **Shell integration**: Supports both bash and zsh with prompt-based branch change detection
- **Offline support**: Graceful fallback to stale cache when network is unavailable

## Quick Start

Add to your `devcontainer.json`:

```json
{
  "features": {
    "ghcr.io/your-org/devcontainer-features/auto-secrets:1": {
      "secretManager": "infisical",
      "branchMapping": {
        "main": "production",
        "staging": "staging",
        "develop": "development"
      }
    }
  }
}
```

Set your secret manager configuration:

```bash
# For Infisical
export INFISICAL_PROJECT_ID="your-project-id"

# For Vault
export VAULT_ADDR="https://vault.company.com"
export VAULT_TOKEN="your-token"
```

That's it! The feature will automatically:

1. Detect your current git branch
2. Map it to the appropriate environment
3. Fetch and cache secrets securely
4. Make them available to your development tools

## Configuration Options

### Basic Configuration

| Option          | Type   | Default       | Description                                                          |
| --------------- | ------ | ------------- | -------------------------------------------------------------------- |
| `secretManager` | string | `"infisical"` | Secret manager backend (`infisical`, `vault`, `aws`, `azure`, `gcp`) |
| `detection`     | string | `"auto"`      | Branch detection method (`auto`, `prompt`, `manual`)                 |
| `shells`        | string | `"both"`      | Shell integration (`bash`, `zsh`, `both`)                            |

### Branch Mapping

```json
{
  "branchMapping": {
    "main": "production",
    "master": "production",
    "prod": "production",
    "staging": "staging",
    "stage": "staging",
    "develop": "development",
    "development": "development",
    "default": "development"
  }
}
```

Pattern-based mapping is also supported:

- `release/*` → staging
- `hotfix/*` → production
- `feature/*` → development

### Automatic Command Integration

Automatically load secrets for infrastructure commands. The value for each command is an array of paths that will be used to filter secrets.

```json
{
  "autoCommands": {
    "terraform": ["/infrastructure/", "/shared/"],
    "kubectl": ["/kubernetes/", "/shared/"],
    "aws": ["/infrastructure/", "/shared/"]
  }
}
```

## Secret Manager Configuration

### Infisical

```json
{
  "secretManagerConfig": {
    "projectId": "${INFISICAL_PROJECT_ID}",
    "baseUrl": "https://app.infisical.com",
    "authMethod": "universal-auth"
  }
}
```

Environment variables:

- `INFISICAL_PROJECT_ID`: Your Infisical project ID
- Authentication handled via `infisical login`

### HashiCorp Vault

```json
{
  "secretManagerConfig": {
    "address": "${VAULT_ADDR}",
    "mount": "secret",
    "kvVersion": "2"
  }
}
```

Environment variables:

- `VAULT_ADDR`: Vault server address
- `VAULT_TOKEN`: Authentication token
- Or use `vault auth` with your preferred method

### AWS Secrets Manager

```json
{
  "secretManagerConfig": {
    "region": "${AWS_REGION}",
    "basePath": "/dev-secrets"
  }
}
```

Environment variables:

- `AWS_REGION`: AWS region
- AWS credentials via IAM roles, profiles, or environment variables

### Azure Key Vault

```json
{
  "secretManagerConfig": {
    "vaultUrl": "${AZURE_VAULT_URL}",
    "tenantId": "${AZURE_TENANT_ID}"
  }
}
```

Environment variables:

- `AZURE_VAULT_URL`: Key Vault URL
- Authentication via Azure CLI or service principal

## Usage

### Automatic Mode (Default)

Secrets are automatically refreshed when:

- You switch git branches
- Cache expires (configurable interval)
- You run infrastructure commands

### Manual Commands

```bash
# Refresh secrets from secret manager
refresh_secrets

# List available secret keys
inspect_secrets

# Show secret values (truncated for security)
inspect_secrets --values

# Load specific secrets for a command
load_secrets DATABASE_URL API_KEY -- node migrate.js

# Load secrets by pattern
load_secrets --pattern="FRONTEND_*" -- npm start

# Load all secrets (use with caution)
load_secrets --all -- debug-script.sh

# Show environment and cache status
debug_env

# Clean up old cache directories
cleanup_cache
```

### Infrastructure Command Integration

When `autoCommands` are configured, these commands automatically load secrets:

```bash
terraform plan    # Automatically loads /infrastructure/ and /shared/ secrets
kubectl get pods  # Automatically loads /kubernetes/ and /shared/ secrets
aws s3 ls         # Automatically loads /infrastructure/ and /shared/ secrets
```

## Security Features

### Multi-Layer Security Model

1. **Secret Manager RBAC**: Your existing permissions control access
2. **Branch-Environment Mapping**: Automatic environment selection
3. **Container Isolation**: Secrets cached in secure tmpfs (RAM-only)
4. **File Permissions**: Strict 700/600 permissions, owner-only access
5. **Atomic Operations**: Race condition protection during cache updates

### Cache Security

- **Memory-only storage**: `/dev/shm` tmpfs - never touches disk
- **Per-user isolation**: User ID in cache path prevents cross-user access
- **Environment separation**: Different environments can't contaminate each other
- **Permission verification**: Continuous monitoring for tampering attempts
- **Automatic cleanup**: Cache vanishes on container stop/crash

### Path-Based Access Control

```json
{
  "secretPaths": {
    "terraform": ["/infrastructure/", "shared/database/"],
    "frontend": ["/frontend/", "shared/api/"],
    "backend": ["/backend/", "shared/"]
  }
}
```

Commands only get secrets they need, following the principle of least privilege.

## Offline Support

The feature gracefully handles network failures:

```json
{
  "offlineMode": {
    "allowStaleCache": true,
    "maxStaleAge": "2h",
    "gracefulFailure": true,
    "retryInterval": "5m"
  }
}
```

- Uses stale cache when secret manager is unreachable
- Never blocks shell startup
- Clear error messages with recovery instructions

## Advanced Configuration

### Cache Management

```json
{
  "cache": {
    "refreshInterval": "15m",
    "strategy": "time_based",
    "backgroundRefresh": false,
    "cleanupInterval": "1h"
  }
}
```

### Multiple Environments Example

```json
{
  "features": {
    "ghcr.io/your-org/devcontainer-features/auto-secrets:1": {
      "secretManager": "vault",
      "branchMapping": {
        "main": "production",
        "release/*": "staging",
        "hotfix/*": "production",
        "feature/*": "development",
        "default": "development"
      },
      "secretPaths": {
        "terraform": ["/secret/infrastructure/", "/secret/shared/"],
        "kubectl": ["/secret/kubernetes/"],
        "npm": ["/secret/frontend/", "/secret/shared/database/"]
      },
      "secretManagerConfig": {
        "address": "${VAULT_ADDR}",
        "mount": "secret",
        "kvVersion": "2"
      }
    }
  }
}
```

## Troubleshooting

### Debug Information

```bash
debug_env
```

Shows:

- Current branch and environment mapping
- Cache status and age
- Secret manager connection status
- Configuration summary

### Common Issues

**Authentication Failed**

```bash
# For Infisical
infisical login

# For Vault
vault auth -method=userpass username=myuser
# or
export VAULT_TOKEN=your-token

# Then refresh
refresh_secrets
```

**No Secrets Found**

```bash
# Check if you're in the right environment
debug_env

# Verify secret manager configuration
inspect_secrets

# Test connection
test_secret_manager_connection
```

**Cache Issues**

```bash
# Clear current cache
cleanup_cache

# Force refresh
refresh_secrets
```

**Permission Errors**

- Ensure `/dev/shm` is available and writable
- Check that cache directories have correct ownership
- Verify no other processes are interfering with cache

### Verbose Logging

```bash
export DEV_ENV_MANAGER_DEBUG=true
refresh_secrets
```

## Performance

- **Shell startup**: Instant (no secret loading on startup)
- **First secret fetch**: ~3 seconds (acceptable for dev workflow)
- **Subsequent shells**: Instant (shared cache)
- **Branch changes**: 3 seconds only when changing environments
- **Infrastructure commands**: Instant after first load

## Security Best Practices

1. **Use branch-based environments**: Don't put production secrets in development branches
2. **Enable path filtering**: Limit secret access by command/tool
3. **Regular cleanup**: Old caches are automatically cleaned up
4. **Monitor access**: Use `debug_env` to verify current environment
5. **Rotate tokens**: Follow your secret manager's rotation policies

## Contributing

The Auto Secrets Manager is modular and extensible:

- `core/`: Branch detection, environment mapping, caching, permissions
- `secret-managers/`: Plugin-style secret manager integrations
- `shells/`: Shell-specific integration (bash, zsh)
- `utils/`: Logging, validation, cleanup utilities

To add a new secret manager:

1. Create `secret-managers/your-manager.sh`
2. Implement required functions: `fetch_*_secrets`, `test_*_connection`, `handle_*_auth_failure`
3. Update `manager-interface.sh` to include your manager

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

- **Issues**: Report bugs and feature requests
- **Discussions**: Ask questions and share use cases
- **Security**: Report security issues privately

The Auto Secrets Manager is designed to be enterprise-ready while remaining simple to use. It respects existing security policies and integrates seamlessly with your development workflow.
