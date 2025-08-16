# Secret Managers Guide

This document provides detailed setup and configuration instructions for all supported secret management services.

## Table of Contents

- [Configuration](#configuration)
- [Credential Management](#credential-management)
- [Infisical](#infisical)
- [Troubleshooting](#troubleshooting)

## Configuration

### General Configuration Pattern

All secret managers follow a consistent configuration pattern:

```json
{
  "secretManager": "service-name",
  "secretManagerConfig": "{'option1':'value1','option2':'value2'}"
}
```

## Credential Management

### How Secrets Are Read

The Auto Secrets Manager distinguishes between **secrets** (sensitive) and **configuration** (non-sensitive):

**Secrets (sensitive - never commit):**

- `INFISICAL_CLIENT_SECRET` - The only actual secret credential

**Note:** The bash/zsh integration scripts will automatically prompt you for setting the secrets if not present at startup.

**Configuration (non-sensitive - can be committed):**

- `client_id` - Service token identifier
- `project_id` - Project identifier
- `host` - Service URL
- All other configuration options

**Note:** Similar for others secret managers.

## Infisical

[Infisical](https://infisical.com/) is an open-source secret management platform with both cloud and self-hosted options. Currently the only supported secret manager with full SDK integration.

### Required Configuration

1. **Set secret manager type:**

   ```json
   {
     "secretManager": "infisical"
   }
   ```

2. **Configure non-sensitive options** (can be committed):

   ```json
   {
     "secretManagerConfig": "{'host':'https://app.infisical.com','project_id':'your-project-id','client_id':'your-client-id'}"
   }
   ```

3. **[Provide secret credential at startup](#credential-management)** (never commit)

### Configuration Options

Configure Infisical-specific settings in `secretManagerConfig`:

| Option       | Description                  | Required | Example                     |
| ------------ | ---------------------------- | -------- | --------------------------- |
| `host`       | Infisical instance URL       | ✅       | `https://app.infisical.com` |
| `project_id` | Infisical project identifier | ✅       | `64a1b2c3d4e5f6789...`      |
| `client_id`  | Service token client ID      | ✅       | `st_prod_abc123...`         |

### Self-Hosted Infisical

For self-hosted Infisical instances:

```json
{
  "secretManagerConfig": "{'host':'https://infisical.yourcompany.com','project_id':'your-project-id','client_id':'your-client-id'}"
}
```

### Troubleshooting Infisical

#### Common Issues

**"Authentication failed"**

```bash
# Check secret credential
env | grep INFISICAL_CLIENT_SECRET

# Test API connection
curl -H "Authorization: Bearer $INFISICAL_CLIENT_SECRET" \
     "https://app.infisical.com/api/v1/auth/service-token"

# Verify project access
auto-secrets debug | grep -A10 "Infisical"
```

**"Project not found"**

```bash
# Check project ID in secretManagerConfig
auto-secrets debug | grep -A5 "secretManagerConfig"

# Verify project exists and service token has access
# Check Infisical dashboard → Project Settings → Service Tokens
```

**"Environment not found"**

```bash
# Check environment exists in Infisical for your project
auto-secrets current-env

# Verify branch mapping configuration
auto-secrets debug | grep -A5 "Branch mapping"

# List available environments in Infisical dashboard
```

## Troubleshooting

### General Debugging

```bash
# Check current configuration
auto-secrets debug

# Test secret manager connection
auto-secrets refresh --verbose

# View configuration sources
auto-secrets debug | grep -A20 "Configuration"
```

### Common Error Patterns

#### Authentication Errors

**Symptoms:**

- "Authentication failed"
- "Invalid credentials"
- "Access denied"

**Solutions:**

```bash
# Check credential environment variables
env | grep -E "(INFISICAL|VAULT|AWS|AZURE|GOOGLE)"

# Test credentials manually
# (service-specific commands)

# Verify configuration file permissions
ls -la ~/.config/auto-secrets/config.json
```

#### Network Connectivity

**Symptoms:**

- "Connection timeout"
- "DNS resolution failed"
- "SSL certificate error"

**Solutions:**

```bash
# Test network connectivity
curl -I https://app.infisical.com

# Check DNS resolution
nslookup app.infisical.com

# Verify SSL certificates
openssl s_client -connect app.infisical.com:443
```

#### Permission Issues

**Symptoms:**

- "Project not found"
- "Environment not accessible"
- "Insufficient permissions"

**Solutions:**

```bash
# Check service permissions in secret manager dashboard
# Verify project/environment access
# Review audit logs
```

### Performance Issues

#### Slow Secret Loading

```bash
# Check cache status
auto-secrets inspect

# Monitor API response times
auto-secrets debug | grep -E "(timing|duration)"

# Optimize cache settings
# Consider path filtering
```

#### High Memory Usage

```bash
# Check cache size
du -sh /dev/shm/auto-secrets/

# Clean old cache
auto-secrets cleanup

# Reduce cache intervals
```

### Getting Help

For secret manager-specific issues:

1. **Check service status pages**
2. **Review service documentation**
3. **Enable debug logging**: `"debug": true`
4. **Check service audit logs**
5. **Test with service CLI tools**
6. **Open GitHub issue** with debug output

---

For configuration help, see [Configuration Guide](configuration.md) or the main [README](../README.md).
