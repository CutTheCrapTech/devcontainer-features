# 🔒 Security

## Security Model

- ✅ **No default branch mappings** - explicit configuration required
- ✅ **Atomic file operations** - prevents race conditions
- ✅ **Restrictive permissions** - cache files are `0o600` (user only)
- ✅ **Memory-based cache** - uses `/dev/shm` for sensitive data
- ✅ **Input validation** - validates all configuration inputs
- ✅ **Logging controls** - sensitive values are redacted from logs

## Best Practices

1. **Store credentials securely**:

   ```bash
   # ❌ Don't hardcode in devcontainer.json
   "INFISICAL_CLIENT_SECRET": "hardcoded-secret"

   # ✅ Use environment variable references
   "INFISICAL_CLIENT_SECRET": "${localEnv:INFISICAL_CLIENT_SECRET}"
   ```

2. **Use least privilege**:

   ```json
   {
     "autoCommands": {
       "terraform": ["/infrastructure/**"], // ✅ Specific paths
       "kubectl": ["/**"] // ❌ Too broad
     }
   }
   ```

3. **Regular secret rotation**:

   ```bash
   # Refresh after credential changes
   auto-secrets refresh
   ```

4. **Monitor access**:

   ```bash
   # Check cache access
   auto-secrets inspect

   # Review logs
   tail /var/log/auto-secrets/auto-secrets.log
   ```

## Reporting Security Issues

Please report security vulnerabilities privately to [security@your-org.com](mailto:security@your-org.com).
