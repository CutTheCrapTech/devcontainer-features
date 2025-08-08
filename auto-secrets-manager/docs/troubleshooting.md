# 🐞 Troubleshooting

## Common Issues

### "No environment detected"

```bash
# Check current state
debug-env

# Verify git repository
git status

# Check branch mappings
auto-secrets current-env --json
```

### "No cached secrets found"

```bash
# Refresh secrets manually
auto-secrets refresh

# Check secret manager connection
auto-secrets debug

# Verify environment variables
env | grep INFISICAL
```

### "Command not found: auto-secrets"

```bash
# Check installation
which auto-secrets

# Reload shell
source ~/.bashrc  # or ~/.zshrc

# Check PATH
echo $PATH | grep -o '/usr/local/bin'
```

## Debug Mode

Enable comprehensive debugging:

```bash
# Temporary
export AUTO_SECRETS_DEBUG=true

# Check logs
tail -f /var/log/auto-secrets/auto-secrets.log

# Run debug command
debug-env
```

## Shell Integration Issues

```bash
# Check shell integration health
auto-secrets-bash-health   # For bash
auto-secrets-zsh-health    # For zsh

# Verify environment variables
env | grep AUTO_SECRETS

# Test branch detection manually
source /usr/local/share/auto-secrets/branch-detection.sh
_auto_secrets_check_branch_change
```

## Cache Issues

```bash
# Clear cache
auto-secrets cleanup --all

# Check cache status
auto-secrets inspect

# Verify cache directory permissions
ls -la /dev/shm/auto-secrets-$USER/
```
