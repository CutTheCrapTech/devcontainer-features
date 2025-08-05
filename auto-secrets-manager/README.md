# Auto Secrets Manager - DevContainer Feature

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Tests](https://github.com/your-org/devcontainer-features/actions/workflows/test.yml/badge.svg)](https://github.com/your-org/devcontainer-features/actions/workflows/test.yml)

A DevContainer feature that automatically manages environment secrets based on git branches. Provides seamless integration with secret managers like Infisical, with atomic caching and shell integration for bash and zsh.

## 🎯 Overview

The Auto Secrets Manager eliminates the need to manually manage environment variables by:

- **🔄 Automatic Detection**: Detects git branch changes and maps them to environments
- **🏎️ Fast Performance**: Uses atomic file operations and intelligent caching (~2-5ms overhead)
- **🛡️ Security First**: No hardcoded defaults, atomic operations prevent race conditions
- **🐚 Shell Integration**: Works seamlessly with bash and zsh
- **🔧 Zero Configuration**: Works out of the box once configured
- **📦 Plugin Architecture**: Extensible secret manager support

## 🚀 Quick Start

### 1. Add to DevContainer Configuration

```json
{
  "features": {
    "ghcr.io/your-org/devcontainer-features/auto-secrets-manager:latest": {
      "secretManager": "infisical",
      "shells": "both",
      "branchMapping": {
        "main": "production",
        "develop": "staging",
        "default": "development"
      },
      "secretManagerConfig": {
        "project_id": "your-project-id",
        "client_id": "your-client-id",
        "client_secret": "your-client-secret"
      }
    }
  }
}
```

### 2. Set Environment Variables

```bash
# In your CI/CD or local environment
export INFISICAL_CLIENT_ID="your-client-id"
export INFISICAL_CLIENT_SECRET="your-client-secret"
export INFISICAL_PROJECT_ID="your-project-id"
```

### 3. Use in Your Project

```bash
# Secrets are automatically available based on your current branch
terraform plan  # Automatically loads production secrets if on main branch
kubectl get pods  # Uses staging secrets if on develop branch

# Manual commands
auto-secrets refresh  # Force refresh secrets cache
auto-secrets inspect  # View cached secrets (redacted)
auto-secrets debug    # Comprehensive troubleshooting
```

## 📋 Configuration Options

### Required Configuration

| Option                | Type   | Description                    | Example                                 |
| --------------------- | ------ | ------------------------------ | --------------------------------------- |
| `secretManager`       | string | Secret manager type            | `"infisical"`                           |
| `shells`              | string | Shell integration              | `"bash"`, `"zsh"`, `"both"`             |
| `branchMapping`       | object | Branch to environment mappings | See [Branch Mapping](#branch-mapping)   |
| `secretManagerConfig` | object | Secret manager configuration   | See [Secret Managers](#secret-managers) |

### Optional Configuration

| Option            | Type    | Default   | Description                      |
| ----------------- | ------- | --------- | -------------------------------- |
| `autoCommands`    | object  | `{}`      | Commands that auto-load secrets  |
| `cacheConfig`     | object  | See below | Cache behavior settings          |
| `showEnvInPrompt` | boolean | `false`   | Show environment in shell prompt |
| `markHistory`     | boolean | `false`   | Mark secret commands in history  |
| `debug`           | boolean | `false`   | Enable debug logging             |

### Default Cache Configuration

```json
{
  "max_age_seconds": 900,
  "background_refresh": true,
  "cleanup_on_exit": false
}
```

## 🌳 Branch Mapping

Branch mappings use pattern matching to determine environments:

```json
{
  "branchMapping": {
    "main": "production",
    "master": "production",
    "staging": "staging",
    "develop": "development",
    "dev": "development",

    // Pattern matching
    "feature/*": "development", // feature/auth -> development
    "feature/**": "development", // feature/ui/components -> development
    "release/*": "staging", // release/v1.0 -> staging
    "hotfix/*": "production", // hotfix/security -> production

    // Default for unmapped branches (required)
    "default": "development"
  }
}
```

### Pattern Syntax

- `*` - Matches any characters except `/`
- `**` - Matches any characters including `/`
- `?` - Matches single character
- No wildcards - Exact match only

### Security Note

🔒 **No default branch mappings are provided for security reasons.** You must explicitly define all mappings.

## 🔐 Secret Managers

### Infisical

Currently supported secret manager with SDK-based integration.

#### Configuration

```json
{
  "secretManagerConfig": {
    "project_id": "your-infisical-project-id",
    "client_id": "your-infisical-client-id",
    "client_secret": "your-infisical-client-secret",
    "site_url": "https://app.infisical.com" // Optional
  }
}
```

#### Environment Variables

Set these in your CI/CD or local environment:

```bash
export INFISICAL_CLIENT_ID="your-client-id"
export INFISICAL_CLIENT_SECRET="your-client-secret"
export INFISICAL_PROJECT_ID="your-project-id"
```

#### Path Filtering

```json
{
  "autoCommands": {
    "terraform": ["/infrastructure/**"],
    "kubectl": ["/kubernetes/**"],
    "docker": ["/docker/**"]
  }
}
```

### Future Secret Managers

Planned support for:

- ✅ Infisical (implemented)
- 🔄 HashiCorp Vault (planned)
- 🔄 AWS Secrets Manager (planned)
- 🔄 Azure Key Vault (planned)
- 🔄 Google Secret Manager (planned)

## 🛠️ Available Commands

### User Commands

```bash
# Secret management
auto-secrets refresh                 # Refresh secrets cache
auto-secrets inspect                 # View cached secrets (redacted)
auto-secrets inspect --show-values   # View actual values (insecure)
auto-secrets inspect --format json   # JSON output

# Debugging and info
auto-secrets debug        # Comprehensive environment debug
auto-secrets current-env  # Show current environment state
auto-secrets --help       # Full CLI help

# Cleanup
auto-secrets cleanup         # Clean stale cache files
auto-secrets cleanup --all   # Clean all cache files
```

### Auto Commands

When configured, these commands automatically load secrets:

```bash
# These automatically get environment secrets
terraform plan
kubectl get pods
docker build .
ansible-playbook site.yml
```

### Shell Integration

```bash
# Check shell integration health
auto-secrets-bash-health     # Bash integration status
auto-secrets-zsh-health      # Zsh integration status (if zsh available)

# Manual environment loading
eval "$(auto-secrets output-env)"                    # Load all secrets
eval "$(auto-secrets output-env --paths /infra/**)" # Load specific paths
```

## 🏗️ Architecture

### High-Level Overview

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Shell Hook    │───▶│   Python CLI     │───▶│ Secret Manager  │
│ (branch detect) │    │  (auto-secrets)  │    │   (Infisical)   │
└─────────────────┘    └──────────────────┘    └─────────────────┘
         │                       │                       │
         │                       ▼                       │
         │              ┌──────────────────┐              │
         └─────────────▶│   Cache Layer    │◀─────────────┘
                        │ (atomic files)   │
                        └──────────────────┘
```

### Component Responsibilities

#### Shell Integration (~30 lines each)

- ✅ Branch change detection via `precmd`/`PROMPT_COMMAND`
- ✅ Optional prompt enhancement
- ✅ Optional history marking
- ✅ Minimal error handling

#### Python Backend

- ✅ All secret manager integrations
- ✅ Branch → environment mapping
- ✅ Atomic cache operations
- ✅ Configuration management
- ✅ Comprehensive logging

#### Cache Layer

- ✅ Atomic file operations (no locking needed)
- ✅ Environment-specific caching
- ✅ Staleness detection
- ✅ Race condition prevention

### File Locations

```
/dev/shm/auto-secrets-$USER/           # Runtime cache (RAM)
├── environments/
│   ├── production.json                # Full cache with metadata
│   ├── production.env                 # Shell-friendly format
│   ├── staging.json
│   └── staging.env
└── state/
    └── current.json                   # Current environment state

/var/log/auto-secrets/                 # Logs
└── auto-secrets.log                   # Main log file

/usr/local/share/auto-secrets/         # Installation
├── branch-detection.sh                # Core branch detection
├── bash-integration.sh                # Bash integration
└── zsh-integration.sh                 # Zsh integration
```

## 🐞 Troubleshooting

### Common Issues

#### "No environment detected"

```bash
# Check current state
debug-env

# Verify git repository
git status

# Check branch mappings
auto-secrets current-env --json
```

#### "No cached secrets found"

```bash
# Refresh secrets manually
auto-secrets refresh

# Check secret manager connection
auto-secrets debug

# Verify environment variables
env | grep INFISICAL
```

#### "Command not found: auto-secrets"

```bash
# Check installation
which auto-secrets

# Reload shell
source ~/.bashrc  # or ~/.zshrc

# Check PATH
echo $PATH | grep -o '/usr/local/bin'
```

### Debug Mode

Enable comprehensive debugging:

```bash
# Temporary
export AUTO_SECRETS_DEBUG=true

# Check logs
tail -f /var/log/auto-secrets/auto-secrets.log

# Run debug command
debug-env
```

### Shell Integration Issues

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

### Cache Issues

```bash
# Clear cache
auto-secrets cleanup --all

# Check cache status
auto-secrets inspect

# Verify cache directory permissions
ls -la /dev/shm/auto-secrets-$USER/
```

## 🧪 Development

### Prerequisites

```bash
# System dependencies
sudo apt-get install python3 python3-pip git jq curl

# Python dependencies
pip3 install -r src/requirements.txt
pip3 install -e src/
```

### Running Tests

```bash
# Run all tests
./run_tests.sh

# Run only unit tests
./run_tests.sh --unit-only

# Run with coverage
./run_tests.sh --verbose

# CI mode
./run_tests.sh --ci
```

### Project Structure

```
auto-secrets-manager/
├── devcontainer-feature/              # DevContainer feature
│   ├── devcontainer-feature.json     # Feature definition
│   └── install.sh                    # Installation script
├── src/                              # Python source
│   ├── auto_secrets/                 # Main package
│   │   ├── cli.py                   # CLI interface
│   │   ├── core/                    # Core modules
│   │   │   ├── config.py           # Configuration
│   │   │   ├── environment.py      # Environment state
│   │   │   ├── branch_manager.py   # Branch mapping
│   │   │   └── cache_manager.py    # Cache operations
│   │   └── secret_managers/         # Secret manager plugins
│   │       ├── base.py             # Abstract base
│   │       └── infisical.py        # Infisical implementation
│   ├── shell/                       # Shell integration
│   │   ├── auto-commands.sh        # Auto commands logic
│   │   ├── branch-detection.sh     # Core branch detection logic
│   │   ├── bash-integration.sh     # Bash integration
│   │   └── zsh-integration.sh      # Zsh integration
│   └── requirements.txt             # Python dependencies
├── tests/                           # Test suite
│   ├── test_config.py              # Configuration tests
│   ├── test_branch_manager.py      # Branch manager tests
│   └── test_environment.py         # Environment tests
├── run_tests.sh                    # Test runner
└── README.md                       # This file
```

### Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/amazing-feature`
3. Make your changes
4. Run tests: `./run_tests.sh`
5. Commit your changes: `git commit -m 'Add amazing feature'`
6. Push to the branch: `git push origin feature/amazing-feature`
7. Open a Pull Request

### Code Quality

```bash
# Format code
black src/
isort src/

# Lint code
flake8 src/
shellcheck src/shell/*.sh

# Type checking
mypy src/auto_secrets/
```

## 🔒 Security

### Security Model

- ✅ **No default branch mappings** - explicit configuration required
- ✅ **Atomic file operations** - prevents race conditions
- ✅ **Restrictive permissions** - cache files are `0o600` (user only)
- ✅ **Memory-based cache** - uses `/dev/shm` for sensitive data
- ✅ **Input validation** - validates all configuration inputs
- ✅ **Logging controls** - sensitive values are redacted from logs

### Best Practices

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

### Reporting Security Issues

Please report security vulnerabilities privately to [security@your-org.com](mailto:security@your-org.com).

## 📊 Performance

### Benchmarks

- **Branch detection**: ~2-5ms (cached)
- **Secret loading**: ~10-50ms (from cache)
- **Initial fetch**: ~100-500ms (from Infisical)
- **Memory usage**: ~5-15MB (Python process)
- **Cache size**: ~1-10KB per environment

### Optimization Tips

1. **Use path filtering**:

   ```json
   {
     "autoCommands": {
       "terraform": ["/infrastructure/**"] // Only load relevant secrets
     }
   }
   ```

2. **Adjust cache settings**:

   ```json
   {
     "cacheConfig": {
       "max_age_seconds": 1800, // 30 minutes for less frequent fetches
       "background_refresh": true,
       "cleanup_on_exit": true // Clean up branch cache on shell exit
     }
   }
   ```

3. **Monitor cache efficiency**:
   ```bash
   auto-secrets inspect  # Check cache age and hit rates
   ```

## 🛣️ Roadmap

### v1.0 (Current)

- ✅ Infisical integration
- ✅ Branch-based environment mapping
- ✅ Bash/Zsh shell integration
- ✅ Atomic caching
- ✅ Comprehensive testing

### v1.1 (Next)

- 🔄 HashiCorp Vault support
- 🔄 AWS Secrets Manager support
- 🔄 Background daemon mode
- 🔄 Metrics and monitoring

### v1.2 (Future)

- 🔄 Azure Key Vault support
- 🔄 Google Secret Manager support
- 🔄 Web UI for configuration
- 🔄 Team management features

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [DevContainers](https://containers.dev/) for the amazing developer experience
- [Infisical](https://infisical.com/) for secure secret management
- The open-source community for tools and inspiration

## 📞 Support

- 📖 [Documentation](https://github.com/your-org/devcontainer-features/tree/main/auto-secrets-manager)
- 🐛 [Issue Tracker](https://github.com/your-org/devcontainer-features/issues)
- 💬 [Discussions](https://github.com/your-org/devcontainer-features/discussions)
- 📧 [Email Support](mailto:support@your-org.com)

---

Made with ❤️ for developers who value security and productivity.
