# Auto Secrets Manager

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A DevContainer feature that automatically manages environment secrets based on git branches. Provides seamless integration with secret managers like Infisical, with atomic caching and shell integration for bash and zsh.

## Example Usage

```json
"features": {
    "ghcr.io/CutTheCrapTech/devcontainer-features/auto-secrets-manager:1": {}
}
```

## Options

| Options Id          | Description                 | Type    | Default Value                                              |
| ------------------- | --------------------------- | ------- | ---------------------------------------------------------- |
| secretManager       | Your secret manager.        | string  | infisical                                                  |
| shells              | Your shells in devContainer | string  | both                                                       |
| branchMapping       | Your shells in devContainer | string  | {}                                                         |
| secretManagerConfig | Your shells in devContainer | string  | {\"host\":\"https://app.infisical.com\"}                   |
| autoCommands        | Your shells in devContainer | string  | {}                                                         |
| cacheConfig         | Your shells in devContainer | string  | {\"refresh_interval\":\"15m\",\"cleanup_interval\":\"7d\"} |
| showEnvInPrompt     | Your shells in devContainer | boolean | false                                                      |
| markHistory         | Your shells in devContainer | boolean | false                                                      |
| debug               | Your shells in devContainer | boolean | false                                                      |
| branchDetection     | Your shells in devContainer | boolean | true                                                       |

## 🎯 Overview

The Auto Secrets Manager eliminates the need to manually manage environment variables by:

- **🔄 Automatic Detection**: Detects git branch changes and maps them to environments
- **🏎️ Fast Performance**: Uses atomic file operations and intelligent caching (~2-5ms overhead)
- **🛡️ Security First**: No hardcoded defaults, atomic operations prevent race conditions
- **🐚 Shell Integration**: Works seamlessly with bash and zsh
- **🔧 Zero Configuration**: Works out of the box once configured
- **📦 Plugin Architecture**: Extensible secret manager support

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

## 🏗️ [Architecture](docs/architecture.md)

## 🐞 [Troubleshooting](docs/troubleshooting.md)

## 🧪 [Development](docs/development.md)

## 🔒 [Security](docs/security.md)

## 📊 [Performance](docs/performance.md)

## 🛣️ [Roadmap](docs/roadmap.md)

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](../LICENSE) file for details.

## 🙏 Acknowledgments

- [DevContainers](https://containers.dev/) for the amazing developer experience
- [Infisical](https://infisical.com/) for secure secret management
- The open-source community for tools and inspiration

---

Made with ❤️ for developers who value security and productivity.

```

```
