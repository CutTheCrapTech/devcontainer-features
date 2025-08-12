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

| Options Id                                                                | Description                                                                                                                           | Type    | Default Value                                      |
| ------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------- | ------- | -------------------------------------------------- |
| [secretManager](docs/configuration.md#secret-managers)                    | The secret manager backend to use (e.g., infisical).                                                                                  | string  | infisical                                          |
| [shells](docs/configuration.md#shell-integration)                         | Shells to configure for integration (bash, zsh, or both).                                                                             | string  | both                                               |
| [branchMapping](docs/configuration.md#branch-mapping)                     | Required. A single-quoted JSON string mapping git branches to your environments (e.g., {'main':'production', 'dev\*':'development'}). | string  | {}                                                 |
| [secretManagerConfig](docs/configuration.md#secret-manager-configuration) | A single-quoted JSON string for provider-specific settings, like host or project_id.                                                  | string  | {'host':'https://app.infisical.com'}               |
| [autoCommands](docs/configuration.md#auto-commands)                       | A single-quoted JSON string to automatically load secrets for specific commands within certain git paths.                             | string  | {}                                                 |
| [cacheConfig](docs/configuration.md#cache-configuration)                  | A single-quoted JSON string to configure cache refresh_interval and cleanup_interval.                                                 | string  | {'refresh_interval':'15m','cleanup_interval':'7d'} |
| [showEnvInPrompt](docs/configuration.md#show-environment-in-prompt)       | If true, displays the current secrets environment name in the shell prompt.                                                           | boolean | false                                              |
| [markHistory](docs/configuration.md#mark-history)                         | If true, marks commands that use secrets in your shell history for easy identification.                                               | boolean | false                                              |
| [debug](docs/configuration.md#debug-mode)                                 | If true, enables verbose logging for troubleshooting the feature's behavior.                                                          | boolean | false                                              |
| [branchDetection](docs/configuration.md#branch-detection)                 | If false, disables the automatic detection of git branch changes. Set to false, when git post checkout check is configured            | boolean | true                                               |

### A Note on Configuration Values

You may notice that options expecting complex data (branchMapping, secretManagerConfig, etc.) are passed as a single-quoted string. This is a deliberate design choice to work around the constraints of the devcontainer.json format and improve readability.

#### 1. What is a "single-quoted string"?

It means you should structure your configuration like a Python dictionary, using single quotes (') for all keys and string values, instead of the standard double quotes (") used in JSON.

**Example:** `{'host':'app.infisical.com', 'retries':3}`

This avoids the need for cumbersome escaping within your devcontainer.json file.

#### 2. Why is this necessary?

The devcontainer.json specification for features currently only supports primitive types for options, primarily strings and booleans. There isn't a native way to define a nested JSON object directly.

This limitation presents a challenge for advanced features like this one that require structured configuration. To overcome this, we've adopted a pragmatic approach: we pass the structured data as a single, easy-to-read string and parse it inside the feature's installation script. It's an outside-the-box solution for a more complex need.

#### 3. A Known Limitation

This simplified parsing approach has one main trade-off: it does not support single quotes (') within the configuration values themselves (e.g., in a password or token).

If a value in your secret manager configuration contains a single quote, the current parsing logic will fail. While we plan to address this in the future, for now, please ensure your configuration values are free of single quotes.

## 🎯 Overview

Managing secrets and environment variables across different branches (development, staging, production) is tedious and error-prone. Manually switching .env files or exporting variables is a common source of mistakes. The Auto Secrets Manager eliminates this problem by:

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
