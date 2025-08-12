# 🏗️ Architecture

## High-Level Overview

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

## Component Responsibilities

### Shell Integration (~30 lines each)

- ✅ Branch change detection via `precmd`/`PROMPT_COMMAND`
- ✅ Optional prompt enhancement
- ✅ Optional history marking
- ✅ Minimal error handling

### Python Backend

- ✅ All secret manager integrations
- ✅ Branch → environment mapping
- ✅ Atomic cache operations
- ✅ Configuration management
- ✅ Comprehensive logging

### Cache Layer

- ✅ Atomic file operations (no locking needed)
- ✅ Environment-specific caching
- ✅ Staleness detection
- ✅ Race condition prevention

## File Locations

```
/dev/shm/auto-secrets-$USER/           # Runtime cache (RAM)
└── environments/
│   ├── production.json                # Full cache with metadata
│   ├── production.env                 # Shell-friendly format
│   ├── staging.json
│   └── staging.env

/var/log/auto-secrets/          # Logs
├── daemon.log                # Python daemon log file
├── shell.log                 # shell log file
└── cli.log                   # Python cli log file

/usr/local/share/auto-secrets/           # Installation
├── auto-commands.sh                   # Auto commands detection
├── branch-detection.sh                # Core branch detection
├── bash-integration.sh                # Bash integration
└── zsh-integration.sh                 # Zsh integration
```
