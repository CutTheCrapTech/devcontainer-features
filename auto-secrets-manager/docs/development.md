# 🧪 Development

## Prerequisites

```bash
# System dependencies
sudo apt-get install python3 python3-pip git jq curl

# Python dependencies
pip3 install -r src/requirements.txt
pip3 install -e src/
```

## Running Tests

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

## Project Structure

```
auto-secrets-manager/
├── src/                              # Python source
│   ├── auto_secrets/                 # Main package
│   │   ├── cli.py                   # CLI interface
│   │   ├── core/                    # Core modules
│   │   │   ├── config.py           # Configuration
│   │   │   ├── branch_manager.py   # Branch mapping
│   │   │   ├── cache_manager.py    # Cache operations
│   │   │   └── utils.py            # Core Utils
│   │   └── secret_managers/         # Secret manager plugins
│   │       ├── base.py             # Abstract base
│   │       └── infisical.py        # Infisical implementation
│   ├── shell/                       # Shell integration
│   │   ├── auto-commands.sh        # Auto commands logic
│   │   ├── branch-detection.sh     # Core branch detection logic
│   │   ├── bash-integration.sh     # Bash integration
│   │   └── zsh-integration.sh      # Zsh integration
│   ├── setup.py                     # Python setup script
│   └── requirements.txt             # Python dependencies
├── tests/                           # Test suite
│   └── *                           # Tests for various components
├── devcontainer-feature.json        # Feature definition
├── install.sh                       # Installation script
├── pytest.ini                       # Pytest configuration
├── run_tests.sh                     # Test runner
└── README.md                        # This file
```

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/amazing-feature`
3. Make your changes
4. Run tests: `./run_tests.sh`
5. Commit your changes: `git commit -m 'Add amazing feature'`
6. Push to the branch: `git push origin feature/amazing-feature`
7. Open a Pull Request

## Code Quality

```bash
./run_tests.sh
```
