"""
Auto Secrets Manager - Configuration Management

Centralized configuration loading from environment variables.
Uses proper UPPER_SNAKE_CASE naming convention with AUTO_SECRETS_ prefix.
"""

import json
import os
from pathlib import Path
from typing import Dict, Optional, Any, Union

from ..logging_config import get_logger


class ConfigError(Exception):
    """Configuration-related errors."""
    pass


def load_config() -> Dict[str, Any]:
    """
    Load configuration from environment variables.

    Returns a dictionary with configuration values, using sensible defaults
    where appropriate and validating required settings.

    Returns:
        Dict[str, Any]: Configuration dictionary

    Raises:
        ConfigError: If required configuration is missing or invalid
    """
    logger = get_logger("config")
    config: Dict[str, Any] = {}

    # === Core Settings ===

    # Secret manager type (required)
    secret_manager = os.getenv("AUTO_SECRETS_SECRET_MANAGER")
    if not secret_manager:
        raise ConfigError(
            "AUTO_SECRETS_SECRET_MANAGER environment variable is required. "
            "Valid values: infisical, vault, aws, azure, gcp"
        )
    config["secret_manager"] = secret_manager

    # Shell integration (required)
    shells = os.getenv("AUTO_SECRETS_SHELLS")
    if not shells:
        raise ConfigError(
            "AUTO_SECRETS_SHELLS environment variable is required. "
            "Valid values: bash, zsh, both"
        )
    config["shells"] = shells

    # Debug mode
    config["debug"] = os.getenv("AUTO_SECRETS_DEBUG", "false").lower() == "true"

    # === Branch Mapping (Security Critical - No Defaults) ===

    branch_mapping_json = os.getenv("AUTO_SECRETS_BRANCH_MAPPINGS")
    if not branch_mapping_json:
        raise ConfigError(
            "AUTO_SECRETS_BRANCH_MAPPINGS environment variable is required. "
            "No default branch mappings are provided for security reasons. "
            "Example: '{\"main\": \"production\", \"develop\": \"staging\", \"default\": \"development\"}'"
        )

    try:
        branch_mappings = json.loads(branch_mapping_json)
        if not isinstance(branch_mappings, dict):
            raise ConfigError("Branch mappings must be a JSON object")

        # Validate that default mapping exists
        if "default" not in branch_mappings:
            raise ConfigError(
                "Branch mappings must include a 'default' entry for unmapped branches"
            )

        config["branch_mappings"] = branch_mappings
        logger.info(f"Loaded branch mappings for {len(branch_mappings)} entries")

    except json.JSONDecodeError as e:
        raise ConfigError(f"Invalid AUTO_SECRETS_BRANCH_MAPPINGS JSON: {e}")

    # === Secret Manager Configuration ===

    sm_config_json = os.getenv("AUTO_SECRETS_SECRET_MANAGER_CONFIG", "{}")
    try:
        secret_manager_config = json.loads(sm_config_json)
        config["secret_manager_config"] = secret_manager_config
    except json.JSONDecodeError as e:
        raise ConfigError(f"Invalid AUTO_SECRETS_SECRET_MANAGER_CONFIG JSON: {e}")

    # === Auto Commands Configuration ===

    auto_commands_json = os.getenv("AUTO_SECRETS_AUTO_COMMANDS", "{}")
    try:
        auto_commands = json.loads(auto_commands_json)
        if not isinstance(auto_commands, dict):
            raise ConfigError("Auto commands must be a JSON object")
        config["auto_commands"] = auto_commands
        logger.debug(f"Loaded auto commands for {len(auto_commands)} commands")
    except json.JSONDecodeError as e:
        raise ConfigError(f"Invalid AUTO_SECRETS_AUTO_COMMANDS JSON: {e}")

    # === Cache Configuration ===

    # Cache base directory
    cache_base_dir = os.getenv("AUTO_SECRETS_CACHE_DIR", "/dev/shm/auto-secrets")
    config["cache_base_dir"] = cache_base_dir

    # Cache settings
    cache_config_json = os.getenv("AUTO_SECRETS_CACHE_CONFIG", '{}')
    try:
        cache_config = json.loads(cache_config_json)
        # Apply defaults
        cache_config.setdefault("refresh_interval", "15m")  # 15 minutes
        cache_config.setdefault("cleanup_interval", "7d")  # 15 minutes
        cache_config.setdefault("background_refresh", True)
        cache_config.setdefault("cleanup_on_exit", False)
        config["cache_config"] = cache_config
    except json.JSONDecodeError as e:
        raise ConfigError(f"Invalid AUTO_SECRETS_CACHE_CONFIG JSON: {e}")

    # === Feature Settings ===

    # Show environment in prompt
    config["show_env_in_prompt"] = os.getenv("AUTO_SECRETS_SHOW_ENV_IN_PROMPT", "false").lower() == "true"

    # Mark secret commands in history
    config["mark_history"] = os.getenv("AUTO_SECRETS_MARK_HISTORY", "false").lower() == "true"

    # Enable feature
    config["enable"] = os.getenv("AUTO_SECRETS_ENABLE", "true").lower() == "true"

    # Cleanup on shell exit
    config["cleanup_on_exit"] = os.getenv("AUTO_SECRETS_CLEANUP_ON_EXIT", "false").lower() == "true"

    # Prefetch secrets on branch change
    config["prefetch_on_branch_change"] = os.getenv("AUTO_SECRETS_PREFETCH_ON_BRANCH_CHANGE", "false").lower() == "true"

    # Require secrets for exec command
    config["require_secrets_for_exec"] = os.getenv("AUTO_SECRETS_REQUIRE_SECRETS_FOR_EXEC", "false").lower() == "true"

    # === Paths and Directories ===

    config["feature_dir"] = os.getenv("AUTO_SECRETS_FEATURE_DIR", "/usr/local/share/auto-secrets")
    config["log_dir"] = os.getenv("AUTO_SECRETS_LOG_DIR", "/var/log/auto-secrets")
    config["log_level"] = os.getenv("AUTO_SECRETS_LOG_LEVEL", "INFO").upper()

    # === Validation ===

    _validate_config(config)

    logger.info("Configuration loaded successfully")
    logger.debug(f"Secret manager: {config['secret_manager']}")
    logger.debug(f"Shells: {config['shells']}")
    logger.debug(f"Debug mode: {config['debug']}")
    logger.debug(f"Cache directory: {config['cache_base_dir']}")

    return config


def _validate_config(config: Dict[str, Any]) -> None:
    """
    Validate the loaded configuration.

    Args:
        config: Configuration dictionary to validate

    Raises:
        ConfigError: If configuration is invalid
    """
    # Validate secret manager
    valid_secret_managers = ["infisical", "vault", "aws", "azure", "gcp"]
    if config["secret_manager"] not in valid_secret_managers:
        raise ConfigError(
            f"Invalid secret manager: {config['secret_manager']}. "
            f"Valid options: {', '.join(valid_secret_managers)}"
        )

    # Validate shells
    valid_shells = ["bash", "zsh", "both"]
    if config["shells"] not in valid_shells:
        raise ConfigError(
            f"Invalid shells configuration: {config['shells']}. "
            f"Valid options: {', '.join(valid_shells)}"
        )

    # Validate branch mappings
    branch_mappings = config["branch_mappings"]
    if not isinstance(branch_mappings, dict) or not branch_mappings:
        raise ConfigError("Branch mappings must be a non-empty dictionary")

    if "default" not in branch_mappings:
        raise ConfigError("Branch mappings must include a 'default' entry")

    # Validate cache configuration
    cache_config = config["cache_config"]
    if cache_config.get("max_age_seconds", 0) < 0:
        raise ConfigError("Cache max_age_seconds must be non-negative")


def get_cache_dir(config: Dict[str, Any], environment: Optional[str] = None) -> Path:
    """
    Get the cache directory path for the current user and optionally environment.

    Args:
        config: Configuration dictionary
        environment: Optional environment name for environment-specific cache

    Returns:
        Path: Cache directory path
    """
    base_path = Path(config["cache_base_dir"])

    if environment:
        return base_path / "environments" / environment
    else:
        return base_path


def get_state_dir(config: Dict[str, Any]) -> Path:
    """
    Get the state directory path for storing current environment state.

    Args:
        config: Configuration dictionary

    Returns:
        Path: State directory path
    """
    return get_cache_dir(config) / "state"


def get_log_file_path(config: Dict[str, Any], log_name: str = "auto-secrets.log") -> Path:
    """
    Get the log file path.

    Args:
        config: Configuration dictionary
        log_name: Log file name

    Returns:
        Path: Log file path
    """
    log_dir = Path(config["log_dir"])

    # Create log directory if it doesn't exist
    try:
        log_dir.mkdir(parents=True, exist_ok=True, mode=0o755)
    except PermissionError:
        # Fallback to user's cache directory
        log_dir = Path.home() / ".cache" / "auto-secrets" / "logs"
        log_dir.mkdir(parents=True, exist_ok=True, mode=0o755)

    return log_dir / log_name


def get_effective_config_path() -> Optional[Path]:
    """
    Get the path where configuration can be saved/loaded from file.

    Returns:
        Optional[Path]: Configuration file path if available
    """
    config_path = os.getenv("AUTO_SECRETS_CONFIG_PATH")
    if config_path:
        return Path(config_path)

    # Default locations to try
    locations = [
        Path.cwd() / ".auto-secrets.json",
        Path.home() / ".config" / "auto-secrets" / "config.json",
        Path("/etc/auto-secrets/config.json")
    ]

    for location in locations:
        if location.exists() and location.is_file():
            return location

    return None


def save_config_to_file(config: Dict[str, Any], file_path: Union[str, Path]) -> None:
    """
    Save configuration to a JSON file.

    Args:
        config: Configuration dictionary to save
        file_path: Path to save the configuration

    Raises:
        ConfigError: If file cannot be written
    """
    try:
        file_path = Path(file_path)
        file_path.parent.mkdir(parents=True, exist_ok=True)

        # Remove sensitive information before saving
        safe_config = config.copy()

        # Redact sensitive keys in secret_manager_config
        if "secret_manager_config" in safe_config:
            sm_config = safe_config["secret_manager_config"].copy()
            for key in sm_config:
                if any(sensitive in key.lower() for sensitive in ["token", "secret", "key", "password"]):
                    sm_config[key] = "***REDACTED***"
            safe_config["secret_manager_config"] = sm_config

        with open(file_path, 'w') as f:
            json.dump(safe_config, f, indent=2, sort_keys=True)

    except (OSError, IOError) as e:
        raise ConfigError(f"Failed to save config to {file_path}: {e}")


def load_config_from_file(file_path: Union[str, Path]) -> Dict[str, Any]:
    """
    Load configuration from a JSON file and merge with environment variables.

    Args:
        file_path: Path to load the configuration from

    Returns:
        Dict[str, Any]: Loaded configuration

    Raises:
        ConfigError: If file cannot be loaded or is invalid
    """
    try:
        with open(file_path, 'r') as f:
            file_config = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        raise ConfigError(f"Failed to load config from {file_path}: {e}")

    # Load environment config first (takes precedence)
    env_config = load_config()

    # Merge file config with environment config (env takes precedence)
    merged_config = file_config.copy()
    merged_config.update(env_config)

    # Re-validate merged config
    _validate_config(merged_config)

    return merged_config


def create_minimal_config_template() -> Dict[str, Any]:
    """
    Create a minimal configuration template for documentation/setup purposes.

    Returns:
        Dict[str, Any]: Template configuration
    """
    return {
        "secret_manager": "infisical",
        "shells": "both",
        "debug": False,
        "branch_mappings": {
            "main": "production",
            "develop": "staging",
            "feature/*": "development",
            "default": "development"
        },
        "secret_manager_config": {
            "# Infisical configuration": "See documentation for setup",
            "client_id": "your-client-id",
            "client_secret": "your-client-secret",
            "project_id": "your-project-id"
        },
        "auto_commands": {
            "terraform": ["/infrastructure/**"],
            "tofu": ["/infrastructure/**"],
            "kubectl": ["/kubernetes/**"],
            "docker": ["/docker/**"]
        },
        "cache_config": {
            "max_age_seconds": 900,
            "background_refresh": True,
            "cleanup_on_exit": False
        },
        "show_env_in_prompt": True,
        "mark_history": True,
        "prefetch_on_branch_change": False
    }
