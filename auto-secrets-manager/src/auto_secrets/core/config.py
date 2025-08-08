"""
Auto Secrets Manager - Configuration Management

Centralized configuration loading from environment variables.
Uses proper UPPER_SNAKE_CASE naming convention with AUTO_SECRETS_ prefix.
"""

import json
import os
import re
from pathlib import Path
from typing import Dict, Optional, Any

from ..logging_config import get_logger
from .utils import CommonUtils


class ConfigError(Exception):
    """Configuration-related errors."""

    pass


class ConfigManager:
    """
    Configuration manager for Auto Secrets Manager.

    Handles loading, validation, and management of configuration from
    environment variables and files.
    """

    _VALID_SECRET_MANAGERS = ["infisical", "vault", "aws", "azure", "gcp"]
    _VALID_SHELLS = ["bash", "zsh", "both"]

    @classmethod
    def _parse_env(cls, env_variable: str, default: Optional[str] = None) -> str:
        """
        Parse environment variables for configuration.

        Args:
            env_variable: Environment variable name to parse

        Raises:
            ConfigError: If configuration is invalid

        Returns:
            Any: Parsed configuration value
        """
        val = os.getenv(env_variable, "").strip()
        if default is None and not val:
            raise ConfigError(f"{env_variable} environment variable is required. ")
        elif default is not None and not val:
            val = default
        return val

    @classmethod
    def _parse_json(
        cls, env_variable: str, json_str: str, default: Optional[str] = None
    ) -> Any:
        """
        Parse environment variables for configuration.

        Args:
            env_variable: env_variable to use in error messages
            json_str: json string to parse

        Raises:
            ConfigError: If invalid json

        Returns:
            Any: Parsed json
        """
        try:
            val = json.loads(json_str)
            return val
        except json.JSONDecodeError as e:
            raise ConfigError(f"Invalid {env_variable} JSON: {e}")

    @classmethod
    def load_config(cls) -> Dict[str, Any]:
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
        config["secret_manager"] = cls._parse_env("AUTO_SECRETS_SECRET_MANAGER")

        # Shell integration (required)
        config["shells"] = cls._parse_env("AUTO_SECRETS_SHELLS")

        # Debug mode
        config["debug"] = cls._parse_env("AUTO_SECRETS_DEBUG", "").lower() == "true"

        # === Branch Mapping (Security Critical - No Defaults) - (required) ===

        branch_mapping_json = cls._parse_env("AUTO_SECRETS_BRANCH_MAPPINGS")
        config["branch_mappings"] = cls._parse_json(
            "AUTO_SECRETS_BRANCH_MAPPINGS", branch_mapping_json
        )
        logger.info(
            f"Loaded branch mappings for {len(config['branch_mappings'])} entries"
        )

        # === Secret Manager Configuration ===

        sm_config_json = cls._parse_env("AUTO_SECRETS_SECRET_MANAGER_CONFIG", "{}")
        config["secret_manager_config"] = cls._parse_json(
            "AUTO_SECRETS_SECRET_MANAGER_CONFIG", sm_config_json
        )

        # === Auto Commands Configuration ===

        auto_commands_json = cls._parse_env("AUTO_SECRETS_AUTO_COMMANDS", "{}")
        config["auto_commands"] = cls._parse_json(
            "AUTO_SECRETS_AUTO_COMMANDS", auto_commands_json
        )
        logger.info(
            f"Loaded branch mappings for {len(config['auto_commands'])} entries"
        )

        # === Cache Configuration ===

        # Cache base directory (required)
        config["cache_base_dir"] = cls._parse_env("AUTO_SECRETS_CACHE_DIR")

        # Cache settings (required)
        cache_config_json = cls._parse_env("AUTO_SECRETS_CACHE_CONFIG")
        config["cache_config"] = cls._parse_json(
            "AUTO_SECRETS_CACHE_CONFIG", cache_config_json
        )

        # === Paths and Directories ===

        config["feature_dir"] = cls._parse_env("AUTO_SECRETS_FEATURE_DIR")
        config["log_dir"] = cls._parse_env("AUTO_SECRETS_LOG_DIR")
        config["log_level"] = cls._parse_env("AUTO_SECRETS_LOG_LEVEL")

        # === Validation ===

        cls._validate_config(config)

        logger.info("Configuration loaded successfully")
        logger.debug(f"Secret manager: {config['secret_manager']}")
        logger.debug(f"Shells: {config['shells']}")
        logger.debug(f"Debug mode: {config['debug']}")
        logger.debug(f"Cache directory: {config['cache_base_dir']}")

        return config

    @classmethod
    def _validate_config(cls, config: Dict[str, Any]) -> None:
        """
        Validate the loaded configuration.

        Args:
            config: Configuration dictionary to validate

        Raises:
            ConfigError: If configuration is invalid
        """
        # Validate secret manager
        if config["secret_manager"] not in cls._VALID_SECRET_MANAGERS:
            raise ConfigError(
                f"Invalid secret manager: {config['secret_manager']}. "
                f"Valid options: {', '.join(cls._VALID_SECRET_MANAGERS)}"
            )

        # Validate shells
        if config["shells"] not in cls._VALID_SHELLS:
            raise ConfigError(
                f"Invalid shells configuration: {config['shells']}. "
                f"Valid options: {', '.join(cls._VALID_SHELLS)}"
            )

        # Validate branch mappings
        branch_mappings = config["branch_mappings"]
        if not isinstance(branch_mappings, dict) or not branch_mappings:
            raise ConfigError("Branch mappings must be a non-empty dictionary")

        if "default" not in branch_mappings:
            raise ConfigError("Branch mappings must include a 'default' entry")

        # Validate cache configuration
        try:
            CommonUtils.parse_duration(config["cache_config"].get("refresh_interval"))
            CommonUtils.parse_duration(config["cache_config"].get("cleanup_interval"))
        except ValueError as e:
            raise ConfigError(f"Invalid cache configuration: {e}")

    @classmethod
    def get_cache_dir(
        cls, config: Dict[str, Any], environment: Optional[str] = None
    ) -> Path:
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

    @classmethod
    def get_log_file_path(
        cls, config: Dict[str, Any], log_name: str = "auto-secrets.log"
    ) -> Path:
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

    @classmethod
    def create_minimal_config_template(cls) -> Dict[str, Any]:
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
                "default": "development",
            },
            "secret_manager_config": {
                "# Infisical configuration": "See documentation for setup",
                "client_id": "your-client-id",
                "client_secret": "your-client-secret",
                "project_id": "your-project-id",
            },
            "auto_commands": {
                "terraform": ["/infrastructure/**"],
                "tofu": ["/infrastructure/**"],
                "kubectl": ["/kubernetes/**"],
                "docker": ["/docker/**"],
            },
            "cache_config": {
                "refresh_interval": "15m",
                "cleanup_interval": "7d",
            },
        }

    @classmethod
    def is_valid_environment_name(cls, environment: str) -> bool:
        """
        Validate environment name format.

        Args:
            environment: Environment name to validate

        Returns:
            bool: True if environment name is valid
        """
        if not environment or not isinstance(environment, str):
            return False

        # Length check
        if len(environment) < 1 or len(environment) > 64:
            return False

        # Must be alphanumeric with hyphens/underscores
        # Can't start or end with special characters
        if len(environment) == 1:
            return re.match(r"^[a-zA-Z0-9]$", environment) is not None
        else:
            return (
                re.match(r"^[a-zA-Z0-9][a-zA-Z0-9_-]*[a-zA-Z0-9]$", environment)
                is not None
            )
