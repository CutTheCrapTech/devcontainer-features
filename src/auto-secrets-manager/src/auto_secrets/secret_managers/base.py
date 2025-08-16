"""
Auto Secrets Manager - Secret Manager Base Class

Abstract base class defining the interface for all secret manager implementations.
Provides common functionality and error handling patterns.
"""

import os
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional, Union

from ..core.crypto_utils import CryptoUtils
from ..logging_config import get_logger


class SecretManagerError(Exception):
  """Base exception for secret manager operations."""

  pass


class AuthenticationError(SecretManagerError):
  """Authentication-related errors."""

  pass


class NetworkError(SecretManagerError):
  """Network-related errors."""

  pass


class ConfigurationError(SecretManagerError):
  """Configuration-related errors."""

  pass


class SecretNotFoundError(SecretManagerError):
  """Secret not found errors."""

  pass


@dataclass
class SecretInfo:
  """Information about a secret."""

  key: str
  path: str
  environment: str
  last_modified: Optional[str] = None
  version: Optional[str] = None
  description: Optional[str] = None


@dataclass
class ConnectionTestResult:
  """Result of connection test."""

  success: bool
  message: str
  details: dict[str, Any]
  authenticated: bool = False


class SecretManagerBase(ABC):
  """
  Abstract base class for all secret manager implementations.

  All secret managers must inherit from this class and implement the required methods.
  """

  def __init__(self, config: dict[str, Any]) -> None:
    """
    Initialize the secret manager with configuration.

    Args:
        config: Configuration dictionary containing manager-specific settings
    """
    self.config = config
    self.debug = config.get("debug", False)
    self.logger = get_logger("cache_manager")
    self.crypto_utils = CryptoUtils()
    self._validate_config()

  def _validate_config(self) -> None:
    """
    Validate the configuration.
    Override in subclasses for manager-specific validation.

    Raises:
        ConfigurationError: If configuration is invalid
    """
    if not isinstance(self.config, dict):
      raise ConfigurationError("Configuration must be a dictionary")

  def _get_secret_json(self) -> dict[str, str]:
      """
      Prompts the user for the Infisical Client Secret and returns it
      as a JSON string.

      This implementation uses getpass to ensure the secret is not echoed
      to the terminal, and it handles empty input or user cancellation.

      Returns:
          str: A dictionary in the format:
               '{"INFISICAL_CLIENT_SECRET": "<secret_value>"}'

      Raises:
          SecretManagerError / NotImplementedError: If no input is provided or the user cancels.
      """
      raise NotImplementedError(
          "This method should be implemented in subclasses to handle secret input."
      )

  def set_secret(self) -> None:
    """
    Sets the secret manager password / secret.
    Override in subclasses for manager-specific validation.

    Raises:
        SecretManagerError
    """
    try:
      input = self._get_secret_json()
      self.crypto_utils.write_dict_to_file_atomically(
        Path("/etc/auto-secrets"),
        "sm-config",
        self.config,
        input,
        encrypt=True
      )
    except Exception as e:
      raise SecretManagerError(f"Failed to set_secret: {e}") from None

  @abstractmethod
  def fetch_secrets(self, environment: str, paths: Optional[list[str]] = None) -> dict[str, str]:
    """
    Fetch secrets for the given environment and optional paths.

    Args:
        environment: Environment name (e.g., "production", "staging")
        paths: Optional list of secret paths to filter by

    Returns:
        dict: Dictionary of secret key-value pairs

    Raises:
        AuthenticationError: If authentication fails
        NetworkError: If network connection fails
        SecretNotFoundError: If environment or secrets not found
        SecretManagerError: For other errors
    """
    raise NotImplementedError

  @abstractmethod
  def test_connection(self) -> ConnectionTestResult:
    """
    Test connection to the secret manager and check authentication.

    Returns:
        ConnectionTestResult: Result of the connection test
    """
    raise NotImplementedError

  def validate_environment(self, environment: str) -> bool:
    """
    Validate environment name format.

    Args:
        environment: Environment name to validate

    Returns:
        bool: True if environment name is valid
    """
    if not environment or len(environment) > 64:
      return False

    # Must be alphanumeric with hyphens/underscores, can't start/end with -/_
    if not re.match(r"^[a-zA-Z0-9][a-zA-Z0-9_-]*[a-zA-Z0-9]$", environment):
      # Special case for single character names
      return bool(len(environment) == 1 and re.match(r"^[a-zA-Z0-9]$", environment))

    return True

  def filter_secrets_by_paths(self, secrets: dict[str, str], paths: list[str]) -> dict[str, str]:
    """
    Filter secrets by path patterns.

    Args:
        secrets: Dictionary of all secrets
        paths: List of path patterns to match

    Returns:
        dict: Filtered secrets dictionary
    """
    if not paths:
      return secrets

    filtered = {}
    for key, value in secrets.items():
      for path_pattern in paths:
        if self._matches_path_pattern(key, path_pattern):
          filtered[key] = value
          break

    return filtered

  def _matches_path_pattern(self, secret_key: str, pattern: str) -> bool:
    """
    Check if secret key matches a path pattern.

    Supports patterns like:
    - /infrastructure/** (recursive)
    - /infrastructure/* (non-recursive)
    - /infrastructure/specific_secret (exact)

    Args:
        secret_key: Secret key to test
        pattern: Pattern to match against

    Returns:
        bool: True if key matches pattern
    """
    # Normalize paths (ensure leading slash)
    if not secret_key.startswith("/"):
      secret_key = "/" + secret_key
    if not pattern.startswith("/"):
      pattern = "/" + pattern
    pattern = pattern.strip()

    # Handle different pattern types
    if pattern.endswith("/**"):
      # Recursive: /infrastructure/** matches /infrastructure/anything/deeper
      base_path = pattern[:-3]  # Remove /**
      return secret_key.startswith(base_path + "/")
    elif pattern.endswith("/*"):
      # Non-recursive: /infrastructure/* matches /infrastructure/something
      # but not /infrastructure/something/deeper
      base_path = pattern[:-2]  # Remove /*
      remaining = secret_key[len(base_path) :] if secret_key.startswith(base_path) else ""
      return remaining.startswith("/") and "/" not in remaining[1:]
    else:
      # Exact match
      return secret_key == pattern

  def get_config_value(self, key: str, default: Any = None, required: bool = False) -> Any:
    """
    Get configuration value with optional default and validation.

    Args:
        key: Configuration key
        default: Default value if key not found
        required: Whether the key is required

    Returns:
        Configuration value

    Raises:
        ConfigurationError: If required key is missing
    """
    if key in self.config:
      return self.config[key]

    # Check environment variables (uppercase with underscores)
    env_key = key.upper().replace("-", "_")
    env_value = os.getenv(env_key)
    if env_value is not None:
      return env_value

    if required and default is None:
      raise ConfigurationError(f"Required configuration key missing: {key}")

    return default

  def expand_environment_variables(self, value: Union[str, int, float, bool, list, dict]) -> str:
    """
    Expand environment variables in configuration values.

    Args:
        value: String that may contain ${VAR} patterns

    Returns:
        str: String with environment variables expanded
    """
    if not isinstance(value, str):
      return str(value)

    # Handle ${VAR} pattern
    pattern = re.compile(r"\$\{([^}]+)\}")

    def replace_var(match: re.Match[str]) -> str:
      var_name = match.group(1)
      return os.getenv(var_name, match.group(0))  # Return original if not found

    return pattern.sub(replace_var, value)

  def log_debug(self, message: str) -> None:
    """
    Log debug message if debug mode is enabled.

    Args:
        message: Debug message to log
    """
    if self.debug:
      self.logger.debug(f"DEBUG [{self.__class__.__name__}]: {message}")

  def log_error(self, message: str) -> None:
    """
    Log error message.

    Args:
        message: Error message to log
    """
    self.logger.error(f"ERROR [{self.__class__.__name__}]: {message}")

  def format_error_message(self, operation: str, error: Exception) -> str:
    """
    Format a standardized error message.

    Args:
        operation: Operation that failed
        error: Exception that occurred

    Returns:
        str: Formatted error message
    """
    return f"{operation} failed: {type(error).__name__}: {error}"

  def create_secret_path(self, environment: str, secret_name: str) -> str:
    """
    Create a standard secret path for the given environment and secret name.
    Override in subclasses for manager-specific path formats.

    Args:
        environment: Environment name
        secret_name: Secret name

    Returns:
        str: Formatted secret path
    """
    return f"/{environment}/{secret_name}"

  def sanitize_secret_key(self, key: str) -> str:
    """
    Sanitize secret key for use as environment variable.

    Args:
        key: Original secret key

    Returns:
        str: Sanitized key suitable for environment variable
    """
    # Remove leading slash and replace remaining slashes with underscores
    clean_key = key.lstrip("/")
    clean_key = clean_key.replace("/", "_")

    # Ensure valid environment variable name (alphanumeric + underscore)
    clean_key = re.sub(r"[^a-zA-Z0-9_]", "_", clean_key)

    # Ensure it starts with letter or underscore
    if clean_key and clean_key[0].isdigit():
      clean_key = "_" + clean_key

    return clean_key.upper()

  def _load_config_file(self) -> dict[str, Any]:
    """
    Load and cache the configuration file.
    Returns:
        Configuration dictionary from file, empty dict if no file found
    """
    try:
      config_data = self.crypto_utils.read_dict_from_file(
        Path("/etc/auto-secrets"),
        "sm-config",
        self.config,
        decrypt=True
      )
      self.log_debug(f"Loaded config file with {len(config_data)} keys")
      return config_data
    except Exception as e:
      raise ConfigurationError(f"Failed to read config file: {e}") from None

  def get_secret_value(self, key: str, required: bool = False) -> Optional[str]:
    """
    Get a secret value from a configuration file
    Args:
        key: Environment variable name (e.g., "INFISICAL_CLIENT_SECRET")
        required: Whether the value is required
    Returns:
        Secret value or None if not found
    Raises:
        ConfigurationError: If required value is missing
    """
    # Check configuration file
    try:
      config_file = self._load_config_file()
      if key in config_file:
        self.log_debug(f"Found {key} in config file")
        return str(config_file[key])
    except ConfigurationError:
      # Log but don't fail - config file is optional
      self.log_debug(f"Could not load config file for {key}")
    if required:
      raise ConfigurationError(f"Required secret '{key}' not found in environment variables or config file")
    return None

  def __repr__(self) -> str:
    """String representation of the secret manager."""
    return f"{self.__class__.__name__}(config_keys={list(self.config.keys())})"
