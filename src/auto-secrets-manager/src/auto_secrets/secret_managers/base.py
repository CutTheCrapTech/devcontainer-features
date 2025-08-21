"""
Auto Secrets Manager - Secret Manager Base Class

Abstract base class defining the interface for all secret manager implementations.
Provides common functionality and error handling patterns.
"""

import os
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from ..core.common_utils import CommonUtils
from ..core.crypto_utils import CryptoUtils
from ..managers.log_manager import AutoSecretsLogger


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


class SecretManagerBaseConfigError(Exception):
  """SecretManagerBaseConfig-related errors."""

  pass


@dataclass
class SecretManagerBaseConfig:
  """Configuration for getting all paths to fetch secrets from."""

  all_paths: list = field(default_factory=list)

  def __post_init__(self) -> None:
    """Initialize from environment variables after dataclass creation."""
    all_paths = os.getenv("AUTO_SECRETS_ALL_SM_PATHS", "[]")
    all_paths_list = CommonUtils.parse_json("AUTO_SECRETS_ALL_PATHS", all_paths)
    if not all_paths_list or not isinstance(all_paths_list, list):
      self.all_paths = ["/"]
      return
    # Check for valid paths
    self.all_paths = all_paths_list


class SecretManagerBase(ABC):
  """
  Abstract base class for all secret manager implementations.

  All secret managers must inherit from this class and implement the required methods.
  """

  def __init__(self, log_manager: AutoSecretsLogger, crypto_utils: CryptoUtils) -> None:
    """
    Initialize the secret manager.

    Args:
      log_manager: The logger manager instance.
      crypto_utils: The cryptography utility instance.
    """
    self.logger = log_manager.get_logger(name="secret_managers", component="base")
    self.crypto_utils = crypto_utils
    config = SecretManagerBaseConfig()
    self.all_paths = config.all_paths

  def _get_secret_json(self) -> dict[str, str]:
    """
    Prompts the user for the primary secret (e.g., API Key, Client Secret, Infisical client secret)
    and returns it as a dictionary.

    This method should be implemented by subclasses to handle the specific secrets required by the secret manager.
    It should use getpass to ensure the secret is not echoed to the terminal.

    Returns:
        str: A dictionary containing the secrets:
             '{"INFISICAL_CLIENT_SECRET": "<secret_value>", "SECRET_KEY": "<value>"}'

    Raises:
        SecretManagerError: If no input is provided or the user cancels.
        NotImplementedError: If the subclass does not implement this method.
    """
    raise NotImplementedError("This method should be implemented in subclasses to handle secret input.")

  def set_secret(self) -> None:
    """
    Sets the secret manager password / secret.
    Override in subclasses for manager-specific validation.

    Raises:
        SecretManagerError
    """
    try:
      input = self._get_secret_json()
      self.crypto_utils.write_dict_to_file_atomically(Path("/etc/auto-secrets"), "sm-config", input, encrypt=True)
    except Exception as e:
      raise SecretManagerError(f"Failed to set_secret: {e}") from None

  @abstractmethod
  def fetch_secrets(self, environment: str) -> dict[str, str]:
    """
    Fetch secrets for the given environment.

    Args:
      environment: Environment name (e.g., "production", "staging")

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
    return CommonUtils.is_valid_name(environment)

  def _load_config_file(self) -> dict[str, Any]:
    """
    Load and cache the configuration file.
    Returns:
        Configuration dictionary from file, empty dict if no file found
    """
    try:
      config_data = self.crypto_utils.read_dict_from_file(Path("/etc/auto-secrets"), "sm-config", decrypt=True)
      self.logger.debug(f"Loaded config file with {len(config_data)} keys")
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
        self.logger.debug(f"Found {key} in config file")
        return str(config_file[key])
    except ConfigurationError:
      # Log but don't fail - config file is optional
      self.logger.debug(f"Could not load config file for {key}")
    if required:
      raise ConfigurationError(f"Required secret '{key}' not found in environment variables or config file")
    return None

  def __repr__(self) -> str:
    """String representation of the secret manager."""
    return f"{self.__class__.__name__}"
