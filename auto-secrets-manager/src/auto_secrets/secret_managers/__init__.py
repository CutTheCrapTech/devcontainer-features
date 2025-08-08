"""
Auto Secrets Manager - Secret Managers Module

Plugin-style secret manager implementations with a common interface.
Currently supports Infisical secret manager with plans for additional providers.
"""

from typing import Any, Optional

from .base import (
  AuthenticationError,
  ConfigurationError,
  ConnectionTestResult,
  NetworkError,
  SecretInfo,
  SecretManagerBase,
  SecretManagerError,
  SecretNotFoundError,
)
from .infisical import InfisicalSecretManager

# Registry of available secret managers
SECRET_MANAGERS = {
  "infisical": InfisicalSecretManager,
  # Future secret managers can be added here:
  # "vault": VaultSecretManager,
  # "aws": AWSSecretsManagerSecretManager,
  # "azure": AzureKeyVaultSecretManager,
  # "gcp": GCPSecretManagerSecretManager,
}


def create_secret_manager(config: dict[str, Any]) -> Optional[SecretManagerBase]:
  """
  Factory function to create secret manager instances from unified config.

  Args:
      config: Unified configuration dictionary containing:
          - secret_manager: Type of secret manager
          - secret_manager_config: Manager-specific configuration

  Returns:
      SecretManagerBase: Initialized secret manager instance or None if not configured

  Raises:
      ValueError: If manager_type is not supported
      SecretManagerError: If initialization fails
  """
  manager_type = config.get("secret_manager")
  if not manager_type:
    return None

  if manager_type not in SECRET_MANAGERS:
    available = ", ".join(SECRET_MANAGERS.keys())
    raise ValueError(f"Unknown secret manager: {manager_type}. Available: {available}")

  manager_config = config.get("secret_manager_config", {})
  manager_config["cache_base_dir"] = config.get("cache_base_dir")
  manager_class = SECRET_MANAGERS[manager_type]

  try:
    return manager_class(manager_config)
  except Exception as e:
    raise SecretManagerError(f"Failed to initialize {manager_type} secret manager: {e}") from None


def create_secret_manager_legacy(manager_type: str, config: dict) -> SecretManagerBase:
  """
  Legacy factory function for backward compatibility.

  Args:
      manager_type: Type of secret manager
      config: Configuration dictionary for the secret manager

  Returns:
      SecretManagerBase: Initialized secret manager instance

  Raises:
      ValueError: If manager_type is not supported
      SecretManagerError: If initialization fails
  """
  if manager_type not in SECRET_MANAGERS:
    available = ", ".join(SECRET_MANAGERS.keys())
    raise ValueError(f"Unknown secret manager: {manager_type}. Available: {available}")

  manager_class = SECRET_MANAGERS[manager_type]

  try:
    return manager_class(config)
  except Exception as e:
    raise SecretManagerError(f"Failed to initialize {manager_type} secret manager: {e}") from None


def get_available_managers() -> list[str]:
  """
  Get list of available secret manager types.

  Returns:
      List[str]: List of available secret manager type strings
  """
  return list(SECRET_MANAGERS.keys())


def validate_secret_manager_config(manager_type: str, config: dict[str, Any]) -> list[str]:
  """
  Validate configuration for a specific secret manager type.

  Args:
      manager_type: Type of secret manager to validate
      config: Configuration to validate

  Returns:
      List[str]: List of validation errors (empty if valid)
  """
  if manager_type not in SECRET_MANAGERS:
    return [f"Unknown secret manager type: {manager_type}"]

  manager_class = SECRET_MANAGERS[manager_type]

  # Basic validation - try to create an instance
  try:
    manager_class(config)
    return []
  except Exception as e:
    return [f"Configuration error: {e}"]


def get_manager_info(manager_type: str) -> dict[str, Any]:
  """
  Get information about a specific secret manager.

  Args:
      manager_type: Type of secret manager

  Returns:
      Dict[str, Any]: Manager information including description and requirements
  """
  if manager_type not in SECRET_MANAGERS:
    return {}

  manager_class = SECRET_MANAGERS[manager_type]

  return {
    "type": manager_type,
    "class": manager_class.__name__,
    "description": getattr(manager_class, "__doc__", "No description available"),
    "module": manager_class.__module__,
    "supports_environments": hasattr(manager_class, "get_available_environments"),
    "supports_test_connection": hasattr(manager_class, "test_connection"),
  }


def list_all_managers_info() -> dict[str, dict[str, Any]]:
  """
  Get information about all available secret managers.

  Returns:
      Dict[str, Dict[str, Any]]: Dictionary mapping manager types to their info
  """
  return {manager_type: get_manager_info(manager_type) for manager_type in SECRET_MANAGERS}


__all__ = [
  # Base classes and exceptions
  "SecretManagerBase",
  "SecretManagerError",
  "AuthenticationError",
  "NetworkError",
  "ConfigurationError",
  "SecretNotFoundError",
  "SecretInfo",
  "ConnectionTestResult",
  # Concrete implementations
  "InfisicalSecretManager",
  # Factory functions
  "create_secret_manager",
  "create_secret_manager_legacy",
  # Utility functions
  "get_available_managers",
  "validate_secret_manager_config",
  "get_manager_info",
  "list_all_managers_info",
  # Registry
  "SECRET_MANAGERS",
]
