"""
Test suite for auto_secrets.secret_managers module.

Tests for factory functions, registry, and utility functions.
"""

from typing import Any
from unittest.mock import Mock, patch

import pytest

from auto_secrets.secret_managers import (
  SECRET_MANAGERS,
  AuthenticationError,
  ConfigurationError,
  InfisicalSecretManager,
  NetworkError,
  SecretInfo,
  SecretManagerBase,
  SecretManagerError,
  SecretNotFoundError,
  create_secret_manager,
  get_available_managers,
  get_manager_info,
  list_all_managers_info,
)


class TestSecretManagerRegistry:
  """Test the secret manager registry."""

  def test_registry_contains_infisical(self) -> None:
    """Test that registry contains expected managers."""
    assert "infisical" in SECRET_MANAGERS
    assert SECRET_MANAGERS["infisical"] == InfisicalSecretManager

  def test_registry_structure(self) -> None:
    """Test registry is properly structured."""
    assert isinstance(SECRET_MANAGERS, dict)
    assert len(SECRET_MANAGERS) > 0

    # All values should be classes
    for manager_name, manager_class in SECRET_MANAGERS.items():
      assert isinstance(manager_name, str)
      assert isinstance(manager_class, type)
      # Should be subclass of SecretManagerBase
      assert issubclass(manager_class, SecretManagerBase)


class TestCreateSecretManager:
  """Test the main factory function."""

  @patch.dict("os.environ", {"INFISICAL_CLIENT_SECRET": "dummy-secret"})
  @patch("auto_secrets.secret_managers.SECRET_MANAGERS")
  def test_create_infisical_manager(self, mock_registry: Mock) -> None:
    """Test creating Infisical secret manager."""
    mock_manager_class = Mock()
    mock_instance = Mock()
    mock_manager_class.return_value = mock_instance
    mock_registry.__getitem__.return_value = mock_manager_class
    mock_registry.__contains__.return_value = True

    config = {
      "secret_manager": "infisical",
      "secret_manager_config": {
        "host": "test-host",
        "project_id": "test-id",
        "client_id": "test-id",
        "client_secret": "test-secret",
      },
      "cache_base_dir": "/tmp/cache",
    }

    result = create_secret_manager(config)

    assert result == mock_instance
    mock_manager_class.assert_called_once_with(
      {
        "host": "test-host",
        "project_id": "test-id",
        "client_id": "test-id",
        "client_secret": "test-secret",
        "cache_base_dir": "/tmp/cache",
      }
    )

  def test_create_manager_no_type_configured(self) -> None:
    """Test behavior when no secret manager type is configured."""
    config: dict[str, Any] = {}
    result = create_secret_manager(config)
    assert result is None

  def test_create_manager_empty_type(self) -> None:
    """Test behavior when secret manager type is empty."""
    config = {"secret_manager": ""}
    result = create_secret_manager(config)
    assert result is None

  def test_create_manager_none_type(self) -> None:
    """Test behavior when secret manager type is None."""
    config = {"secret_manager": None}
    result = create_secret_manager(config)
    assert result is None

  def test_create_manager_unknown_type(self) -> None:
    """Test error for unknown secret manager type."""
    config = {"secret_manager": "unknown-manager"}

    with pytest.raises(ValueError) as exc_info:
      create_secret_manager(config)

    assert "Unknown secret manager: unknown-manager" in str(exc_info.value)
    assert "Available: infisical" in str(exc_info.value)

  @patch("auto_secrets.secret_managers.InfisicalSecretManager")
  def test_create_manager_initialization_fails(self, mock_infisical: Mock) -> None:
    """Test error handling when manager initialization fails."""
    mock_infisical.side_effect = Exception("Initialization failed")

    config = {"secret_manager": "infisical", "secret_manager_config": {"client_id": "test"}}

    with pytest.raises(SecretManagerError) as exc_info:
      create_secret_manager(config)

    assert "Failed to initialize infisical secret manager" in str(exc_info.value)

  @patch.dict("os.environ", {"INFISICAL_CLIENT_SECRET": "dummy-secret"})
  @patch("auto_secrets.secret_managers.SECRET_MANAGERS")
  def test_create_manager_with_full_config(self, mock_registry: Mock) -> None:
    """Test creating manager with complete configuration."""
    mock_manager_class = Mock()
    mock_instance = Mock()
    mock_manager_class.return_value = mock_instance
    mock_registry.__getitem__.return_value = mock_manager_class
    mock_registry.__contains__.return_value = True

    config = {
      "secret_manager": "infisical",
      "secret_manager_config": {
        "client_id": "test-client-id",
        "client_secret": "test-secret",
        "project_id": "test-project",
      },
      "cache_base_dir": "/var/cache/secrets",
      "other_config": "ignored",
    }

    result = create_secret_manager(config)

    assert result == mock_instance
    expected_manager_config = {
      "client_id": "test-client-id",
      "client_secret": "test-secret",
      "project_id": "test-project",
      "cache_base_dir": "/var/cache/secrets",
    }
    mock_manager_class.assert_called_once_with(expected_manager_config)


class TestUtilityFunctions:
  """Test utility functions."""

  def test_get_available_managers(self) -> None:
    """Test getting list of available managers."""
    managers = get_available_managers()

    assert isinstance(managers, list)
    assert "infisical" in managers
    assert len(managers) == len(SECRET_MANAGERS)

  def test_get_manager_info_valid(self) -> None:
    """Test getting info for valid manager."""
    info = get_manager_info("infisical")

    assert isinstance(info, dict)
    assert info["type"] == "infisical"
    assert info["class"] == "InfisicalSecretManager"
    assert "description" in info
    assert "module" in info
    assert "supports_environments" in info
    assert "supports_test_connection" in info

  def test_get_manager_info_unknown(self) -> None:
    """Test getting info for unknown manager."""
    info = get_manager_info("unknown")
    assert info == {}

  def test_list_all_managers_info(self) -> None:
    """Test getting info for all managers."""
    all_info = list_all_managers_info()

    assert isinstance(all_info, dict)
    assert "infisical" in all_info
    assert len(all_info) == len(SECRET_MANAGERS)

    # Each entry should have proper structure
    for manager_type, info in all_info.items():
      assert info["type"] == manager_type
      assert "class" in info
      assert "description" in info


class TestImports:
  """Test that all expected imports are available."""

  def test_base_classes_imported(self) -> None:
    """Test that base classes are properly imported."""
    assert SecretManagerBase is not None
    assert SecretManagerError is not None
    assert AuthenticationError is not None
    assert NetworkError is not None
    assert ConfigurationError is not None
    assert SecretNotFoundError is not None
    assert SecretInfo is not None

  def test_concrete_implementations_imported(self) -> None:
    """Test that concrete implementations are imported."""
    assert InfisicalSecretManager is not None

  def test_factory_functions_imported(self) -> None:
    """Test that factory functions are imported."""
    assert create_secret_manager is not None

  def test_utility_functions_imported(self) -> None:
    """Test that utility functions are imported."""
    assert get_available_managers is not None
    assert get_manager_info is not None
    assert list_all_managers_info is not None


class TestManagerInfoDetails:
  """Test detailed manager information functionality."""

  def test_manager_info_has_supports_flags(self) -> None:
    """Test that manager info includes capability flags."""
    info = get_manager_info("infisical")

    # Should have boolean values for support flags
    assert isinstance(info["supports_environments"], bool)
    assert isinstance(info["supports_test_connection"], bool)

  def test_manager_info_module_path(self) -> None:
    """Test that manager info includes correct module path."""
    info = get_manager_info("infisical")

    assert "auto_secrets.secret_managers" in info["module"]

  def test_all_managers_have_consistent_info(self) -> None:
    """Test that all managers have consistent info structure."""
    all_info = list_all_managers_info()

    required_keys = {"type", "class", "description", "module", "supports_environments", "supports_test_connection"}

    for _manager_type, info in all_info.items():
      assert set(info.keys()) == required_keys
      assert isinstance(info["type"], str)
      assert isinstance(info["class"], str)
      assert isinstance(info["module"], str)
      assert isinstance(info["supports_environments"], bool)
      assert isinstance(info["supports_test_connection"], bool)


if __name__ == "__main__":
  pytest.main([__file__])
