"""
Comprehensive unit tests for factory.py module.

This module tests the SecretManagerFactory, FactoryConfig, and related functionality
with proper type annotations and mypy compatibility.
"""

import os
from collections.abc import Generator
from unittest.mock import Mock, patch

import pytest

from auto_secrets.core.crypto_utils import CryptoUtils
from auto_secrets.managers.log_manager import AutoSecretsLogger
from auto_secrets.secret_managers.base import SecretManagerBase
from auto_secrets.secret_managers.factory import (
  SECRET_MANAGERS,
  FactoryConfig,
  FactoryConfigError,
  SecretManagerFactory,
)
from auto_secrets.secret_managers.infisical import InfisicalSecretManager


class TestFactoryConfig:
  """Test suite for FactoryConfig class."""

  def test_factory_config_init_with_valid_env_var(self) -> None:
    """Test FactoryConfig initialization with valid environment variable."""
    with patch.dict(os.environ, {"AUTO_SECRETS_SECRET_MANAGER": "infisical"}):
      config = FactoryConfig()
      assert config.secret_manager == "infisical"

  def test_factory_config_init_with_empty_env_var(self) -> None:
    """Test FactoryConfig initialization with empty environment variable."""
    with (
      patch.dict(os.environ, {"AUTO_SECRETS_SECRET_MANAGER": ""}),
      pytest.raises(FactoryConfigError, match="secret_manager cannot be empty"),
    ):
      FactoryConfig()

  def test_factory_config_init_with_missing_env_var(self) -> None:
    """Test FactoryConfig initialization with missing environment variable."""
    with (
      patch.dict(os.environ, {}, clear=True),
      pytest.raises(FactoryConfigError, match="secret_manager cannot be empty"),
    ):
      FactoryConfig()

  def test_factory_config_init_with_invalid_secret_manager(self) -> None:
    """Test FactoryConfig initialization with invalid secret manager."""
    with (
      patch.dict(os.environ, {"AUTO_SECRETS_SECRET_MANAGER": "invalid_manager"}),
      pytest.raises(FactoryConfigError, match="secret_manager invalid_manager must be one of"),
    ):
      FactoryConfig()

  def test_factory_config_init_with_none_env_var(self) -> None:
    """Test FactoryConfig initialization when environment variable is None."""
    with (
      patch("os.getenv", return_value=None),
      pytest.raises(FactoryConfigError, match="secret_manager cannot be empty None"),
    ):
      FactoryConfig()

  def test_factory_config_dataclass_fields(self) -> None:
    """Test that FactoryConfig has correct dataclass structure."""
    with patch.dict(os.environ, {"AUTO_SECRETS_SECRET_MANAGER": "infisical"}):
      config = FactoryConfig()
      assert hasattr(config, "secret_manager")
      assert isinstance(config.secret_manager, str)

  @pytest.mark.parametrize("manager_name", list(SECRET_MANAGERS.keys()))
  def test_factory_config_with_all_valid_managers(self, manager_name: str) -> None:
    """Test FactoryConfig with all valid secret managers."""
    with patch.dict(os.environ, {"AUTO_SECRETS_SECRET_MANAGER": manager_name}):
      config = FactoryConfig()
      assert config.secret_manager == manager_name


class TestFactoryConfigError:
  """Test suite for FactoryConfigError exception."""

  def test_factory_config_error_inheritance(self) -> None:
    """Test that FactoryConfigError properly inherits from Exception."""
    error = FactoryConfigError("test error")
    assert isinstance(error, Exception)
    assert str(error) == "test error"

  def test_factory_config_error_with_empty_message(self) -> None:
    """Test FactoryConfigError with empty message."""
    error = FactoryConfigError("")
    assert str(error) == ""

  def test_factory_config_error_with_none_message(self) -> None:
    """Test FactoryConfigError with None message."""
    error = FactoryConfigError(None)
    assert str(error) == "None"


class TestSecretManagerFactory:
  """Test suite for SecretManagerFactory class."""

  @pytest.fixture
  def mock_log_manager(self) -> Mock:
    """Create a mock AutoSecretsLogger for testing."""
    return Mock(spec=AutoSecretsLogger)

  @pytest.fixture
  def mock_crypto_utils(self) -> Mock:
    """Create a mock CryptoUtils for testing."""
    return Mock(spec=CryptoUtils)

  @pytest.fixture
  def mock_secret_manager_instance(self) -> Mock:
    """Create a mock SecretManagerBase instance."""
    mock_instance = Mock(spec=SecretManagerBase)
    return mock_instance

  def test_factory_create_with_infisical_manager(
    self, mock_log_manager: Mock, mock_crypto_utils: Mock, mock_secret_manager_instance: Mock
  ) -> None:
    """Test SecretManagerFactory.create() with Infisical secret manager."""
    with (
      patch.dict(os.environ, {"AUTO_SECRETS_SECRET_MANAGER": "infisical"}),
      patch.dict(
        "auto_secrets.secret_managers.factory.SECRET_MANAGERS",
        {"infisical": Mock(return_value=mock_secret_manager_instance)},
      ),
    ):
      result = SecretManagerFactory.create(mock_log_manager, mock_crypto_utils)
      assert result == mock_secret_manager_instance

  def test_factory_create_classmethod_signature(self) -> None:
    """Test that create method is properly defined as a classmethod."""
    assert hasattr(SecretManagerFactory.create, "__self__")
    assert SecretManagerFactory.create.__self__ is SecretManagerFactory

  @patch("auto_secrets.secret_managers.factory.FactoryConfig")
  def test_factory_create_uses_factory_config(
    self, mock_factory_config_class: Mock, mock_log_manager: Mock, mock_crypto_utils: Mock
  ) -> None:
    """Test that SecretManagerFactory.create() properly uses FactoryConfig."""
    mock_config_instance = Mock()
    mock_config_instance.secret_manager = "infisical"
    mock_factory_config_class.return_value = mock_config_instance

    mock_instance = Mock(spec=SecretManagerBase)
    mock_manager_class = Mock(return_value=mock_instance)

    with patch.dict("auto_secrets.secret_managers.factory.SECRET_MANAGERS", {"infisical": mock_manager_class}):
      result = SecretManagerFactory.create(mock_log_manager, mock_crypto_utils)

      mock_factory_config_class.assert_called_once()
      mock_manager_class.assert_called_once_with(mock_log_manager, mock_crypto_utils)
      assert result == mock_instance

  def test_factory_create_passes_correct_parameters(self, mock_log_manager: Mock, mock_crypto_utils: Mock) -> None:
    """Test that create method passes correct parameters to secret manager constructor."""
    # Create a real instance and patch its __init__
    with (
      patch.dict(os.environ, {"AUTO_SECRETS_SECRET_MANAGER": "infisical"}),
      patch.object(InfisicalSecretManager, "__init__", return_value=None) as mock_init,
    ):
      result = SecretManagerFactory.create(mock_log_manager, mock_crypto_utils)

      # Verify __init__ was called with correct parameters
      mock_init.assert_called_once_with(mock_log_manager, mock_crypto_utils)
      # Verify we got an InfisicalSecretManager instance
      assert isinstance(result, InfisicalSecretManager)

  def test_factory_create_with_factory_config_error(self, mock_log_manager: Mock, mock_crypto_utils: Mock) -> None:
    """Test that FactoryConfigError is properly propagated from create method."""
    with patch.dict(os.environ, {"AUTO_SECRETS_SECRET_MANAGER": "invalid"}), pytest.raises(FactoryConfigError):
      SecretManagerFactory.create(mock_log_manager, mock_crypto_utils)

  def test_factory_create_return_type_annotation(self) -> None:
    """Test that create method has proper return type annotation."""
    import inspect

    sig = inspect.signature(SecretManagerFactory.create)
    assert sig.return_annotation == "SecretManagerBase"

  def test_factory_create_parameter_type_annotations(self) -> None:
    """Test that create method has proper parameter type annotations."""
    import inspect

    sig = inspect.signature(SecretManagerFactory.create)

    params = sig.parameters
    assert "log_manager" in params
    assert "crypto_utils" in params
    assert params["log_manager"].annotation == AutoSecretsLogger
    assert params["crypto_utils"].annotation == CryptoUtils


class TestSecretManagersRegistry:
  """Test suite for SECRET_MANAGERS registry."""

  def test_secret_managers_contains_infisical(self) -> None:
    """Test that SECRET_MANAGERS contains the Infisical manager."""
    assert "infisical" in SECRET_MANAGERS
    assert SECRET_MANAGERS["infisical"] == InfisicalSecretManager

  def test_secret_managers_type_annotations(self) -> None:
    """Test that SECRET_MANAGERS has proper type structure."""
    assert isinstance(SECRET_MANAGERS, dict)

    for key, value in SECRET_MANAGERS.items():
      assert isinstance(key, str)
      assert isinstance(value, type)
      assert issubclass(value, SecretManagerBase)

  def test_secret_managers_is_not_empty(self) -> None:
    """Test that SECRET_MANAGERS is not empty."""
    assert len(SECRET_MANAGERS) > 0

  def test_secret_managers_keys_are_strings(self) -> None:
    """Test that all keys in SECRET_MANAGERS are strings."""
    for key in SECRET_MANAGERS:
      assert isinstance(key, str)
      assert len(key) > 0

  def test_secret_managers_values_are_classes(self) -> None:
    """Test that all values in SECRET_MANAGERS are classes."""
    for manager_class in SECRET_MANAGERS.values():
      assert isinstance(manager_class, type)
      assert hasattr(manager_class, "__init__")


class TestIntegration:
  """Integration tests for the factory module."""

  @pytest.fixture
  def mock_dependencies(self) -> dict[str, Mock]:
    """Create all mock dependencies for integration testing."""
    return {"log_manager": Mock(spec=AutoSecretsLogger), "crypto_utils": Mock(spec=CryptoUtils)}

  def test_end_to_end_factory_creation(self, mock_dependencies: dict[str, Mock]) -> None:
    """Test complete end-to-end factory creation process."""
    with (
      patch.dict(os.environ, {"AUTO_SECRETS_SECRET_MANAGER": "infisical"}),
      patch.object(InfisicalSecretManager, "__init__", return_value=None),
    ):
      mock_instance = Mock(spec=InfisicalSecretManager)
      with patch.object(InfisicalSecretManager, "__new__", return_value=mock_instance):
        result = SecretManagerFactory.create(mock_dependencies["log_manager"], mock_dependencies["crypto_utils"])

        assert result == mock_instance
        assert isinstance(result, Mock)

  def test_factory_with_multiple_manager_types(self, mock_dependencies: dict[str, Mock]) -> None:
    """Test factory behavior with different secret manager types."""
    test_cases = list(SECRET_MANAGERS.keys())

    for manager_name in test_cases:
      with patch.dict(os.environ, {"AUTO_SECRETS_SECRET_MANAGER": manager_name}):
        manager_class = SECRET_MANAGERS[manager_name]

        with patch.object(manager_class, "__init__", return_value=None):
          mock_instance = Mock(spec=manager_class)
          with patch.object(manager_class, "__new__", return_value=mock_instance):
            result = SecretManagerFactory.create(mock_dependencies["log_manager"], mock_dependencies["crypto_utils"])

            assert result == mock_instance

  def test_error_propagation_through_factory(self, mock_dependencies: dict[str, Mock]) -> None:
    """Test that errors are properly propagated through the factory."""
    with patch.dict(os.environ, {"AUTO_SECRETS_SECRET_MANAGER": "nonexistent"}):
      with pytest.raises(FactoryConfigError) as exc_info:
        SecretManagerFactory.create(mock_dependencies["log_manager"], mock_dependencies["crypto_utils"])

      assert "nonexistent" in str(exc_info.value)
      assert "must be one of" in str(exc_info.value)


class TestTypeCompatibility:
  """Test suite for mypy type compatibility."""

  def test_factory_config_type_hints(self) -> None:
    """Test that FactoryConfig has proper type hints."""

    # Check if the class has proper annotations
    annotations = getattr(FactoryConfig, "__annotations__", {})
    assert "secret_manager" in annotations or hasattr(FactoryConfig, "secret_manager")

  def test_secret_managers_type_compatibility(self) -> None:
    """Test that SECRET_MANAGERS is compatible with expected typing."""

    # Verify that SECRET_MANAGERS values are proper types
    for manager_class in SECRET_MANAGERS.values():
      assert callable(manager_class)
      assert hasattr(manager_class, "__init__")

  def test_factory_method_type_compatibility(self) -> None:
    """Test that factory method signatures are type-compatible."""
    import inspect

    sig = inspect.signature(SecretManagerFactory.create)

    # Verify parameter types are properly annotated
    for param_name, param in sig.parameters.items():
      if param_name != "cls":  # Skip the cls parameter for classmethod
        assert param.annotation != inspect.Parameter.empty, f"Parameter {param_name} missing type annotation"


# Test fixtures and utilities for better test organization
@pytest.fixture
def clean_environment() -> Generator[None, None, None]:
  """Fixture to ensure clean environment for each test."""
  original_env = os.environ.copy()
  yield
  os.environ.clear()
  os.environ.update(original_env)


@pytest.fixture
def sample_factory_config() -> FactoryConfig:
  """Fixture providing a sample FactoryConfig for testing."""
  with patch.dict(os.environ, {"AUTO_SECRETS_SECRET_MANAGER": "infisical"}):
    return FactoryConfig()


# Performance and edge case tests
class TestEdgeCases:
  """Test suite for edge cases and unusual scenarios."""

  def test_factory_config_with_whitespace_env_var(self) -> None:
    """Test FactoryConfig with environment variable containing whitespace."""
    # This should fail since "  infisical  " != "infisical"
    with patch.dict(os.environ, {"AUTO_SECRETS_SECRET_MANAGER": "  infisical  "}), pytest.raises(FactoryConfigError):
      FactoryConfig()

  def test_factory_config_case_sensitivity(self) -> None:
    """Test that secret manager names are case-sensitive."""
    with patch.dict(os.environ, {"AUTO_SECRETS_SECRET_MANAGER": "INFISICAL"}), pytest.raises(FactoryConfigError):
      FactoryConfig()

  def test_factory_create_with_subclass_managers(self) -> None:
    """Test factory creation with subclassed secret managers."""
    # Create mock dependencies directly in the test
    mock_log_manager = Mock(spec=AutoSecretsLogger)
    mock_crypto_utils = Mock(spec=CryptoUtils)

    # Create a simple mock class that acts like a secret manager
    mock_custom_manager = Mock(spec=SecretManagerBase)
    mock_custom_class = Mock(return_value=mock_custom_manager)

    # Temporarily add custom manager to registry
    original_managers = SECRET_MANAGERS.copy()

    try:
      SECRET_MANAGERS["custom"] = mock_custom_class

      with patch.dict(os.environ, {"AUTO_SECRETS_SECRET_MANAGER": "custom"}):
        result = SecretManagerFactory.create(mock_log_manager, mock_crypto_utils)

        # Verify the mock class was called with correct parameters
        mock_custom_class.assert_called_once_with(mock_log_manager, mock_crypto_utils)
        assert result == mock_custom_manager
    finally:
      # Restore original registry
      SECRET_MANAGERS.clear()
      SECRET_MANAGERS.update(original_managers)


if __name__ == "__main__":
  # Allow running tests directly
  pytest.main([__file__])
