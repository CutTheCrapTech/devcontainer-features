"""
Comprehensive unit tests for AppManager class.

This module provides complete test coverage for the AppManager singleton class,
including initialization, property access, lazy loading, and error handling.
"""

from unittest.mock import Mock, call, patch

import pytest

from auto_secrets.core.crypto_utils import CryptoUtils
from auto_secrets.core.key_retriever import KeyRetriever
from auto_secrets.core.singleton import SingletonMeta
from auto_secrets.managers.app_manager import AppManager
from auto_secrets.managers.branch_manager import BranchManager
from auto_secrets.managers.cache_manager import CacheManager
from auto_secrets.managers.log_manager import AutoSecretsLogger, ComponentLoggerAdapter
from auto_secrets.secret_managers.base import SecretManagerBase


class TestAppManagerSingleton:
  """Test suite for AppManager singleton behavior."""

  def setup_method(self) -> None:
    """Reset singleton state before each test."""
    # Clear singleton instances to ensure clean state
    if hasattr(SingletonMeta, "_instances"):
      SingletonMeta._instances.clear()

  def teardown_method(self) -> None:
    """Clean up singleton state after each test."""
    if hasattr(SingletonMeta, "_instances"):
      SingletonMeta._instances.clear()

  def test_singleton_behavior(self) -> None:
    """Test that AppManager implements singleton pattern correctly."""
    with patch("auto_secrets.managers.app_manager.AutoSecretsLogger") as mock_logger:
      mock_logger.return_value = Mock(spec=AutoSecretsLogger)

      # Create two instances
      instance1 = AppManager()
      instance2 = AppManager()

      # Verify they are the same object
      assert instance1 is instance2
      assert id(instance1) == id(instance2)

  def test_singleton_with_different_parameters(self) -> None:
    """Test singleton behavior when instantiated with different parameters."""
    with patch("auto_secrets.managers.app_manager.AutoSecretsLogger") as mock_logger:
      mock_logger.return_value = Mock(spec=AutoSecretsLogger)

      # First instance with specific parameters
      smk_bytes: bytes = b"test_key_123"
      instance1 = AppManager(log_file="test.log")
      instance1.smk = smk_bytes  # Set SMK via property

      # Second instance with different parameters (should be ignored due to singleton)
      instance2 = AppManager(log_file="different.log")

      # Verify singleton behavior
      assert instance1 is instance2
      assert instance1.smk == smk_bytes  # Original SMK preserved


class TestAppManagerInitialization:
  """Test suite for AppManager initialization."""

  def setup_method(self) -> None:
    """Reset singleton state before each test."""
    if hasattr(SingletonMeta, "_instances"):
      SingletonMeta._instances.clear()

  def teardown_method(self) -> None:
    """Clean up after each test."""
    if hasattr(SingletonMeta, "_instances"):
      SingletonMeta._instances.clear()

  @patch("auto_secrets.managers.app_manager.CryptoUtils")
  @patch("auto_secrets.managers.app_manager.AutoSecretsLogger")
  def test_init_with_defaults(self, mock_logger_class: Mock, mock_crypto_class: Mock) -> None:
    """Test initialization with default parameters."""
    mock_logger = Mock(spec=AutoSecretsLogger)
    mock_logger_class.return_value = mock_logger
    mock_crypto = Mock(spec=CryptoUtils)
    mock_crypto_class.return_value = mock_crypto

    app_manager = AppManager()

    # Verify logger initialization
    mock_logger_class.assert_called_once_with(log_file=None)
    assert app_manager._log_manager is mock_logger

    # Verify SMK is None initially
    assert app_manager.smk is None

    # Verify CryptoUtils is not initialized yet (lazy loading)
    assert app_manager._crypto_utils is None

    # Access crypto_utils to trigger lazy loading
    crypto_utils = app_manager.crypto_utils
    mock_crypto_class.assert_called_once_with(mock_logger, None)
    assert crypto_utils is mock_crypto

    # Verify other lazy-loaded attributes are None initially
    assert app_manager._branch_manager is None
    assert app_manager._cache_manager is None
    assert app_manager._secret_manager is None
    assert app_manager._key_retriever is None

  @patch("auto_secrets.managers.app_manager.CryptoUtils")
  @patch("auto_secrets.managers.app_manager.AutoSecretsLogger")
  def test_init_with_parameters(self, mock_logger_class: Mock, mock_crypto_class: Mock) -> None:
    """Test initialization with custom parameters."""
    mock_logger = Mock(spec=AutoSecretsLogger)
    mock_logger_class.return_value = mock_logger
    mock_crypto = Mock(spec=CryptoUtils)
    mock_crypto_class.return_value = mock_crypto

    log_file: str = "custom.log"
    smk_bytes: bytes = b"custom_master_key"

    app_manager = AppManager(log_file=log_file)
    app_manager.smk = smk_bytes  # Set SMK via property

    # Verify logger initialization with custom log file
    mock_logger_class.assert_called_once_with(log_file=log_file)
    assert app_manager._log_manager is mock_logger

    # Verify SMK is set
    assert app_manager.smk == smk_bytes

    # Access crypto_utils to trigger initialization with SMK
    crypto_utils = app_manager.crypto_utils
    mock_crypto_class.assert_called_once_with(mock_logger, smk_bytes)
    assert crypto_utils is mock_crypto

  @patch("auto_secrets.managers.app_manager.CryptoUtils")
  @patch("auto_secrets.managers.app_manager.AutoSecretsLogger")
  def test_init_with_none_smk(self, mock_logger_class: Mock, mock_crypto_class: Mock) -> None:
    """Test initialization with explicit None SMK."""
    mock_logger = Mock(spec=AutoSecretsLogger)
    mock_logger_class.return_value = mock_logger
    mock_crypto = Mock(spec=CryptoUtils)
    mock_crypto_class.return_value = mock_crypto

    app_manager = AppManager()
    app_manager.smk = None  # Explicitly set to None

    assert app_manager.smk is None

    # Access crypto_utils to trigger initialization
    _crypto_utils = app_manager.crypto_utils
    mock_crypto_class.assert_called_once_with(mock_logger, None)


class TestAppManagerProperties:
  """Test suite for AppManager property accessors."""

  def setup_method(self) -> None:
    """Set up test fixtures."""
    if hasattr(SingletonMeta, "_instances"):
      SingletonMeta._instances.clear()

  def teardown_method(self) -> None:
    """Clean up after each test."""
    if hasattr(SingletonMeta, "_instances"):
      SingletonMeta._instances.clear()

  @patch("auto_secrets.managers.app_manager.SecretManagerFactory")
  @patch("auto_secrets.managers.app_manager.CryptoUtils")
  @patch("auto_secrets.managers.app_manager.AutoSecretsLogger")
  def test_secret_manager_property_lazy_loading(
    self, mock_logger_class: Mock, mock_crypto_class: Mock, mock_secret_manager_factory: Mock
  ) -> None:
    """Test lazy loading of secret_manager property."""
    mock_logger = Mock(spec=AutoSecretsLogger)
    mock_logger_class.return_value = mock_logger
    mock_crypto = Mock(spec=CryptoUtils)
    mock_crypto_class.return_value = mock_crypto
    mock_secret_manager = Mock(spec=SecretManagerBase)
    mock_secret_manager_factory.create.return_value = mock_secret_manager

    app_manager = AppManager()

    # Initially None
    assert app_manager._secret_manager is None

    # First access - should create instance
    result = app_manager.secret_manager
    assert result is mock_secret_manager
    assert app_manager._secret_manager is mock_secret_manager
    mock_secret_manager_factory.create.assert_called_once_with(mock_logger, mock_crypto)  # type: ignore[unreachable]

    # Second access - should return cached instance
    result2 = app_manager.secret_manager
    assert result2 is mock_secret_manager
    # create should not be called again
    assert mock_secret_manager_factory.create.call_count == 1

  @patch("auto_secrets.managers.app_manager.BranchManager")
  @patch("auto_secrets.managers.app_manager.CryptoUtils")
  @patch("auto_secrets.managers.app_manager.AutoSecretsLogger")
  def test_branch_manager_property_lazy_loading(
    self, mock_logger_class: Mock, mock_crypto_class: Mock, mock_branch_manager_class: Mock
  ) -> None:
    """Test lazy loading of branch_manager property."""
    mock_logger = Mock(spec=AutoSecretsLogger)
    mock_logger_class.return_value = mock_logger
    mock_crypto = Mock(spec=CryptoUtils)
    mock_crypto_class.return_value = mock_crypto
    mock_branch_manager = Mock(spec=BranchManager)
    mock_branch_manager_class.return_value = mock_branch_manager

    app_manager = AppManager()

    # Initially None
    assert app_manager._branch_manager is None

    # First access - should create instance
    result = app_manager.branch_manager
    assert result is mock_branch_manager
    assert app_manager._branch_manager is mock_branch_manager
    mock_branch_manager_class.assert_called_once_with(mock_logger)  # type: ignore[unreachable]

    # Second access - should return cached instance
    result2 = app_manager.branch_manager
    assert result2 is mock_branch_manager
    # Constructor should not be called again
    assert mock_branch_manager_class.call_count == 1

  @patch("auto_secrets.managers.app_manager.CacheManager")
  @patch("auto_secrets.managers.app_manager.CryptoUtils")
  @patch("auto_secrets.managers.app_manager.AutoSecretsLogger")
  def test_cache_manager_property_lazy_loading(
    self, mock_logger_class: Mock, mock_crypto_class: Mock, mock_cache_manager_class: Mock
  ) -> None:
    """Test lazy loading of cache_manager property."""
    mock_logger = Mock(spec=AutoSecretsLogger)
    mock_logger_class.return_value = mock_logger
    mock_crypto = Mock(spec=CryptoUtils)
    mock_crypto_class.return_value = mock_crypto
    mock_cache_manager = Mock(spec=CacheManager)
    mock_cache_manager_class.return_value = mock_cache_manager

    app_manager = AppManager()

    # Initially None
    assert app_manager._cache_manager is None

    # First access - should create instance
    result = app_manager.cache_manager
    assert result is mock_cache_manager
    assert app_manager._cache_manager is mock_cache_manager
    mock_cache_manager_class.assert_called_once_with(mock_logger, mock_crypto)  # type: ignore[unreachable]

    # Second access - should return cached instance
    result2 = app_manager.cache_manager
    assert result2 is mock_cache_manager
    # Constructor should not be called again
    assert mock_cache_manager_class.call_count == 1

  @patch("auto_secrets.managers.app_manager.KeyRetriever")
  @patch("auto_secrets.managers.app_manager.CryptoUtils")
  @patch("auto_secrets.managers.app_manager.AutoSecretsLogger")
  def test_key_retriever_property_lazy_loading(
    self, mock_logger_class: Mock, mock_crypto_class: Mock, mock_key_retriever_class: Mock
  ) -> None:
    """Test lazy loading of key_retriever property."""
    mock_logger = Mock(spec=AutoSecretsLogger)
    mock_logger_class.return_value = mock_logger
    mock_crypto = Mock(spec=CryptoUtils)
    mock_crypto_class.return_value = mock_crypto
    mock_key_retriever = Mock(spec=KeyRetriever)
    mock_key_retriever_class.return_value = mock_key_retriever

    app_manager = AppManager()

    # Initially None
    assert app_manager._key_retriever is None

    # First access - should create instance
    result = app_manager.key_retriever
    assert result is mock_key_retriever
    assert app_manager._key_retriever is mock_key_retriever
    mock_key_retriever_class.assert_called_once_with(mock_logger)  # type: ignore[unreachable]

    # Second access - should return cached instance
    result2 = app_manager.key_retriever
    assert result2 is mock_key_retriever
    # Constructor should not be called again
    assert mock_key_retriever_class.call_count == 1


class TestAppManagerGetLogger:
  """Test suite for AppManager get_logger method."""

  def setup_method(self) -> None:
    """Set up test fixtures."""
    if hasattr(SingletonMeta, "_instances"):
      SingletonMeta._instances.clear()

  def teardown_method(self) -> None:
    """Clean up after each test."""
    if hasattr(SingletonMeta, "_instances"):
      SingletonMeta._instances.clear()

  @patch("auto_secrets.managers.app_manager.CryptoUtils")
  @patch("auto_secrets.managers.app_manager.AutoSecretsLogger")
  def test_get_logger_with_defaults(self, mock_logger_class: Mock, mock_crypto_class: Mock) -> None:
    """Test get_logger method with default parameters."""
    mock_logger = Mock(spec=AutoSecretsLogger)
    mock_component_logger = Mock(spec=ComponentLoggerAdapter)
    mock_logger.get_logger.return_value = mock_component_logger
    mock_logger_class.return_value = mock_logger
    mock_crypto_class.return_value = Mock(spec=CryptoUtils)

    app_manager = AppManager()
    result = app_manager.get_logger()

    assert result is mock_component_logger
    mock_logger.get_logger.assert_called_once_with(name=None, component=None)

  @patch("auto_secrets.managers.app_manager.CryptoUtils")
  @patch("auto_secrets.managers.app_manager.AutoSecretsLogger")
  def test_get_logger_with_name_only(self, mock_logger_class: Mock, mock_crypto_class: Mock) -> None:
    """Test get_logger method with name parameter."""
    mock_logger = Mock(spec=AutoSecretsLogger)
    mock_component_logger = Mock(spec=ComponentLoggerAdapter)
    mock_logger.get_logger.return_value = mock_component_logger
    mock_logger_class.return_value = mock_logger
    mock_crypto_class.return_value = Mock(spec=CryptoUtils)

    app_manager = AppManager()
    logger_name: str = "test_logger"
    result = app_manager.get_logger(name=logger_name)

    assert result is mock_component_logger
    mock_logger.get_logger.assert_called_once_with(name=logger_name, component=None)

  @patch("auto_secrets.managers.app_manager.CryptoUtils")
  @patch("auto_secrets.managers.app_manager.AutoSecretsLogger")
  def test_get_logger_with_component_only(self, mock_logger_class: Mock, mock_crypto_class: Mock) -> None:
    """Test get_logger method with component parameter."""
    mock_logger = Mock(spec=AutoSecretsLogger)
    mock_component_logger = Mock(spec=ComponentLoggerAdapter)
    mock_logger.get_logger.return_value = mock_component_logger
    mock_logger_class.return_value = mock_logger
    mock_crypto_class.return_value = Mock(spec=CryptoUtils)

    app_manager = AppManager()
    component_name: str = "test_component"
    result = app_manager.get_logger(component=component_name)

    assert result is mock_component_logger
    mock_logger.get_logger.assert_called_once_with(name=None, component=component_name)

  @patch("auto_secrets.managers.app_manager.CryptoUtils")
  @patch("auto_secrets.managers.app_manager.AutoSecretsLogger")
  def test_get_logger_with_both_parameters(self, mock_logger_class: Mock, mock_crypto_class: Mock) -> None:
    """Test get_logger method with both name and component parameters."""
    mock_logger = Mock(spec=AutoSecretsLogger)
    mock_component_logger = Mock(spec=ComponentLoggerAdapter)
    mock_logger.get_logger.return_value = mock_component_logger
    mock_logger_class.return_value = mock_logger
    mock_crypto_class.return_value = Mock(spec=CryptoUtils)

    app_manager = AppManager()
    logger_name: str = "test_logger"
    component_name: str = "test_component"
    result = app_manager.get_logger(name=logger_name, component=component_name)

    assert result is mock_component_logger
    mock_logger.get_logger.assert_called_once_with(name=logger_name, component=component_name)

  @patch("auto_secrets.managers.app_manager.CryptoUtils")
  @patch("auto_secrets.managers.app_manager.AutoSecretsLogger")
  def test_get_logger_multiple_calls(self, mock_logger_class: Mock, mock_crypto_class: Mock) -> None:
    """Test multiple calls to get_logger method."""
    mock_logger = Mock(spec=AutoSecretsLogger)
    mock_component_logger1 = Mock(spec=ComponentLoggerAdapter)
    mock_component_logger2 = Mock(spec=ComponentLoggerAdapter)
    mock_logger.get_logger.side_effect = [mock_component_logger1, mock_component_logger2]
    mock_logger_class.return_value = mock_logger
    mock_crypto_class.return_value = Mock(spec=CryptoUtils)

    app_manager = AppManager()

    # First call
    result1 = app_manager.get_logger(name="logger1")
    assert result1 is mock_component_logger1

    # Second call
    result2 = app_manager.get_logger(name="logger2")
    assert result2 is mock_component_logger2

    # Verify both calls were made
    expected_calls = [call(name="logger1", component=None), call(name="logger2", component=None)]
    mock_logger.get_logger.assert_has_calls(expected_calls)


class TestAppManagerIntegration:
  """Integration tests for AppManager."""

  def setup_method(self) -> None:
    """Set up test fixtures."""
    if hasattr(SingletonMeta, "_instances"):
      SingletonMeta._instances.clear()

  def teardown_method(self) -> None:
    """Clean up after each test."""
    if hasattr(SingletonMeta, "_instances"):
      SingletonMeta._instances.clear()

  @patch("auto_secrets.managers.app_manager.KeyRetriever")
  @patch("auto_secrets.managers.app_manager.CacheManager")
  @patch("auto_secrets.managers.app_manager.BranchManager")
  @patch("auto_secrets.managers.app_manager.SecretManagerFactory")
  @patch("auto_secrets.managers.app_manager.CryptoUtils")
  @patch("auto_secrets.managers.app_manager.AutoSecretsLogger")
  def test_all_properties_access_sequence(
    self,
    mock_logger_class: Mock,
    mock_crypto_class: Mock,
    mock_secret_manager_factory: Mock,
    mock_branch_manager_class: Mock,
    mock_cache_manager_class: Mock,
    mock_key_retriever_class: Mock,
  ) -> None:
    """Test accessing all properties in sequence."""
    # Setup mocks
    mock_logger = Mock(spec=AutoSecretsLogger)
    mock_logger_class.return_value = mock_logger
    mock_crypto = Mock(spec=CryptoUtils)
    mock_crypto_class.return_value = mock_crypto
    mock_secret_manager = Mock(spec=SecretManagerBase)
    mock_secret_manager_factory.create.return_value = mock_secret_manager
    mock_branch_manager = Mock(spec=BranchManager)
    mock_branch_manager_class.return_value = mock_branch_manager
    mock_cache_manager = Mock(spec=CacheManager)
    mock_cache_manager_class.return_value = mock_cache_manager
    mock_key_retriever = Mock(spec=KeyRetriever)
    mock_key_retriever_class.return_value = mock_key_retriever

    app_manager = AppManager()

    # Access all properties
    secret_mgr = app_manager.secret_manager
    branch_mgr = app_manager.branch_manager
    cache_mgr = app_manager.cache_manager
    key_ret = app_manager.key_retriever

    # Verify all instances are correct
    assert secret_mgr is mock_secret_manager
    assert branch_mgr is mock_branch_manager
    assert cache_mgr is mock_cache_manager
    assert key_ret is mock_key_retriever

    # Verify initialization calls
    mock_secret_manager_factory.create.assert_called_once_with(mock_logger, mock_crypto)
    mock_branch_manager_class.assert_called_once_with(mock_logger)
    mock_cache_manager_class.assert_called_once_with(mock_logger, mock_crypto)
    mock_key_retriever_class.assert_called_once_with(mock_logger)

  @patch("auto_secrets.managers.app_manager.CryptoUtils")
  @patch("auto_secrets.managers.app_manager.AutoSecretsLogger")
  def test_dependency_injection_flow(self, mock_logger_class: Mock, mock_crypto_class: Mock) -> None:
    """Test that dependencies are correctly injected."""
    mock_logger = Mock(spec=AutoSecretsLogger)
    mock_logger_class.return_value = mock_logger
    mock_crypto = Mock(spec=CryptoUtils)
    mock_crypto_class.return_value = mock_crypto

    smk_bytes: bytes = b"test_smk"
    app_manager = AppManager()
    app_manager.smk = smk_bytes  # Set SMK via property

    # Verify logger was created first
    mock_logger_class.assert_called_once_with(log_file=None)

    # Access crypto_utils to trigger initialization
    crypto_utils = app_manager.crypto_utils
    mock_crypto_class.assert_called_once_with(mock_logger, smk_bytes)

    # Verify the instances are stored correctly
    assert app_manager._log_manager is mock_logger
    assert crypto_utils is mock_crypto
    assert app_manager.smk == smk_bytes


class TestAppManagerTypeAnnotations:
  """Test suite for verifying type annotations and mypy compatibility."""

  def setup_method(self) -> None:
    """Set up test fixtures."""
    if hasattr(SingletonMeta, "_instances"):
      SingletonMeta._instances.clear()

  def teardown_method(self) -> None:
    """Clean up after each test."""
    if hasattr(SingletonMeta, "_instances"):
      SingletonMeta._instances.clear()

  def test_type_annotations_exist(self) -> None:
    """Test that proper type annotations exist on all methods."""
    # Verify __init__ annotations
    init_annotations = AppManager.__init__.__annotations__
    assert "log_file" in init_annotations
    # Note: smk is no longer in __init__ parameters
    assert "return" in init_annotations
    assert init_annotations["return"] is None

    # Verify get_logger annotations
    get_logger_annotations = AppManager.get_logger.__annotations__
    assert "name" in get_logger_annotations
    assert "component" in get_logger_annotations
    assert "return" in get_logger_annotations

  @patch("auto_secrets.managers.app_manager.CryptoUtils")
  @patch("auto_secrets.managers.app_manager.AutoSecretsLogger")
  def test_optional_parameters_typing(self, mock_logger_class: Mock, mock_crypto_class: Mock) -> None:
    """Test that Optional parameters work correctly with type system."""
    mock_logger_class.return_value = Mock(spec=AutoSecretsLogger)
    mock_crypto_class.return_value = Mock(spec=CryptoUtils)

    # Test with None values (should work with Optional typing)
    app_manager = AppManager(log_file=None)
    app_manager.smk = None  # Set via property
    assert app_manager.smk is None

    # Test with actual values
    smk_bytes: bytes = b"test_key"
    app_manager.smk = smk_bytes
    # Note: Due to singleton pattern, this will still return the first instance
    # This test is primarily for type checking


# Fixtures for reuse across test classes
@pytest.fixture
def mock_logger() -> Mock:
  """Create a mock AutoSecretsLogger."""
  return Mock(spec=AutoSecretsLogger)


@pytest.fixture
def mock_crypto_utils() -> Mock:
  """Create a mock CryptoUtils."""
  return Mock(spec=CryptoUtils)


@pytest.fixture
def app_manager_with_mocks(mock_logger: Mock, mock_crypto_utils: Mock) -> AppManager:
  """Create AppManager instance with mocked dependencies."""
  if hasattr(SingletonMeta, "_instances"):
    SingletonMeta._instances.clear()

  with (
    patch("auto_secrets.managers.app_manager.AutoSecretsLogger") as mock_logger_class,
    patch("auto_secrets.managers.app_manager.CryptoUtils") as mock_crypto_class,
  ):
    mock_logger_class.return_value = mock_logger
    mock_crypto_class.return_value = mock_crypto_utils

    return AppManager()


# Additional edge case tests
class TestAppManagerEdgeCases:
  """Test edge cases and error conditions."""

  def setup_method(self) -> None:
    """Set up test fixtures."""
    if hasattr(SingletonMeta, "_instances"):
      SingletonMeta._instances.clear()

  def teardown_method(self) -> None:
    """Clean up after each test."""
    if hasattr(SingletonMeta, "_instances"):
      SingletonMeta._instances.clear()

  @patch("auto_secrets.managers.app_manager.CryptoUtils")
  @patch("auto_secrets.managers.app_manager.AutoSecretsLogger")
  def test_empty_bytes_smk(self, mock_logger_class: Mock, mock_crypto_class: Mock) -> None:
    """Test initialization with empty bytes SMK."""
    mock_logger_class.return_value = Mock(spec=AutoSecretsLogger)
    mock_crypto = Mock(spec=CryptoUtils)
    mock_crypto_class.return_value = mock_crypto

    empty_smk: bytes = b""
    app_manager = AppManager()
    app_manager.smk = empty_smk  # Set via property

    assert app_manager.smk == empty_smk

    # Access crypto_utils to trigger initialization
    _crypto_utils = app_manager.crypto_utils
    mock_crypto_class.assert_called_once_with(mock_logger_class.return_value, empty_smk)

  @patch("auto_secrets.managers.app_manager.CryptoUtils")
  @patch("auto_secrets.managers.app_manager.AutoSecretsLogger")
  def test_empty_string_log_file(self, mock_logger_class: Mock, mock_crypto_class: Mock) -> None:
    """Test initialization with empty string log file."""
    mock_logger_class.return_value = Mock(spec=AutoSecretsLogger)
    mock_crypto_class.return_value = Mock(spec=CryptoUtils)

    AppManager(log_file="")

    mock_logger_class.assert_called_once_with(log_file="")


if __name__ == "__main__":
  pytest.main([__file__])
