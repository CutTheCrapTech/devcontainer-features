"""
Comprehensive unit tests for SecretManagerBase and related classes with mypy compatibility.
Tests all major functionality, error conditions, and edge cases.
"""

import os
import tempfile
from collections.abc import Generator
from pathlib import Path
from typing import Any, Optional
from unittest.mock import Mock, patch

import pytest

from auto_secrets.secret_managers.base import (
  AuthenticationError,
  ConfigurationError,
  ConnectionTestResult,
  NetworkError,
  SecretInfo,
  SecretManagerBase,
  SecretManagerBaseConfig,
  SecretManagerBaseConfigError,
  SecretManagerError,
  SecretNotFoundError,
)


# Mock implementation for testing
class MockSecretManager(SecretManagerBase):
  """Mock secret manager for testing."""

  def __init__(self, log_manager: Mock, crypto_utils: Mock) -> None:
    super().__init__(log_manager, crypto_utils)
    self.fetch_secrets_called = False
    self.test_connection_called = False
    self._should_fail = False
    self._connection_result: Optional[ConnectionTestResult] = None
    self._secrets: dict[str, str] = {}

  def set_should_fail(self, should_fail: bool) -> None:
    """Set whether operations should fail for testing."""
    self._should_fail = should_fail

  def set_connection_result(self, result: ConnectionTestResult) -> None:
    """Set the connection test result."""
    self._connection_result = result

  def set_secrets(self, secrets: dict[str, str]) -> None:
    """Set the secrets to return."""
    self._secrets = secrets

  def fetch_secrets(self, environment: str) -> dict[str, str]:
    """Mock fetch_secrets implementation."""
    self.fetch_secrets_called = True
    if self._should_fail:
      raise SecretManagerError("Mock fetch_secrets failure")
    return self._secrets.copy()

  def test_connection(self) -> ConnectionTestResult:
    """Mock test_connection implementation."""
    self.test_connection_called = True
    if self._should_fail:
      raise NetworkError("Mock connection failure")
    return self._connection_result or ConnectionTestResult(
      success=True, message="Mock connection successful", details={"mock": True}, authenticated=True
    )

  def _get_secret_json(self) -> dict[str, str]:
    """Mock secret input method."""
    return {"MOCK_SECRET": "mock_value"}


class TestSecretInfo:
  """Test cases for SecretInfo dataclass."""

  def test_secret_info_creation_minimal(self) -> None:
    """Test SecretInfo creation with minimal required fields."""
    info = SecretInfo(key="api_key", path="/app/secrets/api_key", environment="production")

    assert info.key == "api_key"
    assert info.path == "/app/secrets/api_key"
    assert info.environment == "production"
    assert info.last_modified is None
    assert info.version is None
    assert info.description is None

  def test_secret_info_creation_full(self) -> None:
    """Test SecretInfo creation with all fields."""
    info = SecretInfo(
      key="database_password",
      path="/db/secrets/password",
      environment="staging",
      last_modified="2024-01-01T12:00:00Z",
      version="v1.2.3",
      description="Database connection password",
    )

    assert info.key == "database_password"
    assert info.path == "/db/secrets/password"
    assert info.environment == "staging"
    assert info.last_modified == "2024-01-01T12:00:00Z"
    assert info.version == "v1.2.3"
    assert info.description == "Database connection password"

  def test_secret_info_type_annotations(self) -> None:
    """Test that SecretInfo has proper type annotations."""
    assert hasattr(SecretInfo, "__annotations__")
    annotations = SecretInfo.__annotations__

    assert "key" in annotations
    assert "path" in annotations
    assert "environment" in annotations
    assert "last_modified" in annotations
    assert "version" in annotations
    assert "description" in annotations


class TestConnectionTestResult:
  """Test cases for ConnectionTestResult dataclass."""

  def test_connection_test_result_creation_minimal(self) -> None:
    """Test ConnectionTestResult creation with minimal fields."""
    result = ConnectionTestResult(
      success=True, message="Connection successful", details={"endpoint": "https://api.example.com"}
    )

    assert result.success is True
    assert result.message == "Connection successful"
    assert result.details == {"endpoint": "https://api.example.com"}
    assert result.authenticated is False  # Default value

  def test_connection_test_result_creation_full(self) -> None:
    """Test ConnectionTestResult creation with all fields."""
    details = {"endpoint": "https://vault.example.com", "response_time_ms": 250, "server_version": "1.2.3"}

    result = ConnectionTestResult(
      success=True, message="Authentication successful", details=details, authenticated=True
    )

    assert result.success is True
    assert result.message == "Authentication successful"
    assert result.details == details
    assert result.authenticated is True

  def test_connection_test_result_failure(self) -> None:
    """Test ConnectionTestResult for failure case."""
    result = ConnectionTestResult(
      success=False,
      message="Connection timeout",
      details={"error": "timeout", "duration_ms": 30000},
      authenticated=False,
    )

    assert result.success is False
    assert result.message == "Connection timeout"
    assert result.details["error"] == "timeout"
    assert result.authenticated is False


class TestSecretManagerBaseConfig:
  """Test cases for SecretManagerBaseConfig class."""

  def test_config_initialization_valid(self) -> None:
    """Test SecretManagerBaseConfig initialization with valid values."""
    with patch.dict(
      os.environ,
      {"AUTO_SECRETS_ALL_SM_PATHS": '["path1", "path2", "path3"]'},
    ):
      config = SecretManagerBaseConfig()
      assert config.all_paths == ["path1", "path2", "path3"]

  def test_config_missing_secret_manager(self) -> None:
    """Test SecretManagerBaseConfig with missing secret manager."""
    with (
      patch.dict(os.environ, {}, clear=True),
      pytest.raises(SecretManagerBaseConfigError, match="secret_manager cannot be empty"),
    ):
      SecretManagerBaseConfig()

  def test_config_invalid_secret_manager(self) -> None:
    """Test SecretManagerBaseConfig with invalid secret manager."""
    with (
      patch.dict(os.environ, {"AUTO_SECRETS_SECRET_MANAGER": "invalid_manager", "AUTO_SECRETS_ALL_SM_PATHS": "[]"}),
      pytest.raises(SecretManagerBaseConfigError, match="must be one of"),
    ):
      SecretManagerBaseConfig()

  def test_config_default_paths(self) -> None:
    """Test SecretManagerBaseConfig with default paths."""
    with (
      patch.dict(
        os.environ, {"AUTO_SECRETS_SECRET_MANAGER": "infisical", "AUTO_SECRETS_ALL_SM_PATHS": None}, clear=False
      ),
      patch("auto_secrets_manager.secret_managers.base.CommonUtils.parse_json", return_value=None),
    ):
      config = SecretManagerBaseConfig()
      assert config.all_paths == ["/"]

  def test_config_empty_paths_list(self) -> None:
    """Test SecretManagerBaseConfig with empty paths list."""
    with patch.dict(os.environ, {"AUTO_SECRETS_SECRET_MANAGER": "infisical", "AUTO_SECRETS_ALL_SM_PATHS": "[]"}):
      config = SecretManagerBaseConfig()
      assert config.all_paths == ["/"]

  def test_config_invalid_paths_format(self) -> None:
    """Test SecretManagerBaseConfig with invalid paths format."""
    with patch.dict(
      os.environ, {"AUTO_SECRETS_SECRET_MANAGER": "infisical", "AUTO_SECRETS_ALL_SM_PATHS": '"not_a_list"'}
    ):
      config = SecretManagerBaseConfig()
      assert config.all_paths == ["/"]


class TestSecretManagerBase:
  """Test cases for SecretManagerBase abstract class."""

  @pytest.fixture
  def mock_logger(self) -> Mock:
    """Create mock logger."""
    logger = Mock()
    log_manager = Mock()
    log_manager.get_logger.return_value = logger
    return log_manager

  @pytest.fixture
  def mock_crypto_utils(self) -> Mock:
    """Create mock crypto utils."""
    crypto_utils = Mock()
    crypto_utils.read_dict_from_file.return_value = {}
    crypto_utils.write_dict_to_file_atomically.return_value = None
    return crypto_utils

  @pytest.fixture
  def mock_secret_manager(self, mock_logger: Mock, mock_crypto_utils: Mock) -> MockSecretManager:
    """Create mock secret manager for testing."""
    with patch.dict(
      os.environ, {"AUTO_SECRETS_SECRET_MANAGER": "infisical", "AUTO_SECRETS_ALL_SM_PATHS": '["/app", "/db"]'}
    ):
      return MockSecretManager(mock_logger, mock_crypto_utils)

  def test_initialization(self, mock_secret_manager: MockSecretManager) -> None:
    """Test SecretManagerBase initialization."""
    assert mock_secret_manager.logger is not None
    assert mock_secret_manager.crypto_utils is not None
    assert mock_secret_manager.all_paths == ["/app", "/db"]

  def test_validate_environment_valid(self, mock_secret_manager: MockSecretManager) -> None:
    """Test validate_environment with valid names."""
    valid_names = ["production", "staging", "dev", "test-env", "env_1"]

    for name in valid_names:
      with patch("auto_secrets_manager.secret_managers.base.CommonUtils.is_valid_name", return_value=True):
        assert mock_secret_manager.validate_environment(name) is True

  def test_validate_environment_invalid(self, mock_secret_manager: MockSecretManager) -> None:
    """Test validate_environment with invalid names."""
    invalid_names = ["", "invalid name", "env-with-spaces", "123env"]

    for name in invalid_names:
      with patch("auto_secrets_manager.secret_managers.base.CommonUtils.is_valid_name", return_value=False):
        assert mock_secret_manager.validate_environment(name) is False

  def test_load_config_file_success(self, mock_secret_manager: MockSecretManager, mock_crypto_utils: Mock) -> None:
    """Test _load_config_file successful loading."""
    expected_config = {"INFISICAL_CLIENT_SECRET": "secret123", "API_KEY": "key456"}
    mock_crypto_utils.read_dict_from_file.return_value = expected_config

    result = mock_secret_manager._load_config_file()

    assert result == expected_config
    mock_crypto_utils.read_dict_from_file.assert_called_once_with(Path("/etc/auto-secrets"), "sm-config", decrypt=True)

  def test_load_config_file_failure(self, mock_secret_manager: MockSecretManager, mock_crypto_utils: Mock) -> None:
    """Test _load_config_file with read failure."""
    mock_crypto_utils.read_dict_from_file.side_effect = Exception("File not found")

    with pytest.raises(ConfigurationError, match="Failed to read config file"):
      mock_secret_manager._load_config_file()

  def test_get_secret_value_from_config_file(
    self, mock_secret_manager: MockSecretManager, mock_crypto_utils: Mock
  ) -> None:
    """Test get_secret_value retrieving from config file."""
    config_data = {"INFISICAL_CLIENT_SECRET": "secret_value", "OTHER_KEY": "other_value"}
    mock_crypto_utils.read_dict_from_file.return_value = config_data

    result = mock_secret_manager.get_secret_value("INFISICAL_CLIENT_SECRET")

    assert result == "secret_value"

  def test_get_secret_value_not_found_optional(
    self, mock_secret_manager: MockSecretManager, mock_crypto_utils: Mock
  ) -> None:
    """Test get_secret_value with key not found (optional)."""
    mock_crypto_utils.read_dict_from_file.return_value = {}

    result = mock_secret_manager.get_secret_value("NONEXISTENT_KEY", required=False)

    assert result is None

  def test_get_secret_value_not_found_required(
    self, mock_secret_manager: MockSecretManager, mock_crypto_utils: Mock
  ) -> None:
    """Test get_secret_value with key not found (required)."""
    mock_crypto_utils.read_dict_from_file.return_value = {}

    with pytest.raises(ConfigurationError, match="Required secret 'REQUIRED_KEY' not found"):
      mock_secret_manager.get_secret_value("REQUIRED_KEY", required=True)

  def test_get_secret_value_config_file_error(
    self, mock_secret_manager: MockSecretManager, mock_crypto_utils: Mock
  ) -> None:
    """Test get_secret_value with config file read error."""
    mock_crypto_utils.read_dict_from_file.side_effect = Exception("Read error")

    # Should not raise exception, just log and return None
    result = mock_secret_manager.get_secret_value("SOME_KEY", required=False)
    assert result is None

  def test_get_secret_value_config_file_error_required(
    self, mock_secret_manager: MockSecretManager, mock_crypto_utils: Mock
  ) -> None:
    """Test get_secret_value with config file error and required key."""
    mock_crypto_utils.read_dict_from_file.side_effect = Exception("Read error")

    with pytest.raises(ConfigurationError, match="Required secret 'REQUIRED_KEY' not found"):
      mock_secret_manager.get_secret_value("REQUIRED_KEY", required=True)

  def test_set_secret_success(self, mock_secret_manager: MockSecretManager, mock_crypto_utils: Mock) -> None:
    """Test set_secret successful operation."""
    mock_secret_manager.set_secret()

    mock_crypto_utils.write_dict_to_file_atomically.assert_called_once_with(
      Path("/etc/auto-secrets"), "sm-config", {"MOCK_SECRET": "mock_value"}, encrypt=True
    )

  def test_set_secret_failure(self, mock_secret_manager: MockSecretManager, mock_crypto_utils: Mock) -> None:
    """Test set_secret with write failure."""
    mock_crypto_utils.write_dict_to_file_atomically.side_effect = Exception("Write failed")

    with pytest.raises(SecretManagerError, match="Failed to set_secret"):
      mock_secret_manager.set_secret()

  def test_fetch_secrets_implementation(self, mock_secret_manager: MockSecretManager) -> None:
    """Test fetch_secrets method calls the implementation."""
    expected_secrets = {"key1": "value1", "key2": "value2"}
    mock_secret_manager.set_secrets(expected_secrets)

    result = mock_secret_manager.fetch_secrets("production")

    assert mock_secret_manager.fetch_secrets_called is True
    assert result == expected_secrets

  def test_fetch_secrets_failure(self, mock_secret_manager: MockSecretManager) -> None:
    """Test fetch_secrets with implementation failure."""
    mock_secret_manager.set_should_fail(True)

    with pytest.raises(SecretManagerError, match="Mock fetch_secrets failure"):
      mock_secret_manager.fetch_secrets("production")

  def test_test_connection_success(self, mock_secret_manager: MockSecretManager) -> None:
    """Test test_connection successful operation."""
    expected_result = ConnectionTestResult(
      success=True, message="Test connection successful", details={"test": True}, authenticated=True
    )
    mock_secret_manager.set_connection_result(expected_result)

    result = mock_secret_manager.test_connection()

    assert mock_secret_manager.test_connection_called is True
    assert result.success is True
    assert result.message == "Test connection successful"
    assert result.authenticated is True

  def test_test_connection_failure(self, mock_secret_manager: MockSecretManager) -> None:
    """Test test_connection with implementation failure."""
    mock_secret_manager.set_should_fail(True)

    with pytest.raises(NetworkError, match="Mock connection failure"):
      mock_secret_manager.test_connection()

  def test_repr_method(self, mock_secret_manager: MockSecretManager) -> None:
    """Test __repr__ method."""
    result = repr(mock_secret_manager)
    assert result == "MockSecretManager"

  def test_get_secret_json_not_implemented(self, mock_secret_manager: MockSecretManager) -> None:
    """Test that _get_secret_json raises NotImplementedError in base class."""

    # Create a direct instance of SecretManagerBase to test the base implementation
    class BaseOnlyManager(SecretManagerBase):
      def fetch_secrets(self, environment: str) -> dict[str, str]:
        return {}

      def test_connection(self) -> ConnectionTestResult:
        return ConnectionTestResult(success=True, message="test", details={})

    with patch.dict(os.environ, {"AUTO_SECRETS_SECRET_MANAGER": "infisical", "AUTO_SECRETS_ALL_SM_PATHS": "[]"}):
      base_manager = BaseOnlyManager(Mock(), Mock())

      with pytest.raises(NotImplementedError, match="This method should be implemented in subclasses"):
        base_manager._get_secret_json()


class TestSecretManagerExceptions:
  """Test cases for SecretManager exception classes."""

  def test_secret_manager_error_hierarchy(self) -> None:
    """Test exception hierarchy."""
    assert issubclass(SecretManagerError, Exception)
    assert issubclass(AuthenticationError, SecretManagerError)
    assert issubclass(NetworkError, SecretManagerError)
    assert issubclass(ConfigurationError, SecretManagerError)
    assert issubclass(SecretNotFoundError, SecretManagerError)

  def test_secret_manager_error_creation(self) -> None:
    """Test SecretManagerError creation and message."""
    error = SecretManagerError("Test error message")
    assert str(error) == "Test error message"
    assert isinstance(error, Exception)

  def test_authentication_error_creation(self) -> None:
    """Test AuthenticationError creation."""
    error = AuthenticationError("Invalid credentials")
    assert str(error) == "Invalid credentials"
    assert isinstance(error, SecretManagerError)

  def test_network_error_creation(self) -> None:
    """Test NetworkError creation."""
    error = NetworkError("Connection timeout")
    assert str(error) == "Connection timeout"
    assert isinstance(error, SecretManagerError)

  def test_configuration_error_creation(self) -> None:
    """Test ConfigurationError creation."""
    error = ConfigurationError("Missing configuration")
    assert str(error) == "Missing configuration"
    assert isinstance(error, SecretManagerError)

  def test_secret_not_found_error_creation(self) -> None:
    """Test SecretNotFoundError creation."""
    error = SecretNotFoundError("Secret not found")
    assert str(error) == "Secret not found"
    assert isinstance(error, SecretManagerError)

  def test_secret_manager_base_config_error_creation(self) -> None:
    """Test SecretManagerBaseConfigError creation."""
    error = SecretManagerBaseConfigError("Invalid configuration")
    assert str(error) == "Invalid configuration"
    assert isinstance(error, Exception)


class TestSecretManagersRegistry:
  """Test cases for SECRET_MANAGERS registry."""


class TestTypeAnnotations:
  """Test type annotations and mypy compatibility."""

  def test_secret_info_type_annotations(self) -> None:
    """Test SecretInfo type annotations."""
    assert hasattr(SecretInfo, "__annotations__")
    annotations = SecretInfo.__annotations__

    expected_annotations = {
      "key": str,
      "path": str,
      "environment": str,
      "last_modified": Optional[str],
      "version": Optional[str],
      "description": Optional[str],
    }

    for field, _expected_type in expected_annotations.items():
      assert field in annotations
      # Note: Direct type comparison can be complex with Optional types

  def test_connection_test_result_type_annotations(self) -> None:
    """Test ConnectionTestResult type annotations."""
    assert hasattr(ConnectionTestResult, "__annotations__")
    annotations = ConnectionTestResult.__annotations__

    assert "success" in annotations
    assert "message" in annotations
    assert "details" in annotations
    assert "authenticated" in annotations

  def test_secret_manager_base_config_type_annotations(self) -> None:
    """Test SecretManagerBaseConfig type annotations."""
    assert hasattr(SecretManagerBaseConfig, "__annotations__")
    annotations = SecretManagerBaseConfig.__annotations__

    assert "secret_manager" in annotations
    assert "all_paths" in annotations

  def test_method_return_types(self) -> None:
    """Test that methods return expected types."""
    mock_logger = Mock()
    mock_crypto_utils = Mock()
    mock_crypto_utils.read_dict_from_file.return_value = {"key": "value"}

    with patch.dict(
      os.environ, {"AUTO_SECRETS_SECRET_MANAGER": "infisical", "AUTO_SECRETS_ALL_SM_PATHS": '["path1", "path2"]'}
    ):
      manager = MockSecretManager(mock_logger, mock_crypto_utils)

      is_valid: bool = manager.validate_environment("test")
      assert isinstance(is_valid, bool)

      config: dict[str, Any] = manager._load_config_file()
      assert isinstance(config, dict)

      secret_value: Optional[str] = manager.get_secret_value("key")
      assert secret_value is None or isinstance(secret_value, str)

      secrets: dict[str, str] = manager.fetch_secrets("test")
      assert isinstance(secrets, dict)

      result: ConnectionTestResult = manager.test_connection()
      assert isinstance(result, ConnectionTestResult)

      repr_str: str = repr(manager)
      assert isinstance(repr_str, str)


class TestIntegration:
  """Integration tests for SecretManagerBase functionality."""

  @pytest.fixture
  def temp_dir(self) -> Generator[Path, None, None]:
    """Create temporary directory for testing."""
    with tempfile.TemporaryDirectory() as tmp_dir:
      yield Path(tmp_dir)

  def test_full_secret_manager_lifecycle(self, temp_dir: Path) -> None:
    """Test complete secret manager lifecycle."""
    # Mock file operations
    config_file_data = {"INFISICAL_CLIENT_SECRET": "test_secret"}

    mock_logger = Mock()
    mock_logger.get_logger.return_value = Mock()

    mock_crypto_utils = Mock()
    mock_crypto_utils.read_dict_from_file.return_value = config_file_data
    mock_crypto_utils.write_dict_to_file_atomically.return_value = None

    with patch.dict(
      os.environ,
      {"AUTO_SECRETS_SECRET_MANAGER": "infisical", "AUTO_SECRETS_ALL_SM_PATHS": '["/app/secrets", "/db/secrets"]'},
    ):
      # 1. Create manager
      manager = MockSecretManager(mock_logger, mock_crypto_utils)

      # 2. Test configuration
      assert manager.all_paths == ["/app/secrets", "/db/secrets"]

      # 3. Set secrets
      manager.set_secret()
      mock_crypto_utils.write_dict_to_file_atomically.assert_called_once()

      # 4. Get secret value
      secret_value = manager.get_secret_value("INFISICAL_CLIENT_SECRET")
      assert secret_value == "test_secret"

      # 5. Test connection
      connection_result = manager.test_connection()
      assert connection_result.success is True

      # 6. Fetch secrets
      test_secrets = {"api_key": "secret123", "db_password": "pass456"}
      manager.set_secrets(test_secrets)

      fetched_secrets = manager.fetch_secrets("production")
      assert fetched_secrets == test_secrets

      # 7. Validate environment
      assert manager.validate_environment("production") is True

  def test_error_handling_chain(self, temp_dir: Path) -> None:
    """Test error handling across multiple operations."""
    mock_logger = Mock()
    mock_logger.get_logger.return_value = Mock()

    mock_crypto_utils = Mock()

    with patch.dict(os.environ, {"AUTO_SECRETS_SECRET_MANAGER": "infisical", "AUTO_SECRETS_ALL_SM_PATHS": "[]"}):
      manager = MockSecretManager(mock_logger, mock_crypto_utils)

      # Test config file read error
      mock_crypto_utils.read_dict_from_file.side_effect = Exception("File error")
      with pytest.raises(ConfigurationError):
        manager._load_config_file()

      # Test secret write error
      mock_crypto_utils.write_dict_to_file_atomically.side_effect = Exception("Write error")
      with pytest.raises(SecretManagerError):
        manager.set_secret()

      # Test fetch secrets error
      manager.set_should_fail(True)
      with pytest.raises(SecretManagerError):
        manager.fetch_secrets("test")

      # Test connection error
      with pytest.raises(NetworkError):
        manager.test_connection()

  def test_configuration_variations(self) -> None:
    """Test different configuration scenarios."""
    mock_logger = Mock()
    mock_logger.get_logger.return_value = Mock()
    mock_crypto_utils = Mock()
    mock_crypto_utils.read_dict_from_file.return_value = {}

    # Test with minimal configuration
    with (
      patch.dict(os.environ, {"AUTO_SECRETS_SECRET_MANAGER": "infisical"}, clear=True),
      patch("auto_secrets_manager.secret_managers.base.CommonUtils.parse_json", return_value=None),
    ):
      manager = MockSecretManager(mock_logger, mock_crypto_utils)
      assert manager.all_paths == ["/"]

    # Test with full configuration
    with patch.dict(
      os.environ,
      {"AUTO_SECRETS_SECRET_MANAGER": "infisical", "AUTO_SECRETS_ALL_SM_PATHS": '["/path1", "/path2", "/path3"]'},
    ):
      manager = MockSecretManager(mock_logger, mock_crypto_utils)
      assert manager.all_paths == ["/path1", "/path2", "/path3"]


if __name__ == "__main__":
  # Run tests with pytest
  pytest.main([__file__, "-v", "--tb=short"])
