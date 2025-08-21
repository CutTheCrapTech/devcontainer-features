"""
Comprehensive unit tests for InfisicalSecretManager class.

This module provides complete test coverage for the InfisicalSecretManager class,
including initialization, configuration, authentication, secret fetching, and error handling.
"""

import os
from typing import Any
from unittest.mock import Mock, patch

import pytest

from auto_secrets.core.crypto_utils import CryptoUtils
from auto_secrets.managers.log_manager import AutoSecretsLogger, ComponentLoggerAdapter
from auto_secrets.secret_managers.base import (
  AuthenticationError,
  NetworkError,
  SecretManagerError,
  SecretNotFoundError,
)
from auto_secrets.secret_managers.infisical import (
  InfisicalConfig,
  InfisicalConfigError,
  InfisicalSecretManager,
)


class TestInfisicalConfig:
  """Test suite for InfisicalConfig dataclass."""

  def setup_method(self) -> None:
    """Clean up environment variables before each test."""
    if "AUTO_SECRETS_SECRET_MANAGER_CONFIG" in os.environ:
      del os.environ["AUTO_SECRETS_SECRET_MANAGER_CONFIG"]

  def teardown_method(self) -> None:
    """Clean up environment variables after each test."""
    if "AUTO_SECRETS_SECRET_MANAGER_CONFIG" in os.environ:
      del os.environ["AUTO_SECRETS_SECRET_MANAGER_CONFIG"]

  @patch("auto_secrets.secret_managers.infisical.CommonUtils.parse_json")
  def test_config_initialization_with_valid_env(self, mock_parse_json: Mock) -> None:
    """Test InfisicalConfig initialization with valid environment config."""
    config_dict = {
      "host": "https://infisical.example.com",
      "project_id": "test-project-123",
      "client_id": "test-client-456",
    }
    mock_parse_json.return_value = config_dict
    os.environ["AUTO_SECRETS_SECRET_MANAGER_CONFIG"] = '{"host": "https://infisical.example.com"}'

    config = InfisicalConfig()

    assert config.host == "https://infisical.example.com"
    assert config.project_id == "test-project-123"
    assert config.client_id == "test-client-456"
    mock_parse_json.assert_called_once_with(
      "AUTO_SECRETS_SECRET_MANAGER_CONFIG", '{"host": "https://infisical.example.com"}'
    )

  @patch("auto_secrets.secret_managers.infisical.CommonUtils.parse_json")
  def test_config_initialization_missing_host(self, mock_parse_json: Mock) -> None:
    """Test InfisicalConfig initialization fails with missing host."""
    config_dict = {"project_id": "test-project-123", "client_id": "test-client-456"}
    mock_parse_json.return_value = config_dict
    os.environ["AUTO_SECRETS_SECRET_MANAGER_CONFIG"] = "{}"

    with pytest.raises(InfisicalConfigError, match="Missing 'host' or invalid value"):
      InfisicalConfig()

  @patch("auto_secrets.secret_managers.infisical.CommonUtils.parse_json")
  def test_config_initialization_empty_host(self, mock_parse_json: Mock) -> None:
    """Test InfisicalConfig initialization fails with empty host."""
    config_dict = {"host": "", "project_id": "test-project-123", "client_id": "test-client-456"}
    mock_parse_json.return_value = config_dict

    with pytest.raises(InfisicalConfigError, match="Missing 'host' or invalid value"):
      InfisicalConfig()

  @patch("auto_secrets.secret_managers.infisical.CommonUtils.parse_json")
  def test_config_initialization_invalid_host_type(self, mock_parse_json: Mock) -> None:
    """Test InfisicalConfig initialization fails with invalid host type."""
    config_dict = {
      "host": 123,  # Invalid type
      "project_id": "test-project-123",
      "client_id": "test-client-456",
    }
    mock_parse_json.return_value = config_dict

    with pytest.raises(InfisicalConfigError, match="Missing 'host' or invalid value"):
      InfisicalConfig()

  @patch("auto_secrets.secret_managers.infisical.CommonUtils.parse_json")
  def test_config_initialization_missing_project_id(self, mock_parse_json: Mock) -> None:
    """Test InfisicalConfig initialization fails with missing project_id."""
    config_dict = {"host": "https://infisical.example.com", "client_id": "test-client-456"}
    mock_parse_json.return_value = config_dict

    with pytest.raises(InfisicalConfigError, match="Missing 'project_id' or invalid value"):
      InfisicalConfig()

  @patch("auto_secrets.secret_managers.infisical.CommonUtils.parse_json")
  def test_config_initialization_missing_client_id(self, mock_parse_json: Mock) -> None:
    """Test InfisicalConfig initialization fails with missing client_id."""
    config_dict = {"host": "https://infisical.example.com", "project_id": "test-project-123"}
    mock_parse_json.return_value = config_dict

    with pytest.raises(InfisicalConfigError, match="Missing 'client_id' or invalid value"):
      InfisicalConfig()

  @patch("auto_secrets.secret_managers.infisical.CommonUtils.parse_json")
  def test_config_initialization_default_env_var(self, mock_parse_json: Mock) -> None:
    """Test InfisicalConfig uses default empty config when env var missing."""
    config_dict = {
      "host": "https://infisical.example.com",
      "project_id": "test-project-123",
      "client_id": "test-client-456",
    }
    mock_parse_json.return_value = config_dict

    InfisicalConfig()

    mock_parse_json.assert_called_once_with("AUTO_SECRETS_SECRET_MANAGER_CONFIG", "{}")


class TestInfisicalSecretManagerInitialization:
  """Test suite for InfisicalSecretManager initialization."""

  @patch("auto_secrets.secret_managers.infisical.InfisicalConfig")
  def test_initialization_success(self, mock_config_class: Mock) -> None:
    """Test successful InfisicalSecretManager initialization."""
    # Setup mocks
    mock_logger = Mock(spec=AutoSecretsLogger)
    mock_component_logger = Mock(spec=ComponentLoggerAdapter)
    mock_logger.get_logger.return_value = mock_component_logger
    mock_crypto_utils = Mock(spec=CryptoUtils)

    mock_config = Mock()
    mock_config.host = "https://infisical.example.com"
    mock_config.project_id = "test-project-123"
    mock_config.client_id = "test-client-456"
    mock_config_class.return_value = mock_config

    with patch.object(InfisicalSecretManager, "get_secret_value", return_value="test-secret"):
      manager = InfisicalSecretManager(mock_logger, mock_crypto_utils)

      # Verify initialization
      assert manager.logger is mock_component_logger
      assert manager.crypto_utils is mock_crypto_utils
      assert manager.host == "https://infisical.example.com"
      assert manager.project_id == "test-project-123"
      assert manager.client_id == "test-client-456"
      assert manager.client_secret == "test-secret"
      assert manager._client is None
      assert manager._authenticated is False

      # Verify logger setup
      assert mock_logger.get_logger.call_count == 2
      mock_logger.get_logger.assert_any_call(name="secret_managers", component="base")
      mock_logger.get_logger.assert_any_call(name="secret_managers", component="infisical")

  @patch("auto_secrets.secret_managers.infisical.InfisicalConfig")
  def test_initialization_with_config_error(self, mock_config_class: Mock) -> None:
    """Test InfisicalSecretManager initialization with config error."""
    mock_logger = Mock(spec=AutoSecretsLogger)
    mock_crypto_utils = Mock(spec=CryptoUtils)

    mock_config_class.side_effect = InfisicalConfigError("Config error")

    with pytest.raises(InfisicalConfigError, match="Config error"):
      InfisicalSecretManager(mock_logger, mock_crypto_utils)

  @patch("auto_secrets.secret_managers.infisical.InfisicalConfig")
  def test_initialization_with_missing_client_secret(self, mock_config_class: Mock) -> None:
    """Test InfisicalSecretManager initialization with missing client secret."""
    mock_logger = Mock(spec=AutoSecretsLogger)
    mock_component_logger = Mock(spec=ComponentLoggerAdapter)
    mock_logger.get_logger.return_value = mock_component_logger
    mock_crypto_utils = Mock(spec=CryptoUtils)

    mock_config = Mock()
    mock_config.host = "https://infisical.example.com"
    mock_config.project_id = "test-project-123"
    mock_config.client_id = "test-client-456"
    mock_config_class.return_value = mock_config

    with (
      patch.object(InfisicalSecretManager, "get_secret_value", side_effect=SecretManagerError("Secret required")),
      pytest.raises(SecretManagerError, match="Secret required"),
    ):
      InfisicalSecretManager(mock_logger, mock_crypto_utils)


class TestInfisicalSecretManagerGetSecretJson:
  """Test suite for _get_secret_json method."""

  def setup_method(self) -> None:
    """Set up test fixtures."""
    self.mock_logger = Mock(spec=AutoSecretsLogger)
    self.mock_component_logger = Mock(spec=ComponentLoggerAdapter)
    self.mock_logger.get_logger.return_value = self.mock_component_logger
    self.mock_crypto_utils = Mock(spec=CryptoUtils)

  @patch("auto_secrets.secret_managers.infisical.InfisicalConfig")
  @patch("auto_secrets.secret_managers.infisical.getpass.getpass")
  def test_get_secret_json_success(self, mock_getpass: Mock, mock_config_class: Mock) -> None:
    """Test successful secret input via getpass."""
    # Setup config mock
    mock_config = Mock()
    mock_config.host = "https://infisical.example.com"
    mock_config.project_id = "test-project-123"
    mock_config.client_id = "test-client-456"
    mock_config_class.return_value = mock_config

    # Setup getpass mock
    mock_getpass.return_value = "test-client-secret"

    with patch.object(InfisicalSecretManager, "get_secret_value", return_value="test-secret"):
      manager = InfisicalSecretManager(self.mock_logger, self.mock_crypto_utils)

      result = manager._get_secret_json()

      expected_result = {"INFISICAL_CLIENT_SECRET": "test-client-secret"}
      assert result == expected_result
      mock_getpass.assert_called_once_with("Enter your Infisical Client Secret: ")

  @patch("auto_secrets.secret_managers.infisical.InfisicalConfig")
  @patch("auto_secrets.secret_managers.infisical.getpass.getpass")
  def test_get_secret_json_empty_input(self, mock_getpass: Mock, mock_config_class: Mock) -> None:
    """Test _get_secret_json with empty input."""
    # Setup config mock
    mock_config = Mock()
    mock_config.host = "https://infisical.example.com"
    mock_config.project_id = "test-project-123"
    mock_config.client_id = "test-client-456"
    mock_config_class.return_value = mock_config

    # Setup getpass mock to return empty string
    mock_getpass.return_value = ""

    with patch.object(InfisicalSecretManager, "get_secret_value", return_value="test-secret"):
      manager = InfisicalSecretManager(self.mock_logger, self.mock_crypto_utils)

      with pytest.raises(SecretManagerError, match="Infisical Client Secret cannot be empty"):
        manager._get_secret_json()

  @patch("auto_secrets.secret_managers.infisical.InfisicalConfig")
  @patch("auto_secrets.secret_managers.infisical.getpass.getpass")
  def test_get_secret_json_keyboard_interrupt(self, mock_getpass: Mock, mock_config_class: Mock) -> None:
    """Test _get_secret_json with keyboard interrupt (Ctrl+C)."""
    # Setup config mock
    mock_config = Mock()
    mock_config.host = "https://infisical.example.com"
    mock_config.project_id = "test-project-123"
    mock_config.client_id = "test-client-456"
    mock_config_class.return_value = mock_config

    # Setup getpass mock to raise KeyboardInterrupt
    mock_getpass.side_effect = KeyboardInterrupt()

    with patch.object(InfisicalSecretManager, "get_secret_value", return_value="test-secret"):
      manager = InfisicalSecretManager(self.mock_logger, self.mock_crypto_utils)

      with pytest.raises(SecretManagerError, match="User cancelled secret input"):
        manager._get_secret_json()

  @patch("auto_secrets.secret_managers.infisical.InfisicalConfig")
  @patch("auto_secrets.secret_managers.infisical.getpass.getpass")
  def test_get_secret_json_eof_error(self, mock_getpass: Mock, mock_config_class: Mock) -> None:
    """Test _get_secret_json with EOF error (Ctrl+D)."""
    # Setup config mock
    mock_config = Mock()
    mock_config.host = "https://infisical.example.com"
    mock_config.project_id = "test-project-123"
    mock_config.client_id = "test-client-456"
    mock_config_class.return_value = mock_config

    # Setup getpass mock to raise EOFError
    mock_getpass.side_effect = EOFError()

    with patch.object(InfisicalSecretManager, "get_secret_value", return_value="test-secret"):
      manager = InfisicalSecretManager(self.mock_logger, self.mock_crypto_utils)

      with pytest.raises(SecretManagerError, match="User cancelled secret input"):
        manager._get_secret_json()


class TestInfisicalSecretManagerClient:
  """Test suite for client initialization and authentication."""

  def setup_method(self) -> None:
    """Set up test fixtures."""
    self.mock_logger = Mock(spec=AutoSecretsLogger)
    self.mock_component_logger = Mock(spec=ComponentLoggerAdapter)
    self.mock_logger.get_logger.return_value = self.mock_component_logger
    self.mock_crypto_utils = Mock(spec=CryptoUtils)

  @patch("auto_secrets.secret_managers.infisical.InfisicalSDKClient")
  @patch("auto_secrets.secret_managers.infisical.InfisicalConfig")
  def test_get_client_initialization(self, mock_config_class: Mock, mock_sdk_client: Mock) -> None:
    """Test client initialization in _get_client."""
    # Setup config mock
    mock_config = Mock()
    mock_config.host = "https://infisical.example.com"
    mock_config.project_id = "test-project-123"
    mock_config.client_id = "test-client-456"
    mock_config_class.return_value = mock_config

    # Setup SDK client mock
    mock_client_instance = Mock()
    mock_sdk_client.return_value = mock_client_instance

    with (
      patch.object(InfisicalSecretManager, "get_secret_value", return_value="test-secret"),
      patch.object(InfisicalSecretManager, "_authenticate") as mock_auth,
    ):
      manager = InfisicalSecretManager(self.mock_logger, self.mock_crypto_utils)

      result = manager._get_client()

      assert result is mock_client_instance
      assert manager._client is mock_client_instance
      mock_sdk_client.assert_called_once_with(host="https://infisical.example.com", cache_ttl=300)
      mock_auth.assert_called_once()

  @patch("auto_secrets.secret_managers.infisical.InfisicalSDKClient")
  @patch("auto_secrets.secret_managers.infisical.InfisicalConfig")
  def test_get_client_initialization_error(self, mock_config_class: Mock, mock_sdk_client: Mock) -> None:
    """Test client initialization error in _get_client."""
    # Setup config mock
    mock_config = Mock()
    mock_config.host = "https://infisical.example.com"
    mock_config.project_id = "test-project-123"
    mock_config.client_id = "test-client-456"
    mock_config_class.return_value = mock_config

    # Setup SDK client mock to raise exception
    mock_sdk_client.side_effect = Exception("Client initialization failed")

    with patch.object(InfisicalSecretManager, "get_secret_value", return_value="test-secret"):
      manager = InfisicalSecretManager(self.mock_logger, self.mock_crypto_utils)

      with pytest.raises(SecretManagerError, match="Failed to initialize Infisical client"):
        manager._get_client()

  @patch("auto_secrets.secret_managers.infisical.InfisicalConfig")
  def test_get_client_cached(self, mock_config_class: Mock) -> None:
    """Test client caching in _get_client."""
    # Setup config mock
    mock_config = Mock()
    mock_config.host = "https://infisical.example.com"
    mock_config.project_id = "test-project-123"
    mock_config.client_id = "test-client-456"
    mock_config_class.return_value = mock_config

    with patch.object(InfisicalSecretManager, "get_secret_value", return_value="test-secret"):
      manager = InfisicalSecretManager(self.mock_logger, self.mock_crypto_utils)

      # Set up a mock client and mark as authenticated
      mock_client = Mock()
      manager._client = mock_client
      manager._authenticated = True

      result = manager._get_client()

      assert result is mock_client

  @patch("auto_secrets.secret_managers.infisical.InfisicalConfig")
  def test_authenticate_success(self, mock_config_class: Mock) -> None:
    """Test successful authentication."""
    # Setup config mock
    mock_config = Mock()
    mock_config.host = "https://infisical.example.com"
    mock_config.project_id = "test-project-123"
    mock_config.client_id = "test-client-456"
    mock_config_class.return_value = mock_config

    with patch.object(InfisicalSecretManager, "get_secret_value", return_value="test-secret"):
      manager = InfisicalSecretManager(self.mock_logger, self.mock_crypto_utils)

      # Set up mock client
      mock_client = Mock()
      mock_auth = Mock()
      mock_universal_auth = Mock()
      mock_client.auth = mock_auth
      mock_auth.universal_auth = mock_universal_auth
      manager._client = mock_client

      manager._authenticate()

      assert manager._authenticated is True
      mock_universal_auth.login.assert_called_once_with(client_id="test-client-456", client_secret="test-secret")
      self.mock_component_logger.debug.assert_called_with("Infisical authentication successful")

  @patch("auto_secrets.secret_managers.infisical.InfisicalConfig")
  def test_authenticate_no_client(self, mock_config_class: Mock) -> None:
    """Test authentication with no client initialized."""
    # Setup config mock
    mock_config = Mock()
    mock_config.host = "https://infisical.example.com"
    mock_config.project_id = "test-project-123"
    mock_config.client_id = "test-client-456"
    mock_config_class.return_value = mock_config

    with patch.object(InfisicalSecretManager, "get_secret_value", return_value="test-secret"):
      manager = InfisicalSecretManager(self.mock_logger, self.mock_crypto_utils)

      with pytest.raises(SecretManagerError, match="Client not initialized"):
        manager._authenticate()

  @patch("auto_secrets.secret_managers.infisical.InfisicalConfig")
  def test_authenticate_failure(self, mock_config_class: Mock) -> None:
    """Test authentication failure."""
    # Setup config mock
    mock_config = Mock()
    mock_config.host = "https://infisical.example.com"
    mock_config.project_id = "test-project-123"
    mock_config.client_id = "test-client-456"
    mock_config_class.return_value = mock_config

    with patch.object(InfisicalSecretManager, "get_secret_value", return_value="test-secret"):
      manager = InfisicalSecretManager(self.mock_logger, self.mock_crypto_utils)

      # Set up mock client that fails authentication
      mock_client = Mock()
      mock_auth = Mock()
      mock_universal_auth = Mock()
      mock_universal_auth.login.side_effect = Exception("Auth failed")
      mock_client.auth = mock_auth
      mock_auth.universal_auth = mock_universal_auth
      manager._client = mock_client

      with pytest.raises(AuthenticationError, match="Infisical authentication failed"):
        manager._authenticate()


class TestInfisicalSecretManagerFetchSecrets:
  """Test suite for fetch_secrets method."""

  def setup_method(self) -> None:
    """Set up test fixtures."""
    self.mock_logger = Mock(spec=AutoSecretsLogger)
    self.mock_component_logger = Mock(spec=ComponentLoggerAdapter)
    self.mock_logger.get_logger.return_value = self.mock_component_logger
    self.mock_crypto_utils = Mock(spec=CryptoUtils)

  @patch("auto_secrets.secret_managers.infisical.InfisicalConfig")
  def test_fetch_secrets_success(self, mock_config_class: Mock) -> None:
    """Test successful secret fetching."""
    # Setup config mock
    mock_config = Mock()
    mock_config.host = "https://infisical.example.com"
    mock_config.project_id = "test-project-123"
    mock_config.client_id = "test-client-456"
    mock_config_class.return_value = mock_config

    with patch.object(InfisicalSecretManager, "get_secret_value", return_value="test-secret"):
      manager = InfisicalSecretManager(self.mock_logger, self.mock_crypto_utils)

      # Set up validation and paths
      with patch.object(manager, "validate_environment", return_value=True):
        manager.all_paths = ["/", "/app"]

        # Set up mock client
        mock_client = Mock()
        mock_secrets = Mock()
        mock_secret1 = Mock()
        mock_secret1.secretKey = "DB_PASSWORD"
        mock_secret1.secretValue = "secret123"
        mock_secret1.secretPath = "/"

        mock_secret2 = Mock()
        mock_secret2.secretKey = "API_KEY"
        mock_secret2.secretValue = "api456"
        mock_secret2.secretPath = "/app"

        mock_response = Mock()
        mock_response.secrets = [mock_secret1, mock_secret2]
        mock_secrets.list_secrets.return_value = mock_response
        mock_client.secrets = mock_secrets

        with patch.object(manager, "_get_client", return_value=mock_client):
          result = manager.fetch_secrets("production")

          expected_result = {"/DB_PASSWORD": "secret123", "/app/API_KEY": "api456"}
          assert result == expected_result

          # Verify calls
          assert mock_secrets.list_secrets.call_count == 2
          mock_secrets.list_secrets.assert_any_call(
            project_id="test-project-123",
            environment_slug="production",
            secret_path="/",
            expand_secret_references=True,
            include_imports=True,
            recursive=True,
          )
          mock_secrets.list_secrets.assert_any_call(
            project_id="test-project-123",
            environment_slug="production",
            secret_path="/app",
            expand_secret_references=True,
            include_imports=True,
            recursive=True,
          )

  @patch("auto_secrets.secret_managers.infisical.InfisicalConfig")
  def test_fetch_secrets_invalid_environment(self, mock_config_class: Mock) -> None:
    """Test fetch_secrets with invalid environment."""
    # Setup config mock
    mock_config = Mock()
    mock_config.host = "https://infisical.example.com"
    mock_config.project_id = "test-project-123"
    mock_config.client_id = "test-client-456"
    mock_config_class.return_value = mock_config

    with patch.object(InfisicalSecretManager, "get_secret_value", return_value="test-secret"):
      manager = InfisicalSecretManager(self.mock_logger, self.mock_crypto_utils)

      with (
        patch.object(manager, "validate_environment", return_value=False),
        pytest.raises(SecretManagerError, match="Invalid environment name"),
      ):
        manager.fetch_secrets("invalid-env")

  @patch("auto_secrets.secret_managers.infisical.InfisicalConfig")
  def test_fetch_secrets_authentication_error(self, mock_config_class: Mock) -> None:
    """Test fetch_secrets with authentication error."""
    # Setup config mock
    mock_config = Mock()
    mock_config.host = "https://infisical.example.com"
    mock_config.project_id = "test-project-123"
    mock_config.client_id = "test-client-456"
    mock_config_class.return_value = mock_config

    with patch.object(InfisicalSecretManager, "get_secret_value", return_value="test-secret"):
      manager = InfisicalSecretManager(self.mock_logger, self.mock_crypto_utils)

      with patch.object(manager, "validate_environment", return_value=True):
        manager.all_paths = ["/"]
        mock_client = Mock()
        mock_secrets = Mock()
        mock_secrets.list_secrets.side_effect = Exception("unauthorized access")
        mock_client.secrets = mock_secrets

        with (
          patch.object(manager, "_get_client", return_value=mock_client),
          pytest.raises(AuthenticationError, match="Insufficient permissions"),
        ):
          manager.fetch_secrets("production")

  @patch("auto_secrets.secret_managers.infisical.InfisicalConfig")
  def test_fetch_secrets_network_error(self, mock_config_class: Mock) -> None:
    """Test fetch_secrets with network error."""
    # Setup config mock
    mock_config = Mock()
    mock_config.host = "https://infisical.example.com"
    mock_config.project_id = "test-project-123"
    mock_config.client_id = "test-client-456"
    mock_config_class.return_value = mock_config

    with patch.object(InfisicalSecretManager, "get_secret_value", return_value="test-secret"):
      manager = InfisicalSecretManager(self.mock_logger, self.mock_crypto_utils)

      with patch.object(manager, "validate_environment", return_value=True):
        manager.all_paths = ["/"]
        mock_client = Mock()
        mock_secrets = Mock()
        mock_secrets.list_secrets.side_effect = Exception("network timeout")
        mock_client.secrets = mock_secrets

        with (
          patch.object(manager, "_get_client", return_value=mock_client),
          pytest.raises(NetworkError, match="Network error fetching secrets"),
        ):
          manager.fetch_secrets("production")

  @patch("auto_secrets.secret_managers.infisical.InfisicalConfig")
  def test_fetch_secrets_project_not_found(self, mock_config_class: Mock) -> None:
    """Test fetch_secrets with project not found error."""
    # Setup config mock
    mock_config = Mock()
    mock_config.host = "https://infisical.example.com"
    mock_config.project_id = "test-project-123"
    mock_config.client_id = "test-client-456"
    mock_config_class.return_value = mock_config

    with patch.object(InfisicalSecretManager, "get_secret_value", return_value="test-secret"):
      manager = InfisicalSecretManager(self.mock_logger, self.mock_crypto_utils)

      with patch.object(manager, "validate_environment", return_value=True):
        manager.all_paths = ["/"]
        mock_client = Mock()
        mock_secrets = Mock()
        mock_secrets.list_secrets.side_effect = Exception("project not found")
        mock_client.secrets = mock_secrets

        with (
          patch.object(manager, "_get_client", return_value=mock_client),
          pytest.raises(SecretNotFoundError, match="Project 'test-project-123' not found"),
        ):
          manager.fetch_secrets("production")

  @patch("auto_secrets.secret_managers.infisical.InfisicalConfig")
  def test_fetch_secrets_environment_not_found(self, mock_config_class: Mock) -> None:
    """Test fetch_secrets with environment not found error."""
    # Setup config mock
    mock_config = Mock()
    mock_config.host = "https://infisical.example.com"
    mock_config.project_id = "test-project-123"
    mock_config.client_id = "test-client-456"
    mock_config_class.return_value = mock_config

    with patch.object(InfisicalSecretManager, "get_secret_value", return_value="test-secret"):
      manager = InfisicalSecretManager(self.mock_logger, self.mock_crypto_utils)

      with patch.object(manager, "validate_environment", return_value=True):
        manager.all_paths = ["/"]
        mock_client = Mock()
        mock_secrets = Mock()
        mock_secrets.list_secrets.side_effect = Exception("environment not found")
        mock_client.secrets = mock_secrets

        with (
          patch.object(manager, "_get_client", return_value=mock_client),
          pytest.raises(SecretNotFoundError, match="Environment 'production' not found"),
        ):
          manager.fetch_secrets("production")

  @patch("auto_secrets.secret_managers.infisical.InfisicalConfig")
  def test_fetch_secrets_empty_results(self, mock_config_class: Mock) -> None:
    """Test fetch_secrets with no secrets found."""
    # Setup config mock
    mock_config = Mock()
    mock_config.host = "https://infisical.example.com"
    mock_config.project_id = "test-project-123"
    mock_config.client_id = "test-client-456"
    mock_config_class.return_value = mock_config

    with patch.object(InfisicalSecretManager, "get_secret_value", return_value="test-secret"):
      manager = InfisicalSecretManager(self.mock_logger, self.mock_crypto_utils)

      with patch.object(manager, "validate_environment", return_value=True):
        manager.all_paths = ["/app"]
        mock_client = Mock()
        mock_secrets = Mock()
        mock_response = Mock()
        mock_response.secrets = []  # No secrets found
        mock_secrets.list_secrets.return_value = mock_response
        mock_client.secrets = mock_secrets

        with patch.object(manager, "_get_client", return_value=mock_client):
          result = manager.fetch_secrets("production")
          assert result == {}
          self.mock_component_logger.debug.assert_any_call(
            "No secrets found for paths ['/app'] in environment production"
          )

  @patch("auto_secrets.secret_managers.infisical.InfisicalConfig")
  def test_fetch_secrets_with_none_values(self, mock_config_class: Mock) -> None:
    """Test fetch_secrets filtering out secrets with None values."""
    # Setup config mock
    mock_config = Mock()
    mock_config.host = "https://infisical.example.com"
    mock_config.project_id = "test-project-123"
    mock_config.client_id = "test-client-456"
    mock_config_class.return_value = mock_config

    with patch.object(InfisicalSecretManager, "get_secret_value", return_value="test-secret"):
      manager = InfisicalSecretManager(self.mock_logger, self.mock_crypto_utils)

      with patch.object(manager, "validate_environment", return_value=True):
        manager.all_paths = ["/"]
        mock_client = Mock()
        mock_secrets = Mock()
        # Create secrets with some having None values
        mock_secret1 = Mock()
        mock_secret1.secretKey = "VALID_SECRET"
        mock_secret1.secretValue = "valid_value"
        mock_secret1.secretPath = "/"
        mock_secret2 = Mock()
        mock_secret2.secretKey = "NONE_VALUE_SECRET"
        mock_secret2.secretValue = None  # This should be filtered out
        mock_secret2.secretPath = "/"
        mock_secret3 = Mock()
        mock_secret3.secretKey = None  # This should be filtered out
        mock_secret3.secretValue = "value"
        mock_secret3.secretPath = "/"
        mock_response = Mock()
        mock_response.secrets = [mock_secret1, mock_secret2, mock_secret3]
        mock_secrets.list_secrets.return_value = mock_response
        mock_client.secrets = mock_secrets

        with patch.object(manager, "_get_client", return_value=mock_client):
          result = manager.fetch_secrets("production")
          # Only valid secret should be included
          expected_result = {"/VALID_SECRET": "valid_value"}
          assert result == expected_result


class TestInfisicalSecretManagerTestConnection:
  """Test suite for test_connection method."""

  def setup_method(self) -> None:
    """Set up test fixtures."""
    self.mock_logger = Mock(spec=AutoSecretsLogger)
    self.mock_component_logger = Mock(spec=ComponentLoggerAdapter)
    self.mock_logger.get_logger.return_value = self.mock_component_logger
    self.mock_crypto_utils = Mock(spec=CryptoUtils)

  @patch("auto_secrets.secret_managers.infisical.InfisicalConfig")
  def test_connection_test_success(self, mock_config_class: Mock) -> None:
    """Test successful connection test."""
    # Setup config mock
    mock_config = Mock()
    mock_config.host = "https://infisical.example.com"
    mock_config.project_id = "test-project-123"
    mock_config.client_id = "test-client-456"
    mock_config_class.return_value = mock_config

    with patch.object(InfisicalSecretManager, "get_secret_value", return_value="test-secret"):
      manager = InfisicalSecretManager(self.mock_logger, self.mock_crypto_utils)

      # Mock successful client and authentication
      mock_client = Mock()
      mock_auth = Mock()
      mock_universal_auth = Mock()
      mock_client.auth = mock_auth
      mock_auth.universal_auth = mock_universal_auth

      with patch.object(manager, "_get_client", return_value=mock_client):
        result = manager.test_connection()

        assert result.success is True
        assert result.authenticated is True
        assert result.message == "Connection test successful"
        assert result.details["sdk_available"] is True
        assert result.details["authenticated"] is True
        assert result.details["project_access"] is True
        assert result.details["host"] == "https://infisical.example.com"
        assert result.details["project_id"] == "test-project-123"

  @patch("auto_secrets.secret_managers.infisical.InfisicalConfig")
  def test_connection_test_authentication_failure(self, mock_config_class: Mock) -> None:
    """Test connection test with authentication failure."""
    # Setup config mock
    mock_config = Mock()
    mock_config.host = "https://infisical.example.com"
    mock_config.project_id = "test-project-123"
    mock_config.client_id = "test-client-456"
    mock_config_class.return_value = mock_config

    with patch.object(InfisicalSecretManager, "get_secret_value", return_value="test-secret"):
      manager = InfisicalSecretManager(self.mock_logger, self.mock_crypto_utils)

      # Mock authentication failure
      with patch.object(manager, "_get_client", side_effect=AuthenticationError("Auth failed")):
        result = manager.test_connection()

        assert result.success is False
        assert result.authenticated is False
        assert "Authentication failed: Auth failed" in result.message
        assert result.details["sdk_available"] is False
        assert result.details["authenticated"] is False
        assert result.details["project_access"] is False

  @patch("auto_secrets.secret_managers.infisical.InfisicalConfig")
  def test_connection_test_client_initialization_failure(self, mock_config_class: Mock) -> None:
    """Test connection test with client initialization failure."""
    # Setup config mock
    mock_config = Mock()
    mock_config.host = "https://infisical.example.com"
    mock_config.project_id = "test-project-123"
    mock_config.client_id = "test-client-456"
    mock_config_class.return_value = mock_config

    with patch.object(InfisicalSecretManager, "get_secret_value", return_value="test-secret"):
      manager = InfisicalSecretManager(self.mock_logger, self.mock_crypto_utils)

      # Mock client initialization failure
      with patch.object(manager, "_get_client", side_effect=Exception("Client init failed")):
        result = manager.test_connection()

        assert result.success is False
        assert result.authenticated is False
        assert "Failed to initialize client: Client init failed" in result.message
        assert result.details["sdk_available"] is False
        assert result.details["authenticated"] is False
        assert result.details["project_access"] is False

  @patch("auto_secrets.secret_managers.infisical.InfisicalConfig")
  def test_connection_test_unexpected_exception(self, mock_config_class: Mock) -> None:
    """Test connection test with unexpected exception."""
    # Setup config mock
    mock_config = Mock()
    mock_config.host = "https://infisical.example.com"
    mock_config.project_id = "test-project-123"
    mock_config.client_id = "test-client-456"
    mock_config_class.return_value = mock_config

    with (
      patch.object(InfisicalSecretManager, "get_secret_value", side_effect=Exception("Unexpected error")),
      pytest.raises(Exception, match="Unexpected error"),
    ):
      InfisicalSecretManager(self.mock_logger, self.mock_crypto_utils)


class TestInfisicalSecretManagerClearCache:
  """Test suite for clear_authentication_cache method."""

  def setup_method(self) -> None:
    """Set up test fixtures."""
    self.mock_logger = Mock(spec=AutoSecretsLogger)
    self.mock_component_logger = Mock(spec=ComponentLoggerAdapter)
    self.mock_logger.get_logger.return_value = self.mock_component_logger
    self.mock_crypto_utils = Mock(spec=CryptoUtils)

  @patch("auto_secrets.secret_managers.infisical.InfisicalConfig")
  def test_clear_authentication_cache(self, mock_config_class: Mock) -> None:
    """Test clearing authentication cache."""
    # Setup config mock
    mock_config = Mock()
    mock_config.host = "https://infisical.example.com"
    mock_config.project_id = "test-project-123"
    mock_config.client_id = "test-client-456"
    mock_config_class.return_value = mock_config

    with patch.object(InfisicalSecretManager, "get_secret_value", return_value="test-secret"):
      manager = InfisicalSecretManager(self.mock_logger, self.mock_crypto_utils)

      # Set up authenticated state
      manager._client = Mock()
      manager._authenticated = True

      # Clear cache
      manager.clear_authentication_cache()

      # Verify state is cleared
      assert manager._authenticated is False
      assert manager._client is None

  @patch("auto_secrets.secret_managers.infisical.InfisicalConfig")
  def test_clear_authentication_cache_no_client(self, mock_config_class: Mock) -> None:
    """Test clearing authentication cache with no existing client."""
    # Setup config mock
    mock_config = Mock()
    mock_config.host = "https://infisical.example.com"
    mock_config.project_id = "test-project-123"
    mock_config.client_id = "test-client-456"
    mock_config_class.return_value = mock_config

    with patch.object(InfisicalSecretManager, "get_secret_value", return_value="test-secret"):
      manager = InfisicalSecretManager(self.mock_logger, self.mock_crypto_utils)

      # Initial state - no client, not authenticated
      assert manager._client is None
      assert manager._authenticated is False

      # Clear cache (should not raise error)
      manager.clear_authentication_cache()

      # Verify state remains the same
      assert manager._authenticated is False
      assert manager._client is None


class TestInfisicalSecretManagerIntegration:
  """Integration tests for InfisicalSecretManager."""

  def setup_method(self) -> None:
    """Set up test fixtures."""
    self.mock_logger = Mock(spec=AutoSecretsLogger)
    self.mock_component_logger = Mock(spec=ComponentLoggerAdapter)
    self.mock_logger.get_logger.return_value = self.mock_component_logger
    self.mock_crypto_utils = Mock(spec=CryptoUtils)

  @patch("auto_secrets.secret_managers.infisical.InfisicalSDKClient")
  @patch("auto_secrets.secret_managers.infisical.InfisicalConfig")
  def test_full_workflow_success(self, mock_config_class: Mock, mock_sdk_client: Mock) -> None:
    """Test complete workflow from initialization to secret fetching."""
    # Setup config mock
    mock_config = Mock()
    mock_config.host = "https://infisical.example.com"
    mock_config.project_id = "test-project-123"
    mock_config.client_id = "test-client-456"
    mock_config_class.return_value = mock_config

    # Setup SDK client mock
    mock_client_instance = Mock()
    mock_auth = Mock()
    mock_universal_auth = Mock()
    mock_secrets = Mock()
    mock_client_instance.auth = mock_auth
    mock_auth.universal_auth = mock_universal_auth
    mock_client_instance.secrets = mock_secrets

    # Setup secret response
    mock_secret = Mock()
    mock_secret.secretKey = "DATABASE_URL"
    mock_secret.secretValue = "postgresql://localhost:5432/db"
    mock_secret.secretPath = "/"
    mock_response = Mock()
    mock_response.secrets = [mock_secret]
    mock_secrets.list_secrets.return_value = mock_response
    mock_sdk_client.return_value = mock_client_instance

    with patch.object(InfisicalSecretManager, "get_secret_value", return_value="test-client-secret"):
      manager = InfisicalSecretManager(self.mock_logger, self.mock_crypto_utils)

      with patch.object(manager, "validate_environment", return_value=True):
        manager.all_paths = ["/"]

        # Test connection first
        connection_result = manager.test_connection()
        assert connection_result.success is True

        # Fetch secrets
        secrets = manager.fetch_secrets("production")
        expected_secrets = {"/DATABASE_URL": "postgresql://localhost:5432/db"}
        assert secrets == expected_secrets

        # Verify client was properly initialized and authenticated
        mock_sdk_client.assert_called_once_with(host="https://infisical.example.com", cache_ttl=300)
        mock_universal_auth.login.assert_called_with(client_id="test-client-456", client_secret="test-client-secret")

  @patch("auto_secrets.secret_managers.infisical.InfisicalConfig")
  def test_authentication_retry_after_cache_clear(self, mock_config_class: Mock) -> None:
    """Test that authentication is retried after clearing cache."""
    # Setup config mock
    mock_config = Mock()
    mock_config.host = "https://infisical.example.com"
    mock_config.project_id = "test-project-123"
    mock_config.client_id = "test-client-456"
    mock_config_class.return_value = mock_config

    with patch.object(InfisicalSecretManager, "get_secret_value", return_value="test-secret"):
      manager = InfisicalSecretManager(self.mock_logger, self.mock_crypto_utils)

      # Set up mock client and authenticate
      mock_client = Mock()
      manager._client = mock_client
      manager._authenticated = True

      # Clear cache
      manager.clear_authentication_cache()

      # Verify cache is cleared
      assert manager._authenticated is False
      assert manager._client is None

      with (  # type: ignore[unreachable]
        patch.object(manager, "_authenticate") as mock_auth,
        patch("auto_secrets.secret_managers.infisical.InfisicalSDKClient") as mock_sdk_client,
      ):
        mock_new_client = Mock()
        mock_sdk_client.return_value = mock_new_client

        result = manager._get_client()

        assert result is mock_new_client
        mock_auth.assert_called_once()


class TestInfisicalSecretManagerTypeAnnotations:
  """Test suite for verifying type annotations and mypy compatibility."""

  def test_type_annotations_exist(self) -> None:
    """Test that proper type annotations exist on all methods."""
    # Verify __init__ annotations
    init_annotations = InfisicalSecretManager.__init__.__annotations__
    assert "log_manager" in init_annotations
    assert "crypto_utils" in init_annotations
    assert "return" in init_annotations
    assert init_annotations["return"] is None

    # Verify fetch_secrets annotations
    fetch_secrets_annotations = InfisicalSecretManager.fetch_secrets.__annotations__
    assert "environment" in fetch_secrets_annotations
    assert "return" in fetch_secrets_annotations

    # Verify test_connection annotations
    test_connection_annotations = InfisicalSecretManager.test_connection.__annotations__
    assert "return" in test_connection_annotations

    # Verify clear_authentication_cache annotations
    clear_cache_annotations = InfisicalSecretManager.clear_authentication_cache.__annotations__
    assert "return" in clear_cache_annotations
    assert clear_cache_annotations["return"] is None

  def test_infisical_config_annotations(self) -> None:
    """Test InfisicalConfig dataclass annotations."""
    annotations = InfisicalConfig.__annotations__
    assert "host" in annotations
    assert "project_id" in annotations
    assert "client_id" in annotations

  def test_method_return_types(self) -> None:
    """Test that methods have proper return type annotations."""
    # _get_secret_json should return dict[str, str]
    get_secret_json_annotations = InfisicalSecretManager._get_secret_json.__annotations__
    assert "return" in get_secret_json_annotations

    # _get_client should return InfisicalSDKClient
    get_client_annotations = InfisicalSecretManager._get_client.__annotations__
    assert "return" in get_client_annotations

    # _authenticate should return None
    authenticate_annotations = InfisicalSecretManager._authenticate.__annotations__
    assert "return" in authenticate_annotations
    assert authenticate_annotations["return"] is None


class TestInfisicalSecretManagerErrorHandling:
  """Test suite for error handling scenarios."""

  def setup_method(self) -> None:
    """Set up test fixtures."""
    self.mock_logger = Mock(spec=AutoSecretsLogger)
    self.mock_component_logger = Mock(spec=ComponentLoggerAdapter)
    self.mock_logger.get_logger.return_value = self.mock_component_logger
    self.mock_crypto_utils = Mock(spec=CryptoUtils)

  @patch("auto_secrets.secret_managers.infisical.InfisicalConfig")
  def test_multiple_path_errors_handling(self, mock_config_class: Mock) -> None:
    """Test error handling when multiple paths fail."""
    # Setup config mock
    mock_config = Mock()
    mock_config.host = "https://infisical.example.com"
    mock_config.project_id = "test-project-123"
    mock_config.client_id = "test-client-456"
    mock_config_class.return_value = mock_config
    with patch.object(InfisicalSecretManager, "get_secret_value", return_value="test-secret"):
      manager = InfisicalSecretManager(self.mock_logger, self.mock_crypto_utils)
      with patch.object(manager, "validate_environment", return_value=True):
        manager.all_paths = ["/app", "/config"]
        mock_client = Mock()
        mock_secrets = Mock()

        def list_secrets_side_effect(*args: Any, **kwargs: Any) -> Mock:
          secret_path = kwargs.get("secret_path")
          if secret_path == "/app":
            mock_secret = Mock()
            mock_secret.secretKey = "APP_SECRET"
            mock_secret.secretValue = "app_value"
            mock_secret.secretPath = "/app"
            mock_response = Mock()
            mock_response.secrets = [mock_secret]
            return mock_response
          elif secret_path == "/config":
            raise Exception("unauthorized access")
          # Handle case where secret_path doesn't match expected values
          return Mock()

        mock_secrets.list_secrets.side_effect = list_secrets_side_effect
        mock_client.secrets = mock_secrets
        # Should raise error for the unauthorized path
        with (
          patch.object(manager, "_get_client", return_value=mock_client),
          pytest.raises(AuthenticationError, match="Insufficient permissions"),
        ):
          manager.fetch_secrets("production")

  @patch("auto_secrets.secret_managers.infisical.InfisicalConfig")
  def test_secret_path_normalization(self, mock_config_class: Mock) -> None:
    """Test that secret paths are properly normalized."""
    # Setup config mock
    mock_config = Mock()
    mock_config.host = "https://infisical.example.com"
    mock_config.project_id = "test-project-123"
    mock_config.client_id = "test-client-456"
    mock_config_class.return_value = mock_config

    with patch.object(InfisicalSecretManager, "get_secret_value", return_value="test-secret"):
      manager = InfisicalSecretManager(self.mock_logger, self.mock_crypto_utils)

      with patch.object(manager, "validate_environment", return_value=True):
        manager.all_paths = ["app", "/config/"]  # Mixed path formats
        mock_client = Mock()
        mock_secrets = Mock()
        mock_response = Mock()
        mock_response.secrets = []
        mock_secrets.list_secrets.return_value = mock_response
        mock_client.secrets = mock_secrets

        with patch.object(manager, "_get_client", return_value=mock_client):
          manager.fetch_secrets("production")
          # Verify paths were normalized
          call_args_list = mock_secrets.list_secrets.call_args_list
          paths_called = [call.kwargs["secret_path"] for call in call_args_list]
          assert "/app" in paths_called
          assert "/config/" in paths_called


# Fixtures for reuse across test classes
@pytest.fixture
def mock_infisical_config() -> Mock:
  """Create a mock InfisicalConfig."""
  config = Mock()
  config.host = "https://infisical.example.com"
  config.project_id = "test-project-123"
  config.client_id = "test-client-456"
  return config


@pytest.fixture
def mock_logger_setup() -> tuple[Mock, Mock]:
  """Create mock logger setup."""
  mock_logger = Mock(spec=AutoSecretsLogger)
  mock_component_logger = Mock(spec=ComponentLoggerAdapter)
  mock_logger.get_logger.return_value = mock_component_logger
  return mock_logger, mock_component_logger


@pytest.fixture
def infisical_manager_with_mocks(
  mock_logger_setup: tuple[Mock, Mock], mock_infisical_config: Mock
) -> InfisicalSecretManager:
  """Create InfisicalSecretManager instance with mocked dependencies."""
  mock_logger, _ = mock_logger_setup
  mock_crypto_utils = Mock(spec=CryptoUtils)

  with patch("auto_secrets.secret_managers.infisical.InfisicalConfig") as mock_config_class:
    mock_config_class.return_value = mock_infisical_config

    with patch.object(InfisicalSecretManager, "get_secret_value", return_value="test-secret"):
      return InfisicalSecretManager(mock_logger, mock_crypto_utils)


if __name__ == "__main__":
  pytest.main([__file__])
