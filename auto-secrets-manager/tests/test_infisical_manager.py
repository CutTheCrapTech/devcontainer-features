"""
Tests for auto_secrets.secret_managers.infisical module.

Tests the InfisicalSecretManager implementation.
"""

import os
import pytest
from unittest.mock import Mock, patch
from dataclasses import dataclass

from auto_secrets.secret_managers.infisical import InfisicalSecretManager  # type: ignore
from auto_secrets.secret_managers.base import (  # type: ignore
    SecretManagerError,
    AuthenticationError,
)


# Mock classes to simulate Infisical SDK responses
@dataclass
class MockSecret:
    """Mock secret response from Infisical SDK."""
    secretKey: str
    secretValue: str
    secretPath: str


@dataclass
class MockSecretsResponse:
    """Mock secrets list response from Infisical SDK."""
    secrets: list


class TestInfisicalSecretManager:
    """Test InfisicalSecretManager class."""

    def setup_method(self):
        """Set up test fixtures."""
        self.valid_config = {
            "host": "https://app.infisical.com",
            "project_id": "test_project_123",
            "client_id": "test_client_456",
        }

        # Mock environment variables
        self.env_vars = {
            "INFISICAL_CLIENT_SECRET": "test_secret_789",
        }

    def teardown_method(self):
        """Clean up after tests."""
        # Clear any environment variables that might have been set
        for key in ["INFISICAL_PROJECT_ID", "INFISICAL_CLIENT_ID", "INFISICAL_CLIENT_SECRET"]:
            if key in os.environ:
                del os.environ[key]

    @patch.dict(os.environ, {"INFISICAL_CLIENT_SECRET": "test_secret_789"})
    @patch('auto_secrets.secret_managers.infisical.InfisicalSDKClient')
    def test_init_with_config(self, mock_sdk_client):
        """Test initialization with valid configuration."""
        manager = InfisicalSecretManager(self.valid_config)

        assert manager.host == "https://app.infisical.com"
        assert manager.project_id == "test_project_123"
        assert manager.client_id == "test_client_456"
        assert manager.client_secret == "test_secret_789"
        assert manager._client is None
        assert manager._authenticated is False

    @patch.dict(os.environ, {"INFISICAL_CLIENT_SECRET": "test_secret_789"})
    @patch('auto_secrets.secret_managers.infisical.InfisicalSDKClient')
    def test_init_with_default_host(self, mock_sdk_client):
        """Test initialization with default host."""
        config = self.valid_config.copy()
        del config["host"]

        manager = InfisicalSecretManager(config)

        assert manager.host == "https://app.infisical.com"  # Default value

    @patch.dict(os.environ, {"INFISICAL_PROJECT_ID": "env_project", "INFISICAL_CLIENT_SECRET": "test_secret"})
    @patch('auto_secrets.secret_managers.infisical.InfisicalSDKClient')
    def test_init_with_env_variables(self, mock_sdk_client):
        """Test initialization using environment variables."""
        config = {"client_id": "test_client"}

        manager = InfisicalSecretManager(config)

        assert manager.project_id == "env_project"
        assert manager.client_id == "test_client"

    @patch('auto_secrets.secret_managers.infisical.InfisicalSDKClient')
    def test_init_missing_project_id(self, mock_sdk_client):
        """Test initialization with missing project_id."""
        config = {"client_id": "test_client"}

        with pytest.raises(SecretManagerError, match="Infisical project_id is required"):
            InfisicalSecretManager(config)

    @patch.dict(os.environ, {"INFISICAL_CLIENT_SECRET": "test_secret"})
    @patch('auto_secrets.secret_managers.infisical.InfisicalSDKClient')
    def test_init_missing_client_id(self, mock_sdk_client):
        """Test initialization with missing client_id."""
        config = {"project_id": "test_project"}

        with pytest.raises(SecretManagerError, match="Infisical client_id is required"):
            InfisicalSecretManager(config)

    @patch.dict(os.environ, {}, clear=True)
    @patch('auto_secrets.secret_managers.infisical.InfisicalSDKClient')
    def test_init_missing_client_secret(self, mock_sdk_client):
        """Test initialization with missing client_secret."""
        with pytest.raises(SecretManagerError, match="Infisical client_secret is required"):
            InfisicalSecretManager(self.valid_config)

    @patch.dict(os.environ, {"INFISICAL_CLIENT_SECRET": "test_secret"})
    @patch('auto_secrets.secret_managers.infisical.InfisicalSDKClient')
    def test_get_client_initialization(self, mock_sdk_client):
        """Test client initialization."""
        mock_client_instance = Mock()
        mock_sdk_client.return_value = mock_client_instance

        manager = InfisicalSecretManager(self.valid_config)

        with patch.object(manager, '_authenticate'):
            client = manager._get_client()

            assert client == mock_client_instance
            mock_sdk_client.assert_called_once_with(
                host="https://app.infisical.com",
                cache_ttl=300
            )

    @patch.dict(os.environ, {"INFISICAL_CLIENT_SECRET": "test_secret"})
    @patch('auto_secrets.secret_managers.infisical.InfisicalSDKClient')
    def test_get_client_initialization_failure(self, mock_sdk_client):
        """Test client initialization failure."""
        mock_sdk_client.side_effect = Exception("SDK initialization failed")

        manager = InfisicalSecretManager(self.valid_config)

        with pytest.raises(SecretManagerError, match="Failed to initialize Infisical client"):
            manager._get_client()

    @patch.dict(os.environ, {"INFISICAL_CLIENT_SECRET": "test_secret"})
    @patch('auto_secrets.secret_managers.infisical.InfisicalSDKClient')
    def test_authenticate_success(self, mock_sdk_client):
        """Test successful authentication."""
        mock_client_instance = Mock()
        mock_auth = Mock()
        mock_universal_auth = Mock()
        mock_auth.universal_auth = mock_universal_auth
        mock_client_instance.auth = mock_auth
        mock_sdk_client.return_value = mock_client_instance

        manager = InfisicalSecretManager(self.valid_config)
        manager._client = mock_client_instance

        manager._authenticate()

        assert manager._authenticated is True
        mock_universal_auth.login.assert_called_once_with(
            client_id="test_client_456",
            client_secret="test_secret"
        )

    @patch.dict(os.environ, {"INFISICAL_CLIENT_SECRET": "test_secret"})
    @patch('auto_secrets.secret_managers.infisical.InfisicalSDKClient')
    def test_authenticate_failure(self, mock_sdk_client):
        """Test authentication failure."""
        mock_client_instance = Mock()
        mock_auth = Mock()
        mock_universal_auth = Mock()
        mock_universal_auth.login.side_effect = Exception("Auth failed")
        mock_auth.universal_auth = mock_universal_auth
        mock_client_instance.auth = mock_auth
        mock_sdk_client.return_value = mock_client_instance

        manager = InfisicalSecretManager(self.valid_config)
        manager._client = mock_client_instance

        with pytest.raises(AuthenticationError, match="Infisical authentication failed"):
            manager._authenticate()

    @patch.dict(os.environ, {"INFISICAL_CLIENT_SECRET": "test_secret"})
    @patch('auto_secrets.secret_managers.infisical.InfisicalSDKClient')
    def test_authenticate_no_client(self, mock_sdk_client):
        """Test authentication with no client initialized."""
        manager = InfisicalSecretManager(self.valid_config)

        with pytest.raises(SecretManagerError, match="Client not initialized"):
            manager._authenticate()

    @patch.dict(os.environ, {"INFISICAL_CLIENT_SECRET": "test_secret"})
    @patch('auto_secrets.secret_managers.infisical.InfisicalSDKClient')
    def test_fetch_secrets_success(self, mock_sdk_client):
        """Test successful secret fetching."""
        # Setup mock client and response
        mock_client_instance = Mock()
        mock_secrets = Mock()
        mock_client_instance.secrets = mock_secrets
        mock_sdk_client.return_value = mock_client_instance

        # Create mock secrets response
        mock_secret1 = MockSecret("API_KEY", "secret123", "/api")
        mock_secret2 = MockSecret("DB_PASS", "dbpass456", "/db")
        mock_response = MockSecretsResponse([mock_secret1, mock_secret2])
        mock_secrets.list_secrets.return_value = mock_response

        manager = InfisicalSecretManager(self.valid_config)

        with patch.object(manager, '_get_client', return_value=mock_client_instance):
            secrets = manager.fetch_secrets("production")

            expected = {
                "/api/API_KEY": "secret123",
                "/db/DB_PASS": "dbpass456"
            }
            assert secrets == expected

            mock_secrets.list_secrets.assert_called_once_with(
                project_id="test_project_123",
                environment_slug="production",
                secret_path="/",
                expand_secret_references=True,
                include_imports=True,
                recursive=True
            )

    @patch.dict(os.environ, {"INFISICAL_CLIENT_SECRET": "test_secret"})
    @patch('auto_secrets.secret_managers.infisical.InfisicalSDKClient')
    def test_fetch_secrets_with_paths(self, mock_sdk_client):
        """Test fetching secrets with specific paths."""
        mock_client_instance = Mock()
        mock_secrets = Mock()
        mock_client_instance.secrets = mock_secrets
        mock_sdk_client.return_value = mock_client_instance

        # Create mock response for each path
        mock_secret1 = MockSecret("API_KEY", "secret123", "/api")
        mock_secret2 = MockSecret("DB_PASS", "dbpass456", "/db")

        def mock_list_secrets(**kwargs):
            if kwargs["secret_path"] == "/api":
                return MockSecretsResponse([mock_secret1])
            elif kwargs["secret_path"] == "/db":
                return MockSecretsResponse([mock_secret2])
            return MockSecretsResponse([])

        mock_secrets.list_secrets.side_effect = mock_list_secrets

        manager = InfisicalSecretManager(self.valid_config)

        with patch.object(manager, '_get_client', return_value=mock_client_instance):
            secrets = manager.fetch_secrets("production", paths=["/api", "/db"])

            expected = {
                "/api/API_KEY": "secret123",
                "/db/DB_PASS": "dbpass456"
            }
            assert secrets == expected

            assert mock_secrets.list_secrets.call_count == 2

    @patch.dict(os.environ, {"INFISICAL_CLIENT_SECRET": "test_secret"})
    @patch('auto_secrets.secret_managers.infisical.InfisicalSDKClient')
    def test_fetch_secrets_invalid_environment(self, mock_sdk_client):
        """Test fetching secrets with invalid environment name."""
        manager = InfisicalSecretManager(self.valid_config)

        with pytest.raises(SecretManagerError, match="Invalid environment name"):
            manager.fetch_secrets("invalid-env-name-")

    @patch.dict(os.environ, {"INFISICAL_CLIENT_SECRET": "test_secret"})
    @patch('auto_secrets.secret_managers.infisical.InfisicalSDKClient')
    def test_fetch_secrets_api_error(self, mock_sdk_client):
        """Test fetching secrets with API error."""
        mock_client_instance = Mock()
        mock_secrets = Mock()
        mock_secrets.list_secrets.side_effect = Exception("API Error")
        mock_client_instance.secrets = mock_secrets
        mock_sdk_client.return_value = mock_client_instance

        manager = InfisicalSecretManager(self.valid_config)

        with patch.object(manager, '_get_client', return_value=mock_client_instance):
            with pytest.raises(SecretManagerError, match="Failed to fetch secrets"):
                manager.fetch_secrets("production")

    @patch.dict(os.environ, {"INFISICAL_CLIENT_SECRET": "test_secret"})
    @patch('auto_secrets.secret_managers.infisical.InfisicalSDKClient')
    def test_fetch_secrets_with_root_path_secrets(self, mock_sdk_client):
        """Test fetching secrets with root path normalization."""
        mock_client_instance = Mock()
        mock_secrets = Mock()
        mock_client_instance.secrets = mock_secrets
        mock_sdk_client.return_value = mock_client_instance

        # Secret at root path "/"
        mock_secret = MockSecret("ROOT_KEY", "rootvalue", "/")
        mock_response = MockSecretsResponse([mock_secret])
        mock_secrets.list_secrets.return_value = mock_response

        manager = InfisicalSecretManager(self.valid_config)

        with patch.object(manager, '_get_client', return_value=mock_client_instance):
            secrets = manager.fetch_secrets("production")

            expected = {"/ROOT_KEY": "rootvalue"}
            assert secrets == expected

    @patch.dict(os.environ, {"INFISICAL_CLIENT_SECRET": "test_secret"})
    @patch('auto_secrets.secret_managers.infisical.InfisicalSDKClient')
    def test_fetch_secrets_none_values_filtered(self, mock_sdk_client):
        """Test that secrets with None values are filtered out."""
        mock_client_instance = Mock()
        mock_secrets = Mock()
        mock_client_instance.secrets = mock_secrets
        mock_sdk_client.return_value = mock_client_instance

        # Mix of valid and invalid secrets
        mock_secret1 = MockSecret("VALID_KEY", "valid_value", "/")
        mock_secret2 = MockSecret("INVALID_KEY", None, "/")  # None value
        mock_secret3 = MockSecret("", "empty_key_value", "/")  # Empty key
        mock_secret4 = MockSecret("ANOTHER_VALID", "another_value", "/")

        mock_response = MockSecretsResponse([mock_secret1, mock_secret2, mock_secret3, mock_secret4])
        mock_secrets.list_secrets.return_value = mock_response

        manager = InfisicalSecretManager(self.valid_config)

        with patch.object(manager, '_get_client', return_value=mock_client_instance):
            secrets = manager.fetch_secrets("production")

            # Only valid secrets should be returned
            expected = {
                "/VALID_KEY": "valid_value",
                "/ANOTHER_VALID": "another_value"
            }
            assert secrets == expected

    @patch.dict(os.environ, {"INFISICAL_CLIENT_SECRET": "test_secret"})
    @patch('auto_secrets.secret_managers.infisical.InfisicalSDKClient')
    def test_test_connection_success(self, mock_sdk_client):
        """Test successful connection test."""
        mock_client_instance = Mock()
        mock_secrets = Mock()
        mock_client_instance.secrets = mock_secrets
        mock_sdk_client.return_value = mock_client_instance

        # Mock successful response
        mock_response = MockSecretsResponse([])
        mock_secrets.list_secrets.return_value = mock_response

        manager = InfisicalSecretManager(self.valid_config)

        with patch.object(manager, '_get_client', return_value=mock_client_instance):
            result = manager.test_connection()

            assert result.success is True
            assert result.authenticated is True
            assert "Connection test successful" in result.message
            assert "project_id" in result.details

    @patch.dict(os.environ, {"INFISICAL_CLIENT_SECRET": "test_secret"})
    @patch('auto_secrets.secret_managers.infisical.InfisicalSDKClient')
    def test_test_connection_network_error(self, mock_sdk_client):
        """Test connection test with network error."""
        mock_client_instance = Mock()
        mock_auth = Mock()
        mock_universal_auth = Mock()
        mock_universal_auth.login.side_effect = Exception("Network timeout")
        mock_auth.universal_auth = mock_universal_auth
        mock_client_instance.auth = mock_auth
        mock_sdk_client.return_value = mock_client_instance

        manager = InfisicalSecretManager(self.valid_config)

        result = manager.test_connection()

        assert result.success is False
        assert result.authenticated is False
        assert "Authentication failed" in result.message
        assert "Network timeout" in result.message

    @patch.dict(os.environ, {"INFISICAL_CLIENT_SECRET": "test_secret"})
    @patch('auto_secrets.secret_managers.infisical.InfisicalSDKClient')
    def test_repr(self, mock_sdk_client):
        """Test string representation."""
        manager = InfisicalSecretManager(self.valid_config)

        repr_str = repr(manager)
        assert "InfisicalSecretManager" in repr_str
        assert "config_keys=" in repr_str

    @patch.dict(os.environ, {"INFISICAL_CLIENT_SECRET": "test_secret"})
    @patch('auto_secrets.secret_managers.infisical.InfisicalSDKClient')
    def test_debug_logging(self, mock_sdk_client):
        """Test debug logging functionality."""
        config = self.valid_config.copy()

        manager = InfisicalSecretManager(config)

        with patch.object(manager, 'log_debug') as mock_log_debug:
            mock_client_instance = Mock()
            mock_secrets = Mock()
            mock_client_instance.secrets = mock_secrets
            mock_response = MockSecretsResponse([])
            mock_secrets.list_secrets.return_value = mock_response

            with patch.object(manager, '_get_client', return_value=mock_client_instance):
                manager.fetch_secrets("production")

                # Should have logged debug messages
                mock_log_debug.assert_called()

    @patch.dict(os.environ, {"INFISICAL_CLIENT_SECRET": "test_secret"})
    @patch('auto_secrets.secret_managers.infisical.InfisicalSDKClient')
    def test_path_normalization_in_fetch(self, mock_sdk_client):
        """Test path normalization during fetch."""
        mock_client_instance = Mock()
        mock_secrets = Mock()
        mock_client_instance.secrets = mock_secrets
        mock_sdk_client.return_value = mock_client_instance

        mock_response = MockSecretsResponse([])
        mock_secrets.list_secrets.return_value = mock_response

        manager = InfisicalSecretManager(self.valid_config)

        with patch.object(manager, '_get_client', return_value=mock_client_instance):
            # Test paths without leading slash
            manager.fetch_secrets("production", paths=["api", "db/passwords"])

            # Verify paths were normalized
            calls = mock_secrets.list_secrets.call_args_list
            paths_called = [call.kwargs["secret_path"] for call in calls]
            assert "/api" in paths_called
            assert "/db/passwords" in paths_called

    @patch.dict(os.environ, {"INFISICAL_CLIENT_SECRET": "test_secret"})
    @patch('auto_secrets.secret_managers.infisical.InfisicalSDKClient')
    def test_empty_secrets_response(self, mock_sdk_client):
        """Test handling empty secrets response."""
        mock_client_instance = Mock()
        mock_secrets = Mock()
        mock_client_instance.secrets = mock_secrets
        mock_sdk_client.return_value = mock_client_instance

        mock_response = MockSecretsResponse([])
        mock_secrets.list_secrets.return_value = mock_response

        manager = InfisicalSecretManager(self.valid_config)

        with patch.object(manager, '_get_client', return_value=mock_client_instance):
            secrets = manager.fetch_secrets("production")

            assert secrets == {}

    @patch.dict(os.environ, {"INFISICAL_CLIENT_SECRET": "test_secret"})
    @patch('auto_secrets.secret_managers.infisical.InfisicalSDKClient')
    def test_multiple_path_requests(self, mock_sdk_client):
        """Test fetching secrets from multiple paths."""
        mock_client_instance = Mock()
        mock_secrets = Mock()
        mock_client_instance.secrets = mock_secrets
        mock_sdk_client.return_value = mock_client_instance

        # Setup different responses for different paths
        def mock_list_secrets(**kwargs):
            path = kwargs["secret_path"]
            if path == "/api":
                return MockSecretsResponse([MockSecret("API_KEY", "api_value", "/api")])
            elif path == "/db":
                return MockSecretsResponse([MockSecret("DB_PASS", "db_value", "/db")])
            elif path == "/cache":
                return MockSecretsResponse([MockSecret("CACHE_KEY", "cache_value", "/cache")])
            return MockSecretsResponse([])

        mock_secrets.list_secrets.side_effect = mock_list_secrets

        manager = InfisicalSecretManager(self.valid_config)

        with patch.object(manager, '_get_client', return_value=mock_client_instance):
            secrets = manager.fetch_secrets("production", paths=["/api", "/db", "/cache"])

            expected = {
                "/api/API_KEY": "api_value",
                "/db/DB_PASS": "db_value",
                "/cache/CACHE_KEY": "cache_value"
            }
            assert secrets == expected
            assert mock_secrets.list_secrets.call_count == 3


class TestInfisicalSecretManagerIntegration:
    """Integration tests for InfisicalSecretManager."""

    @patch.dict(os.environ, {"INFISICAL_CLIENT_SECRET": "integration_secret"})
    @patch('auto_secrets.secret_managers.infisical.InfisicalSDKClient')
    def test_full_workflow(self, mock_sdk_client):
        """Test complete workflow from initialization to secret fetching."""
        config = {
            "host": "https://test.infisical.com",
            "project_id": "integration_project",
            "client_id": "integration_client",
            "debug": True
        }

        # Setup comprehensive mock
        mock_client_instance = Mock()
        mock_auth = Mock()
        mock_universal_auth = Mock()
        mock_secrets = Mock()

        mock_auth.universal_auth = mock_universal_auth
        mock_client_instance.auth = mock_auth
        mock_client_instance.secrets = mock_secrets
        mock_sdk_client.return_value = mock_client_instance

        # Mock secrets response
        mock_secrets_list = [
            MockSecret("API_KEY", "secret_api_value", "/api"),
            MockSecret("DB_PASSWORD", "secret_db_value", "/database"),
            MockSecret("CACHE_TOKEN", "secret_cache_value", "/cache")
        ]
        mock_response = MockSecretsResponse(mock_secrets_list)
        mock_secrets.list_secrets.return_value = mock_response

        # Test the workflow
        manager = InfisicalSecretManager(config)

        # 1. Test connection
        connection_result = manager.test_connection()
        assert connection_result.success is True
        assert connection_result.authenticated is True

        # 2. Fetch all secrets
        all_secrets = manager.fetch_secrets("production")
        expected_all = {
            "/api/API_KEY": "secret_api_value",
            "/database/DB_PASSWORD": "secret_db_value",
            "/cache/CACHE_TOKEN": "secret_cache_value"
        }
        assert all_secrets == expected_all

        # 3. Fetch filtered secrets
        with patch.object(manager, '_get_client', return_value=mock_client_instance):
            # Mock filtered response for /api path only
            api_response = MockSecretsResponse([MockSecret("API_KEY", "secret_api_value", "/api")])
            mock_secrets.list_secrets.return_value = api_response

            filtered_secrets = manager.fetch_secrets("production", paths=["/api"])
            expected_filtered = {"/api/API_KEY": "secret_api_value"}
            assert filtered_secrets == expected_filtered

        # Verify authentication was called
        mock_universal_auth.login.assert_called_with(
            client_id="integration_client",
            client_secret="integration_secret"
        )
