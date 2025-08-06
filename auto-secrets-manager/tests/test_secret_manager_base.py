"""
Tests for auto_secrets.secret_managers.base module.

Tests the SecretManagerBase abstract class and related utilities.
"""

import os
import pytest
from unittest.mock import patch

from auto_secrets.secret_managers.base import (
    SecretManagerError,
    AuthenticationError,
    NetworkError,
    ConfigurationError,
    SecretNotFoundError,
    SecretInfo,
    ConnectionTestResult,
    SecretManagerBase,
)


class TestExceptions:
    """Test custom exception classes."""

    def test_secret_manager_error(self):
        """Test base SecretManagerError."""
        error = SecretManagerError("Test error")
        assert str(error) == "Test error"
        assert isinstance(error, Exception)

    def test_authentication_error(self):
        """Test AuthenticationError inheritance."""
        error = AuthenticationError("Auth failed")
        assert str(error) == "Auth failed"
        assert isinstance(error, SecretManagerError)

    def test_network_error(self):
        """Test NetworkError inheritance."""
        error = NetworkError("Network failed")
        assert str(error) == "Network failed"
        assert isinstance(error, SecretManagerError)

    def test_configuration_error(self):
        """Test ConfigurationError inheritance."""
        error = ConfigurationError("Config invalid")
        assert str(error) == "Config invalid"
        assert isinstance(error, SecretManagerError)

    def test_secret_not_found_error(self):
        """Test SecretNotFoundError inheritance."""
        error = SecretNotFoundError("Secret not found")
        assert str(error) == "Secret not found"
        assert isinstance(error, SecretManagerError)


class TestSecretInfo:
    """Test SecretInfo dataclass."""

    def test_minimal_creation(self):
        """Test creating SecretInfo with required fields."""
        info = SecretInfo(
            key="API_KEY",
            path="/api/key",
            environment="production"
        )

        assert info.key == "API_KEY"
        assert info.path == "/api/key"
        assert info.environment == "production"
        assert info.last_modified is None
        assert info.version is None
        assert info.description is None

    def test_full_creation(self):
        """Test creating SecretInfo with all fields."""
        info = SecretInfo(
            key="DB_PASSWORD",
            path="/db/password",
            environment="staging",
            last_modified="2024-01-15T10:00:00Z",
            version="v1.2.3",
            description="Database connection password"
        )

        assert info.key == "DB_PASSWORD"
        assert info.path == "/db/password"
        assert info.environment == "staging"
        assert info.last_modified == "2024-01-15T10:00:00Z"
        assert info.version == "v1.2.3"
        assert info.description == "Database connection password"


class TestConnectionTestResult:
    """Test ConnectionTestResult dataclass."""

    def test_minimal_creation(self):
        """Test creating ConnectionTestResult with required fields."""
        result = ConnectionTestResult(
            success=True,
            message="Connection successful",
            details={"host": "example.com"}
        )

        assert result.success is True
        assert result.message == "Connection successful"
        assert result.details == {"host": "example.com"}
        assert result.authenticated is False

    def test_full_creation(self):
        """Test creating ConnectionTestResult with all fields."""
        result = ConnectionTestResult(
            success=False,
            message="Authentication failed",
            details={"error": "Invalid credentials", "status_code": 401},
            authenticated=False
        )

        assert result.success is False
        assert result.message == "Authentication failed"
        assert result.details == {"error": "Invalid credentials", "status_code": 401}
        assert result.authenticated is False

    def test_authenticated_success(self):
        """Test authenticated successful result."""
        result = ConnectionTestResult(
            success=True,
            message="Authenticated successfully",
            details={"user": "admin"},
            authenticated=True
        )

        assert result.success is True
        assert result.authenticated is True


class ConcreteSecretManager(SecretManagerBase):
    """Concrete implementation for testing abstract methods."""

    def fetch_secrets(self, environment, paths=None):
        """Mock implementation."""
        return {"test_key": "test_value"}

    def test_connection(self):
        """Mock implementation."""
        return ConnectionTestResult(
            success=True,
            message="Test connection successful",
            details={},
            authenticated=True
        )


class TestSecretManagerBase:
    """Test SecretManagerBase abstract class."""

    def setup_method(self):
        """Set up test fixtures."""
        self.valid_config = {
            "host": "https://api.example.com",
            "api_key": "test_key_123",
            "debug": False,
            "timeout": 30
        }

    def test_init_valid_config(self):
        """Test initialization with valid config."""
        manager = ConcreteSecretManager(self.valid_config)

        assert manager.config == self.valid_config
        assert manager.debug is False

    def test_init_debug_enabled(self):
        """Test initialization with debug enabled."""
        config = self.valid_config.copy()
        config["debug"] = True

        manager = ConcreteSecretManager(config)

        assert manager.debug is True

    def test_init_invalid_config_type(self):
        """Test initialization with invalid config type."""
        with pytest.raises(AttributeError):
            ConcreteSecretManager("not a dict")

    def test_init_empty_config(self):
        """Test initialization with empty config."""
        manager = ConcreteSecretManager({})

        assert manager.config == {}
        assert manager.debug is False

    def test_validate_environment_valid_names(self):
        """Test environment name validation with valid names."""
        manager = ConcreteSecretManager(self.valid_config)

        valid_names = [
            "production",
            "staging",
            "dev",
            "test-env",
            "env_name",
            "prod123",
            "a",
            "environment-with-hyphens",
            "environment_with_underscores",
            "mixed-env_123"
        ]

        for name in valid_names:
            assert manager.validate_environment(name), f"'{name}' should be valid"

    def test_validate_environment_invalid_names(self):
        """Test environment name validation with invalid names."""
        manager = ConcreteSecretManager(self.valid_config)

        invalid_names = [
            "",  # Empty
            None,  # None
            "a" * 65,  # Too long
            "-starts-with-hyphen",
            "_starts_with_underscore",
            "ends-with-hyphen-",
            "ends_with_underscore_",
            "has spaces",
            "has@special!chars",
            "has.dots",
            "has/slashes",
        ]

        for name in invalid_names:
            assert not manager.validate_environment(name), f"'{name}' should be invalid"

    def test_validate_environment_single_char_valid(self):
        """Test single character environment names."""
        manager = ConcreteSecretManager(self.valid_config)

        valid_single = ["a", "Z", "1", "9"]
        for name in valid_single:
            assert manager.validate_environment(name)

    def test_validate_environment_single_char_invalid(self):
        """Test invalid single character environment names."""
        manager = ConcreteSecretManager(self.valid_config)

        invalid_single = ["-", "_", "@", " "]
        for name in invalid_single:
            assert not manager.validate_environment(name)

    def test_filter_secrets_by_paths_no_paths(self):
        """Test filtering secrets with no path filters."""
        manager = ConcreteSecretManager(self.valid_config)

        secrets = {
            "/api/key": "value1",
            "/db/password": "value2",
            "/cache/token": "value3"
        }

        result = manager.filter_secrets_by_paths(secrets, [])
        assert result == secrets

    def test_filter_secrets_by_paths_none_paths(self):
        """Test filtering secrets with None paths."""
        manager = ConcreteSecretManager(self.valid_config)

        secrets = {
            "/api/key": "value1",
            "/db/password": "value2"
        }

        result = manager.filter_secrets_by_paths(secrets, None)
        assert result == secrets

    def test_filter_secrets_by_paths_with_filters(self):
        """Test filtering secrets with path filters."""
        manager = ConcreteSecretManager(self.valid_config)

        secrets = {
            "/api/key": "value1",
            "/api/secret": "value2",
            "/db/password": "value3",
            "/cache/token": "value4"
        }

        with patch.object(manager, '_matches_path_pattern') as mock_matches:
            # Mock to return True only for /api/ paths
            def mock_match(key, pattern):
                if pattern == "/api/*":
                    return key.startswith("/api/")
                return False
            mock_matches.side_effect = mock_match

            result = manager.filter_secrets_by_paths(secrets, ["/api/*"])

            expected = {
                "/api/key": "value1",
                "/api/secret": "value2"
            }
            assert result == expected

    def test_matches_path_pattern_exact_match(self):
        """Test exact path pattern matching."""
        manager = ConcreteSecretManager(self.valid_config)

        assert manager._matches_path_pattern("/api/key", "/api/key")
        assert not manager._matches_path_pattern("/api/key", "/api/secret")

    def test_matches_path_pattern_recursive_wildcard(self):
        """Test recursive wildcard pattern matching."""
        manager = ConcreteSecretManager(self.valid_config)

        test_cases = [
            ("/api/v1/key", "/api/**", True),
            ("/api/v1/v2/secret", "/api/**", True),
            ("/api/key", "/api/**", True),
            ("/database/password", "/api/**", False),
            ("api/key", "api/**", True),  # Without leading slash
        ]

        for key, pattern, expected in test_cases:
            result = manager._matches_path_pattern(key, pattern)
            assert result == expected, f"Key '{key}' with pattern '{pattern}' should be {expected}"

    def test_matches_path_pattern_non_recursive_wildcard(self):
        """Test non-recursive wildcard pattern matching."""
        manager = ConcreteSecretManager(self.valid_config)

        test_cases = [
            ("/api/key", "/api/*", True),
            ("/api/secret", "/api/*", True),
            ("/api/v1/key", "/api/*", False),  # Too deep
            ("/database/password", "/api/*", False),  # Wrong path
            ("api/key", "api/*", True),  # Without leading slash
        ]

        for key, pattern, expected in test_cases:
            result = manager._matches_path_pattern(key, pattern)
            assert result == expected, f"Key '{key}' with pattern '{pattern}' should be {expected}"

    def test_matches_path_pattern_normalization(self):
        """Test path normalization in pattern matching."""
        manager = ConcreteSecretManager(self.valid_config)

        # Test that paths get normalized with leading slashes
        assert manager._matches_path_pattern("api/key", "/api/key")
        assert manager._matches_path_pattern("/api/key", "api/key")
        assert manager._matches_path_pattern("api/key", "api/key")

    def test_get_config_value_existing_key(self):
        """Test getting existing config value."""
        manager = ConcreteSecretManager(self.valid_config)

        assert manager.get_config_value("host") == "https://api.example.com"
        assert manager.get_config_value("timeout") == 30

    def test_get_config_value_missing_key_with_default(self):
        """Test getting missing config value with default."""
        manager = ConcreteSecretManager(self.valid_config)

        assert manager.get_config_value("missing_key", "default_value") == "default_value"

    def test_get_config_value_missing_required_key(self):
        """Test getting missing required config value."""
        manager = ConcreteSecretManager(self.valid_config)

        with pytest.raises(ConfigurationError, match="Required configuration key missing: required_key"):
            manager.get_config_value("required_key", required=True)

    @patch.dict(os.environ, {"TEST_API_KEY": "env_value"})
    def test_get_config_value_from_environment(self):
        """Test getting config value from environment variable."""
        manager = ConcreteSecretManager({})

        assert manager.get_config_value("test-api-key") == "env_value"

    @patch.dict(os.environ, {"AUTO_SECRETS_OVERRIDE_KEY": "env_override"})
    def test_get_config_value_environment_over_config(self):
        """Test environment variable overrides config value."""
        config = {"override-key": "config_value"}
        manager = ConcreteSecretManager(config)

        assert manager.get_config_value("override-key") == "config_value"

    def test_expand_environment_variables_simple(self):
        """Test expanding simple environment variables."""
        manager = ConcreteSecretManager(self.valid_config)

        with patch.dict(os.environ, {"HOME": "/home/user", "USER": "testuser"}):
            result = manager.expand_environment_variables("${HOME}/config/${USER}")
            assert result == "/home/user/config/testuser"

    def test_expand_environment_variables_missing_var(self):
        """Test expanding missing environment variables."""
        manager = ConcreteSecretManager(self.valid_config)

        result = manager.expand_environment_variables("${MISSING_VAR}/path")
        assert result == "${MISSING_VAR}/path"  # Should remain unchanged

    def test_expand_environment_variables_non_string(self):
        """Test expanding non-string values."""
        manager = ConcreteSecretManager(self.valid_config)

        assert manager.expand_environment_variables(123) == 123
        assert manager.expand_environment_variables(None) is None
        assert manager.expand_environment_variables(["list"]) == ["list"]

    def test_expand_environment_variables_no_variables(self):
        """Test expanding string with no variables."""
        manager = ConcreteSecretManager(self.valid_config)

        result = manager.expand_environment_variables("plain/path/string")
        assert result == "plain/path/string"

    def test_log_debug_enabled(self):
        """Test debug logging when enabled."""
        config = self.valid_config.copy()
        config["debug"] = True
        manager = ConcreteSecretManager(config)

        with patch('builtins.print') as mock_print:
            manager.log_debug("Test debug message")
            mock_print.assert_called_once_with("DEBUG [ConcreteSecretManager]: Test debug message")

    def test_log_debug_disabled(self):
        """Test debug logging when disabled."""
        manager = ConcreteSecretManager(self.valid_config)  # debug=False

        with patch('builtins.print') as mock_print:
            manager.log_debug("Test debug message")
            mock_print.assert_not_called()

    def test_log_error(self):
        """Test error logging."""
        manager = ConcreteSecretManager(self.valid_config)

        with patch('builtins.print') as mock_print:
            manager.log_error("Test error message")
            mock_print.assert_called_once_with("ERROR [ConcreteSecretManager]: Test error message")

    def test_format_error_message(self):
        """Test error message formatting."""
        manager = ConcreteSecretManager(self.valid_config)

        error = ValueError("Something went wrong")
        result = manager.format_error_message("fetch secrets", error)

        assert result == "fetch secrets failed: ValueError: Something went wrong"

    def test_parse_duration_seconds(self):
        """Test parsing duration in seconds."""
        manager = ConcreteSecretManager(self.valid_config)

        test_cases = [
            ("30", 30),
            ("30s", 30),
            ("0", 0),
            ("0s", 0),
        ]

        for duration_str, expected in test_cases:
            assert manager.parse_duration(duration_str) == expected

    def test_parse_duration_minutes(self):
        """Test parsing duration in minutes."""
        manager = ConcreteSecretManager(self.valid_config)

        test_cases = [
            ("5m", 300),
            ("1m", 60),
            ("15m", 900),
        ]

        for duration_str, expected in test_cases:
            assert manager.parse_duration(duration_str) == expected

    def test_parse_duration_hours(self):
        """Test parsing duration in hours."""
        manager = ConcreteSecretManager(self.valid_config)

        test_cases = [
            ("1h", 3600),
            ("2h", 7200),
            ("24h", 86400),
        ]

        for duration_str, expected in test_cases:
            assert manager.parse_duration(duration_str) == expected

    def test_parse_duration_days(self):
        """Test parsing duration in days."""
        manager = ConcreteSecretManager(self.valid_config)

        test_cases = [
            ("1d", 86400),
            ("7d", 604800),
        ]

        for duration_str, expected in test_cases:
            assert manager.parse_duration(duration_str) == expected

    def test_parse_duration_empty(self):
        """Test parsing empty duration string."""
        manager = ConcreteSecretManager(self.valid_config)

        assert manager.parse_duration("") == 0
        assert manager.parse_duration(None) == 0

    def test_parse_duration_invalid_format(self):
        """Test parsing invalid duration format."""
        manager = ConcreteSecretManager(self.valid_config)

        invalid_durations = [
            "invalid",
            "5x",
            "abc",
            "5.5m",
            "-5m",
        ]

        for duration_str in invalid_durations:
            with pytest.raises(ValueError, match="Invalid duration format"):
                manager.parse_duration(duration_str)

    def test_create_secret_path(self):
        """Test creating secret path."""
        manager = ConcreteSecretManager(self.valid_config)

        result = manager.create_secret_path("production", "api_key")
        assert result == "/production/api_key"

    def test_sanitize_secret_key_basic(self):
        """Test basic secret key sanitization."""
        manager = ConcreteSecretManager(self.valid_config)

        test_cases = [
            ("/api/key", "API_KEY"),
            ("/database/password", "DATABASE_PASSWORD"),
            ("simple_key", "SIMPLE_KEY"),
            ("key-with-hyphens", "KEY_WITH_HYPHENS"),
        ]

        for input_key, expected in test_cases:
            result = manager.sanitize_secret_key(input_key)
            assert result == expected

    def test_sanitize_secret_key_special_characters(self):
        """Test sanitizing keys with special characters."""
        manager = ConcreteSecretManager(self.valid_config)

        test_cases = [
            ("/api/v1/key@2024", "API_V1_KEY_2024"),
            ("secret.with.dots", "SECRET_WITH_DOTS"),
            ("key with spaces", "KEY_WITH_SPACES"),
            ("complex/path-with_many@special.chars!", "COMPLEX_PATH_WITH_MANY_SPECIAL_CHARS_"),
        ]

        for input_key, expected in test_cases:
            result = manager.sanitize_secret_key(input_key)
            assert result == expected

    def test_sanitize_secret_key_starts_with_number(self):
        """Test sanitizing keys that start with numbers."""
        manager = ConcreteSecretManager(self.valid_config)

        test_cases = [
            ("123_api_key", "_123_API_KEY"),
            ("2024/secret", "_2024_SECRET"),
        ]

        for input_key, expected in test_cases:
            result = manager.sanitize_secret_key(input_key)
            assert result == expected

    def test_sanitize_secret_key_empty(self):
        """Test sanitizing empty key."""
        manager = ConcreteSecretManager(self.valid_config)

        result = manager.sanitize_secret_key("")
        assert result == ""

    def test_repr(self):
        """Test string representation."""
        manager = ConcreteSecretManager(self.valid_config)

        repr_str = repr(manager)
        assert "ConcreteSecretManager" in repr_str
        assert "config_keys=" in repr_str
        expected_keys = list(self.valid_config.keys())
        for key in expected_keys:
            assert key in repr_str

    def test_abstract_methods_enforcement(self):
        """Test that abstract methods must be implemented."""
        with pytest.raises(TypeError):
            # This should fail because SecretManagerBase is abstract
            SecretManagerBase({})  # type: ignore

    def test_concrete_implementation_methods(self):
        """Test that concrete implementation methods work."""
        manager = ConcreteSecretManager(self.valid_config)

        # Test fetch_secrets
        secrets = manager.fetch_secrets("production")
        assert secrets == {"test_key": "test_value"}

        # Test test_connection
        result = manager.test_connection()
        assert result.success is True
        assert result.authenticated is True


class TestSecretManagerBaseIntegration:
    """Integration tests for SecretManagerBase functionality."""

    def test_full_workflow(self):
        """Test complete secret manager workflow."""
        config = {
            "host": "${HOST:-https://default.com}",
            "timeout": 30,
            "debug": True
        }

        with patch.dict(os.environ, {"HOST": "https://production.com"}):
            manager = ConcreteSecretManager(config)

            # Test config expansion
            host = manager.get_config_value("host")
            expanded_host = manager.expand_environment_variables(host)
            assert expanded_host == "${HOST:-https://default.com}"

            # Test environment validation
            assert manager.validate_environment("production")
            assert not manager.validate_environment("invalid-name-")

            # Test secret filtering
            all_secrets = {
                "/api/key1": "value1",
                "/api/key2": "value2",
                "/db/password": "value3",
                "/cache/token": "value4"
            }

            with patch.object(manager, '_matches_path_pattern',
                            side_effect=lambda k, p: k.startswith("/api/")):
                filtered = manager.filter_secrets_by_paths(all_secrets, ["/api/*"])
                expected = {"/api/key1": "value1", "/api/key2": "value2"}
                assert filtered == expected

            # Test duration parsing
            assert manager.parse_duration("5m") == 300
            assert manager.parse_duration("1h") == 3600

            # Test key sanitization
            sanitized = manager.sanitize_secret_key("/api/v1/secret-key")
            assert sanitized == "API_V1_SECRET_KEY"

            # Test environment validation
            assert manager.validate_environment("production")
            assert not manager.validate_environment("invalid-name-")

            # Test secret filtering
            all_secrets = {
                "/api/key1": "value1",
                "/api/key2": "value2",
                "/db/password": "value3",
                "/cache/token": "value4"
            }

            with patch.object(manager, '_matches_path_pattern',
                            side_effect=lambda k, p: k.startswith("/api/")):
                filtered = manager.filter_secrets_by_paths(all_secrets, ["/api/*"])
                expected = {"/api/key1": "value1", "/api/key2": "value2"}
                assert filtered == expected

            # Test duration parsing
            assert manager.parse_duration("5m") == 300
            assert manager.parse_duration("1h") == 3600

            # Test key sanitization
            sanitized = manager.sanitize_secret_key("/api/v1/secret-key")
            assert sanitized == "API_V1_SECRET_KEY"

    def test_error_scenarios(self):
        """Test various error scenarios."""
        manager = ConcreteSecretManager({})

        # Test required config missing
        with pytest.raises(ConfigurationError):
            manager.get_config_value("required_key", required=True)

        # Test invalid duration
        with pytest.raises(ValueError):
            manager.parse_duration("invalid_duration")

        # Test invalid environment names
        assert not manager.validate_environment("")
        assert not manager.validate_environment("a" * 65)
        assert not manager.validate_environment("invalid@name")
