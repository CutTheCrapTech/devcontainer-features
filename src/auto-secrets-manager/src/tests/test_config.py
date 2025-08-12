"""
Test suite for auto_secrets.core.config module.

Comprehensive tests for configuration loading, validation, and management.
"""

import json
import os
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from auto_secrets.core.config import ConfigError, ConfigManager


class TestLoadConfig:
  """Test configuration loading from environment variables."""

  def setup_method(self) -> None:
    """Set up test environment variables."""
    self.env_vars = {
      "AUTO_SECRETS_SECRET_MANAGER": "infisical",
      "AUTO_SECRETS_SHELLS": "both",
      "AUTO_SECRETS_DEBUG": "false",
      "AUTO_SECRETS_BRANCH_MAPPINGS": json.dumps(
        {"main": "production", "develop": "staging", "default": "development"}
      ),
      "AUTO_SECRETS_SECRET_MANAGER_CONFIG": json.dumps({"client_id": "test-client-id", "client_secret": "test-secret"}),
      "AUTO_SECRETS_AUTO_COMMANDS": json.dumps({"terraform": ["/infrastructure/**"], "kubectl": ["/kubernetes/**"]}),
      "AUTO_SECRETS_CACHE_DIR": "/tmp/auto-secrets-test",
      "AUTO_SECRETS_FEATURE_DIR": "/tmp/auto-secrets",
      "AUTO_SECRETS_LOG_DIR": "/tmp/auto-secrets",
      "AUTO_SECRETS_LOG_LEVEL": "INFO",
      "AUTO_SECRETS_CACHE_CONFIG": json.dumps(
        {
          "refresh_interval": "10m",
          "cleanup_interval": "7d",
        }
      ),
    }

  def test_load_valid_config(self) -> None:
    """Test loading a complete valid configuration."""
    with patch.dict(os.environ, self.env_vars, clear=True):
      config = ConfigManager.load_config()

      assert config["secret_manager"] == "infisical"
      assert config["shells"] == "both"
      assert config["debug"] is False
      assert config["branch_mappings"]["main"] == "production"
      assert config["branch_mappings"]["default"] == "development"
      assert config["secret_manager_config"]["client_id"] == "test-client-id"
      assert config["auto_commands"]["terraform"] == ["/infrastructure/**"]
      assert config["cache_base_dir"] == "/tmp/auto-secrets-test"

  def test_missing_required_secret_manager(self) -> None:
    """Test error when secret manager is missing."""
    env_vars = self.env_vars.copy()
    del env_vars["AUTO_SECRETS_SECRET_MANAGER"]

    with patch.dict(os.environ, env_vars, clear=True):
      with pytest.raises(ConfigError) as exc_info:
        ConfigManager.load_config()
      assert "AUTO_SECRETS_SECRET_MANAGER environment variable is required" in str(exc_info.value)

  def test_missing_required_shells(self) -> None:
    """Test error when shells configuration is missing."""
    env_vars = self.env_vars.copy()
    del env_vars["AUTO_SECRETS_SHELLS"]

    with patch.dict(os.environ, env_vars, clear=True):
      with pytest.raises(ConfigError) as exc_info:
        ConfigManager.load_config()
      assert "AUTO_SECRETS_SHELLS environment variable is required" in str(exc_info.value)

  def test_missing_branch_mappings(self) -> None:
    """Test error when branch mappings are missing."""
    env_vars = self.env_vars.copy()
    del env_vars["AUTO_SECRETS_BRANCH_MAPPINGS"]

    with patch.dict(os.environ, env_vars, clear=True):
      with pytest.raises(ConfigError) as exc_info:
        ConfigManager.load_config()
      assert "AUTO_SECRETS_BRANCH_MAPPINGS environment variable is required" in str(exc_info.value)

  def test_invalid_branch_mappings_json(self) -> None:
    """Test error when branch mappings JSON is invalid."""
    env_vars = self.env_vars.copy()
    env_vars["AUTO_SECRETS_BRANCH_MAPPINGS"] = "invalid-json"

    with patch.dict(os.environ, env_vars, clear=True):
      with pytest.raises(ConfigError) as exc_info:
        ConfigManager.load_config()
      assert "Invalid AUTO_SECRETS_BRANCH_MAPPINGS JSON" in str(exc_info.value)

  def test_branch_mappings_missing_default(self) -> None:
    """Test error when branch mappings don't include default."""
    env_vars = self.env_vars.copy()
    env_vars["AUTO_SECRETS_BRANCH_MAPPINGS"] = json.dumps({"main": "production", "develop": "staging"})

    with patch.dict(os.environ, env_vars, clear=True):
      with pytest.raises(ConfigError) as exc_info:
        ConfigManager.load_config()
      assert "must include a 'default' entry" in str(exc_info.value)

  def test_debug_mode_enabled(self) -> None:
    """Test debug mode configuration."""
    env_vars = self.env_vars.copy()
    env_vars["AUTO_SECRETS_DEBUG"] = "true"

    with patch.dict(os.environ, env_vars, clear=True):
      config = ConfigManager.load_config()
      assert config["debug"] is True

  def test_default_values(self) -> None:
    """Test that default values are applied correctly."""
    with patch.dict(os.environ, self.env_vars, clear=True):
      config = ConfigManager.load_config()

      # Test cache config defaults
      assert config["cache_config"]["refresh_interval"] == "10m"  # from env

  def test_invalid_json_configs(self) -> None:
    """Test handling of invalid JSON in various config fields."""
    test_cases = [
      ("AUTO_SECRETS_SECRET_MANAGER_CONFIG", "invalid-json"),
      ("AUTO_SECRETS_AUTO_COMMANDS", "not-json"),
      ("AUTO_SECRETS_CACHE_CONFIG", "{invalid}"),
    ]

    for env_var, invalid_json in test_cases:
      env_vars = self.env_vars.copy()
      env_vars[env_var] = invalid_json

      with patch.dict(os.environ, env_vars, clear=True):
        with pytest.raises(ConfigError) as exc_info:
          ConfigManager.load_config()
        assert f"Invalid {env_var} JSON" in str(exc_info.value)


class TestConfigValidation:
  """Test configuration validation."""

  def test_validate_valid_config(self) -> None:
    """Test validation of a valid configuration."""
    config: dict[str, Any] = {
      "secret_manager": "infisical",
      "shells": "both",
      "branch_mappings": {
        "main": "production",
        "default": "development",
      },
      "cache_config": {
        "refresh_interval": "15m",
        "cleanup_interval": "7d",
      },
    }

    # Should not raise any exception
    ConfigManager._validate_config(config)

  def test_validate_invalid_secret_manager(self) -> None:
    """Test validation with invalid secret manager."""
    config: dict[str, Any] = {
      "secret_manager": "invalid-manager",
      "shells": "both",
      "branch_mappings": {
        "main": "production",
        "default": "development",
      },
      "cache_config": {
        "refresh_interval": "15m",
        "cleanup_interval": "7d",
      },
    }

    with pytest.raises(ConfigError) as exc_info:
      ConfigManager._validate_config(config)
    assert "Invalid secret manager" in str(exc_info.value)

  def test_validate_invalid_shells(self) -> None:
    """Test validation with invalid shells configuration."""
    config: dict[str, Any] = {
      "secret_manager": "infisical",
      "shells": "invalid-shell",
      "branch_mappings": {
        "main": "production",
        "default": "development",
      },
      "cache_config": {
        "refresh_interval": "15m",
        "cleanup_interval": "7d",
      },
    }

    with pytest.raises(ConfigError) as exc_info:
      ConfigManager._validate_config(config)
    assert "Invalid shells configuration" in str(exc_info.value)

  def test_validate_empty_branch_mappings(self) -> None:
    """Test validation with empty branch mappings."""
    config: dict[str, Any] = {
      "secret_manager": "infisical",
      "shells": "both",
      "branch_mappings": {},
      "cache_config": {
        "refresh_interval": "10m",
        "cleanup_interval": "7d",
      },
    }

    with pytest.raises(ConfigError) as exc_info:
      ConfigManager._validate_config(config)
    assert "non-empty dictionary" in str(exc_info.value)

  def test_validate_invalid_refresh_interval(self) -> None:
    """Test validation with negative cache age."""
    config: dict[str, Any] = {
      "secret_manager": "infisical",
      "shells": "both",
      "branch_mappings": {"main": "production", "default": "development"},
      "cache_config": {
        "refresh_interval": "m",
        "cleanup_interval": "7d",
      },
    }

    with pytest.raises(ConfigError) as exc_info:
      ConfigManager._validate_config(config)
    assert "Invalid duration format" in str(exc_info.value)

  def test_validate_invalid_cleanup_interval(self) -> None:
    """Test validation with negative cache age."""
    config: dict[str, Any] = {
      "secret_manager": "infisical",
      "shells": "both",
      "branch_mappings": {"main": "production", "default": "development"},
      "cache_config": {
        "refresh_interval": "15m",
        "cleanup_interval": "d",
      },
    }

    with pytest.raises(ConfigError) as exc_info:
      ConfigManager._validate_config(config)
    assert "Invalid duration format" in str(exc_info.value)


class TestCacheDirectories:
  """Test cache directory management functions."""

  def test_get_cache_dir_no_environment(self) -> None:
    """Test getting base cache directory."""
    config = {"cache_base_dir": "/tmp/test-cache"}

    cache_dir = ConfigManager.get_cache_dir(config)
    expected = Path("/tmp/test-cache")
    assert cache_dir == expected

  def test_get_cache_dir_with_environment(self) -> None:
    """Test getting environment-specific cache directory."""
    config = {"cache_base_dir": "/tmp/test-cache"}

    cache_dir = ConfigManager.get_cache_dir(config, "production")
    expected = Path("/tmp/test-cache/environments/production")
    assert cache_dir == expected

  @patch("pathlib.Path.mkdir")
  def test_get_log_file_path_creates_directory(self, mock_mkdir: Any) -> None:
    """Test that log directory is created if it doesn't exist."""
    config = {"log_dir": "/var/log/auto-secrets"}

    ConfigManager.get_log_file_path(config)
    mock_mkdir.assert_called_once_with(parents=True, exist_ok=True, mode=0o755)


class TestConfigTemplate:
  """Test configuration template creation."""

  def test_create_minimal_config_template(self) -> None:
    """Test creating minimal configuration template."""
    template = ConfigManager.create_minimal_config_template()

    # Verify required fields are present
    assert template["secret_manager"] == "infisical"
    assert template["shells"] == "both"
    assert template["debug"] is False
    assert "branch_mappings" in template
    assert "default" in template["branch_mappings"]
    assert "secret_manager_config" in template
    assert "auto_commands" in template
    assert "cache_config" in template

    # Verify structure is valid
    assert isinstance(template["branch_mappings"], dict)
    assert isinstance(template["auto_commands"], dict)
    assert isinstance(template["cache_config"], dict)


class TestEnvironmentNameValidation:
  """Test environment name validation."""

  def test_valid_environment_names(self) -> None:
    """Test validation of valid environment names."""
    valid_names = [
      "production",
      "staging",
      "development",
      "test",
      "prod-1",
      "staging_v2",
      "dev-feature-123",
      "a",  # Single character
      "env123",
      "test-env-name",
    ]

    for name in valid_names:
      assert ConfigManager.is_valid_environment_name(name), f"'{name}' should be valid"

  def test_invalid_environment_names(self) -> None:
    """Test validation of invalid environment names."""
    invalid_names = [
      "",  # Empty
      None,  # None
      123,  # Not string
      "-production",  # Starts with hyphen
      "staging-",  # Ends with hyphen
      "_development",  # Starts with underscore
      "test_",  # Ends with underscore
      "prod@duction",  # Invalid character
      "staging with spaces",  # Spaces
      "a" * 65,  # Too long
      "test/env",  # Invalid character
      "test.env",  # Invalid character
    ]

    for name in invalid_names:
      assert not ConfigManager.is_valid_environment_name(
        name  # type: ignore[arg-type]
      ), f"'{name}' should be invalid"


class TestConfigIntegration:
  """Integration tests for configuration system."""

  def test_full_config_lifecycle(self) -> None:
    """Test complete configuration lifecycle."""
    # Set up environment
    env_vars = {
      "AUTO_SECRETS_SECRET_MANAGER": "infisical",
      "AUTO_SECRETS_SHELLS": "zsh",
      "AUTO_SECRETS_DEBUG": "true",
      "AUTO_SECRETS_BRANCH_MAPPINGS": json.dumps(
        {
          "main": "production",
          "develop": "staging",
          "feature/*": "development",
          "default": "development",
        }
      ),
      "AUTO_SECRETS_SECRET_MANAGER_CONFIG": json.dumps({"project_id": "test-project", "client_id": "test-client"}),
      "AUTO_SECRETS_CACHE_CONFIG": json.dumps(
        {
          "refresh_interval": "10m",
          "cleanup_interval": "7d",
        }
      ),
      "AUTO_SECRETS_CACHE_DIR": "/tmp/test-cache",
      "AUTO_SECRETS_FEATURE_DIR": "/tmp/auto-secrets",
      "AUTO_SECRETS_LOG_DIR": "/tmp/auto-secrets",
      "AUTO_SECRETS_LOG_LEVEL": "INFO",
    }

    with patch.dict(os.environ, env_vars, clear=True):
      # Load configuration
      config = ConfigManager.load_config()

      # Verify configuration is loaded correctly
      assert config["secret_manager"] == "infisical"
      assert config["shells"] == "zsh"
      assert config["debug"] is True

      # Test cache directory functions
      with patch("os.getuid", return_value=1000):
        cache_dir = ConfigManager.get_cache_dir(config)
        env_cache_dir = ConfigManager.get_cache_dir(config, "production")

        assert cache_dir == Path("/tmp/test-cache")
        assert env_cache_dir == Path("/tmp/test-cache/environments/production")


if __name__ == "__main__":
  pytest.main([__file__])
