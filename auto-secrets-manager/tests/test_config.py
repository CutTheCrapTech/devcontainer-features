"""
Test suite for auto_secrets.core.config module.

Comprehensive tests for configuration loading, validation, and management.
"""

import json
import os
import pytest
import tempfile
from pathlib import Path
from unittest.mock import patch

from auto_secrets.core.config import (  # type: ignore
    load_config,
    ConfigError,
    _validate_config,
    get_cache_dir,
    get_state_dir,
    get_log_file_path,
    get_effective_config_path,
    save_config_to_file,
    load_config_from_file,
    create_minimal_config_template
)
from auto_secrets.core.environment import is_valid_environment_name  # type: ignore


class TestLoadConfig:
    """Test configuration loading from environment variables."""

    def setup_method(self):
        """Set up test environment variables."""
        self.env_vars = {
            'AUTO_SECRETS_SECRET_MANAGER': 'infisical',
            'AUTO_SECRETS_SHELLS': 'both',
            'AUTO_SECRETS_DEBUG': 'false',
            'AUTO_SECRETS_BRANCH_MAPPINGS': json.dumps({
                'main': 'production',
                'develop': 'staging',
                'default': 'development'
            }),
            'AUTO_SECRETS_SECRET_MANAGER_CONFIG': json.dumps({
                'client_id': 'test-client-id',
                'client_secret': 'test-secret'
            }),
            'AUTO_SECRETS_AUTO_COMMANDS': json.dumps({
                'terraform': ['/infrastructure/**'],
                'kubectl': ['/kubernetes/**']
            }),
            'AUTO_SECRETS_CACHE_DIR': '/tmp/auto-secrets-test',
            'AUTO_SECRETS_CACHE_CONFIG': json.dumps({
                'max_age_seconds': 600,
                'background_refresh': True
            }),
            'AUTO_SECRETS_SHOW_ENV_IN_PROMPT': 'true',
            'AUTO_SECRETS_MARK_HISTORY': 'false',
            'AUTO_SECRETS_ENABLE': 'true'
        }

    def test_load_valid_config(self):
        """Test loading a complete valid configuration."""
        with patch.dict(os.environ, self.env_vars, clear=True):
            config = load_config()

            assert config['secret_manager'] == 'infisical'
            assert config['shells'] == 'both'
            assert config['debug'] is False
            assert config['branch_mappings']['main'] == 'production'
            assert config['branch_mappings']['default'] == 'development'
            assert config['secret_manager_config']['client_id'] == 'test-client-id'
            assert config['auto_commands']['terraform'] == ['/infrastructure/**']
            assert config['cache_base_dir'] == '/tmp/auto-secrets-test'
            assert config['show_env_in_prompt'] is True
            assert config['mark_history'] is False
            assert config['enable'] is True

    def test_missing_required_secret_manager(self):
        """Test error when secret manager is missing."""
        env_vars = self.env_vars.copy()
        del env_vars['AUTO_SECRETS_SECRET_MANAGER']

        with patch.dict(os.environ, env_vars, clear=True):
            with pytest.raises(ConfigError) as exc_info:
                load_config()
            assert "AUTO_SECRETS_SECRET_MANAGER environment variable is required" in str(exc_info.value)

    def test_missing_required_shells(self):
        """Test error when shells configuration is missing."""
        env_vars = self.env_vars.copy()
        del env_vars['AUTO_SECRETS_SHELLS']

        with patch.dict(os.environ, env_vars, clear=True):
            with pytest.raises(ConfigError) as exc_info:
                load_config()
            assert "AUTO_SECRETS_SHELLS environment variable is required" in str(exc_info.value)

    def test_missing_branch_mappings(self):
        """Test error when branch mappings are missing."""
        env_vars = self.env_vars.copy()
        del env_vars['AUTO_SECRETS_BRANCH_MAPPINGS']

        with patch.dict(os.environ, env_vars, clear=True):
            with pytest.raises(ConfigError) as exc_info:
                load_config()
            assert "AUTO_SECRETS_BRANCH_MAPPINGS environment variable is required" in str(exc_info.value)

    def test_invalid_branch_mappings_json(self):
        """Test error when branch mappings JSON is invalid."""
        env_vars = self.env_vars.copy()
        env_vars['AUTO_SECRETS_BRANCH_MAPPINGS'] = 'invalid-json'

        with patch.dict(os.environ, env_vars, clear=True):
            with pytest.raises(ConfigError) as exc_info:
                load_config()
            assert "Invalid AUTO_SECRETS_BRANCH_MAPPINGS JSON" in str(exc_info.value)

    def test_branch_mappings_missing_default(self):
        """Test error when branch mappings don't include default."""
        env_vars = self.env_vars.copy()
        env_vars['AUTO_SECRETS_BRANCH_MAPPINGS'] = json.dumps({
            'main': 'production',
            'develop': 'staging'
        })

        with patch.dict(os.environ, env_vars, clear=True):
            with pytest.raises(ConfigError) as exc_info:
                load_config()
            assert "must include a 'default' entry" in str(exc_info.value)

    def test_debug_mode_enabled(self):
        """Test debug mode configuration."""
        env_vars = self.env_vars.copy()
        env_vars['AUTO_SECRETS_DEBUG'] = 'true'

        with patch.dict(os.environ, env_vars, clear=True):
            config = load_config()
            assert config['debug'] is True

    def test_default_values(self):
        """Test that default values are applied correctly."""
        with patch.dict(os.environ, self.env_vars, clear=True):
            config = load_config()

            # Test cache config defaults
            assert config['cache_config']['max_age_seconds'] == 600  # from env
            assert config['cache_config']['background_refresh'] is True

            # Test other defaults
            assert config['enable'] is True
            assert config['cleanup_on_exit'] is False
            assert config['prefetch_on_branch_change'] is False

    def test_invalid_json_configs(self):
        """Test handling of invalid JSON in various config fields."""
        test_cases = [
            ('AUTO_SECRETS_SECRET_MANAGER_CONFIG', 'invalid-json'),
            ('AUTO_SECRETS_AUTO_COMMANDS', 'not-json'),
            ('AUTO_SECRETS_CACHE_CONFIG', '{invalid}')
        ]

        for env_var, invalid_json in test_cases:
            env_vars = self.env_vars.copy()
            env_vars[env_var] = invalid_json

            with patch.dict(os.environ, env_vars, clear=True):
                with pytest.raises(ConfigError) as exc_info:
                    load_config()
                assert f"Invalid {env_var} JSON" in str(exc_info.value)


class TestConfigValidation:
    """Test configuration validation."""

    def test_validate_valid_config(self):
        """Test validation of a valid configuration."""
        config = {
            'secret_manager': 'infisical',
            'shells': 'both',
            'branch_mappings': {'main': 'production', 'default': 'development'},
            'cache_config': {'max_age_seconds': 900}
        }

        # Should not raise any exception
        _validate_config(config)

    def test_validate_invalid_secret_manager(self):
        """Test validation with invalid secret manager."""
        config = {
            'secret_manager': 'invalid-manager',
            'shells': 'both',
            'branch_mappings': {'main': 'production', 'default': 'development'},
            'cache_config': {'max_age_seconds': 900}
        }

        with pytest.raises(ConfigError) as exc_info:
            _validate_config(config)
        assert "Invalid secret manager" in str(exc_info.value)

    def test_validate_invalid_shells(self):
        """Test validation with invalid shells configuration."""
        config = {
            'secret_manager': 'infisical',
            'shells': 'invalid-shell',
            'branch_mappings': {'main': 'production', 'default': 'development'},
            'cache_config': {'max_age_seconds': 900}
        }

        with pytest.raises(ConfigError) as exc_info:
            _validate_config(config)
        assert "Invalid shells configuration" in str(exc_info.value)

    def test_validate_empty_branch_mappings(self):
        """Test validation with empty branch mappings."""
        config = {
            'secret_manager': 'infisical',
            'shells': 'both',
            'branch_mappings': {},
            'cache_config': {'max_age_seconds': 900}
        }

        with pytest.raises(ConfigError) as exc_info:
            _validate_config(config)
        assert "non-empty dictionary" in str(exc_info.value)

    def test_validate_negative_cache_age(self):
        """Test validation with negative cache age."""
        config = {
            'secret_manager': 'infisical',
            'shells': 'both',
            'branch_mappings': {'main': 'production', 'default': 'development'},
            'cache_config': {'max_age_seconds': -100}
        }

        with pytest.raises(ConfigError) as exc_info:
            _validate_config(config)
        assert "max_age_seconds must be non-negative" in str(exc_info.value)


class TestCacheDirectories:
    """Test cache directory management functions."""

    def test_get_cache_dir_no_environment(self):
        """Test getting base cache directory."""
        config = {'cache_base_dir': '/tmp/test-cache'}

        cache_dir = get_cache_dir(config)
        expected = Path('/tmp/test-cache')
        assert cache_dir == expected

    def test_get_cache_dir_with_environment(self):
        """Test getting environment-specific cache directory."""
        config = {'cache_base_dir': '/tmp/test-cache'}

        cache_dir = get_cache_dir(config, 'production')
        expected = Path('/tmp/test-cache/environments/production')
        assert cache_dir == expected

    def test_get_state_dir(self):
        """Test getting state directory."""
        config = {'cache_base_dir': '/tmp/test-cache'}

        state_dir = get_state_dir(config)
        expected = Path('/tmp/test-cache/state')
        assert state_dir == expected

    @patch('pathlib.Path.mkdir')
    def test_get_log_file_path_creates_directory(self, mock_mkdir):
        """Test that log directory is created if it doesn't exist."""
        config = {'log_dir': '/var/log/auto-secrets'}

        get_log_file_path(config)
        mock_mkdir.assert_called_once_with(parents=True, exist_ok=True, mode=0o755)


class TestConfigFileOperations:
    """Test configuration file save/load operations."""

    def test_save_and_load_config(self):
        """Test saving and loading configuration to/from file."""
        config = {
            'secret_manager': 'infisical',
            'shells': 'both',
            'debug': False,
            'branch_mappings': {'main': 'production', 'default': 'development'},
            'secret_manager_config': {'client_id': 'test-id'},
            'auto_commands': {'terraform': ['/infra/**']},
            'cache_config': {'max_age_seconds': 900}
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            config_file = Path(temp_dir) / 'config.json'

            # Save config
            save_config_to_file(config, config_file)
            assert config_file.exists()

            # Load config
            with patch.dict(os.environ, {
                'AUTO_SECRETS_SECRET_MANAGER': 'infisical',
                'AUTO_SECRETS_SHELLS': 'both',
                'AUTO_SECRETS_BRANCH_MAPPINGS': json.dumps({'main': 'production', 'default': 'development'})
            }, clear=True):
                loaded_config = load_config_from_file(config_file)

            # Verify main fields are preserved
            assert loaded_config['secret_manager'] == 'infisical'
            assert loaded_config['shells'] == 'both'
            assert loaded_config['branch_mappings']['main'] == 'production'

    def test_save_config_redacts_sensitive_data(self):
        """Test that sensitive data is redacted when saving to file."""
        config = {
            'secret_manager': 'infisical',
            'shells': 'both',
            'branch_mappings': {'default': 'development'},
            'secret_manager_config': {
                'client_id': 'test-id',
                'client_secret': 'super-secret',
                'token': 'secret-token'
            }
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            config_file = Path(temp_dir) / 'config.json'

            save_config_to_file(config, config_file)

            # Read raw file content
            with open(config_file, 'r') as f:
                saved_data = json.load(f)

            # Check that sensitive values are redacted
            sm_config = saved_data['secret_manager_config']
            assert sm_config['client_id'] == 'test-id'  # Not sensitive
            assert sm_config['client_secret'] == '***REDACTED***'
            assert sm_config['token'] == '***REDACTED***'

    def test_load_config_from_nonexistent_file(self):
        """Test loading config from non-existent file."""
        with pytest.raises(ConfigError) as exc_info:
            load_config_from_file('/nonexistent/config.json')
        assert "Failed to load config from" in str(exc_info.value)

    def test_load_config_from_invalid_json(self):
        """Test loading config from file with invalid JSON."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            f.write('invalid json content')
            f.flush()

            try:
                with pytest.raises(ConfigError) as exc_info:
                    load_config_from_file(f.name)
                assert "Failed to load config from" in str(exc_info.value)
            finally:
                os.unlink(f.name)

    def test_get_effective_config_path_env_var(self):
        """Test getting config path from environment variable."""
        with patch.dict(os.environ, {'AUTO_SECRETS_CONFIG_PATH': '/custom/config.json'}):
            path = get_effective_config_path()
            assert path == Path('/custom/config.json')

    def test_get_effective_config_path_search(self):
        """Test searching for config file in standard locations."""
        with tempfile.TemporaryDirectory() as temp_dir:
            config_file = Path(temp_dir) / '.auto-secrets.json'
            config_file.touch()

            with patch('pathlib.Path.cwd', return_value=Path(temp_dir)):
                with patch.dict(os.environ, {}, clear=True):
                    path = get_effective_config_path()
                    assert path == config_file


class TestConfigTemplate:
    """Test configuration template creation."""

    def test_create_minimal_config_template(self):
        """Test creating minimal configuration template."""
        template = create_minimal_config_template()

        # Verify required fields are present
        assert template['secret_manager'] == 'infisical'
        assert template['shells'] == 'both'
        assert template['debug'] is False
        assert 'branch_mappings' in template
        assert 'default' in template['branch_mappings']
        assert 'secret_manager_config' in template
        assert 'auto_commands' in template
        assert 'cache_config' in template

        # Verify structure is valid
        assert isinstance(template['branch_mappings'], dict)
        assert isinstance(template['auto_commands'], dict)
        assert isinstance(template['cache_config'], dict)


class TestEnvironmentNameValidation:
    """Test environment name validation."""

    def test_valid_environment_names(self):
        """Test validation of valid environment names."""
        valid_names = [
            'production',
            'staging',
            'development',
            'test',
            'prod-1',
            'staging_v2',
            'dev-feature-123',
            'a',  # Single character
            'env123',
            'test-env-name'
        ]

        for name in valid_names:
            assert is_valid_environment_name(name), f"'{name}' should be valid"

    def test_invalid_environment_names(self):
        """Test validation of invalid environment names."""
        invalid_names = [
            '',  # Empty
            None,  # None
            123,  # Not string
            '-production',  # Starts with hyphen
            'staging-',  # Ends with hyphen
            '_development',  # Starts with underscore
            'test_',  # Ends with underscore
            'prod@duction',  # Invalid character
            'staging with spaces',  # Spaces
            'a' * 65,  # Too long
            'test/env',  # Invalid character
            'test.env',  # Invalid character
        ]

        for name in invalid_names:
            assert not is_valid_environment_name(name), f"'{name}' should be invalid"


class TestConfigIntegration:
    """Integration tests for configuration system."""

    def test_full_config_lifecycle(self):
        """Test complete configuration lifecycle."""
        # Set up environment
        env_vars = {
            'AUTO_SECRETS_SECRET_MANAGER': 'infisical',
            'AUTO_SECRETS_SHELLS': 'zsh',
            'AUTO_SECRETS_DEBUG': 'true',
            'AUTO_SECRETS_BRANCH_MAPPINGS': json.dumps({
                'main': 'production',
                'develop': 'staging',
                'feature/*': 'development',
                'default': 'development'
            }),
            'AUTO_SECRETS_SECRET_MANAGER_CONFIG': json.dumps({
                'project_id': 'test-project',
                'client_id': 'test-client'
            }),
            'AUTO_SECRETS_CACHE_DIR': '/tmp/test-cache',
            'AUTO_SECRETS_ENABLE': 'true'
        }

        with patch.dict(os.environ, env_vars, clear=True):
            # Load configuration
            config = load_config()

            # Verify configuration is loaded correctly
            assert config['secret_manager'] == 'infisical'
            assert config['shells'] == 'zsh'
            assert config['debug'] is True
            assert config['enable'] is True

            # Test cache directory functions
            with patch('os.getuid', return_value=1000):
                cache_dir = get_cache_dir(config)
                state_dir = get_state_dir(config)
                env_cache_dir = get_cache_dir(config, 'production')

                assert cache_dir == Path('/tmp/test-cache')
                assert state_dir == Path('/tmp/test-cache/state')
                assert env_cache_dir == Path('/tmp/test-cache/environments/production')

            # Test file operations
            with tempfile.TemporaryDirectory() as temp_dir:
                config_file = Path(temp_dir) / 'test-config.json'

                # Save and reload
                save_config_to_file(config, config_file)
                loaded_config = load_config_from_file(config_file)

                # Verify critical fields are preserved
                assert loaded_config['secret_manager'] == config['secret_manager']
                assert loaded_config['shells'] == config['shells']
                assert loaded_config['branch_mappings'] == config['branch_mappings']


if __name__ == '__main__':
    pytest.main([__file__])
