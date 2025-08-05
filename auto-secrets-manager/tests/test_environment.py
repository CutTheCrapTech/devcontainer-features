"""
Test suite for auto_secrets.core.environment module.

Comprehensive tests for environment state management and persistence.
"""

import os
import pytest
import tempfile
import time
from unittest.mock import patch

from auto_secrets.core.environment import ( # type: ignore
    EnvironmentState,
    EnvironmentStateManager,
    get_current_environment,
    save_environment_state,
    clear_environment_state,
    is_valid_environment_name,
    get_environment_debug_info
)


class TestEnvironmentState:
    """Test the EnvironmentState dataclass."""

    def test_empty_state_creation(self):
        """Test creating empty environment state."""
        state = EnvironmentState()

        assert state.environment is None
        assert state.branch is None
        assert state.repo_path is None
        assert state.timestamp is None

    def test_full_state_creation(self):
        """Test creating full environment state."""
        timestamp = int(time.time())
        state = EnvironmentState(
            environment="production",
            branch="main",
            repo_path="/home/user/project",
            timestamp=timestamp
        )

        assert state.environment == "production"
        assert state.branch == "main"
        assert state.repo_path == "/home/user/project"
        assert state.timestamp == timestamp

    def test_to_dict(self):
        """Test converting state to dictionary."""
        state = EnvironmentState(
            environment="staging",
            branch="develop",
            repo_path="/project",
            timestamp=1234567890
        )

        result = state.to_dict()
        expected = {
            "environment": "staging",
            "branch": "develop",
            "repo_path": "/project",
            "timestamp": 1234567890
        }

        assert result == expected

    def test_from_dict(self):
        """Test creating state from dictionary."""
        data = {
            "environment": "development",
            "branch": "feature/test",
            "repo_path": "/test/repo",
            "timestamp": 1234567890
        }

        state = EnvironmentState.from_dict(data)

        assert state.environment == "development"
        assert state.branch == "feature/test"
        assert state.repo_path == "/test/repo"
        assert state.timestamp == 1234567890

    def test_from_dict_partial(self):
        """Test creating state from partial dictionary."""
        data = {"environment": "test"}

        state = EnvironmentState.from_dict(data)

        assert state.environment == "test"
        assert state.branch is None
        assert state.repo_path is None
        assert state.timestamp is None

    def test_from_dict_empty(self):
        """Test creating state from empty dictionary."""
        state = EnvironmentState.from_dict({})

        assert state.environment is None
        assert state.branch is None
        assert state.repo_path is None
        assert state.timestamp is None

    def test_is_valid_empty(self):
        """Test validity check for empty state."""
        state = EnvironmentState()
        assert not state.is_valid()

    def test_is_valid_partial(self):
        """Test validity check for partial state."""
        state = EnvironmentState(environment="test")
        assert not state.is_valid()  # Missing branch

        state = EnvironmentState(branch="main")
        assert not state.is_valid()  # Missing environment

    def test_is_valid_complete(self):
        """Test validity check for complete state."""
        state = EnvironmentState(environment="test", branch="main")
        assert state.is_valid()

    def test_age_seconds_no_timestamp(self):
        """Test age calculation with no timestamp."""
        state = EnvironmentState()
        assert state.age_seconds() is None

    def test_age_seconds_with_timestamp(self):
        """Test age calculation with timestamp."""
        # Set timestamp to 10 seconds ago
        past_time = int(time.time()) - 10
        state = EnvironmentState(timestamp=past_time)

        age = state.age_seconds()
        assert age is not None
        assert age >= 10
        assert age <= 12  # Allow some margin for test execution time


class TestEnvironmentStateManager:
    """Test the EnvironmentStateManager class."""

    def setup_method(self):
        """Set up test configuration."""
        self.temp_dir = tempfile.mkdtemp()
        self.config = {
            "cache_base_dir": self.temp_dir,
            "debug": False
        }

    def teardown_method(self):
        """Clean up after tests."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_init(self):
        """Test manager initialization."""
        manager = EnvironmentStateManager(self.config)

        assert manager.config == self.config
        assert manager.state_file.parent.exists()
        assert manager._cached_state is None
        assert manager._cache_time is None

    def test_get_current_state_no_file(self):
        """Test getting state when no file exists."""
        manager = EnvironmentStateManager(self.config)

        state = manager.get_current_state()

        assert isinstance(state, EnvironmentState)
        assert not state.is_valid()

    def test_save_and_get_state(self):
        """Test saving and retrieving state."""
        manager = EnvironmentStateManager(self.config)

        # Create test state
        test_state = EnvironmentState(
            environment="production",
            branch="main",
            repo_path="/test/repo",
            timestamp=int(time.time())
        )

        # Save state
        manager.save_state(test_state)

        # Retrieve state
        retrieved_state = manager.get_current_state(use_cache=False)

        assert retrieved_state.environment == "production"
        assert retrieved_state.branch == "main"
        assert retrieved_state.repo_path == "/test/repo"
        assert retrieved_state.timestamp == test_state.timestamp

    def test_save_state_adds_timestamp(self):
        """Test that save_state adds timestamp if missing."""
        manager = EnvironmentStateManager(self.config)

        # Create state without timestamp
        test_state = EnvironmentState(
            environment="test",
            branch="main"
        )

        # Save state
        manager.save_state(test_state)

        # Verify timestamp was added
        assert test_state.timestamp is not None
        assert test_state.timestamp > 0

    def test_caching_behavior(self):
        """Test state caching behavior."""
        manager = EnvironmentStateManager(self.config)

        # Create and save test state
        test_state = EnvironmentState(environment="test", branch="main")
        manager.save_state(test_state)

        # First call should read from file and cache
        state1 = manager.get_current_state()
        assert manager._cached_state is not None
        assert manager._cache_time is not None

        # Second call should use cache
        with patch.object(manager, '_load_state_from_file') as mock_load:
            state2 = manager.get_current_state()
            mock_load.assert_not_called()

        assert state1.environment == state2.environment

    def test_cache_bypass(self):
        """Test bypassing cache with use_cache=False."""
        manager = EnvironmentStateManager(self.config)

        # Create and save test state
        test_state = EnvironmentState(environment="test", branch="main")
        manager.save_state(test_state)

        # First call to populate cache
        manager.get_current_state()

        # Second call with use_cache=False should reload
        with patch.object(manager, '_load_state_from_file') as mock_load:
            mock_load.return_value = test_state
            manager.get_current_state(use_cache=False)
            mock_load.assert_called_once()

    def test_clear_state(self):
        """Test clearing state."""
        manager = EnvironmentStateManager(self.config)

        # Create and save test state
        test_state = EnvironmentState(environment="test", branch="main")
        manager.save_state(test_state)

        # Verify state exists
        assert manager.state_file.exists()

        # Clear state
        manager.clear_state()

        # Verify state file is removed and cache is cleared
        assert not manager.state_file.exists()
        assert manager._cached_state is None
        assert manager._cache_time is None

    def test_state_file_creation_error(self):
        """Test handling of state file creation errors."""
        # Use read-only directory
        readonly_config = {
            "cache_base_dir": "/dev/null/readonly",
            "debug": False
        }

        manager = EnvironmentStateManager(readonly_config)
        test_state = EnvironmentState(environment="test", branch="main")

        with pytest.raises(Exception):  # Should raise some OS error
            manager.save_state(test_state)

    def test_corrupted_state_file(self):
        """Test handling of corrupted state file."""
        manager = EnvironmentStateManager(self.config)

        # Create corrupted state file
        manager.state_file.parent.mkdir(parents=True, exist_ok=True)
        with open(manager.state_file, 'w') as f:
            f.write("invalid json content")

        # Should return empty state without crashing
        state = manager.get_current_state()
        assert isinstance(state, EnvironmentState)
        assert not state.is_valid()

    def test_get_state_info(self):
        """Test getting state information."""
        manager = EnvironmentStateManager(self.config)

        # Create and save test state
        test_state = EnvironmentState(
            environment="production",
            branch="main",
            timestamp=int(time.time()) - 100  # 100 seconds ago
        )
        manager.save_state(test_state)

        # Get state info
        info = manager.get_state_info()

        assert info["state_file"] == str(manager.state_file)
        assert info["state_file_exists"] is True
        assert info["current_state"]["environment"] == "production"
        assert info["state_valid"] is True
        assert info["state_age_seconds"] is not None
        assert info["cache_active"] is True


class TestUtilityFunctions:
    """Test utility functions."""

    def setup_method(self):
        """Set up test configuration."""
        self.temp_dir = tempfile.mkdtemp()
        self.config = {
            "cache_base_dir": self.temp_dir,
            "debug": False
        }

    def teardown_method(self):
        """Clean up after tests."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_get_current_environment_with_config(self):
        """Test getting current environment with provided config."""
        state = get_current_environment(self.config)
        assert isinstance(state, EnvironmentState)

    @patch('auto_secrets.core.environment.load_config')
    def test_get_current_environment_without_config(self, mock_load_config):
        """Test getting current environment without config (loads from environment)."""
        mock_load_config.return_value = self.config

        state = get_current_environment()
        assert isinstance(state, EnvironmentState)
        mock_load_config.assert_called_once()

    def test_save_environment_state_with_config(self):
        """Test saving environment state with provided config."""
        test_state = EnvironmentState(environment="test", branch="main")

        save_environment_state(test_state, self.config)

        # Verify state was saved
        retrieved_state = get_current_environment(self.config)
        assert retrieved_state.environment == "test"
        assert retrieved_state.branch == "main"

    @patch('auto_secrets.core.environment.load_config')
    def test_save_environment_state_without_config(self, mock_load_config):
        """Test saving environment state without config."""
        mock_load_config.return_value = self.config
        test_state = EnvironmentState(environment="test", branch="main")

        save_environment_state(test_state)

        mock_load_config.assert_called_once()

    def test_clear_environment_state_with_config(self):
        """Test clearing environment state with provided config."""
        # First save some state
        test_state = EnvironmentState(environment="test", branch="main")
        save_environment_state(test_state, self.config)

        # Verify state exists
        state = get_current_environment(self.config)
        assert state.is_valid()

        # Clear state
        clear_environment_state(self.config)

        # Verify state is cleared
        state = get_current_environment(self.config)
        assert not state.is_valid()

    @patch('auto_secrets.core.environment.load_config')
    def test_clear_environment_state_without_config(self, mock_load_config):
        """Test clearing environment state without config."""
        mock_load_config.return_value = self.config

        clear_environment_state()

        mock_load_config.assert_called_once()


class TestEnvironmentNameValidation:
    """Test environment name validation."""

    def test_valid_environment_names(self):
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
            "my_env_123"
        ]

        for name in valid_names:
            assert is_valid_environment_name(name), f"'{name}' should be valid"

    def test_invalid_environment_names(self):
        """Test validation of invalid environment names."""
        invalid_names = [
            "",  # Empty string
            None,  # None
            123,  # Not a string
            "-production",  # Starts with hyphen
            "staging-",  # Ends with hyphen
            "_development",  # Starts with underscore
            "test_",  # Ends with underscore
            "prod@duction",  # Invalid character
            "staging with spaces",  # Contains spaces
            "a" * 65,  # Too long (over 64 chars)
            "test/env",  # Invalid character (slash)
            "test.env",  # Invalid character (dot)
            "test#env",  # Invalid character (hash)
            "test$env",  # Invalid character (dollar)
        ]

        for name in invalid_names:
            assert not is_valid_environment_name(name), f"'{name}' should be invalid"

    def test_edge_case_environment_names(self):
        """Test edge cases in environment name validation."""
        # Boundary cases
        assert is_valid_environment_name("a")  # Minimum length
        assert is_valid_environment_name("a" * 64)  # Maximum length
        assert not is_valid_environment_name("a" * 65)  # Over maximum

        # Mixed valid characters
        assert is_valid_environment_name("env123abc")
        assert is_valid_environment_name("test-env_123")

        # Just numbers (should be valid if within constraints)
        assert is_valid_environment_name("1")
        assert is_valid_environment_name("123")


class TestDebugInfo:
    """Test debug information generation."""

    def setup_method(self):
        """Set up test configuration."""
        self.temp_dir = tempfile.mkdtemp()
        self.config = {
            "cache_base_dir": self.temp_dir,
            "debug": False
        }

    def teardown_method(self):
        """Clean up after tests."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_get_environment_debug_info_with_config(self):
        """Test getting debug info with provided config."""
        debug_info = get_environment_debug_info(self.config)

        assert "state_manager" in debug_info
        assert "working_directory" in debug_info
        assert "user_id" in debug_info
        assert "environment_variables" in debug_info

        # Check user_id is valid
        assert debug_info["user_id"] == os.getuid()

        # Check working directory
        assert debug_info["working_directory"] == os.getcwd()

    @patch('auto_secrets.core.environment.load_config')
    def test_get_environment_debug_info_without_config(self, mock_load_config):
        """Test getting debug info without config."""
        mock_load_config.return_value = self.config

        debug_info = get_environment_debug_info()

        assert isinstance(debug_info, dict)
        mock_load_config.assert_called_once()

    @patch.dict(os.environ, {
        'AUTO_SECRETS_DEBUG': 'true',
        'AUTO_SECRETS_ENABLE': 'false',
        'OTHER_VAR': 'should_not_appear'
    })
    def test_get_environment_debug_info_filters_env_vars(self):
        """Test that debug info only includes AUTO_SECRETS_ environment variables."""
        debug_info = get_environment_debug_info(self.config)

        env_vars = debug_info["environment_variables"]

        # Should include AUTO_SECRETS_ variables
        assert "AUTO_SECRETS_DEBUG" in env_vars
        assert "AUTO_SECRETS_ENABLE" in env_vars

        # Should not include other variables
        assert "OTHER_VAR" not in env_vars


class TestAtomicOperations:
    """Test atomic file operations behavior."""

    def setup_method(self):
        """Set up test configuration."""
        self.temp_dir = tempfile.mkdtemp()
        self.config = {
            "cache_base_dir": self.temp_dir,
            "debug": False
        }

    def teardown_method(self):
        """Clean up after tests."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_atomic_save_creates_temp_file(self):
        """Test that atomic save uses temporary file."""
        manager = EnvironmentStateManager(self.config)
        test_state = EnvironmentState(environment="test", branch="main")

        # Monitor filesystem during save
        temp_files_before = list(manager.state_file.parent.glob("*.tmp"))

        manager.save_state(test_state)

        # After save, temp file should be cleaned up
        temp_files_after = list(manager.state_file.parent.glob("*.tmp"))

        # Temp file count should be the same (cleaned up)
        assert len(temp_files_after) == len(temp_files_before)

        # But final file should exist
        assert manager.state_file.exists()

    def test_state_file_permissions(self):
        """Test that state file has correct permissions."""
        manager = EnvironmentStateManager(self.config)
        test_state = EnvironmentState(environment="test", branch="main")

        manager.save_state(test_state)

        # Check file permissions (should be 0o600)
        file_mode = manager.state_file.stat().st_mode & 0o777
        assert file_mode == 0o600


if __name__ == '__main__':
    pytest.main([__file__])
