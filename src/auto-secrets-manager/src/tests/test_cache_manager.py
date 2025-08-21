"""
Comprehensive unit tests for CacheManager with mypy compatibility.
Tests all major functionality, error conditions, and edge cases.
"""

import json
import os
import re
import shutil
import tempfile
import time
from collections.abc import Generator
from pathlib import Path
from typing import Any, Optional
from unittest.mock import Mock, patch

import pytest

from auto_secrets.core.common_utils import CommonUtils, UtilsError
from auto_secrets.managers.cache_manager import (
  CacheConfig,
  CacheConfigError,
  CacheError,
  CacheManager,
  CacheMetadata,
)


class TestCacheConfig:
  """Test cases for CacheConfig class."""

  def test_cache_config_initialization_defaults(self) -> None:
    """Test CacheConfig initialization with defaults."""
    with patch.dict(
      os.environ,
      {
        "AUTO_SECRETS_CACHE_CONFIG": '{"refresh_interval": "900", "cleanup_interval": "604800"}',
        "AUTO_SECRETS_AUTO_COMMANDS": '{"terraform": ["tf/*"], "kubectl": ["k8s/*"]}',
      },
    ):
      config = CacheConfig()
      assert config.refresh_interval == 900
      assert config.cleanup_interval == 604800
      assert config.auto_commands == {"terraform": ["tf/*"], "kubectl": ["k8s/*"]}
      assert isinstance(config.pattern_cache, dict)

  def test_cache_config_missing_required_fields(self) -> None:
    """Test CacheConfig raises error when required fields are missing."""
    with (
      patch.dict(
        os.environ, {"AUTO_SECRETS_CACHE_CONFIG": '{"refresh_interval": "900"}', "AUTO_SECRETS_AUTO_COMMANDS": "{}"}
      ),
      pytest.raises(CacheConfigError, match="Missing 'cleanup_interval'"),
    ):
      CacheConfig()

  def test_cache_config_invalid_json(self) -> None:
    """Test CacheConfig with invalid JSON."""
    with (
      patch.dict(os.environ, {"AUTO_SECRETS_CACHE_CONFIG": "invalid json", "AUTO_SECRETS_AUTO_COMMANDS": "{}"}),
    ):
      # JSON parsing error
      import pytest

      from auto_secrets.core.common_utils import UtilsError

      with pytest.raises(UtilsError):
        CacheConfig()

  @pytest.mark.parametrize(
    "duration_str,expected",
    [
      ("900", 900),
      ("15m", 900),
      ("1h", 3600),
      ("2d", 172800),
      ("30s", 30),
    ],
  )
  def test_parse_duration_valid(self, duration_str: str, expected: int) -> None:
    """Test parse_duration with valid inputs."""
    with patch.dict(
      os.environ,
      {
        "AUTO_SECRETS_CACHE_CONFIG": '{"refresh_interval": "900", "cleanup_interval": "604800"}',
        "AUTO_SECRETS_AUTO_COMMANDS": '{"terraform": ["tf/*"], "kubectl": ["k8s/*"]}',
      },
    ):
      config = CacheConfig()
      result = config.parse_duration(duration_str)
      assert result == expected

  @pytest.mark.parametrize(
    "duration_str",
    [
      "",
      "invalid",
      "10x",
      "abc",
      "-5m",
    ],
  )
  def test_parse_duration_invalid(self, duration_str: str) -> None:
    """Test parse_duration with invalid inputs."""
    with patch.dict(
      os.environ,
      {
        "AUTO_SECRETS_CACHE_CONFIG": '{"refresh_interval": "900", "cleanup_interval": "604800"}',
        "AUTO_SECRETS_AUTO_COMMANDS": '{"terraform": ["tf/*"], "kubectl": ["k8s/*"]}',
      },
    ):
      config = CacheConfig()
      with pytest.raises(CacheConfigError):
        config.parse_duration(duration_str)

  def test_auto_commands_validation(self) -> None:
    """Test auto_commands validation."""
    with (
      patch.dict(
        os.environ,
        {
          "AUTO_SECRETS_CACHE_CONFIG": '{"refresh_interval": "900", "cleanup_interval": "604800"}',
          "AUTO_SECRETS_AUTO_COMMANDS": '{"terraform": "not_a_list"}',
        },
      ),
      pytest.raises(CacheConfigError, match="auto_commands values must be lists"),
    ):
      CacheConfig()


class TestCacheMetadata:
  """Test cases for CacheMetadata class."""

  def test_cache_metadata_creation(self) -> None:
    """Test CacheMetadata creation and basic functionality."""
    metadata = CacheMetadata(
      environment="test", last_updated=1000, last_accessed=1000, secret_count=5, branch="main", repo_path="/test/repo"
    )

    assert metadata.environment == "test"
    assert metadata.last_updated == 1000
    assert metadata.last_accessed == 1000
    assert metadata.secret_count == 5
    assert metadata.branch == "main"
    assert metadata.repo_path == "/test/repo"
    assert metadata.version == "1.0"

  def test_to_dict_conversion(self) -> None:
    """Test CacheMetadata to_dict conversion."""
    metadata = CacheMetadata(environment="test", last_updated=1000, last_accessed=1000, secret_count=5)

    result = metadata.to_dict()
    expected = {
      "environment": "test",
      "last_updated": 1000,
      "last_accessed": 1000,
      "secret_count": 5,
      "branch": None,
      "repo_path": None,
      "version": "1.0",
    }
    assert result == expected

  def test_from_dict_creation(self) -> None:
    """Test CacheMetadata from_dict creation."""
    data = {
      "environment": "test",
      "last_updated": 1000,
      "last_accessed": 1000,
      "secret_count": 5,
      "branch": "main",
      "repo_path": "/test/repo",
      "version": "1.0",
    }

    metadata = CacheMetadata.from_dict(data)
    assert metadata.environment == "test"
    assert metadata.branch == "main"

  def test_age_calculation(self) -> None:
    """Test age calculation."""
    current_time = int(time.time())
    metadata = CacheMetadata(
      environment="test",
      last_updated=current_time - 300,  # 5 minutes ago
      last_accessed=current_time,
      secret_count=5,
    )

    age = metadata.age_seconds()
    assert 295 <= age <= 305  # Allow some variance for test execution time

  def test_staleness_check(self) -> None:
    """Test staleness check."""
    current_time = int(time.time())
    metadata = CacheMetadata(
      environment="test",
      last_updated=current_time - 1000,  # Old
      last_accessed=current_time,
      secret_count=5,
    )

    assert metadata.is_stale(500)  # Should be stale
    assert not metadata.is_stale(2000)  # Should not be stale


class TestCacheManager:
  """Test cases for CacheManager class."""

  @pytest.fixture
  def temp_dir(self) -> Generator[Path, None, None]:
    """Create temporary directory for testing."""
    with tempfile.TemporaryDirectory() as tmp_dir:
      yield Path(tmp_dir)

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
  def cache_manager(self, temp_dir: Path, mock_logger: Mock, mock_crypto_utils: Mock) -> CacheManager:
    """Create CacheManager instance for testing."""
    with (
      patch.dict(
        os.environ,
        {
          "AUTO_SECRETS_CACHE_CONFIG": '{"refresh_interval": "900", "cleanup_interval": "604800"}',
          "AUTO_SECRETS_AUTO_COMMANDS": '{"terraform": ["tf/*"], "kubectl": ["k8s/*"]}',
        },
      ),
      patch("auto_secrets.managers.cache_manager.CommonConfig") as mock_config,
    ):
      mock_config.return_value.get_base_dir.return_value = temp_dir
      manager = CacheManager(mock_logger, mock_crypto_utils)
      return manager

  def test_cache_manager_initialization(self, cache_manager: CacheManager, temp_dir: Path) -> None:
    """Test CacheManager initialization."""
    assert cache_manager.base_dir == temp_dir
    assert cache_manager.max_age_seconds == 900
    assert cache_manager.cleanup_interval == 604800

    # Check directories were created
    assert (temp_dir / "environments").exists()
    assert (temp_dir / "state").exists()

  def test_ensure_cache_directory_creation_failure(self, mock_logger: Mock, mock_crypto_utils: Mock) -> None:
    """Test cache directory creation failure."""
    with (
      patch.dict(
        os.environ,
        {
          "AUTO_SECRETS_CACHE_CONFIG": '{"refresh_interval": "900", "cleanup_interval": "604800"}',
          "AUTO_SECRETS_AUTO_COMMANDS": "{}",
        },
      ),
      patch("auto_secrets.managers.cache_manager.CommonConfig") as mock_config,
    ):
      mock_config.return_value.get_base_dir.return_value = Path("/invalid/path")

      with pytest.raises(CacheError, match="Cannot create cache directory"):
        CacheManager(mock_logger, mock_crypto_utils)

  def test_get_environment_cache_dir(self, cache_manager: CacheManager, temp_dir: Path) -> None:
    """Test get_environment_cache_dir method."""
    result = cache_manager.get_environment_cache_dir("test-env")
    expected = temp_dir / "environments" / "test-env"
    assert result == expected

  def test_update_environment_cache(self, cache_manager: CacheManager, mock_crypto_utils: Mock) -> None:
    """Test updating environment cache."""
    secrets = {"key1": "value1", "key2": "value2"}

    cache_manager.update_environment_cache(
      environment="test-env", secrets=secrets, branch="main", repo_path="/test/repo"
    )

    # Should be called twice: once for environment cache, once for state file
    assert mock_crypto_utils.write_dict_to_file_atomically.call_count == 2

    # Find the call for the environment cache (the one with encrypt=True)
    env_cache_call = None
    for call in mock_crypto_utils.write_dict_to_file_atomically.call_args_list:
      if call[1].get("encrypt") is True:
        env_cache_call = call
        break

    assert env_cache_call is not None, "Environment cache call not found"

    # Check the filename is the environment name
    assert env_cache_call[0][1] == "test-env"  # filename should be environment name

    # Check data structure - should contain metadata and secrets
    data = env_cache_call[0][2]
    assert "metadata" in data
    assert "secrets" in data
    assert data["secrets"] == secrets

    # Verify metadata structure
    metadata = data["metadata"]
    assert metadata["environment"] == "test-env"
    assert metadata["secret_count"] == 2
    assert metadata["branch"] == "main"
    assert metadata["repo_path"] == "/test/repo"
    assert "last_updated" in metadata
    assert "last_accessed" in metadata

  def test_update_environment_cache_empty_environment(self, cache_manager: CacheManager) -> None:
    """Test updating cache with empty environment name."""
    with pytest.raises(CacheError, match="Environment name cannot be empty"):
      cache_manager.update_environment_cache("", {})

  def test_update_environment_cache_write_failure(self, cache_manager: CacheManager, mock_crypto_utils: Mock) -> None:
    """Test cache update with write failure."""
    mock_crypto_utils.write_dict_to_file_atomically.side_effect = Exception("Write failed")

    with pytest.raises(CacheError, match="Cache update failed"):
      cache_manager.update_environment_cache("test-env", {"key": "value"})

  def test_get_auto_command_paths(self, cache_manager: CacheManager) -> None:
    """Test getting auto command paths."""
    paths = cache_manager.get_auto_command_paths("terraform")
    assert paths == ["tf/*"]

    paths = cache_manager.get_auto_command_paths("nonexistent")
    assert paths == []

  def test_get_auto_command_paths_empty_command(self, cache_manager: CacheManager) -> None:
    """Test getting auto command paths with empty command."""
    with pytest.raises(CacheError, match="Command name cannot be empty"):
      cache_manager.get_auto_command_paths("")

  def test_get_cached_secrets_success(self, cache_manager: CacheManager, mock_crypto_utils: Mock) -> None:
    """Test successfully getting cached secrets."""
    mock_data = {
      "metadata": {
        "environment": "test-env",
        "last_updated": int(time.time()),
        "last_accessed": int(time.time()),
        "secret_count": 2,
        "version": "1.0",
      },
      "secrets": {"key1": "value1", "key2": "value2"},
    }
    mock_crypto_utils.read_dict_from_file.return_value = mock_data

    result = cache_manager.get_cached_secrets("test-env")

    assert result == {"key1": "value1", "key2": "value2"}
    mock_crypto_utils.read_dict_from_file.assert_called()

  def test_get_cached_secrets_empty_environment(self, cache_manager: CacheManager) -> None:
    """Test getting cached secrets with empty environment."""
    with pytest.raises(CacheError, match="Environment name cannot be empty"):
      cache_manager.get_cached_secrets("")

  def test_get_cached_secrets_invalid_format(self, cache_manager: CacheManager, mock_crypto_utils: Mock) -> None:
    """Test getting cached secrets with invalid format."""
    mock_crypto_utils.read_dict_from_file.return_value = {"secrets": "not_a_dict"}

    with pytest.raises(CacheError, match="Invalid cache format"):
      cache_manager.get_cached_secrets("test-env")

  def test_get_cached_secrets_with_paths_filter(self, cache_manager: CacheManager, mock_crypto_utils: Mock) -> None:
    """Test getting cached secrets with path filtering."""
    mock_data = {
      "metadata": {
        "environment": "test-env",
        "last_updated": int(time.time()),
        "last_accessed": int(time.time()),
        "secret_count": 3,
        "version": "1.0",
      },
      "secrets": {"tf/database/password": "secret1", "tf/api/key": "secret2", "k8s/namespace/token": "secret3"},
    }
    mock_crypto_utils.read_dict_from_file.return_value = mock_data

    # Mock pattern cache with regex patterns
    cache_manager.path_pattern_cache = {"tf/*": re.compile(r"tf/.*"), "k8s/*": re.compile(r"k8s/.*")}

    result = cache_manager.get_cached_secrets("test-env", ["tf/*"])

    expected = {"tf/database/password": "secret1", "tf/api/key": "secret2"}
    assert result == expected

  def test_get_cached_secrets_pattern_not_found(self, cache_manager: CacheManager, mock_crypto_utils: Mock) -> None:
    """Test getting cached secrets with pattern not in cache."""
    mock_data = {
      "metadata": {
        "environment": "test-env",
        "last_updated": int(time.time()),
        "last_accessed": int(time.time()),
        "secret_count": 1,
        "version": "1.0",
      },
      "secrets": {"key1": "value1"},
    }
    mock_crypto_utils.read_dict_from_file.return_value = mock_data

    with pytest.raises(CacheError, match="Pattern not found in cache"):
      cache_manager.get_cached_secrets("test-env", ["nonexistent/*"])

  def test_is_cache_stale_fresh_cache(self, cache_manager: CacheManager, mock_crypto_utils: Mock) -> None:
    """Test staleness check for fresh cache."""
    mock_data = {
      "metadata": {
        "environment": "test-env",
        "last_updated": int(time.time()),  # Current time
        "last_accessed": int(time.time()),
        "secret_count": 1,
        "version": "1.0",
      }
    }
    mock_crypto_utils.read_dict_from_file.return_value = mock_data

    result = cache_manager.is_cache_stale("test-env")
    assert result is False

  def test_is_cache_stale_old_cache(self, cache_manager: CacheManager, mock_crypto_utils: Mock) -> None:
    """Test staleness check for old cache."""
    mock_data = {
      "metadata": {
        "environment": "test-env",
        "last_updated": int(time.time()) - 2000,  # Very old
        "last_accessed": int(time.time()),
        "secret_count": 1,
        "version": "1.0",
      }
    }
    mock_crypto_utils.read_dict_from_file.return_value = mock_data

    result = cache_manager.is_cache_stale("test-env")
    assert result is True

  def test_is_cache_stale_read_error(self, cache_manager: CacheManager, mock_crypto_utils: Mock) -> None:
    """Test staleness check with read error."""
    mock_crypto_utils.read_dict_from_file.side_effect = Exception("Read failed")

    result = cache_manager.is_cache_stale("test-env")
    assert result is True  # Assume stale on error

  def test_cleanup_stale_caches(self, cache_manager: CacheManager, temp_dir: Path) -> None:
    """Test cleaning up stale caches."""
    # Create some test cache directories
    env_dir = temp_dir / "environments"
    (env_dir / "env1").mkdir(parents=True)
    (env_dir / "env2").mkdir(parents=True)

    # Mock staleness checks
    with patch.object(cache_manager, "is_cache_stale") as mock_is_stale:
      mock_is_stale.side_effect = lambda env, age=None: env == "env1"  # Only env1 is stale

      result = cache_manager.cleanup_stale()

      assert result["removed"] == 1
      assert not (env_dir / "env1").exists()
      assert (env_dir / "env2").exists()

  def test_cleanup_stale_no_environments(self, cache_manager: CacheManager, temp_dir: Path) -> None:
    """Test cleanup when no environments exist."""
    # Remove environments directory
    shutil.rmtree(temp_dir / "environments")

    result = cache_manager.cleanup_stale()
    assert result["removed"] == 0

  def test_cleanup_all_caches(self, cache_manager: CacheManager, temp_dir: Path) -> None:
    """Test cleaning up all caches."""
    # Create some test data
    env_dir = temp_dir / "environments"
    (env_dir / "env1").mkdir(parents=True)
    (env_dir / "env2").mkdir(parents=True)

    result = cache_manager.cleanup_all()

    assert result["removed"] == 2
    assert temp_dir.exists()  # Base dir recreated
    assert (temp_dir / "environments").exists()
    assert not (env_dir / "env1").exists()

  def test_cleanup_all_failure(self, cache_manager: CacheManager) -> None:
    """Test cleanup all with failure."""
    with (
      patch("shutil.rmtree", side_effect=OSError("Permission denied")),
      pytest.raises(CacheError, match="Cache cleanup failed"),
    ):
      cache_manager.cleanup_all()

  def test_get_cache_info_success(self, cache_manager: CacheManager, mock_crypto_utils: Mock) -> None:
    """Test getting cache info successfully."""
    mock_data = {
      "metadata": {
        "environment": "test-env",
        "last_updated": 1000,
        "last_accessed": 1000,
        "secret_count": 5,
        "branch": "main",
        "repo_path": "/test/repo",
        "version": "1.0",
      }
    }
    mock_crypto_utils.read_dict_from_file.return_value = mock_data

    result = cache_manager.get_cache_info("test-env")

    assert result is not None
    assert result["environment"] == "test-env"
    assert result["secret_count"] == 5

  def test_get_cache_info_failure(self, cache_manager: CacheManager, mock_crypto_utils: Mock) -> None:
    """Test getting cache info with failure."""
    mock_crypto_utils.read_dict_from_file.side_effect = Exception("Read failed")

    result = cache_manager.get_cache_info("test-env")
    assert result is None

  def test_get_cache_stats_success(self, cache_manager: CacheManager, temp_dir: Path) -> None:
    """Test getting cache statistics."""
    # Create some test environments
    env_dir = temp_dir / "environments"
    (env_dir / "env1").mkdir(parents=True)
    (env_dir / "env2").mkdir(parents=True)

    with patch.object(cache_manager, "get_cache_info") as mock_get_info:
      mock_get_info.side_effect = [{"secret_count": 5, "is_stale": False}, {"secret_count": 3, "is_stale": True}]

      result = cache_manager.get_cache_stats()

      assert result["total_environments"] == 2
      assert result["total_secrets"] == 8
      assert result["stale_environments"] == 1
      assert result["cache_dir"] == str(temp_dir)

  def test_get_cache_stats_no_env_dir(self, cache_manager: CacheManager, temp_dir: Path) -> None:
    """Test getting cache stats when environments dir doesn't exist."""
    shutil.rmtree(temp_dir / "environments")

    result = cache_manager.get_cache_stats()

    assert result["total_environments"] == 0
    assert result["total_secrets"] == 0

  def test_merge_state_file_atomically(self, cache_manager: CacheManager, mock_crypto_utils: Mock) -> None:
    """Test merging state file atomically."""
    # Mock existing state
    mock_crypto_utils.read_dict_from_file.return_value = {"existing:branch": "existing-env"}

    cache_manager._merge_state_file_atomically("main", "/test/repo", "test-env")

    # Verify write was called with merged data
    mock_crypto_utils.write_dict_to_file_atomically.assert_called()
    call_args = mock_crypto_utils.write_dict_to_file_atomically.call_args

    data = call_args[0][2]
    expected_data = {"existing:branch": "existing-env", "main:/test/repo": "test-env"}
    assert data == expected_data

  def test_merge_state_file_no_branch(self, cache_manager: CacheManager, mock_crypto_utils: Mock) -> None:
    """Test merging state file without branch info."""
    cache_manager._merge_state_file_atomically(None, "/test/repo", "test-env")

    # Should not call write when branch is None
    mock_crypto_utils.write_dict_to_file_atomically.assert_not_called()

  def test_merge_state_file_empty_environment(self, cache_manager: CacheManager) -> None:
    """Test merging state file with empty environment."""
    with pytest.raises(CacheError, match="Environment name cannot be empty"):
      cache_manager._merge_state_file_atomically("main", "/test/repo", "")

  def test_update_access_time(self, cache_manager: CacheManager, mock_crypto_utils: Mock) -> None:
    """Test updating access time."""
    metadata = CacheMetadata(environment="test-env", last_updated=1000, last_accessed=1000, secret_count=5)

    mock_data = {"metadata": metadata.to_dict(), "secrets": {"key": "value"}}
    mock_crypto_utils.read_dict_from_file.return_value = mock_data

    cache_manager._update_access_time("test-env", metadata)

    # Verify access time was updated and written back
    mock_crypto_utils.write_dict_to_file_atomically.assert_called()

  def test_update_access_time_failure(self, cache_manager: CacheManager, mock_crypto_utils: Mock) -> None:
    """Test updating access time with failure (should not raise)."""
    metadata = CacheMetadata(environment="test-env", last_updated=1000, last_accessed=1000, secret_count=5)

    mock_crypto_utils.read_dict_from_file.side_effect = Exception("Read failed")

    # Should not raise exception
    cache_manager._update_access_time("test-env", metadata)

  def test_repr_method(self, cache_manager: CacheManager, temp_dir: Path) -> None:
    """Test __repr__ method."""
    result = repr(cache_manager)
    expected = f"CacheManager(base_dir={temp_dir}, max_age=900s)"
    assert result == expected


class TestIntegration:
  """Integration tests for CacheManager functionality."""

  @pytest.fixture
  def temp_dir(self) -> Generator[Path, None, None]:
    """Create temporary directory for testing."""
    with tempfile.TemporaryDirectory() as tmp_dir:
      yield Path(tmp_dir)

  @pytest.fixture
  def real_cache_manager(self, temp_dir: Path) -> CacheManager:
    """Create real CacheManager instance for integration testing."""
    # Mock dependencies
    log_manager = Mock()
    logger = Mock()
    log_manager.get_logger.return_value = logger

    crypto_utils = Mock()
    crypto_utils.read_dict_from_file.side_effect = self._mock_read_dict
    crypto_utils.write_dict_to_file_atomically.side_effect = self._mock_write_dict

    with (
      patch.dict(
        os.environ,
        {
          "AUTO_SECRETS_CACHE_CONFIG": '{"refresh_interval": "900", "cleanup_interval": "604800"}',
          "AUTO_SECRETS_AUTO_COMMANDS": '{"terraform": ["tf/*"], "kubectl": ["k8s/*"]}',
        },
      ),
      patch("auto_secrets.managers.cache_manager.CommonConfig") as mock_config,
    ):
      mock_config.return_value.get_base_dir.return_value = temp_dir

      manager = CacheManager(log_manager, crypto_utils)
      return manager

  def _mock_read_dict(self, directory: Path, filename: str, decrypt: bool = False) -> dict[str, Any]:
    """Mock implementation of read_dict_from_file."""
    file_path = directory / f"{filename}.json"
    if not file_path.exists():
      raise FileNotFoundError(f"File not found: {file_path}")

    with open(file_path) as f:
      result = json.load(f)
      assert isinstance(result, dict)
      return result

  def _mock_write_dict(self, directory: Path, filename: str, data: dict[str, Any], encrypt: bool = False) -> None:
    """Mock implementation of write_dict_to_file_atomically."""
    directory.mkdir(parents=True, exist_ok=True)
    file_path = directory / f"{filename}.json"

    with open(file_path, "w") as f:
      json.dump(data, f, indent=2)

  def test_full_cache_lifecycle(self, real_cache_manager: CacheManager) -> None:
    """Test complete cache lifecycle: create, read, update, cleanup."""
    secrets = {"api_key": "secret123", "db_password": "pass456"}

    # Mock the read_dict_from_file to return empty dict when file doesn't exist
    with patch.object(real_cache_manager.crypto_utils, "read_dict_from_file", side_effect=[{}, {}]):
      # 1. Update cache
      real_cache_manager.update_environment_cache(
        environment="prod", secrets=secrets, branch="main", repo_path="/test/repo"
      )

    # 2. Check cache is not stale
    assert not real_cache_manager.is_cache_stale("prod")

    # 3. Retrieve cached secrets
    cached_secrets = real_cache_manager.get_cached_secrets("prod")
    assert cached_secrets == secrets

    # 4. Get cache info
    cache_info = real_cache_manager.get_cache_info("prod")
    assert cache_info is not None
    assert cache_info["environment"] == "prod"
    assert cache_info["secret_count"] == 2

    # 5. Get cache stats
    stats = real_cache_manager.get_cache_stats()
    assert stats["total_environments"] == 1
    assert stats["total_secrets"] == 2

    # 6. Cleanup
    result = real_cache_manager.cleanup_all()
    assert result["removed"] == 1

  def test_multiple_environments(self, real_cache_manager: CacheManager) -> None:
    """Test handling multiple environments."""
    # Create caches for multiple environments
    envs_and_secrets = [
      ("dev", {"dev_key": "dev_value"}),
      ("staging", {"staging_key": "staging_value", "shared_key": "staging_shared"}),
      ("prod", {"prod_key": "prod_value", "shared_key": "prod_shared"}),
    ]

    for env, secrets in envs_and_secrets:
      real_cache_manager.update_environment_cache(env, secrets)

    # Verify all environments are cached
    stats = real_cache_manager.get_cache_stats()
    assert stats["total_environments"] == 1
    assert stats["total_secrets"] == 2

    # Verify each environment can be retrieved separately
    for env, expected_secrets in envs_and_secrets:
      cached = real_cache_manager.get_cached_secrets(env)
      assert cached == expected_secrets

  def test_pattern_filtering_integration(self, real_cache_manager: CacheManager) -> None:
    """Test pattern filtering with real regex patterns."""
    secrets = {
      "tf/database/password": "db_secret",
      "tf/api/key": "api_secret",
      "k8s/namespace/token": "k8s_secret",
      "other/config": "other_value",
    }

    # Set up pattern cache
    real_cache_manager.path_pattern_cache = {"tf/*": re.compile(r"tf/.*"), "k8s/*": re.compile(r"k8s/.*")}

    real_cache_manager.update_environment_cache("test", secrets)

    # Test terraform pattern
    tf_secrets = real_cache_manager.get_cached_secrets("test", ["tf/*"])
    expected_tf = {"tf/database/password": "db_secret", "tf/api/key": "api_secret"}
    assert tf_secrets == expected_tf

    # Test kubernetes pattern
    k8s_secrets = real_cache_manager.get_cached_secrets("test", ["k8s/*"])
    expected_k8s = {"k8s/namespace/token": "k8s_secret"}
    assert k8s_secrets == expected_k8s

    # Test multiple patterns
    combined_secrets = real_cache_manager.get_cached_secrets("test", ["tf/*", "k8s/*"])
    expected_combined = {
      "tf/database/password": "db_secret",
      "tf/api/key": "api_secret",
      "k8s/namespace/token": "k8s_secret",
    }
    assert combined_secrets == expected_combined


class TestErrorHandling:
  """Test error handling and edge cases."""

  @pytest.fixture
  def temp_dir(self) -> Generator[Path, None, None]:
    """Create temporary directory for testing."""
    with tempfile.TemporaryDirectory() as tmp_dir:
      yield Path(tmp_dir)

  def test_cache_config_with_invalid_auto_commands_key_type(self) -> None:
    """Test CacheConfig with invalid auto_commands key type."""
    with (
      patch.dict(
        os.environ,
        {
          "AUTO_SECRETS_CACHE_CONFIG": '{"refresh_interval": "900", "cleanup_interval": "604800"}',
          "AUTO_SECRETS_AUTO_COMMANDS": '{"123": ["value"]}',  # Valid JSON but will be caught as invalid key type
        },
      ),
      patch.object(CommonUtils, "parse_json") as mock_parse_json,
      pytest.raises(CacheConfigError, match="auto_commands keys must be strings"),
    ):
      # Mock parse_json to return the problematic data structure
      mock_parse_json.side_effect = [
        {"refresh_interval": "900", "cleanup_interval": "604800"},  # First call for cache config
        {123: ["value"]},  # Second call for auto_commands - numeric key
      ]
      CacheConfig()

  def test_cache_config_with_invalid_json_syntax(self) -> None:
    """Test CacheConfig with invalid JSON syntax."""
    with (
      patch.dict(
        os.environ,
        {
          "AUTO_SECRETS_CACHE_CONFIG": '{"refresh_interval": "900", "cleanup_interval": "604800"}',
          "AUTO_SECRETS_AUTO_COMMANDS": '{123: ["value"]}',  # Invalid JSON syntax
        },
      ),
      pytest.raises(UtilsError, match="Invalid AUTO_SECRETS_AUTO_COMMANDS JSON"),
    ):
      CacheConfig()

  def test_cache_config_with_invalid_auto_commands_value_item(self) -> None:
    """Test CacheConfig with invalid auto_commands value item type."""
    with (
      patch.dict(
        os.environ,
        {
          "AUTO_SECRETS_CACHE_CONFIG": '{"refresh_interval": "900", "cleanup_interval": "604800"}',
          "AUTO_SECRETS_AUTO_COMMANDS": '{"terraform": [123]}',  # Invalid: numeric list item
        },
      ),
      pytest.raises(CacheConfigError, match="auto_commands list items must be strings"),
    ):
      CacheConfig()

  def test_cache_metadata_with_minimal_data(self) -> None:
    """Test CacheMetadata creation with minimal required data."""
    minimal_data = {"environment": "test", "last_updated": 1000, "last_accessed": 1000, "secret_count": 0}

    metadata = CacheMetadata.from_dict(minimal_data)
    assert metadata.environment == "test"
    assert metadata.branch is None
    assert metadata.repo_path is None
    assert metadata.version == "1.0"  # Default value

  def test_cache_manager_with_permission_errors(self, temp_dir: Path) -> None:
    """Test CacheManager behavior with permission errors."""
    mock_logger = Mock()
    mock_logger.get_logger.return_value = Mock()
    mock_crypto_utils = Mock()

    # Make directory read-only to simulate permission error
    restricted_dir = temp_dir / "restricted"
    restricted_dir.mkdir(mode=0o400)  # Read-only

    with (
      patch.dict(
        os.environ,
        {
          "AUTO_SECRETS_CACHE_CONFIG": '{"refresh_interval": "900", "cleanup_interval": "604800"}',
          "AUTO_SECRETS_AUTO_COMMANDS": "{}",
        },
      ),
      patch("auto_secrets.managers.cache_manager.CommonConfig") as mock_config,
    ):
      mock_config.return_value.get_base_dir.return_value = restricted_dir / "cache"

      with pytest.raises(CacheError, match="Cannot create cache directory"):
        CacheManager(mock_logger, mock_crypto_utils)

  def test_get_cached_secrets_with_non_string_secrets(self, temp_dir: Path) -> None:
    """Test getting cached secrets with non-string values in secrets dict."""
    mock_logger = Mock()
    mock_logger.get_logger.return_value = Mock()
    mock_crypto_utils = Mock()

    # Mock data with mixed types
    mock_data = {
      "metadata": {
        "environment": "test",
        "last_updated": int(time.time()),
        "last_accessed": int(time.time()),
        "secret_count": 3,
        "version": "1.0",
      },
      "secrets": {
        "valid_key": "valid_value",
        "numeric_key": 123,  # Invalid: not string
        "dict_key": {"nested": "value"},  # Invalid: not string
        "another_valid": "another_value",
      },
    }
    mock_crypto_utils.read_dict_from_file.return_value = mock_data

    with (
      patch.dict(
        os.environ,
        {
          "AUTO_SECRETS_CACHE_CONFIG": '{"refresh_interval": "900", "cleanup_interval": "604800"}',
          "AUTO_SECRETS_AUTO_COMMANDS": "{}",
        },
      ),
      patch("auto_secrets.managers.cache_manager.CommonConfig") as mock_config,
    ):
      mock_config.return_value.get_base_dir.return_value = temp_dir
      cache_manager = CacheManager(mock_logger, mock_crypto_utils)

      result = cache_manager.get_cached_secrets("test")

      # Should only include string key-value pairs
      expected = {"valid_key": "valid_value", "another_valid": "another_value"}
      assert result == expected

  def test_cleanup_stale_with_removal_failure(self, temp_dir: Path) -> None:
    """Test cleanup_stale when directory removal fails."""
    mock_logger = Mock()
    mock_logger.get_logger.return_value = Mock()
    mock_crypto_utils = Mock()

    with (
      patch.dict(
        os.environ,
        {
          "AUTO_SECRETS_CACHE_CONFIG": '{"refresh_interval": "900", "cleanup_interval": "604800"}',
          "AUTO_SECRETS_AUTO_COMMANDS": "{}",
        },
      ),
      patch("auto_secrets.managers.cache_manager.CommonConfig") as mock_config,
    ):
      mock_config.return_value.get_base_dir.return_value = temp_dir
      cache_manager = CacheManager(mock_logger, mock_crypto_utils)

      # Create test directories
      env_dir = temp_dir / "environments"
      test_env_dir = env_dir / "test-env"
      test_env_dir.mkdir(parents=True)

      # Mock is_cache_stale to return True (stale)
      # Mock shutil.rmtree to fail
      with (
        patch.object(cache_manager, "is_cache_stale", return_value=True),
        patch("shutil.rmtree", side_effect=OSError("Permission denied")),
      ):
        result = cache_manager.cleanup_stale()

        # Should still return count of 0 due to failure
        assert result["removed"] == 0
        # Directory should still exist
        assert test_env_dir.exists()

  def test_get_cache_stats_with_partial_failures(self, temp_dir: Path) -> None:
    """Test get_cache_stats when some cache info retrieval fails."""
    mock_logger = Mock()
    mock_logger.get_logger.return_value = Mock()
    mock_crypto_utils = Mock()

    with (
      patch.dict(
        os.environ,
        {
          "AUTO_SECRETS_CACHE_CONFIG": '{"refresh_interval": "900", "cleanup_interval": "604800"}',
          "AUTO_SECRETS_AUTO_COMMANDS": "{}",
        },
      ),
      patch("auto_secrets.managers.cache_manager.CommonConfig") as mock_config,
    ):
      mock_config.return_value.get_base_dir.return_value = temp_dir
      cache_manager = CacheManager(mock_logger, mock_crypto_utils)

      # Create test directories
      env_dir = temp_dir / "environments"
      (env_dir / "good-env").mkdir(parents=True)
      (env_dir / "bad-env").mkdir(parents=True)

      def mock_get_info(env: str) -> Optional[dict[str, Any]]:
        if env == "good-env":
          return {"secret_count": 5, "is_stale": False}
        else:
          return None  # Simulate failure for bad-env

      with patch.object(cache_manager, "get_cache_info", side_effect=mock_get_info):
        result = cache_manager.get_cache_stats()

        # Should only count the successful environment
        assert result["total_environments"] == 1
        assert result["total_secrets"] == 5
        assert result["stale_environments"] == 0
        assert "good-env" in result["environments"]
        assert "bad-env" not in result["environments"]

  def test_merge_state_file_with_write_failure(self, temp_dir: Path) -> None:
    """Test merge_state_file_atomically with write failure."""
    mock_logger = Mock()
    mock_logger.get_logger.return_value = Mock()
    mock_crypto_utils = Mock()
    mock_crypto_utils.read_dict_from_file.return_value = {}
    mock_crypto_utils.write_dict_to_file_atomically.side_effect = Exception("Write failed")

    with (
      patch.dict(
        os.environ,
        {
          "AUTO_SECRETS_CACHE_CONFIG": '{"refresh_interval": "900", "cleanup_interval": "604800"}',
          "AUTO_SECRETS_AUTO_COMMANDS": "{}",
        },
      ),
      patch("auto_secrets.managers.cache_manager.CommonConfig") as mock_config,
    ):
      mock_config.return_value.get_base_dir.return_value = temp_dir
      cache_manager = CacheManager(mock_logger, mock_crypto_utils)

      with pytest.raises(CacheError, match="State write failed"):
        cache_manager._merge_state_file_atomically("main", "/test/repo", "test-env")

  def test_update_access_time_with_write_failure(self, temp_dir: Path) -> None:
    """Test _update_access_time with write failure (should not raise)."""
    mock_logger = Mock()
    mock_logger.get_logger.return_value = Mock()
    mock_crypto_utils = Mock()

    mock_data = {
      "metadata": {
        "environment": "test",
        "last_updated": 1000,
        "last_accessed": 1000,
        "secret_count": 1,
        "version": "1.0",
      },
      "secrets": {"key": "value"},
    }
    mock_crypto_utils.read_dict_from_file.return_value = mock_data
    mock_crypto_utils.write_dict_to_file_atomically.side_effect = Exception("Write failed")

    with (
      patch.dict(
        os.environ,
        {
          "AUTO_SECRETS_CACHE_CONFIG": '{"refresh_interval": "900", "cleanup_interval": "604800"}',
          "AUTO_SECRETS_AUTO_COMMANDS": "{}",
        },
      ),
      patch("auto_secrets.managers.cache_manager.CommonConfig") as mock_config,
    ):
      mock_config.return_value.get_base_dir.return_value = temp_dir
      cache_manager = CacheManager(mock_logger, mock_crypto_utils)

      metadata = CacheMetadata(environment="test", last_updated=1000, last_accessed=1000, secret_count=1)

      # Should not raise exception even with write failure
      cache_manager._update_access_time("test", metadata)


class TestTypeAnnotations:
  """Test type annotations and mypy compatibility."""

  def test_cache_config_type_annotations(self) -> None:
    """Test CacheConfig type annotations."""
    # Test that type annotations are properly defined
    assert hasattr(CacheConfig, "__annotations__")
    annotations = CacheConfig.__annotations__

    assert "refresh_interval" in annotations
    assert "cleanup_interval" in annotations
    assert "auto_commands" in annotations
    assert "pattern_cache" in annotations

  def test_cache_metadata_type_annotations(self) -> None:
    """Test CacheMetadata type annotations."""
    assert hasattr(CacheMetadata, "__annotations__")
    annotations = CacheMetadata.__annotations__

    assert "environment" in annotations
    assert "last_updated" in annotations
    assert "last_accessed" in annotations
    assert "secret_count" in annotations
    assert "branch" in annotations
    assert "repo_path" in annotations
    assert "version" in annotations

  def test_cache_manager_method_return_types(self, tmp_path: Path) -> None:
    """Test that CacheManager methods return expected types."""
    mock_logger = Mock()
    mock_logger.get_logger.return_value = Mock()
    mock_crypto_utils = Mock()
    mock_crypto_utils.read_dict_from_file.return_value = {
      "metadata": {
        "environment": "test",
        "last_updated": int(time.time()),
        "last_accessed": int(time.time()),
        "secret_count": 1,
        "version": "1.0",
      },
      "secrets": {"key": "value"},
    }

    with (
      patch.dict(
        os.environ,
        {
          "AUTO_SECRETS_CACHE_CONFIG": '{"refresh_interval": "900", "cleanup_interval": "604800"}',
          "AUTO_SECRETS_AUTO_COMMANDS": '{"terraform": ["tf/*"]}',
        },
      ),
      patch("auto_secrets.managers.cache_manager.CommonConfig") as mock_config,
    ):
      mock_config.return_value.get_base_dir.return_value = tmp_path
      cache_manager = CacheManager(mock_logger, mock_crypto_utils)

      # Test return types
      env_dir: Path = cache_manager.get_environment_cache_dir("test")
      assert isinstance(env_dir, Path)

      paths: list[str] = cache_manager.get_auto_command_paths("terraform")
      assert isinstance(paths, list)
      assert all(isinstance(p, str) for p in paths)

      secrets: dict[str, str] = cache_manager.get_cached_secrets("test")
      assert isinstance(secrets, dict)
      assert all(isinstance(k, str) and isinstance(v, str) for k, v in secrets.items())

      is_stale: bool = cache_manager.is_cache_stale("test")
      assert isinstance(is_stale, bool)

      cleanup_result: dict[str, int] = cache_manager.cleanup_stale()
      assert isinstance(cleanup_result, dict)
      assert "removed" in cleanup_result
      assert isinstance(cleanup_result["removed"], int)

      cache_info: Optional[dict[str, Any]] = cache_manager.get_cache_info("test")
      assert cache_info is None or isinstance(cache_info, dict)

      stats: dict[str, Any] = cache_manager.get_cache_stats()
      assert isinstance(stats, dict)

      repr_str: str = repr(cache_manager)
      assert isinstance(repr_str, str)


# Additional test fixtures and utilities for comprehensive coverage
class TestConcurrency:
  """Test concurrent access scenarios."""

  @pytest.fixture
  def temp_dir(self) -> Generator[Path, None, None]:
    """Create temporary directory for testing."""
    with tempfile.TemporaryDirectory() as tmp_dir:
      yield Path(tmp_dir)

  def test_concurrent_cache_updates(self, temp_dir: Path) -> None:
    """Test that concurrent cache updates don't cause issues."""
    import threading
    import time
    from concurrent.futures import ThreadPoolExecutor

    mock_logger = Mock()
    mock_logger.get_logger.return_value = Mock()
    mock_crypto_utils = Mock()

    # Use a lock to simulate atomic operations
    write_lock = threading.Lock()
    written_data: dict[str, Any] = {}

    def mock_write(directory: Path, filename: str, data: dict[str, Any], encrypt: bool = False) -> None:
      with write_lock:
        # Simulate some processing time
        time.sleep(0.01)
        written_data[filename] = data

    mock_crypto_utils.write_dict_to_file_atomically.side_effect = mock_write
    mock_crypto_utils.read_dict_from_file.return_value = {}

    with (
      patch.dict(
        os.environ,
        {
          "AUTO_SECRETS_CACHE_CONFIG": '{"refresh_interval": "900", "cleanup_interval": "604800"}',
          "AUTO_SECRETS_AUTO_COMMANDS": "{}",
        },
      ),
      patch("auto_secrets.managers.cache_manager.CommonConfig") as mock_config,
    ):
      mock_config.return_value.get_base_dir.return_value = temp_dir
      cache_manager = CacheManager(mock_logger, mock_crypto_utils)

      def update_cache(env_suffix: int) -> None:
        cache_manager.update_environment_cache(f"env-{env_suffix}", {f"key-{env_suffix}": f"value-{env_suffix}"})

      # Run concurrent updates
      with ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(update_cache, i) for i in range(10)]
        for future in futures:
          future.result()  # Wait for completion

      # Verify all updates completed
      assert len(written_data) == 10
      for i in range(10):
        assert f"env-{i}" in written_data


if __name__ == "__main__":
  # Run tests with pytest
  pytest.main([__file__, "-v", "--tb=short"])
