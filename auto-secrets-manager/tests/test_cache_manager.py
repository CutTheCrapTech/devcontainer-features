"""
Tests for auto_secrets.core.cache_manager module.

Tests the CacheMetadata dataclass and CacheManager class functionality
including secure caching, atomic operations, and staleness detection.
"""

import json
import tempfile
from pathlib import Path
from unittest.mock import patch
import pytest
from typing import Dict, Any

from auto_secrets.core.cache_manager import (  # type: ignore
    CacheError,
    CacheMetadata,
    CacheManager,
)


class TestCacheMetadata:
    """Test CacheMetadata dataclass."""

    def test_empty_metadata_creation(self):
        """Test creating metadata with minimal required fields."""
        metadata = CacheMetadata(
            environment="test",
            created_at=1234567890,
            last_updated=1234567890,
            last_accessed=1234567890,
            secret_count=0
        )

        assert metadata.environment == "test"
        assert metadata.created_at == 1234567890
        assert metadata.last_updated == 1234567890
        assert metadata.last_accessed == 1234567890
        assert metadata.secret_count == 0
        assert metadata.branch is None
        assert metadata.repo_path is None
        assert metadata.status == "ok"
        assert metadata.error_message is None
        assert metadata.version == "1.0"

    def test_full_metadata_creation(self):
        """Test creating metadata with all fields."""
        metadata = CacheMetadata(
            environment="production",
            created_at=1234567890,
            last_updated=1234567895,
            last_accessed=1234567900,
            secret_count=42,
            branch="main",
            repo_path="/path/to/repo",
            status="stale",
            error_message="Test error",
            version="2.0"
        )

        assert metadata.environment == "production"
        assert metadata.created_at == 1234567890
        assert metadata.last_updated == 1234567895
        assert metadata.last_accessed == 1234567900
        assert metadata.secret_count == 42
        assert metadata.branch == "main"
        assert metadata.repo_path == "/path/to/repo"
        assert metadata.status == "stale"
        assert metadata.error_message == "Test error"
        assert metadata.version == "2.0"

    def test_to_dict(self):
        """Test converting metadata to dictionary."""
        metadata = CacheMetadata(
            environment="test",
            created_at=1234567890,
            last_updated=1234567890,
            last_accessed=1234567890,
            secret_count=5,
            branch="develop"
        )

        result = metadata.to_dict()
        expected = {
            "environment": "test",
            "created_at": 1234567890,
            "last_updated": 1234567890,
            "last_accessed": 1234567890,
            "secret_count": 5,
            "branch": "develop",
            "repo_path": None,
            "status": "ok",
            "error_message": None,
            "version": "1.0"
        }

        assert result == expected

    def test_from_dict_complete(self):
        """Test creating metadata from complete dictionary."""
        data = {
            "environment": "staging",
            "created_at": 1234567890,
            "last_updated": 1234567895,
            "last_accessed": 1234567900,
            "secret_count": 10,
            "branch": "feature/test",
            "repo_path": "/repo",
            "status": "error",
            "error_message": "Connection failed",
            "version": "1.5"
        }

        metadata = CacheMetadata.from_dict(data)

        assert metadata.environment == "staging"
        assert metadata.created_at == 1234567890
        assert metadata.last_updated == 1234567895
        assert metadata.last_accessed == 1234567900
        assert metadata.secret_count == 10
        assert metadata.branch == "feature/test"
        assert metadata.repo_path == "/repo"
        assert metadata.status == "error"
        assert metadata.error_message == "Connection failed"
        assert metadata.version == "1.5"

    def test_from_dict_partial(self):
        """Test creating metadata from partial dictionary."""
        data = {
            "environment": "test",
            "created_at": 1234567890,
            "last_updated": 1234567890,
            "last_accessed": 1234567890,
            "secret_count": 3
        }

        metadata = CacheMetadata.from_dict(data)

        assert metadata.environment == "test"
        assert metadata.created_at == 1234567890
        assert metadata.last_updated == 1234567890
        assert metadata.last_accessed == 1234567890
        assert metadata.secret_count == 3
        assert metadata.branch is None
        assert metadata.repo_path is None
        assert metadata.status == "ok"
        assert metadata.error_message is None
        assert metadata.version == "1.0"

    @patch('time.time')
    def test_age_seconds(self, mock_time):
        """Test calculating age in seconds."""
        mock_time.return_value = 1234567900

        metadata = CacheMetadata(
            environment="test",
            created_at=1234567890,
            last_updated=1234567850,  # 50 seconds ago
            last_accessed=1234567890,
            secret_count=1
        )

        assert metadata.age_seconds() == 50

    def test_is_stale_true(self):
        """Test staleness detection when cache is stale."""
        with patch('time.time', return_value=1234567900):
            metadata = CacheMetadata(
                environment="test",
                created_at=1234567890,
                last_updated=1234567800,  # 100 seconds ago
                last_accessed=1234567890,
                secret_count=1
            )

            assert metadata.is_stale(max_age_seconds=50)

    def test_is_stale_false(self):
        """Test staleness detection when cache is fresh."""
        with patch('time.time', return_value=1234567900):
            metadata = CacheMetadata(
                environment="test",
                created_at=1234567890,
                last_updated=1234567880,  # 20 seconds ago
                last_accessed=1234567890,
                secret_count=1
            )

            assert not metadata.is_stale(max_age_seconds=50)

    def test_is_stale_exact_boundary(self):
        """Test staleness detection at exact boundary."""
        with patch('time.time', return_value=1234567900):
            metadata = CacheMetadata(
                environment="test",
                created_at=1234567890,
                last_updated=1234567850,  # Exactly 50 seconds ago
                last_accessed=1234567890,
                secret_count=1
            )

            assert not metadata.is_stale(max_age_seconds=50)


class TestCacheManager:
    """Test CacheManager class."""

    def setup_method(self) -> None:
        """Set up test fixtures."""
        self.test_config: Dict[str, Any] = {
            "cache_config": {
                "max_age_seconds": 900,
                "cache_dir": "/tmp/test_cache"
            }
        }
        self.temp_dir = None

    def teardown_method(self):
        """Clean up test fixtures."""
        if self.temp_dir:
            import shutil
            try:
                shutil.rmtree(self.temp_dir)
            except FileNotFoundError:
                pass

    def _get_temp_config(self):
        """Get config with temporary directory."""
        self.temp_dir = tempfile.mkdtemp()
        config = self.test_config.copy()
        config["cache_config"] = {"max_age_seconds": 900}
        config["cache_base_dir"] = self.temp_dir
        return config

    @patch('auto_secrets.core.cache_manager.get_cache_dir')
    def test_init_with_config(self, mock_get_cache_dir):
        """Test CacheManager initialization."""
        mock_get_cache_dir.return_value = Path("/tmp/test_cache")

        with patch.object(CacheManager, '_ensure_cache_directory'):
            manager = CacheManager(self.test_config)

            assert manager.config == self.test_config
            assert manager.cache_dir == Path("/tmp/test_cache")
            assert manager.max_age_seconds == 900

    @patch('auto_secrets.core.cache_manager.get_cache_dir')
    def test_init_default_max_age(self, mock_get_cache_dir):
        """Test CacheManager with default max_age_seconds."""
        mock_get_cache_dir.return_value = Path("/tmp/test_cache")
        config = {"cache_config": {}}

        with patch.object(CacheManager, '_ensure_cache_directory'):
            manager = CacheManager(config)

            assert manager.max_age_seconds == 900  # Default value

    @patch('auto_secrets.core.cache_manager.get_cache_dir')
    def test_init_no_cache_config(self, mock_get_cache_dir):
        """Test CacheManager with no cache_config."""
        mock_get_cache_dir.return_value = Path("/tmp/test_cache")
        config = {}

        with patch.object(CacheManager, '_ensure_cache_directory'):
            manager = CacheManager(config)

            assert manager.max_age_seconds == 900  # Default value

    @patch('auto_secrets.core.cache_manager.get_cache_dir')
    def test_ensure_cache_directory_success(self, mock_get_cache_dir):
        """Test successful cache directory creation."""
        with tempfile.TemporaryDirectory() as temp_dir:
            cache_dir = Path(temp_dir) / "cache"
            mock_get_cache_dir.return_value = cache_dir

            assert cache_dir.exists()
            assert (cache_dir / "environments").exists()
            assert (cache_dir / "state").exists()

    @patch('auto_secrets.core.cache_manager.get_cache_dir')
    @patch('pathlib.Path.mkdir')
    def test_ensure_cache_directory_failure(self, mock_mkdir, mock_get_cache_dir):
        """Test cache directory creation failure."""
        mock_get_cache_dir.return_value = Path("/invalid/path")
        mock_mkdir.side_effect = OSError("Permission denied")

        with pytest.raises(CacheError, match="Cannot create cache directory"):
            CacheManager(self.test_config)

    @patch('auto_secrets.core.cache_manager.get_cache_dir')
    def test_get_environment_cache_dir(self, mock_get_cache_dir):
        """Test getting environment-specific cache directory."""
        mock_get_cache_dir.return_value = Path("/tmp/test_cache")

        with patch.object(CacheManager, '_ensure_cache_directory'):
            manager = CacheManager(self.test_config)

            result = manager.get_environment_cache_dir("production")
            expected = Path("/tmp/test_cache/environments/production")

            assert result == expected

    @patch('auto_secrets.core.cache_manager.get_cache_dir')
    @patch('time.time')
    def test_update_environment_cache_success(self, mock_time, mock_get_cache_dir):
        """Test successful cache update."""
        mock_time.return_value = 1234567890

        with tempfile.TemporaryDirectory() as temp_dir:
            cache_dir = Path(temp_dir)
            mock_get_cache_dir.return_value = cache_dir

            manager = CacheManager(self.test_config)

            secrets = {
                "API_KEY": "secret123",
                "DB_PASSWORD": "dbpass456"
            }

            with patch.object(manager, '_write_file_atomically') as mock_write_file, \
                 patch.object(manager, '_write_env_file_atomically') as mock_write_env:

                manager.update_environment_cache("production", secrets)

                # Check that files were written
                assert mock_write_file.call_count == 1
                assert mock_write_env.call_count == 1

                # Check metadata creation
                metadata_call = mock_write_file.call_args[0]
                assert "production.json" in str(metadata_call[0])

    @patch('auto_secrets.core.cache_manager.get_cache_dir')
    def test_update_environment_cache_with_branch_info(self, mock_get_cache_dir):
        """Test cache update with branch information."""
        with tempfile.TemporaryDirectory() as temp_dir:
            cache_dir = Path(temp_dir)
            mock_get_cache_dir.return_value = cache_dir

            manager = CacheManager(self.test_config)

            secrets = {"API_KEY": "secret123"}

            with patch.object(manager, '_write_file_atomically') as mock_write_file, \
                 patch('time.time', return_value=1234567890):

                manager.update_environment_cache(
                    "production",
                    secrets,
                    branch="main",
                    repo_path="/repo"
                )

                # Verify metadata includes branch info
                metadata_call = mock_write_file.call_args[0]
                metadata_content = metadata_call[1]["metadata"]

                assert metadata_content["branch"] == "main"
                assert metadata_content["repo_path"] == "/repo"

    @patch('auto_secrets.core.cache_manager.get_cache_dir')
    def test_get_cached_secrets_success(self, mock_get_cache_dir):
        """Test successful retrieval of cached secrets."""
        with tempfile.TemporaryDirectory() as temp_dir:
            cache_dir = Path(temp_dir)
            mock_get_cache_dir.return_value = cache_dir

            # Create cache structure
            env_dir = cache_dir / "environments" / "production"
            env_dir.mkdir(parents=True)

            # Create test file with correct structure
            cache_file = env_dir / "production.json"
            secrets_data = {"API_KEY": "secret123", "DB_PASSWORD": "dbpass456"}
            cache_data = {
                "metadata": {
                    "environment": "production",
                    "created_at": 1234567890,
                    "last_updated": 1234567890,
                    "last_accessed": 1234567890,
                    "secret_count": 2,
                    "status": "ok"
                },
                "secrets": secrets_data
            }
            with open(cache_file, 'w') as f:
                json.dump(cache_data, f)

            manager = CacheManager(self.test_config)

            with patch.object(manager, '_update_access_time'):
                result = manager.get_cached_secrets("production")

                assert result == secrets_data

    @patch('auto_secrets.core.cache_manager.get_cache_dir')
    def test_get_cached_secrets_not_found(self, mock_get_cache_dir):
        """Test cached secrets retrieval when cache doesn't exist."""
        with tempfile.TemporaryDirectory() as temp_dir:
            cache_dir = Path(temp_dir)
            mock_get_cache_dir.return_value = cache_dir

            manager = CacheManager(self.test_config)

            result = manager.get_cached_secrets("nonexistent")

            assert result == {}

    @patch('auto_secrets.core.cache_manager.get_cache_dir')
    def test_get_cached_secrets_corrupted(self, mock_get_cache_dir):
        """Test cached secrets retrieval with corrupted files."""
        with tempfile.TemporaryDirectory() as temp_dir:
            cache_dir = Path(temp_dir)
            mock_get_cache_dir.return_value = cache_dir

            # Create cache structure with corrupted file
            env_dir = cache_dir / "environments" / "production"
            env_dir.mkdir(parents=True)

            cache_file = env_dir / "production.json"
            with open(cache_file, 'w') as f:
                f.write("invalid json content")

            manager = CacheManager(self.test_config)

            with pytest.raises(CacheError):
                manager.get_cached_secrets("production")

    @patch('auto_secrets.core.cache_manager.get_cache_dir')
    def test_get_cached_secrets_with_paths_filter(self, mock_get_cache_dir):
        """Test cached secrets retrieval with path filtering."""
        with tempfile.TemporaryDirectory() as temp_dir:
            cache_dir = Path(temp_dir)
            mock_get_cache_dir.return_value = cache_dir

            # Create cache structure
            env_dir = cache_dir / "environments" / "production"
            env_dir.mkdir(parents=True)

            cache_file = env_dir / "production.json"
            secrets_data = {
                "/api/key": "secret123",
                "/db/password": "dbpass456",
                "/cache/token": "token789"
            }
            cache_data = {
                "metadata": {
                    "environment": "production",
                    "created_at": 1234567890,
                    "last_updated": 1234567890,
                    "last_accessed": 1234567890,
                    "secret_count": 3,
                    "status": "ok"
                },
                "secrets": secrets_data
            }
            with open(cache_file, 'w') as f:
                json.dump(cache_data, f)

            manager = CacheManager(self.test_config)

            with patch.object(manager, '_update_access_time'), \
                 patch.object(manager, '_path_matches', side_effect=[True, False, False]):

                result = manager.get_cached_secrets("production", paths=["/api/*"])

                expected = {"/api/key": "secret123"}
                assert result == expected

    def test_path_matches_exact(self):
        """Test exact path matching."""
        config = self._get_temp_config()
        manager = CacheManager(config)

        assert manager._path_matches("/api/key", "/api/key")
        assert not manager._path_matches("/api/key", "/api/secret")

    def test_path_matches_wildcard(self):
        """Test wildcard path matching."""
        config = self._get_temp_config()
        manager = CacheManager(config)

        assert manager._path_matches("/api/key", "/api/*")
        assert manager._path_matches("/api/secret", "/api/*")
        assert not manager._path_matches("/db/password", "/api/*")

    def test_path_matches_recursive(self):
        """Test recursive path matching."""
        config = self._get_temp_config()
        manager = CacheManager(config)

        assert manager._path_matches("/api/v1/key", "/api/**")
        assert manager._path_matches("/api/v2/secret", "/api/**")
        assert not manager._path_matches("/db/password", "/api/**")

    @patch('auto_secrets.core.cache_manager.get_cache_dir')
    def test_is_cache_stale_true(self, mock_get_cache_dir):
        """Test cache staleness detection when stale."""
        with tempfile.TemporaryDirectory() as temp_dir:
            cache_dir = Path(temp_dir)
            mock_get_cache_dir.return_value = cache_dir

            # Create stale cache
            env_dir = cache_dir / "environments" / "production"
            env_dir.mkdir(parents=True)

            metadata_file = env_dir / "metadata.json"
            with patch('time.time', return_value=1234567890):
                metadata_data = {
                    "environment": "production",
                    "created_at": 1234567890,
                    "last_updated": 1234566990,  # 900+ seconds ago
                    "last_accessed": 1234567890,
                    "secret_count": 1,
                    "status": "ok"
                }
                with open(metadata_file, 'w') as f:
                    json.dump(metadata_data, f)

                manager = CacheManager(self.test_config)

                with patch('time.time', return_value=1234569000):  # Much later
                    assert manager.is_cache_stale("production")

    @patch('auto_secrets.core.cache_manager.get_cache_dir')
    def test_is_cache_stale_false(self, mock_get_cache_dir):
        """Test cache staleness detection when fresh."""
        with tempfile.TemporaryDirectory() as temp_dir:
            cache_dir = Path(temp_dir)
            mock_get_cache_dir.return_value = cache_dir

            # Create fresh cache
            env_dir = cache_dir / "environments" / "production"
            env_dir.mkdir(parents=True)

            cache_file = env_dir / "production.json"
            current_time = 1234567890
            cache_data = {
                "metadata": {
                    "environment": "production",
                    "created_at": current_time,
                    "last_updated": current_time,
                    "last_accessed": current_time,
                    "secret_count": 1,
                    "status": "ok"
                },
                "secrets": {"key": "value"}
            }
            with open(cache_file, 'w') as f:
                json.dump(cache_data, f)

            manager = CacheManager(self.test_config)

            with patch('time.time', return_value=current_time + 300):  # 5 minutes later
                assert not manager.is_cache_stale("production")

    @patch('auto_secrets.core.cache_manager.get_cache_dir')
    def test_is_cache_stale_missing_metadata(self, mock_get_cache_dir):
        """Test cache staleness when metadata is missing."""
        with tempfile.TemporaryDirectory() as temp_dir:
            cache_dir = Path(temp_dir)
            mock_get_cache_dir.return_value = cache_dir

            manager = CacheManager(self.test_config)

            # No metadata file exists
            assert manager.is_cache_stale("production")

    @patch('auto_secrets.core.cache_manager.get_cache_dir')
    def test_mark_environment_stale(self, mock_get_cache_dir):
        """Test marking environment cache as stale."""
        with tempfile.TemporaryDirectory() as temp_dir:
            cache_dir = Path(temp_dir)
            mock_get_cache_dir.return_value = cache_dir

            # Create cache
            env_dir = cache_dir / "environments" / "production"
            env_dir.mkdir(parents=True)

            cache_file = env_dir / "production.json"
            cache_data = {
                "metadata": {
                    "environment": "production",
                    "created_at": 1234567890,
                    "last_updated": 1234567890,
                    "last_accessed": 1234567890,
                    "secret_count": 1,
                    "status": "ok"
                },
                "secrets": {"API_KEY": "secret123"}
            }
            with open(cache_file, 'w') as f:
                json.dump(cache_data, f)

            manager = CacheManager(self.test_config)

            manager.mark_environment_stale("production", "Test error")

            # Check that metadata was updated
            with open(cache_file, 'r') as f:
                updated_data = json.load(f)

            assert updated_data["metadata"]["status"] == "stale"
            assert updated_data["metadata"]["error_message"] == "Marked stale: Test error"

    @patch('auto_secrets.core.cache_manager.get_cache_dir')
    def test_cleanup_stale(self, mock_get_cache_dir):
        """Test cleanup of stale cache entries."""
        with tempfile.TemporaryDirectory() as temp_dir:
            cache_dir = Path(temp_dir)
            mock_get_cache_dir.return_value = cache_dir

            # Create environments directory
            envs_dir = cache_dir / "environments"
            envs_dir.mkdir(parents=True)

            # Create stale environment
            stale_env = envs_dir / "stale_env"
            stale_env.mkdir()
            stale_cache_data = {
                "metadata": {
                  "environment": "stale_env",
                  "created_at": 1234567890,
                  "last_updated": 1234567890,
                  "last_accessed": 1234567890,
                  "secret_count": 1,
                  "status": "ok",
                },
                "secrets": {"key": "value"}
            }
            with open(stale_env / "stale_env.json", 'w') as f:
                json.dump(stale_cache_data, f)

            # Create fresh environment
            fresh_env = envs_dir / "fresh_env"
            fresh_env.mkdir()
            fresh_cache_data = {
                "metadata": {"environment": "fresh_env", "created_at": 1234567890, "last_updated": 1234567890, "last_accessed": 1234567890, "secret_count": 1, "status": "ok"},
                "secrets": {"key": "value"}
            }
            with open(fresh_env / "fresh_env.json", 'w') as f:
                json.dump(fresh_cache_data, f)

            manager = CacheManager(self.test_config)

            with patch.object(manager, 'is_cache_stale', side_effect=lambda env, max_age=None: env == "stale_env"):
                result = manager.cleanup_stale()

                assert result["removed"] == 1
                assert not stale_env.exists()
                assert fresh_env.exists()

    @patch('auto_secrets.core.cache_manager.get_cache_dir')
    def test_cleanup_all(self, mock_get_cache_dir):
        """Test cleanup of all cache entries."""
        with tempfile.TemporaryDirectory() as temp_dir:
            cache_dir = Path(temp_dir)
            mock_get_cache_dir.return_value = cache_dir

            # Create environments directory with content
            envs_dir = cache_dir / "environments"
            envs_dir.mkdir(parents=True)

            env1 = envs_dir / "env1"
            env1.mkdir()
            (env1 / "secrets.json").write_text('{"key": "value"}')

            env2 = envs_dir / "env2"
            env2.mkdir()
            (env2 / "secrets.json").write_text('{"key": "value"}')

            manager = CacheManager(self.test_config)

            result = manager.cleanup_all()

            assert result["removed"] == 2
            assert not env1.exists()
            assert not env2.exists()

    @patch('auto_secrets.core.cache_manager.get_cache_dir')
    def test_get_cache_info(self, mock_get_cache_dir):
        """Test getting cache information."""
        with tempfile.TemporaryDirectory() as temp_dir:
            cache_dir = Path(temp_dir)
            mock_get_cache_dir.return_value = cache_dir

            # Create cache structure
            envs_dir = cache_dir / "environments"
            envs_dir.mkdir(parents=True)

            # Create test environment
            env_dir = envs_dir / "production"
            env_dir.mkdir()

            cache_file = env_dir / "production.json"
            cache_data = {
                "metadata": {
                    "environment": "production",
                    "created_at": 1234567890,
                    "last_updated": 1234567890,
                    "last_accessed": 1234567890,
                    "secret_count": 2,
                    "status": "ok"
                },
                "secrets": {"key1": "value1", "key2": "value2"}
            }
            with open(cache_file, 'w') as f:
                json.dump(cache_data, f)

            manager = CacheManager(self.test_config)

            result = manager.get_cache_info("production")

            assert result["secret_count"] == 2

    def test_write_file_atomically_success(self):
        """Test atomic file writing success."""
        config = self._get_temp_config()
        manager = CacheManager(config)

        with tempfile.TemporaryDirectory() as temp_dir:
            target_file = Path(temp_dir) / "test.json"
            content = {"test": "data"}

            manager._write_file_atomically(target_file, content)

            assert target_file.exists()
            assert json.loads(target_file.read_text()) == content

    def test_write_file_atomically_failure(self):
        """Test atomic file writing failure."""
        config = self._get_temp_config()
        manager = CacheManager(config)

        invalid_path = Path("/invalid/path/test.json")
        content = {"test": "data"}

        with pytest.raises(OSError):
            manager._write_file_atomically(invalid_path, content)

    def test_write_env_file_atomically_success(self):
        """Test atomic environment file writing."""
        config = self._get_temp_config()
        manager = CacheManager(config)

        with tempfile.TemporaryDirectory() as temp_dir:
            target_file = Path(temp_dir) / "test.env"
            secrets = {"API_KEY": "secret123", "DB_PASS": "dbpass456"}

            manager._write_env_file_atomically(target_file, secrets)

            assert target_file.exists()
            content = target_file.read_text()
            assert "export API_KEY=" in content
            assert "export DB_PASS=" in content

    def test_write_env_file_atomically_with_special_chars(self):
        """Test environment file writing with special characters."""
        config = self._get_temp_config()
        manager = CacheManager(config)

        with tempfile.TemporaryDirectory() as temp_dir:
            target_file = Path(temp_dir) / "test.env"
            secrets = {
                "API_KEY": "secret'with\"quotes",
                "COMPLEX_VAR": "value with spaces & symbols!"
            }

            manager._write_env_file_atomically(target_file, secrets)

            content = target_file.read_text()
            # Should be properly escaped
            assert 'export API_KEY=' in content
            assert 'export COMPLEX_VAR=' in content

    def test_update_access_time_success(self):
        """Test updating access time successfully."""
        config = self._get_temp_config()

        def test_update_access_time_success(self, mock_get_cache_dir):
            """Test successful access time update."""
            with tempfile.TemporaryDirectory() as temp_dir:
                cache_dir = Path(temp_dir)
                mock_get_cache_dir.return_value = cache_dir

                # Create cache structure
                env_dir = cache_dir / "environments" / "production"
                env_dir.mkdir(parents=True)

                cache_file = env_dir / "production.json"
                cache_data = {
                    "metadata": {
                        "environment": "production",
                        "created_at": 1234567890,
                        "last_updated": 1234567890,
                        "last_accessed": 1234567890,
                        "secret_count": 1,
                        "status": "ok"
                    },
                    "secrets": {"API_KEY": "secret123"}
                }
                with open(cache_file, 'w') as f:
                    json.dump(cache_data, f)

                manager = CacheManager(self.test_config)
                metadata = CacheMetadata(
                  environment="production",
                  created_at=1234567890,
                  last_updated=1234567890,
                  last_accessed=1234567890,
                  secret_count=1
                )

                with patch('time.time', return_value=1234567950):
                    manager._update_access_time("production", metadata)

                    # Check that access time was updated
                    with open(cache_file, 'r') as f:
                        updated_data = json.load(f)

                    assert updated_data["metadata"]["last_accessed"] == 1234567950

    def test_update_access_time_failure(self):
        """Test updating access time with file error."""
        config = self._get_temp_config()
        manager = CacheManager(config)

        invalid_file = Path("/invalid/path/metadata.json")
        metadata = CacheMetadata(environment="test", created_at=0, last_updated=0, last_accessed=0, secret_count=0)

        # Should not raise exception, just log error
        manager._update_access_time(invalid_file, metadata)

    @patch('auto_secrets.core.cache_manager.get_cache_dir')
    def test_save_current_state(self, mock_get_cache_dir):
        """Test saving current state."""
        with tempfile.TemporaryDirectory() as temp_dir:
            cache_dir = Path(temp_dir)
            mock_get_cache_dir.return_value = cache_dir

            manager = CacheManager(self.test_config)

            state_data = CacheMetadata(
                environment="production",
                created_at=1234567890,
                last_updated=1234567890,
                last_accessed=1234567890,
                secret_count=0
            )

            with patch.object(manager, '_write_file_atomically') as mock_write:
                manager.save_current_state(state_data)

                mock_write.assert_called_once()
                call_args = mock_write.call_args[0]
                assert "current.json" in str(call_args[0])

    @patch('auto_secrets.core.cache_manager.get_cache_dir')
    def test_get_cache_stats(self, mock_get_cache_dir):
        """Test getting comprehensive cache statistics."""
        with tempfile.TemporaryDirectory() as temp_dir:
            cache_dir = Path(temp_dir)
            mock_get_cache_dir.return_value = cache_dir

            # Create test cache structure
            envs_dir = cache_dir / "environments"
            envs_dir.mkdir(parents=True)

            # Create production environment
            prod_env = envs_dir / "production"
            prod_env.mkdir()
            prod_cache_data = {
                "metadata": {
                    "environment": "production",
                    "created_at": 1234567890,
                    "last_updated": 1234567900,
                    "last_accessed": 1234567950,
                    "secret_count": 2,
                    "status": "ok"
                },
                "secrets": {"key1": "val1", "key2": "val2"}
            }
            with open(prod_env / "production.json", 'w') as f:
                json.dump(prod_cache_data, f)

            # Create staging environment (stale)
            staging_env = envs_dir / "staging"
            staging_env.mkdir()
            staging_cache_data = {
                "metadata": {
                    "environment": "staging",
                    "created_at": 1234567000,
                    "last_updated": 1234567000,
                    "last_accessed": 1234567000,
                    "secret_count": 1,
                    "status": "stale"
                },
                "secrets": {"key1": "val1"}
            }
            with open(staging_env / "staging.json", 'w') as f:
                json.dump(staging_cache_data, f)

            manager = CacheManager(self.test_config)

            with patch('time.time', return_value=1234568000):
                stats = manager.get_cache_stats()

                assert stats["total_environments"] == 2
                assert stats["total_secrets"] == 3
                assert stats["stale_environments"] == 1
                assert stats["total_environments"] - stats["stale_environments"] == 1
                assert "production" in stats["environments"]
                assert "staging" in stats["environments"]

    @patch('auto_secrets.core.cache_manager.get_cache_dir')
    def test_get_cache_stats_empty(self, mock_get_cache_dir):
        """Test getting cache statistics when no cache exists."""
        with tempfile.TemporaryDirectory() as temp_dir:
            cache_dir = Path(temp_dir)
            mock_get_cache_dir.return_value = cache_dir

            manager = CacheManager(self.test_config)

            stats = manager.get_cache_stats()

            assert stats["total_environments"] == 0
            assert stats["total_secrets"] == 0
            assert stats["stale_environments"] == 0
            assert stats["environments"] == {}

    def test_repr(self):
        """Test string representation."""
        config = self._get_temp_config()
        manager = CacheManager(config)

        repr_str = repr(manager)
        assert "CacheManager" in repr_str
        assert "max_age=" in repr_str

    @patch('auto_secrets.core.cache_manager.get_cache_dir')
    def test_integration_full_cache_lifecycle(self, mock_get_cache_dir):
        """Test complete cache lifecycle integration."""
        with tempfile.TemporaryDirectory() as temp_dir:
            cache_dir = Path(temp_dir)
            mock_get_cache_dir.return_value = cache_dir

            manager = CacheManager(self.test_config)

            # 1. Update cache with secrets
            secrets = {
                "/api/key": "secret123",
                "/db/password": "dbpass456"
            }

            with patch('time.time', return_value=1234567890):
                manager.update_environment_cache("production", secrets, branch="main")

            # 2. Verify cache was created
            with patch('time.time', return_value=1234567890):
                assert not manager.is_cache_stale("production")

            # 3. Retrieve cached secrets
            retrieved = manager.get_cached_secrets("production")
            assert retrieved == secrets

            # 4. Test path filtering
            filtered = manager.get_cached_secrets("production", paths=["/api/*"])
            expected_filtered = {"/api/key": "secret123"}
            assert filtered == expected_filtered

            # 5. Mark as stale
            manager.mark_environment_stale("production", "Test staleness")

            # 6. Verify staleness
            cache_info = manager.get_cache_info("production")
            assert cache_info["status"] == "stale"

            # 7. Cleanup stale caches
            with patch.object(manager, 'is_cache_stale', return_value=True):
                cleanup_result = manager.cleanup_stale()
                assert cleanup_result["removed"] == 1

            # 8. Verify cleanup
            final_retrieved = manager.get_cached_secrets("production")
            assert final_retrieved == {}

    @patch('auto_secrets.core.cache_manager.get_cache_dir')
    def test_error_handling_permissions(self, mock_get_cache_dir):
        """Test error handling for permission issues."""
        with tempfile.TemporaryDirectory() as temp_dir:
            cache_dir = Path(temp_dir)
            mock_get_cache_dir.return_value = cache_dir

            manager = CacheManager(self.test_config)

            # Create a directory we can't write to (simulate permission error)
            readonly_dir = cache_dir / "readonly"
            readonly_dir.mkdir(mode=0o444)

            try:
                with patch.object(manager, 'get_environment_cache_dir', return_value=readonly_dir):
                    with pytest.raises(CacheError):
                        manager.update_environment_cache("test", {"key": "value"})
            finally:
                # Cleanup: restore permissions
                readonly_dir.chmod(0o755)

    @patch('auto_secrets.core.cache_manager.get_cache_dir')
    def test_concurrent_access_simulation(self, mock_get_cache_dir):
        """Test simulation of concurrent access scenarios."""
        with tempfile.TemporaryDirectory() as temp_dir:
            cache_dir = Path(temp_dir)
            mock_get_cache_dir.return_value = cache_dir

            manager = CacheManager(self.test_config)

            # Simulate concurrent writes by testing atomic operations
            secrets1 = {"key1": "value1"}
            secrets2 = {"key2": "value2"}

            with patch('time.time', return_value=1234567890):
                manager.update_environment_cache("test1", secrets1)
                manager.update_environment_cache("test2", secrets2)

            # Verify both caches exist and are independent
            result1 = manager.get_cached_secrets("test1")
            result2 = manager.get_cached_secrets("test2")

            assert result1 == secrets1
            assert result2 == secrets2

    @patch('auto_secrets.core.cache_manager.get_cache_dir')
    def test_large_secrets_handling(self, mock_get_cache_dir):
        """Test handling of large secret payloads."""
        with tempfile.TemporaryDirectory() as temp_dir:
            cache_dir = Path(temp_dir)
            mock_get_cache_dir.return_value = cache_dir

            manager = CacheManager(self.test_config)

            # Create large secret payload
            large_secrets = {}
            for i in range(1000):
                large_secrets[f"/secret_{i:04d}"] = f"very_long_secret_value_{i:04d}" * 10

            with patch('time.time', return_value=1234567890):
                manager.update_environment_cache("large_env", large_secrets)

            # Verify retrieval works correctly
            retrieved = manager.get_cached_secrets("large_env")
            assert len(retrieved) == 1000
            assert retrieved["/secret_0000"] == "very_long_secret_value_0000" * 10
