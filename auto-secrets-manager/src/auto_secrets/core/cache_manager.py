"""
Auto Secrets Manager - Cache Manager

Handles secure caching of secrets with atomic operations.
Implements race-condition-free updates using atomic rename operations.
Provides environment-specific caching with proper staleness detection.
"""

import json
import os
import shutil
import tempfile
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..logging_config import get_logger
from .config import ConfigManager
from .utils import CommonUtils


class CacheError(Exception):
    """Cache-related errors."""
    pass


@dataclass
class CacheMetadata:
    """Metadata for cached secrets."""
    environment: str
    created_at: int
    last_updated: int
    last_accessed: int
    secret_count: int
    branch: Optional[str] = None
    repo_path: Optional[str] = None
    status: str = "ok"  # ok, stale, error
    error_message: Optional[str] = None
    version: str = "1.0"

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'CacheMetadata':
        """Create from dictionary loaded from JSON."""
        return cls(**data)

    def age_seconds(self) -> int:
        """Get age of cache in seconds."""
        return int(time.time() - self.last_updated)

    def is_stale(self, max_age_seconds: int) -> bool:
        """Check if cache is stale based on age."""
        return self.age_seconds() > max_age_seconds


class CacheManager:
    """
    Manages secure caching of secrets with atomic operations.

    Uses atomic file operations (write to temp file, then rename) to prevent
    race conditions and corruption. No file locking is needed.
    """

    def __init__(self, config: Dict[str, Any]) -> None:
        self.config = config
        self.logger = get_logger("cache_manager")
        self.cache_dir = ConfigManager.get_cache_dir(config)

        refresh_interval = config.get("cache_config", {}).get("refresh_interval", "15m")
        self.max_age_seconds = CommonUtils.parse_duration(refresh_interval)

        # Ensure cache directory exists
        self._ensure_cache_directory()

    def _ensure_cache_directory(self) -> None:
        """Ensure cache directory exists with proper permissions."""
        try:
            self.cache_dir.mkdir(parents=True, exist_ok=True, mode=0o700)

            # Create environment subdirectory
            env_dir = self.cache_dir / "environments"
            env_dir.mkdir(exist_ok=True, mode=0o700)

            # Create state subdirectory
            state_dir = self.cache_dir / "state"
            state_dir.mkdir(exist_ok=True, mode=0o700)

            self.logger.debug(f"Cache directory initialized: {self.cache_dir}")

        except OSError as e:
            self.logger.error(f"Failed to create cache directory: {e}")
            raise CacheError(f"Cannot create cache directory: {e}")

    def get_environment_cache_dir(self, environment: str) -> Path:
        """Get cache directory for specific environment."""
        return self.cache_dir / "environments" / environment

    def update_environment_cache(
      self, environment: str,
      secrets: Dict[str, str],
      branch: Optional[str] = None,
      repo_path: Optional[str] = None
    ) -> None:
        """
        Update environment cache atomically.

        Args:
            environment: Environment name
            secrets: Dictionary of secret key-value pairs
            branch: Optional branch name
            repo_path: Optional repository path

        Raises:
            CacheError: If cache update fails
        """
        if not environment:
            raise CacheError("Environment name cannot be empty")

        self.logger.info(f"Updating cache for environment: {environment} ({len(secrets)} secrets)")

        try:
            env_cache_dir = self.get_environment_cache_dir(environment)

            # Create metadata
            current_time = int(time.time())
            metadata = CacheMetadata(
                environment=environment,
                created_at=current_time,
                last_updated=current_time,
                last_accessed=current_time,
                secret_count=len(secrets),
                branch=branch,
                repo_path=repo_path,
                status="ok"
            )

            # Write secrets in JSON format (full data)
            self._write_file_atomically(
                env_cache_dir / f"{environment}.json",
                {
                    "metadata": metadata.to_dict(),
                    "secrets": secrets
                }
            )

            # Write secrets in shell-friendly format
            self._write_env_file_atomically(
                env_cache_dir / f"{environment}.env",
                secrets
            )

            self.logger.info(f"Successfully cached {len(secrets)} secrets for {environment}")

        except Exception as e:
            self.logger.error(f"Failed to update cache for {environment}: {e}")
            raise CacheError(f"Cache update failed: {e}")

    def get_cached_secrets(self, environment: str, paths: Optional[List[str]] = None) -> Dict[str, str]:
        """
        Get cached secrets for environment.

        Args:
            environment: Environment name
            paths: Optional list of secret paths to filter by

        Returns:
            Dict[str, str]: Cached secrets

        Raises:
            CacheError: If cache cannot be read
        """
        if not environment:
            raise CacheError("Environment name cannot be empty")

        self.logger.debug(f"Retrieving cached secrets for environment: {environment}")

        try:
            env_cache_dir = self.get_environment_cache_dir(environment)
            cache_file = env_cache_dir / f"{environment}.json"

            if not cache_file.exists():
                self.logger.debug(f"No cache file found for environment: {environment}")
                return {}

            # Read cache file
            with open(cache_file, 'r') as f:
                cache_data = json.load(f)

            secrets = cache_data.get("secrets", {})
            metadata = CacheMetadata.from_dict(cache_data.get("metadata", {}))

            # Update last accessed time
            self._update_access_time(environment, metadata)

            # Filter by paths if specified
            if paths:
                filtered_secrets = {}
                for path in paths:
                    # Simple path matching - can be enhanced for glob patterns
                    matching_keys = [k for k in secrets.keys() if self._path_matches(k, path)]
                    for key in matching_keys:
                        filtered_secrets[key] = secrets[key]
                secrets = filtered_secrets

            self.logger.debug(f"Retrieved {len(secrets)} cached secrets for {environment}")
            return secrets

        except (OSError, json.JSONDecodeError) as e:
            self.logger.error(f"Failed to read cache for {environment}: {e}")
            raise CacheError(f"Cannot read cache: {e}")

    def _path_matches(self, secret_key: str, path_filter: str) -> bool:
        """
        Check if secret key matches path filter.

        Args:
            secret_key: Secret key to test
            path_filter: Path pattern to match against

        Returns:
            bool: True if key matches filter
        """
        # Simple implementation - can be enhanced with glob patterns
        if path_filter.endswith("**"):
            prefix = path_filter[:-2]
            return secret_key.startswith(prefix)
        elif path_filter.endswith("*"):
            prefix = path_filter[:-1]
            return secret_key.startswith(prefix) and "/" not in secret_key[len(prefix):]
        else:
            return secret_key == path_filter

    def is_cache_stale(self, environment: str, max_age_seconds: Optional[int] = None) -> bool:
        """
        Check if environment cache is stale.

        Args:
            environment: Environment name
            max_age_seconds: Custom max age, uses config default if None

        Returns:
            bool: True if cache is stale or doesn't exist
        """
        max_age = max_age_seconds or self.max_age_seconds

        try:
            env_cache_dir = self.get_environment_cache_dir(environment)
            cache_file = env_cache_dir / f"{environment}.json"

            if not cache_file.exists():
                return True

            with open(cache_file, 'r') as f:
                cache_data = json.load(f)

            metadata = CacheMetadata.from_dict(cache_data.get("metadata", {}))
            is_stale = metadata.is_stale(max_age)

            self.logger.debug(
              f"Cache staleness check for {environment}: stale={is_stale}, age={metadata.age_seconds()}s"
            )
            return is_stale

        except Exception as e:
            self.logger.warning(f"Error checking cache staleness for {environment}: {e}")
            return True  # Assume stale on error

    def mark_environment_stale(self, environment: str, reason: str = "Manual") -> None:
        """
        Mark environment cache as stale.

        Args:
            environment: Environment name
            reason: Reason for marking stale
        """
        self.logger.info(f"Marking environment {environment} as stale: {reason}")

        try:
            env_cache_dir = self.get_environment_cache_dir(environment)
            cache_file = env_cache_dir / f"{environment}.json"

            if not cache_file.exists():
                self.logger.debug(f"No cache to mark stale for {environment}")
                return

            # Read current cache
            with open(cache_file, 'r') as f:
                cache_data = json.load(f)

            # Update metadata
            metadata = CacheMetadata.from_dict(cache_data.get("metadata", {}))
            metadata.status = "stale"
            metadata.error_message = f"Marked stale: {reason}"
            cache_data["metadata"] = metadata.to_dict()

            # Write back atomically
            self._write_file_atomically(cache_file, cache_data)

        except Exception as e:
            self.logger.error(f"Failed to mark {environment} as stale: {e}")

    def cleanup_stale(self, max_age_seconds: Optional[int] = None) -> Dict[str, int]:
        """
        Clean up stale cache entries.

        Args:
            max_age_seconds: Custom max age, uses config default if None

        Returns:
            Dict[str, int]: Dictionary with "removed" key containing number of cleaned up cache entries
        """
        max_age = max_age_seconds or self.max_age_seconds
        cleaned_count = 0

        self.logger.info(f"Cleaning up caches older than {max_age} seconds")

        try:
            env_dir = self.cache_dir / "environments"
            if not env_dir.exists():
                return {"removed": 0}

            for env_cache_dir in env_dir.iterdir():
                if not env_cache_dir.is_dir():
                    continue

                environment = env_cache_dir.name
                if self.is_cache_stale(environment, max_age):
                    try:
                        shutil.rmtree(env_cache_dir)
                        cleaned_count += 1
                        self.logger.debug(f"Cleaned up stale cache for {environment}")
                    except OSError as e:
                        self.logger.warning(f"Failed to clean up cache for {environment}: {e}")

            self.logger.info(f"Cleaned up {cleaned_count} stale cache entries")
            return {"removed": cleaned_count}

        except Exception as e:
            self.logger.error(f"Error during cache cleanup: {e}")
            return {"removed": cleaned_count}

    def cleanup_all(self) -> Dict[str, int]:
        """Clean up all cache files."""
        self.logger.info("Cleaning up all cache files")
        removed_count = 0

        try:
            if self.cache_dir.exists():
                # Count environments before removal
                env_dir = self.cache_dir / "environments"
                if env_dir.exists():
                    removed_count = len([d for d in env_dir.iterdir() if d.is_dir()])

                shutil.rmtree(self.cache_dir)
                self.logger.info("All cache files cleaned up")

            # Recreate directory structure
            self._ensure_cache_directory()
            return {"removed": removed_count}

        except Exception as e:
            self.logger.error(f"Failed to clean up all caches: {e}")
            raise CacheError(f"Cache cleanup failed: {e}")

    def get_cache_info(self, environment: str) -> Optional[Dict[str, Any]]:
        """
        Get cache information for environment.

        Args:
            environment: Environment name

        Returns:
            Dict[str, Any]: Cache information or None if no cache exists
        """
        try:
            env_cache_dir = self.get_environment_cache_dir(environment)
            cache_file = env_cache_dir / f"{environment}.json"

            if not cache_file.exists():
                return None

            with open(cache_file, 'r') as f:
                cache_data = json.load(f)

            metadata = CacheMetadata.from_dict(cache_data.get("metadata", {}))

            return {
                "environment": environment,
                "secret_count": metadata.secret_count,
                "created_at": metadata.created_at,
                "last_updated": metadata.last_updated,
                "last_accessed": metadata.last_accessed,
                "age_seconds": metadata.age_seconds(),
                "is_stale": metadata.is_stale(self.max_age_seconds),
                "status": metadata.status,
                "error_message": metadata.error_message,
                "cache_file": str(cache_file)
            }

        except Exception as e:
            self.logger.error(f"Failed to get cache info for {environment}: {e}")
            return None

    def _write_file_atomically(self, target_path: Path, data: Any) -> None:
        """
        Write data to file atomically using temp file and rename.

        Args:
            target_path: Target file path
            data: Data to write (will be JSON serialized)
        """
        temp_path = None
        try:
            # Ensure parent directory exists
            target_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)

            # Create temporary file in same directory
            with tempfile.NamedTemporaryFile(
                mode='w',
                dir=target_path.parent,
                prefix=f".{target_path.name}.",
                suffix='.tmp',
                delete=False
            ) as tmp_file:
                json.dump(data, tmp_file, indent=2)
                tmp_file.flush()
                os.fsync(tmp_file.fileno())
                temp_path = tmp_file.name

            # Set proper permissions
            os.chmod(temp_path, 0o600)

            # Atomic rename
            os.rename(temp_path, target_path)

        except Exception as e:
            # Clean up temp file if it exists
            try:
                if temp_path:
                    os.unlink(temp_path)
            except OSError:
                pass
            raise e

    def _write_env_file_atomically(self, target_path: Path, secrets: Dict[str, str]) -> None:
        """
        Write secrets in shell-friendly .env format atomically.

        Args:
            target_path: Target file path
            secrets: Secrets dictionary
        """
        temp_path = None
        try:
            # Ensure parent directory exists
            target_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)

            # Create temporary file
            with tempfile.NamedTemporaryFile(
                mode='w',
                dir=target_path.parent,
                prefix=f".{target_path.name}.",
                suffix='.tmp',
                delete=False
            ) as tmp_file:
                tmp_file.write("# Auto-generated environment file\n")
                tmp_file.write(f"# Generated at: {time.ctime()}\n\n")

                for key, value in sorted(secrets.items()):
                    # Escape single quotes in values
                    escaped_value = value.replace("'", "'\"'\"'")
                    tmp_file.write(f"export {key}='{escaped_value}'\n")

                tmp_file.flush()
                os.fsync(tmp_file.fileno())
                temp_path = tmp_file.name

            # Set proper permissions
            os.chmod(temp_path, 0o600)

            # Atomic rename
            os.rename(temp_path, target_path)

        except Exception as e:
            # Clean up temp file if it exists
            try:
                if temp_path:
                    os.unlink(temp_path)
            except OSError:
                pass
            raise e

    def _update_access_time(self, environment: str, metadata: CacheMetadata) -> None:
        """
        Update last accessed time for cache entry.

        Args:
            environment: Environment name
            metadata: Current metadata object
        """
        try:
            env_cache_dir = self.get_environment_cache_dir(environment)
            cache_file = env_cache_dir / f"{environment}.json"

            if not cache_file.exists():
                return

            # Read current cache
            with open(cache_file, 'r') as f:
                cache_data = json.load(f)

            # Update access time
            metadata.last_accessed = int(time.time())
            cache_data["metadata"] = metadata.to_dict()

            # Write back (non-critical, so don't fail on error)
            try:
                self._write_file_atomically(cache_file, cache_data)
            except Exception as e:
                self.logger.debug(f"Failed to update access time for {environment}: {e}")

        except Exception as e:
            self.logger.debug(f"Failed to update access time for {environment}: {e}")

    def get_cache_stats(self) -> Dict[str, Any]:
        """
        Get overall cache statistics.

        Returns:
            Dict[str, Any]: Cache statistics
        """
        stats: Dict[str, Any] = {
            "cache_dir": str(self.cache_dir),
            "cache_dir_exists": self.cache_dir.exists(),
            "total_environments": 0,
            "total_secrets": 0,
            "stale_environments": 0,
            "environments": {}
        }

        try:
            env_dir = self.cache_dir / "environments"
            if not env_dir.exists():
                return stats

            for env_cache_dir in env_dir.iterdir():
                if not env_cache_dir.is_dir():
                    continue

                environment = env_cache_dir.name
                cache_info = self.get_cache_info(environment)

                if cache_info:
                    stats["total_environments"] += 1
                    stats["total_secrets"] += cache_info["secret_count"]

                    if cache_info["is_stale"]:
                        stats["stale_environments"] += 1

                    stats["environments"][environment] = cache_info

        except Exception as e:
            self.logger.error(f"Failed to get cache stats: {e}")
            stats["error"] = str(e)

        return stats

    def __repr__(self) -> str:
        """String representation of CacheManager."""
        return f"CacheManager(cache_dir={self.cache_dir}, max_age={self.max_age_seconds}s)"
