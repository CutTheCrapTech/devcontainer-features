"""
Auto Secrets Manager - Cache Manager

Handles secure caching of secrets with atomic operations.
Implements race-condition-free updates using atomic rename operations.
Provides environment-specific caching with proper staleness detection.
"""

import json
import os
import re
import shutil
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Optional

from ..core.common_utils import CommonUtils
from ..core.crypto_utils import CryptoUtils
from .common_config import CommonConfig
from .log_manager import AutoSecretsLogger


class CacheConfigError(Exception):
  """Cacheconfig-related errors."""

  pass


class CacheError(Exception):
  """Cache-related errors."""

  pass


@dataclass
class CacheConfig:
  """Cache configuration settings."""

  refresh_interval: int = 900  # Default to 15 minutes
  cleanup_interval: int = 604800  # Default to 7 days
  auto_commands: dict[str, list[str]] = field(default_factory=dict)
  pattern_cache: dict[str, re.Pattern] = field(default_factory=dict)

  def __post_init__(self) -> None:
    """Initialize from environment variables after dataclass creation."""
    cache_config = os.getenv("AUTO_SECRETS_CACHE_CONFIG", "{}")
    cache_config_dict = CommonUtils.parse_json("AUTO_SECRETS_CACHE_CONFIG", cache_config)

    auto_commands = os.getenv("AUTO_SECRETS_AUTO_COMMANDS", "{}")
    auto_commands_dict = CommonUtils.parse_json("AUTO_SECRETS_AUTO_COMMANDS", auto_commands)

    if "refresh_interval" not in cache_config_dict:
      raise CacheConfigError("Missing 'refresh_interval' in AUTO_SECRETS_CACHE_CONFIG")
    if "cleanup_interval" not in cache_config_dict:
      raise CacheConfigError("Missing 'cleanup_interval' in AUTO_SECRETS_CACHE_CONFIG")

    self.refresh_interval = self.parse_duration(cache_config_dict.get("refresh_interval"))
    self.cleanup_interval = self.parse_duration(cache_config_dict.get("cleanup_interval"))

    if not isinstance(self.auto_commands, dict):
      raise CacheConfigError(f"auto_commands must be a dict, got {type(self.auto_commands)}")

    for key, value in auto_commands_dict.items():
      if not isinstance(key, str):
        raise CacheConfigError(f"auto_commands keys must be strings, got {type(key)} for key {key}")
      CommonUtils.is_valid_name(key)
      if not isinstance(value, list):
        raise CacheConfigError(f"auto_commands values must be lists, got {type(value)} for key {key}")
      for item in value:
        if not isinstance(item, str):
          raise CacheConfigError(f"auto_commands list items must be strings, got {type(item)} in key {key}")
        self.pattern_cache[key] = CommonUtils.get_regex_from_pattern(key)
    self.auto_commands = auto_commands_dict

  def parse_duration(self, duration_str: str) -> int:
    """
    Parse duration string to seconds.

    Args:
        duration_str: Duration string like "5m", "1h", "30s"

    Returns:
        int: Duration in seconds

    Raises:
        CacheConfigError: If duration format is invalid
    """
    if not duration_str:
      raise CacheConfigError(f"Invalid duration format: {duration_str}")

    duration_str = duration_str.strip().lower()
    match = re.match(r"^(\d+)([smhd]?)$", duration_str)

    if not match:
      raise CacheConfigError(f"Invalid duration format: {duration_str}")

    number, unit = match.groups()
    number = int(number)

    multipliers = {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400}

    return number * multipliers.get(unit, 1)


@dataclass
class CacheMetadata:
  """Metadata for cached secrets."""

  environment: str
  last_updated: int
  last_accessed: int
  secret_count: int
  branch: Optional[str] = None
  repo_path: Optional[str] = None
  version: str = "1.0"

  def to_dict(self) -> dict[str, Any]:
    """Convert to dictionary for JSON serialization."""
    return asdict(self)

  @classmethod
  def from_dict(cls, data: dict[str, Any]) -> "CacheMetadata":
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

  def __init__(self, log_manager: AutoSecretsLogger, crypto_utils: CryptoUtils) -> None:
    self.logger = log_manager.get_logger(name="cache_manager", component="cache_manager")

    cache_config = CacheConfig()
    self.max_age_seconds = cache_config.refresh_interval
    self.cleanup_interval = cache_config.cleanup_interval
    self.auto_commands = cache_config.auto_commands
    self.path_pattern_cache = cache_config.pattern_cache

    common_config = CommonConfig()
    self.base_dir = common_config.get_base_dir()

    self.crypto_utils = crypto_utils

    # Ensure cache directory exists
    self._ensure_cache_directory()

  def _ensure_cache_directory(self) -> None:
    """Ensure cache directory exists with proper permissions."""
    try:
      self.base_dir.mkdir(parents=True, exist_ok=True, mode=0o700)

      # Create environment subdirectory
      env_dir = self.base_dir / "environments"
      env_dir.mkdir(exist_ok=True, mode=0o700)

      # Create state subdirectory
      state_dir = self.base_dir / "state"
      state_dir.mkdir(exist_ok=True, mode=0o700)

      self.logger.debug(f"Cache directories initialized: {self.base_dir}")
    except OSError as e:
      self.logger.error(f"Failed to create cache directory: {e}")
      raise CacheError(f"Cannot create cache directory: {e}") from None

  def get_environment_cache_dir(self, environment: str) -> Path:
    """Get cache directory for specific environment."""
    return self.base_dir / "environments" / environment

  def _merge_state_file_atomically(
    self,
    branch: Optional[str],
    repo_path: Optional[str],
    environment: str,
  ) -> None:
    """
    Merge state file (branch to env mapping) atomically for branch and repo path.

    Args:
        branch: Branch name
        repo_path: Optional repository path
        environment: Environment name

    Raises:
        CacheError: If state file cannot be written
    """
    if not branch or not repo_path:
      return
    if not environment:
      raise CacheError("Environment name cannot be empty")

    self.logger.info(f"Writing state for branch: {branch}")

    try:
      state_dir = self.base_dir / "state"

      # Ensure parent directory exists
      state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)

      # Create metadata
      metadata = {f"{branch}:{repo_path}": environment}

      # Read existing state if it exists
      existing_metadata = self.crypto_utils.read_dict_from_file(state_dir, "current_branch", decrypt=False)

      # Merge with existing metadata
      new_metadata = existing_metadata | metadata

      # Write metadata atomically, unencrypted.
      self.crypto_utils.write_dict_to_file_atomically(state_dir, "current_branch", new_metadata, encrypt=False)

      self.logger.info(f"State for {branch} written successfully")

    except Exception as e:
      self.logger.error(f"Failed to write state for {branch}: {e}")
      raise CacheError(f"State write failed: {e}") from None

  def update_environment_cache(
    self,
    environment: str,
    secrets: dict[str, str],
    branch: Optional[str] = None,
    repo_path: Optional[str] = None,
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
        last_updated=current_time,
        last_accessed=current_time,
        secret_count=len(secrets),
        branch=branch,
        repo_path=repo_path,
      )

      # Write secrets in JSON format (full data)
      self.crypto_utils.write_dict_to_file_atomically(
        env_cache_dir,
        f"{environment}",
        {"metadata": metadata.to_dict(), "secrets": secrets},
        encrypt=True,
      )

      self._merge_state_file_atomically(branch, repo_path, environment)

      self.logger.info(f"Successfully cached {len(secrets)} secrets for {environment}")

    except Exception as e:
      self.logger.error(f"Failed to update cache for {environment}: {e}")
      raise CacheError(f"Cache update failed: {e}") from None

  def get_auto_command_paths(self, command: str) -> list[str]:
    """
    Get paths for auto commands based on the command name.

    Args:
        command: Command name (e.g., "terraform", "kubectl")

    Returns:
        List[str]: List of secret paths for the command
    """
    if not command:
      raise CacheError("Command name cannot be empty")

    return self.auto_commands.get(command, [])

  def get_cached_secrets(self, environment: str, paths: Optional[list[str]] = None) -> dict[str, str]:
    """
    Get cached secrets for environment.
    Args:
        environment: Environment name
        paths: Optional list of shell-style glob patterns to filter secrets by
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
      cache_data = self.crypto_utils.read_dict_from_file(env_cache_dir, f"{environment}", decrypt=True)

      raw_secrets = cache_data.get("secrets", {})

      # Validate that secrets is a dict with string values
      if not isinstance(raw_secrets, dict):
        raise CacheError("Invalid cache format: secrets must be a dictionary")

      secrets: dict[str, str] = {}
      for key, value in raw_secrets.items():
        if not isinstance(key, str) or not isinstance(value, str):
          self.logger.warning(f"Skipping non-string secret: {key}")
          continue
        secrets[key] = value

      metadata = CacheMetadata.from_dict(cache_data.get("metadata", {}))
      # Update last accessed time
      self._update_access_time(environment, metadata)
      # Filter by paths if specified
      if paths:
        filtered_secrets = {}
        for path in paths:
          if path not in self.path_pattern_cache:
            self.logger.warning(f"Pattern not found in cache: '{path}'")
            raise CacheError(f"Pattern not found in cache: '{path}'")
          matching_keys = [k for k in secrets if self.path_pattern_cache[path].match(k)]
          for key in matching_keys:
            filtered_secrets[key] = secrets[key]
        secrets = filtered_secrets
      self.logger.debug(f"Retrieved {len(secrets)} cached secrets for {environment}")
      return secrets
    except (OSError, json.JSONDecodeError) as e:
      self.logger.error(
        f"Failed to read cache for {environment} from file '{env_cache_dir / f'{environment}.enc.json'}' or '{env_cache_dir / f'{environment}.json'}': {e}"
      )
      raise CacheError(f"Cannot read cache: {e}") from None

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
      cache_data = self.crypto_utils.read_dict_from_file(env_cache_dir, f"{environment}", decrypt=True)

      metadata = CacheMetadata.from_dict(cache_data.get("metadata", {}))
      is_stale = metadata.is_stale(max_age)

      self.logger.debug(f"Cache staleness check for {environment}: stale={is_stale}, age={metadata.age_seconds()}s")
      return is_stale

    except Exception as e:
      self.logger.warning(f"Error checking cache staleness for {environment}: {e}")
      return True  # Assume stale on error

  def cleanup_stale(self, max_age_seconds: Optional[int] = None) -> dict[str, int]:
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
      env_dir = self.base_dir / "environments"
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
            self.logger.warning(f"Failed to clean up cache directory '{env_cache_dir}' for {environment}: {e}")

      self.logger.info(f"Cleaned up {cleaned_count} stale cache entries")
      return {"removed": cleaned_count}

    except Exception as e:
      self.logger.error(f"Error during cache cleanup: {e}")
      return {"removed": cleaned_count}

  def cleanup_all(self) -> dict[str, int]:
    """Clean up all cache files."""
    self.logger.info("Cleaning up all cache files")
    removed_count = 0

    try:
      if self.base_dir.exists():
        # Count environments before removal
        env_dir = self.base_dir / "environments"
        if env_dir.exists():
          removed_count = len([d for d in env_dir.iterdir() if d.is_dir()])

        shutil.rmtree(self.base_dir)
        self.logger.info("All cache files cleaned up")

      # Recreate directory structure
      self._ensure_cache_directory()
      return {"removed": removed_count}

    except Exception as e:
      self.logger.error(f"Failed to clean up all caches: {e}")
      raise CacheError(f"Cache cleanup failed: {e}") from None

  def get_cache_info(self, environment: str) -> Optional[dict[str, Any]]:
    """
    Get cache information for environment.

    Args:
        environment: Environment name

    Returns:
        Dict[str, Any]: Cache information or None if no cache exists
    """
    try:
      env_cache_dir = self.get_environment_cache_dir(environment)
      cache_data = self.crypto_utils.read_dict_from_file(env_cache_dir, f"{environment}", decrypt=True)

      metadata = CacheMetadata.from_dict(cache_data.get("metadata", {}))

      return metadata.to_dict()

    except Exception as e:
      self.logger.error(f"Failed to get cache info for {environment}: {e}")
      return None

  def _update_access_time(self, environment: str, metadata: CacheMetadata) -> None:
    """
    Update last accessed time for cache entry.

    Args:
        environment: Environment name
        metadata: Current metadata object
    """
    try:
      env_cache_dir = self.get_environment_cache_dir(environment)
      cache_data = self.crypto_utils.read_dict_from_file(env_cache_dir, f"{environment}", decrypt=True)

      # Update access time
      metadata.last_accessed = int(time.time())
      cache_data["metadata"] = metadata.to_dict()

      # Write back (non-critical, so don't fail on error)
      try:
        self.crypto_utils.write_dict_to_file_atomically(env_cache_dir, f"{environment}", cache_data, encrypt=True)
      except Exception as e:
        self.logger.debug(f"Failed to update access time for {environment}: {e}")

    except Exception as e:
      self.logger.debug(f"Failed to update access time for {environment}: {e}")

  def get_cache_stats(self) -> dict[str, Any]:
    """
    Get overall cache statistics.

    Returns:
        Dict[str, Any]: Cache statistics
    """
    stats: dict[str, Any] = {
      "cache_dir": str(self.base_dir),
      "cache_dir_exists": self.base_dir.exists(),
      "total_environments": 0,
      "total_secrets": 0,
      "stale_environments": 0,
      "environments": {},
    }

    try:
      env_dir = self.base_dir / "environments"
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
    return f"CacheManager(base_dir={self.base_dir}, max_age={self.max_age_seconds}s)"
