"""
Auto Secrets Manager - Background Daemon

Background daemon for proactive secret cache refresh and maintenance.
Runs as a simple background process managed by DevContainer lifecycle.
"""

import logging
import os
import sys
import time
from typing import Optional

from .monitored_process import MonitoredProcess


class DaemonError(Exception):
  pass


class SecretsDaemon(MonitoredProcess):
  """Background daemon for secret cache management."""

  def __init__(self) -> None:
    try:
      super().__init__(process_name="daemon", heartbeat_interval=30.0)
      self.logger.info("Daemon initialized successfully")
    except Exception as e:
      if self.logger:
        self.logger.critical(f"Daemon failed to initialize: {e}")
      else:
        logging.critical(f"Daemon failed to initialize: {e}", exc_info=True)
      sys.exit(1)

  def _acquire_smk(self) -> Optional[bytes]:
    """Acquire the Session Master Key from the inherited file descriptor."""
    self.logger.info("Acquiring Session Master Key from file descriptor...")
    smk_fd_str = os.environ.get("AUTO_SECRETS_SMK_FD")
    if not smk_fd_str:
      return None

    try:
      smk_fd = int(smk_fd_str)
      with os.fdopen(smk_fd, "rb") as f:
        smk = f.read()
      if not smk:
        raise DaemonError("Failed to read key from file descriptor (empty).")
      self.logger.info("Successfully acquired Session Master Key.")
      return smk
    except (ValueError, OSError) as e:
      self.logger.error(f"Failed to process SMK file descriptor {smk_fd_str}: {e}")
      sys.exit(1)

  def _get_environments_to_refresh(self) -> list:
    """Get list of environments that need refreshing."""
    environments_to_refresh = []

    try:
      # Check all environments that have stale caches
      try:
        cache_dir = self.app.cache_manager.base_dir / "environments"

        if cache_dir.exists():
          for cache_file in cache_dir.glob("*.env"):
            env_name = cache_file.stem
            if self.app.cache_manager.is_cache_stale(env_name):
              environments_to_refresh.append(env_name)

      except Exception as e:
        self.logger.debug(f"Error checking cached environments: {e}")

    except Exception as e:
      self.logger.error(f"Error determining environments to refresh: {e}")

    return list(set(environments_to_refresh))  # Remove duplicates

  def _refresh_environment_secrets(self, environment: str) -> bool:
    """Refresh secrets for a specific environment."""
    try:
      self.logger.info(f"Refreshing secrets for environment: {environment}")

      # Test connection first
      if not self.app.secret_manager.test_connection():
        self.logger.error("Connection test failed")
        return False

      # Fetch secrets
      secrets = self.app.secret_manager.fetch_secrets(environment)

      # Update cache atomically
      self.app.cache_manager.update_environment_cache(environment, secrets)

      self.logger.info(f"Successfully refreshed {len(secrets)} secrets for {environment}")
      return True

    except Exception as e:
      self.logger.error(f"Failed to refresh secrets for {environment}: {e}")
      return False

  def _refresh_all_environments(self) -> None:
    environments = self._get_environments_to_refresh()
    if environments:
      for env in environments:
        if not self.running:
          break
        self._refresh_environment_secrets(env)

  def _cleanup_old_caches(self) -> None:
    """Clean up old cache files."""
    try:
      cleanup_age = self.app.cache_manager.cleanup_interval

      if cleanup_age > 0:
        # Simple cleanup based on file age
        cleaned_count = self.app.cache_manager.cleanup_stale(max_age_seconds=cleanup_age)
        self.logger.info(f"Cleaned up {cleaned_count} stale cache entries")

    except Exception as e:
      self.logger.error(f"Cache cleanup failed: {e}")

  def _initialize(self) -> None:
    """Pre Run"""
    self._refresh_interval = self.app.cache_manager.max_age_seconds  # TODO
    self._last_refresh: Optional[float] = None
    self._last_cleanup = time.time()
    self._cleanup_check_interval = 3600

  def _run(self) -> None:
    """Main daemon loop."""
    try:
      current_time = time.time()
      # Get and refresh environments
      if self._last_refresh is None or (current_time - self._last_refresh) > self._refresh_interval:
        self._refresh_all_environments()
        self._last_refresh = current_time

      # Periodic cleanup
      if (current_time - self._last_cleanup) > self._cleanup_check_interval:
        self._cleanup_old_caches()
        self._last_cleanup = current_time
    except Exception as e:
      self.logger.warning(f"Error in main loop, continuing despite error: {e}")
      pass


def main() -> None:
  """Main entry point for daemon."""
  daemon = SecretsDaemon()

  try:
    daemon.start(sleep=5.0)
  except KeyboardInterrupt:
    print("\nDaemon interrupted")
    daemon.stop()
    sys.exit(0)
  except Exception as e:
    print(f"FATAL: Daemon error: {e}")
    sys.exit(1)


if __name__ == "__main__":
  main()
