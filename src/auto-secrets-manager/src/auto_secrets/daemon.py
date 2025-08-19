"""
Auto Secrets Manager - Background Daemon

Background daemon for proactive secret cache refresh and maintenance.
Runs as a simple background process managed by DevContainer lifecycle.
"""

import os
import signal
import sys
import time
from datetime import datetime
from pathlib import Path
from types import FrameType
from typing import Optional

from .core.process_utils import ProcessUtils
from .managers.app_manager import AppManager
from .managers.log_manager import AutoSecretsLogger


class DaemonError(Exception):
  pass


class SecretsDaemon:
  """Background daemon for secret cache management."""

  def __init__(self) -> None:
    try:
      self.running = False
      self.pid_file: Optional[Path]
      self.smk: Optional[bytes] = None
      self.logger = AutoSecretsLogger(log_file="daemon.log").get_logger("daemon", "daemon")

      ProcessUtils.set_parent_death_signal(self.logger)

      self._acquire_smk()  # Initialize AppManager after getting smk
      self.app = AppManager(log_file="daemon.log", smk=self.smk)
      self.crypto_utils = self.app.crypto_utils

      self.logger = self.app.get_logger("daemon", "daemon")

      # Set up PID file
      self._setup_pid_file()

      self.logger.info("Daemon initialized successfully")
    except Exception as e:
      self.logger.error(f"Failed to initialize daemon: {e}")
      raise

  def _acquire_smk(self) -> None:
    """Acquire the Session Master Key from the inherited file descriptor."""
    self.logger.info("Acquiring Session Master Key from file descriptor...")
    smk_fd_str = os.environ.get("AUTO_SECRETS_SMK_FD")
    if not smk_fd_str:
      raise DaemonError("AUTO_SECRETS_SMK_FD environment variable not set. Cannot start.")

    try:
      smk_fd = int(smk_fd_str)
      with os.fdopen(smk_fd, "rb") as f:
        self.smk = f.read()
      if not self.smk:
        raise DaemonError("Failed to read key from file descriptor (empty).")
      self.logger.info("Successfully acquired Session Master Key.")
    except (ValueError, OSError) as e:
      self.logger.error(f"Failed to process SMK file descriptor {smk_fd_str}: {e}")
      sys.exit(1)

  def _setup_pid_file(self) -> None:
    """Set up PID file for daemon process management."""
    try:
      state_dir = self.app.cache_manager.base_dir / "state"
      state_dir.mkdir(parents=True, exist_ok=True)

      self.pid_file = state_dir / "daemon.pid"

      # Check if daemon is already running
      if self.pid_file.exists():
        try:
          with open(self.pid_file) as f:
            old_pid = int(f.read().strip())

          # Check if process is still running
          try:
            os.kill(old_pid, 0)  # Signal 0 just checks if process exists
            self.logger.error(f"Daemon already running with PID {old_pid}")
            sys.exit(1)
          except OSError:
            # Process doesn't exist, remove stale PID file
            self.pid_file.unlink()
            self.logger.info(f"Removed stale PID file for process {old_pid}")
        except (ValueError, OSError):
          # Invalid PID file, remove it
          self.pid_file.unlink()
          self.logger.info("Removed invalid PID file")

      # Write current PID
      with open(self.pid_file, "w") as f:
        f.write(str(os.getpid()))

      self.logger.info(f"PID file created: {self.pid_file}")

    except Exception as e:
      self.logger.error(f"Failed to setup PID file: {e}")
      # Continue without PID file
      self.pid_file = None

  def _setup_signal_handlers(self) -> None:
    """Set up signal handlers for graceful shutdown."""

    def signal_handler(signum: int, frame: Optional[FrameType]) -> None:
      self.logger.info(f"Received signal {signum}, shutting down gracefully...")
      self.running = False

    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)

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

  def _update_heartbeat(self) -> None:
    """Update heartbeat file to indicate daemon is alive."""
    try:
      if self.pid_file:
        heartbeat_file = self.pid_file.parent / "daemon.heartbeat"
        with open(heartbeat_file, "w") as f:
          f.write(datetime.now().isoformat())
    except Exception as e:
      self.logger.debug(f"Failed to update heartbeat: {e}")

  def run(self) -> None:
    """Main daemon loop."""
    try:
      self._setup_signal_handlers()

      self.running = True
      refresh_interval = self.app.cache_manager.max_age_seconds

      self.logger.info(f"Daemon started with refresh interval: {refresh_interval}s")

      last_cleanup = time.time()
      cleanup_check_interval = 3600  # Attempt clean up every hour

      while self.running:
        start_time = time.time()

        try:
          # Update heartbeat
          self._update_heartbeat()

          # Get environments that need refreshing
          environments = self._get_environments_to_refresh()

          if environments:
            self.logger.info(f"Refreshing {len(environments)} environments: {environments}")

            for env in environments:
              if not self.running:  # Check if we should stop
                break  # type: ignore[unreachable]

              success = self._refresh_environment_secrets(env)
              if not success:
                self.logger.warning(f"Failed to refresh environment: {env}")
          else:
            self.logger.debug("No environments need refreshing")

          # Periodic cleanup
          current_time = time.time()
          if current_time - last_cleanup > cleanup_check_interval:
            self._cleanup_old_caches()
            last_cleanup = current_time

        except Exception as e:
          self.logger.error(f"Error in daemon loop: {e}")

        # Sleep until next refresh cycle
        elapsed = time.time() - start_time
        sleep_time = max(0, refresh_interval - elapsed)

        if sleep_time > 0:
          self.logger.debug(f"Sleeping for {sleep_time:.1f}s until next refresh")

          # Sleep in small increments to allow for graceful shutdown
          while sleep_time > 0 and self.running:
            chunk = min(sleep_time, 5.0)  # Sleep in 5-second chunks
            time.sleep(chunk)
            sleep_time -= chunk

      self.logger.info("Daemon loop ended")

    except Exception as e:
      self.logger.error(f"Fatal error in daemon: {e}")
      sys.exit(1)

    finally:
      self._cleanup()

  def _cleanup(self) -> None:
    """Clean up daemon resources."""
    try:
      self.logger.info("Cleaning up daemon resources...")

      # Remove PID file
      if self.pid_file and self.pid_file.exists():
        self.pid_file.unlink()
        self.logger.info("PID file removed")

      # Remove heartbeat file
      if self.pid_file:
        heartbeat_file = self.pid_file.parent / "daemon.heartbeat"
        if heartbeat_file.exists():
          heartbeat_file.unlink()

      self.logger.info("Daemon cleanup completed")

    except Exception as e:
      self.logger.error(f"Error during cleanup: {e}")

  def stop(self) -> None:
    """Stop the daemon gracefully."""
    self.running = False


def main() -> None:
  """Main entry point for daemon."""
  daemon = SecretsDaemon()

  try:
    daemon.run()
  except KeyboardInterrupt:
    print("\nDaemon interrupted")
    daemon.stop()
    sys.exit(0)
  except Exception as e:
    print(f"FATAL: Daemon error: {e}")
    sys.exit(1)


if __name__ == "__main__":
  main()
