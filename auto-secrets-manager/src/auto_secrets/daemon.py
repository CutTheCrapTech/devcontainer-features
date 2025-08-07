"""
Auto Secrets Manager - Background Daemon

Background daemon for proactive secret cache refresh and maintenance.
Runs as a simple background process managed by DevContainer lifecycle.
"""

import os
import sys
import time
import signal
from typing import Dict, Any

import logging
from datetime import datetime

from pathlib import Path

from .logging_config import get_logger
from .core.config import load_config
from .core.cache_manager import CacheManager
from .core.environment import get_current_environment
from .secret_managers import create_secret_manager, SecretManagerBase
from .core.utils import CommonUtils


class SecretsDaemon:
    """Background daemon for secret cache management."""

    def __init__(self):
        self.config: Dict[str, Any]
        self.cache_manager: CacheManager
        self.secret_manager: SecretManagerBase
        self.running = False
        self.pid_file = None
        self.log_file = None
        self.logger: logging.Logger

        self.initialize()

    def initialize(self) -> None:
        """Initialize daemon configuration and components."""
        try:
            # Load configuration
            self.config = load_config()

            # Set up logging
            self._setup_logging()

            # Initialize components
            self.cache_manager = CacheManager(self.config)

            secret_manager = create_secret_manager(self.config)
            if not secret_manager:
                raise ValueError("Failed to create secret manager - check configuration")
            self.secret_manager = secret_manager

            # Set up PID file
            self._setup_pid_file()

            # Initialize logger
            self.logger = get_logger("daemon")
            self.logger.info("Daemon initialized successfully")

        except Exception as e:
            # Set up basic logging if not already done
            if self.logger is None:
                logging.basicConfig(level=logging.INFO)
                self.logger = get_logger("daemon")

            self.logger.error(f"Failed to initialize daemon: {e}")
            raise

    def _setup_logging(self) -> None:
        """Set up logging for the daemon."""
        try:
            logs_dir = Path(self.config["log_dir"])

            self.log_file = logs_dir / "daemon.log"

            # Import and use the proper logging setup
            from .logging_config import setup_logging
            setup_logging(
                log_level="DEBUG" if self.config.get('debug', False) else "INFO",
                log_dir=str(logs_dir),
                log_file="daemon.log"
            )

            self.logger = get_logger("daemon")

        except Exception as e:
            print(f"Failed to setup logging: {e}")
            # Fall back to basic logging
            self.logger = get_logger("daemon")

    def _setup_pid_file(self) -> None:
        """Set up PID file for daemon process management."""
        try:
            state_dir = self.cache_manager.cache_dir / "state"
            state_dir.mkdir(parents=True, exist_ok=True)

            self.pid_file = state_dir / "daemon.pid"

            # Check if daemon is already running
            if self.pid_file.exists():
                try:
                    with open(self.pid_file, 'r') as f:
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
            with open(self.pid_file, 'w') as f:
                f.write(str(os.getpid()))

            self.logger.info(f"PID file created: {self.pid_file}")

        except Exception as e:
            self.logger.error(f"Failed to setup PID file: {e}")
            # Continue without PID file
            self.pid_file = None

    def _setup_signal_handlers(self) -> None:
        """Set up signal handlers for graceful shutdown."""
        def signal_handler(signum, frame):
            self.logger.info(f"Received signal {signum}, shutting down gracefully...")
            self.running = False

        signal.signal(signal.SIGTERM, signal_handler)
        signal.signal(signal.SIGINT, signal_handler)

        # Handle SIGHUP as a reload signal
        def reload_handler(signum, frame):
            self.logger.info("Received SIGHUP, reloading configuration...")
            try:
                self.config = load_config()
                self.cache_manager = CacheManager(self.config)
                secret_manager = create_secret_manager(self.config)
                if not secret_manager:
                    raise ValueError("Failed to create secret manager - check configuration")
                self.secret_manager = secret_manager
                self.logger.info("Configuration reloaded successfully")
            except Exception as e:
                self.logger.error(f"Failed to reload configuration: {e}")

        signal.signal(signal.SIGHUP, reload_handler)

    def _get_refresh_interval(self) -> int:
        """Get refresh interval in seconds from configuration."""
        default_interval = 900  # 15 minutes

        try:
            interval_str = self.config.get('cache_config', {}).get("refresh_interval", "15m")
            return CommonUtils.parse_duration(interval_str)
        except Exception as e:
            self.logger.warning(f"Invalid refresh interval, using default: {e}")
            return default_interval

    def _get_environments_to_refresh(self) -> list:
        """Get list of environments that need refreshing."""
        environments_to_refresh = []

        try:
            # Get current environment (highest priority)
            current_env = get_current_environment()
            if current_env and current_env.environment:
                env_name = current_env.environment
                if self.cache_manager.is_cache_stale(env_name):
                    environments_to_refresh.append(env_name)
                    self.logger.debug(f"Current environment {env_name} cache is stale")

            # Check other environments that have stale caches
            try:
                cache_dir = self.cache_manager.cache_dir / "environments"

                if cache_dir.exists():
                    for cache_file in cache_dir.glob("*.env"):
                        env_name = cache_file.stem
                        current_env_name = current_env.environment if current_env else None
                        if env_name != current_env_name and self.cache_manager.is_cache_stale(env_name):
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
            if not self.secret_manager.test_connection():
                self.logger.error("Connection test failed")
                return False

            # Fetch secrets
            secrets = self.secret_manager.fetch_secrets(environment)

            # Update cache atomically
            self.cache_manager.update_environment_cache(environment, secrets)

            self.logger.info(f"Successfully refreshed {len(secrets)} secrets for {environment}")
            return True

        except Exception as e:
            self.logger.error(f"Failed to refresh secrets for {environment}: {e}")
            return False

    def _cleanup_old_caches(self) -> None:
        """Clean up old cache files."""
        try:
            cache_config = self.config.get('cache_config', {})
            cleanup_interval_str = cache_config.get("cleanup_interval", "7d")
            cleanup_age = CommonUtils.parse_duration(cleanup_interval_str)

            if cleanup_age > 0:
                # Simple cleanup based on file age
                cleaned_count = self.cache_manager.cleanup_stale(max_age_seconds=cleanup_age)
                self.logger.info(f"Cleaned up {cleaned_count} stale cache entries")

        except Exception as e:
            self.logger.error(f"Cache cleanup failed: {e}")

    def _update_heartbeat(self) -> None:
        """Update heartbeat file to indicate daemon is alive."""
        try:
            if self.pid_file:
                heartbeat_file = self.pid_file.parent / "daemon.heartbeat"
                with open(heartbeat_file, 'w') as f:
                    f.write(datetime.now().isoformat())
        except Exception as e:
            self.logger.debug(f"Failed to update heartbeat: {e}")

    def run(self) -> None:
        """Main daemon loop."""
        try:
            self.initialize()
            self._setup_signal_handlers()

            self.running = True
            refresh_interval = self._get_refresh_interval()

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
                                break

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
