"""
Auto Secrets Manager - Monitored Process Base Class
Base class providing heartbeat functionality for child processes.
"""

import os
import signal
import sys
import time
from abc import ABC, abstractmethod
from datetime import datetime
from pathlib import Path
from types import FrameType
from typing import Optional

from .core.process_utils import ProcessUtils
from .managers.app_manager import AppManager


class MonitoredProcess(ABC):
  """Base class for processes that support heartbeat monitoring and common daemon functionality."""

  def __init__(self, process_name: str, heartbeat_interval: float = 30.0):
    """
    Initialize monitored process.

    Args:
        process_name: Name of the process (used for heartbeat file naming)
        heartbeat_interval: Seconds between heartbeat updates
        log_file: Optional log file name (defaults to "{process_name}.log")
    """
    self.process_name = process_name.lower()
    self.heartbeat_interval = heartbeat_interval
    self.last_heartbeat = 0.0
    self.running = False
    self.pid_file: Optional[Path]
    self.heartbeat_file: Optional[Path]

    self.app = AppManager(log_file=f"{self.process_name}.log")
    self.logger = self.app.get_logger(self.process_name, self.process_name)

    self.state_dir = self.app.cache_manager.base_dir / "state"
    self.state_dir.mkdir(parents=True, exist_ok=True)
    self._setup_heartbeat()
    self._setup_pid_file()

    # Process management
    ProcessUtils.set_parent_death_signal(self.logger)
    self._setup_signal_handlers()

    self.app.smk = self._acquire_smk()
    self.crypto_utils = self.app.crypto_utils
    self.session_encryption_key = self.crypto_utils.derive_session_encryption_key()

    self.logger.info(f"{self.process_name.title()} process initialized with {heartbeat_interval}s heartbeat interval")

  @abstractmethod
  def _acquire_smk(self) -> Optional[bytes]:
    """
    Acquire the Session Master Key from the inherited file descriptor.
    """
    raise NotImplementedError("This method should be implemented in subclasses acquire smk.")

  def _setup_signal_handlers(self) -> None:
    """Set up signal handlers for graceful shutdown."""

    def signal_handler(signum: int, frame: Optional[FrameType]) -> None:
      self.logger.info(f"Received signal {signum}, shutting down gracefully...")
      self.running = False

    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)

  def _setup_pid_file(self) -> None:
    """Set up PID file for daemon process management."""
    try:
      self.pid_file = self.state_dir / f"{self.process_name}.pid"

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

  def _setup_heartbeat(self) -> None:
    """Initialize heartbeat file path."""
    self.heartbeat_file = self.state_dir / f"{self.process_name}.heartbeat"
    self.logger.info(f"Heartbeat file: {self.heartbeat_file}")

  def _update_heartbeat(self) -> None:
    """Update heartbeat file to indicate process is alive."""
    if not self.heartbeat_file:
      return

    try:
      with open(self.heartbeat_file, "w") as f:
        f.write(datetime.now().isoformat())
      self.last_heartbeat = time.time()
    except Exception as e:
      self.logger.debug(f"Failed to update heartbeat: {e}")

  def _should_update_heartbeat(self) -> bool:
    """Check if it's time to update heartbeat."""
    return time.time() - self.last_heartbeat >= self.heartbeat_interval

  def _maybe_update_heartbeat(self) -> None:
    """Update heartbeat if interval has elapsed."""
    if self._should_update_heartbeat():
      self._update_heartbeat()

  def _cleanup_heartbeat(self) -> None:
    """Remove heartbeat file during cleanup."""
    try:
      if self.heartbeat_file and self.heartbeat_file.exists():
        self.heartbeat_file.unlink()
        self.logger.info("Heartbeat file removed")
    except Exception as e:
      self.logger.debug(f"Error removing heartbeat file: {e}")

  def _cleanup_pid_file(self) -> None:
    """Remove pid file during cleanup."""
    try:
      if self.pid_file and self.pid_file.exists():
        self.pid_file.unlink()
        self.logger.info("PID file removed")
    except Exception as e:
      self.logger.debug(f"Error removing pid file: {e}")

  def start(
    self,
    sleep: float = 10.0,
  ) -> None:
    """Start the monitored process - calls run() with proper setup/cleanup."""
    try:
      self.running = True
      self.logger.info(f"{self.process_name.title()} starting...")

      # Initial heartbeat
      self._update_heartbeat()

      self._initialize()

      # Run the main process logic
      self._run_loop(sleep)

    except Exception as e:
      self.logger.error(f"Fatal error in {self.process_name}: {e}", exc_info=True)
      raise
    finally:
      self._cleanup()

  def stop(self) -> None:
    """Stop the process gracefully."""
    self.logger.info(f"Stopping {self.process_name}...")
    self.running = False

  def _cleanup(self) -> None:
    """Base cleanup - subclasses should override and call super()._cleanup()."""
    self.logger.info(f"Cleaning up {self.process_name} resources...")
    self._cleanup_heartbeat()
    self._cleanup_pid_file()
    self.logger.info(f"{self.process_name.title()} cleanup completed")

  @abstractmethod
  def _initialize(self) -> None:
    """Process-specific initialization - called after base setup and before start / _run_loop."""
    raise NotImplementedError("This method should be implemented in subclasses to run code outside the main loop.")

  @abstractmethod
  def _run(self) -> None:
    """Main process loop inner code - must be implemented by subclasses."""
    raise NotImplementedError("This method should be implemented in subclasses to run code inside the main loop.")

  def _run_loop(self, sleep: float) -> None:
    """Main process loop - _run must be implemented by subclasses."""
    while self.running:
      self._maybe_update_heartbeat()
      self._run()
      time.sleep(sleep)
