"""
Auto Secrets Manager - Supervisor

The root process responsible for managing the session lifecycle.
1. Acquires the Session Master Key (SMK) via a one-time user authentication.
2. Launches and manages the Key Master and Daemon child processes using fork().
3. Securely passes the SMK file descriptor to its children via inheritance.
4. Monitors children and restarts them if they terminate unexpectedly.
"""

import logging
import os
import signal
import sys
import time
from typing import Any, Optional

# --- Project-specific imports ---
from .daemon import SecretsDaemon
from .key_master import KeyMaster
from .managers.app_manager import AppManager
from .managers.common_config import CommonConfig
from .monitored_process import MonitoredProcess


class SupervisorError(Exception):
  pass


class Supervisor(MonitoredProcess):
  """The main supervisor process."""

  def __init__(self) -> None:
    try:
      super().__init__(process_name="supervisor", heartbeat_interval=60.0)

      common_config = CommonConfig()
      self.ssh_agent_key_comment = common_config.ssh_agent_key_comment
      self.ssh_agent_enabled = bool(self.ssh_agent_key_comment)
      if self.ssh_agent_enabled:
        self.logger.info(f"SSH agent integration ENABLED for key comment: '{self.ssh_agent_key_comment}'")
      else:
        self.logger.info("SSH agent integration DISABLED (ssh_agent_key_comment is not set or empty)")

      self.child_pids: dict[str, int] = {}
      self.smk_fd: Optional[int] = None
      self.key_retriever = self.app.key_retriever

    except Exception as e:
      if self.logger:
        self.logger.critical(f"Supervisor failed to initialize: {e}", exc_info=True)
      else:
        logging.critical(f"Supervisor failed to initialize: {e}", exc_info=True)
      sys.exit(1)

  def _acquire_smk(self) -> Optional[bytes]:
    """Supervisor doesn't need SMK itself."""
    return None

  def _get_session_master_key(self) -> None:
    """
    Acquires the Session Master Key (SMK) using the KeyRetriever.
    THIS IS THE PRIMARY SECURITY BOUNDARY.
    """
    self.logger.info("Acquiring Session Master Key via KeyRetriever...")
    try:
      retriever = self.key_retriever
      self.smk_fd = retriever.derive_smk_from_ssh_agent()
      if self.smk_fd is None:
        raise SupervisorError("Failed to derive key from SSH agent.")
      self.logger.info(f"SMK acquired in memfd descriptor: {self.smk_fd}")
    except Exception as e:
      self.logger.critical(f"Could not acquire Session Master Key: {e}", exc_info=True)
      sys.exit(1)

  def _check_child_heartbeat(self, name: str, pid: int, max_age_minutes: int = 2) -> bool:
    """Check if child process heartbeat is healthy."""
    try:
      heartbeat_file = self.state_dir / f"{name.lower()}.heartbeat"
      if not heartbeat_file.exists():
        self.logger.warning(f"No heartbeat file found for {name} - process may be unhealthy")
        return False  # No heartbeat = not healthy

      from datetime import datetime, timedelta

      heartbeat_time = datetime.fromisoformat(heartbeat_file.read_text().strip())
      age = datetime.now() - heartbeat_time

      # Consider stale if older than max_age_minutes
      if age > timedelta(minutes=max_age_minutes):
        self.logger.warning(f"{name} heartbeat is stale: {age.total_seconds():.1f}s old (max: {max_age_minutes}m)")
        return False

      self.logger.debug(f"{name} heartbeat is healthy: {age.total_seconds():.1f}s old")
      return True

    except Exception as e:
      self.logger.error(f"Error checking {name} heartbeat: {e}")
      return False  # Assume unhealthy on error

  def _launch_child(self, name: str, target_class: Any) -> None:
    """Fork the process to launch a child running the target class."""
    self.logger.info(f"Forking to launch child process: {name}")
    pid = os.fork()

    if pid == 0:  # This is the child process
      try:
        # The child instantiates its class and runs forever.
        # It does not return from here.
        instance = target_class()
        instance.run()
        sys.exit(0)
      except Exception as e:
        # Log to stderr if the child fails very early
        print(f"FATAL ERROR in child process '{name}': {e}", file=sys.stderr)
        sys.exit(1)

    else:  # This is the parent process
      self.logger.info(f"Launched {name} with PID: {pid}")
      self.child_pids[name] = pid

  def _initialize(self) -> None:
    """Setup supervisor-specific resources."""
    if self.ssh_agent_enabled:
      self.logger.info("Acquiring session key for children...")
      self._get_session_master_key()
      if self.smk_fd is not None:
        os.environ["AUTO_SECRETS_SMK_FD"] = str(self.smk_fd)
        self._launch_child("KeyMaster", KeyMaster)

    self._launch_child("Daemon", SecretsDaemon)

  def _run(self) -> None:
    """Monitor child processes."""
    for name, pid in list(self.child_pids.items()):
      pid_dead, status = os.waitpid(pid, os.WNOHANG)
      if pid_dead == pid:
        self.logger.warning(f"{name} terminated, restarting...")
        target = KeyMaster if name == "KeyMaster" else SecretsDaemon
        self._launch_child(name, target)
      else:
        # Process is alive, check heartbeat
        if not self._check_child_heartbeat(name, pid, max_age_minutes=3):
          self.logger.warning(f"{name} heartbeat stale, killing and restarting...")
          try:
            os.kill(pid, signal.SIGTERM)
          except ProcessLookupError:
            self.logger.info(f"{name} already gone, restarting...")
            pass
          # Give it a few seconds to die
          time.sleep(3)

          # Check if it actually died
          pid_dead, status = os.waitpid(pid, os.WNOHANG)
          if pid_dead == pid:
            # Successfully killed, restart it
            self.logger.info(f"{name} killed successfully, restarting...")
            target = KeyMaster if name == "KeyMaster" else SecretsDaemon
            self._launch_child(name, target)
          else:
            # Still alive, log warning and continue
            self.logger.warning(f"{name} didn't die after SIGTERM, will retry next iteration")

  def _cleanup(self) -> None:
    """Gracefully terminate child processes and clean up resources."""
    self.logger.info("Supervisor cleaning up...")

    for name, pid in self.child_pids.items():
      try:
        os.kill(pid, signal.SIGTERM)
        self.logger.info(f"Sent SIGTERM to {name} (PID: {pid}).")
      except ProcessLookupError:
        self.logger.info(f"{name} (PID: {pid}) already terminated.")
      except Exception as e:
        self.logger.error(f"Error terminating {name}: {e}")

    # Wait a moment for children to exit
    time.sleep(2)

    if self.smk_fd is not None:
      os.close(self.smk_fd)
      self.logger.info("SMK file descriptor closed.")

    if self.pid_file and self.pid_file.exists():
      self.pid_file.unlink()
      self.logger.info("Supervisor PID file removed.")

    self.logger.info("Supervisor shutdown complete.")

    super()._cleanup()


def main() -> None:
  """Instantiate and run the Supervisor. This is the script entry point."""
  print("Starting Auto Secrets Supervisor daemon...")
  try:
    supervisor = Supervisor()
    supervisor.start(sleep=5.0)
  except KeyboardInterrupt:
    # This catch is for a Ctrl+C during the initial setup phase.
    # The signal handlers inside the class handle it once the run loop starts.
    print("\nSupervisor startup interrupted by user. Exiting.")
    sys.exit(0)
  except Exception as e:
    # Catches critical errors during initialization (e.g., config loading).
    # The internal logger will have already recorded the details.
    print(f"FATAL SUPERVISOR ERROR: {e}", file=sys.stderr)
    sys.exit(1)


if __name__ == "__main__":
  app = AppManager(log_file="supervisor.log")
  main()
