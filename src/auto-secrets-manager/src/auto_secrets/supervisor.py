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
from pathlib import Path
from types import FrameType
from typing import Any, Optional

# --- Project-specific imports ---
from .core.cache_manager import CacheManager
from .core.config import ConfigManager
from .core.key_retriever import KeyRetriever
from .daemon import SecretsDaemon
from .key_master import KeyMaster
from .logging_config import get_logger, setup_logging


class Supervisor:
    """The main supervisor process."""

    def __init__(self) -> None:
        self.running = True
        self.config: dict[str, Any]
        self.pid_file: Optional[Path] = None

        self.ssh_agent_enabled = False
        self.ssh_agent_key_comment: Optional[str] = None

        self.child_pids: dict[str, int] = {}
        self.smk_fd: Optional[int] = None

        self._initialize()

    def _initialize(self) -> None:
        """Load config, set up logging, and determine if SSH agent should be used."""
        try:
            self.config = ConfigManager.load_config()
            setup_logging(
                log_level=self.config["log_level"],
                log_dir=self.config["log_dir"],
                log_file="supervisor.log",
            )
            self.logger = get_logger("supervisor")

            cache_manager = CacheManager(self.config)
            self.state_dir = cache_manager.cache_dir / "state"
            self.state_dir.mkdir(parents=True, exist_ok=True)

            self.ssh_agent_key_comment = self.config.get("ssh_agent_key_comment")
            self.ssh_agent_enabled = bool(self.ssh_agent_key_comment)

            if self.ssh_agent_enabled:
                self.logger.info(f"SSH agent integration ENABLED for key comment: '{self.ssh_agent_key_comment}'")
            else:
                self.logger.info("SSH agent integration DISABLED (ssh_agent_key_comment is not set or empty)")

        except Exception as e:
            logging.critical(f"Supervisor failed to initialize: {e}", exc_info=True)
            sys.exit(1)

    def _setup_pid_file(self) -> None:
        """Create and lock a PID file in the correct state directory."""
        self.pid_file = self.state_dir / "supervisor.pid"
        if self.pid_file.exists():
            try:
                old_pid = int(self.pid_file.read_text().strip())
                os.kill(old_pid, 0)
                self.logger.error(f"Supervisor already running with PID {old_pid}.")
                sys.exit(1)
            except (OSError, ValueError):
                self.logger.warning("Removing stale supervisor PID file.")
                self.pid_file.unlink()

        self.pid_file.write_text(str(os.getpid()))
        self.logger.info(f"Supervisor PID file created: {self.pid_file}")

    def _setup_signal_handlers(self) -> None:
        """Set up signal handlers for graceful shutdown."""

        def signal_handler(signum: int, frame: Optional[FrameType]) -> None:
            self.logger.info(f"Received signal {signum}, initiating shutdown...")
            self.running = False

        signal.signal(signal.SIGTERM, signal_handler)
        signal.signal(signal.SIGINT, signal_handler)

    def _get_session_master_key(self) -> None:
        """
        Acquires the Session Master Key (SMK) using the KeyRetriever.
        THIS IS THE PRIMARY SECURITY BOUNDARY.
        """
        self.logger.info("Acquiring Session Master Key via KeyRetriever...")
        try:
            assert self.ssh_agent_key_comment, "Cannot get session key: ssh_agent_key_comment is not set."
            retriever = KeyRetriever(ssh_agent_key_comment=self.ssh_agent_key_comment, logger=self.logger)
            self.smk_fd = retriever.derive_smk_from_ssh_agent()
            if self.smk_fd is None:
                raise RuntimeError("Failed to derive key from SSH agent.")
            self.logger.info(f"SMK acquired in memfd descriptor: {self.smk_fd}")
        except Exception as e:
            self.logger.critical(
                f"Could not acquire Session Master Key: {e}", exc_info=True
            )
            sys.exit(1)

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

    def run(self) -> None:
      """Main supervisor loop: launch and monitor child processes."""
      self._setup_pid_file()
      self._setup_signal_handlers()
      self.logger.info(f"Supervisor started with PID: {os.getpid()}")

      try:
          # --- The logic now uses the derived ssh_agent_enabled flag ---
          if self.ssh_agent_enabled:
              self.logger.info("Acquiring session key...")
              self._get_session_master_key()

              if self.smk_fd is not None:
                  os.environ["AUTO_SECRETS_SMK_FD"] = str(self.smk_fd)
                  self._launch_child("KeyMaster", KeyMaster)
              else:
                  self.logger.error("Failed to get a valid SMK_FD, KeyMaster will not be launched.")

          # --- The Daemon is always launched ---
          self.logger.info("Launching the background daemon...")
          self._launch_child("Daemon", SecretsDaemon)

          # Monitoring loop remains robust
          while self.running:
              for name, pid in list(self.child_pids.items()):
                  pid_dead, status = os.waitpid(pid, os.WNOHANG)
                  if pid_dead == pid:
                      self.logger.warning(
                          f"{name} (PID: {pid}) terminated with status {status}. Restarting..."
                      )
                      target = KeyMaster if name == "KeyMaster" else SecretsDaemon
                      self._launch_child(name, target)

              time.sleep(5)
      finally:
          self._cleanup()

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

def main() -> None:
    """Instantiate and run the Supervisor. This is the script entry point."""
    print("Starting Auto Secrets Supervisor daemon...")
    try:
        supervisor = Supervisor()
        supervisor.run()
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
    main()
