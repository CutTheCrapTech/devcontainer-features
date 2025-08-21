"""
Auto Secrets Manager - Key Master

The secure gatekeeper for the Session Master Key (SMK).
- Launched by the Supervisor only when SSH agent integration is enabled.
- Listens on a Unix domain socket for requests from the CLI.
- Rigorously authenticates clients before deriving and vending short-lived keys.
"""

import logging
import os
import socket
import sys
from pathlib import Path
from typing import Any, Optional

# --- Project-specific imports ---
from .key_master_config import LEGITIMATE_CLI_PATHS
from .monitored_process import MonitoredProcess


class KeyMasterError(Exception):
  pass


class KeyMaster(MonitoredProcess):
  """Manages the SMK and serves authenticated clients."""

  def __init__(self) -> None:
    try:
      super().__init__(process_name="key_master", heartbeat_interval=30.0)
      self.socket: Optional[socket.socket] = None
      self.socket_path: Path

      self._setup_socket()

      self.logger.info("Key Master initialized successfully")
    except Exception as e:
      if self.logger:
        self.logger.critical(f"Key Master failed to initialize: {e}")
      else:
        logging.critical(f"Key Master failed to initialize: {e}", exc_info=True)
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
        raise KeyMasterError("Failed to read key from file descriptor (empty).")
      self.logger.info("Successfully acquired Session Master Key.")
      return smk
    except (ValueError, OSError) as e:
      self.logger.error(f"Failed to process SMK file descriptor {smk_fd_str}: {e}")
      sys.exit(1)

  def _setup_socket(self) -> None:
    """Create and bind the Unix domain socket."""
    state_dir = self.app.cache_manager.base_dir / "state"
    self.socket_path = state_dir / "key_master.sock"

    if self.socket_path.exists():
      self.logger.warning(f"Removing stale socket file: {self.socket_path}")
      self.socket_path.unlink()

    self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    self.socket.bind(str(self.socket_path))
    os.chmod(self.socket_path, 0o600)
    self.socket.listen(5)
    self.logger.info(f"Listening on Unix socket: {self.socket_path}")

  def _is_client_authentic(self, conn: socket.socket) -> bool:
    """Perform the multi-factor authentication of a connecting client."""
    try:
      creds = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)  # type: ignore[attr-defined]
      pid, uid, _gid = (
        int.from_bytes(creds[0:4], "little"),
        int.from_bytes(creds[4:8], "little"),
        int.from_bytes(creds[8:12], "little"),
      )
    except (OSError, AttributeError) as e:
      self.logger.error(f"Failed to get client credentials from socket: {e}. Denying.")
      return False

    if uid != os.getuid():
      self.logger.warning(
        f"Authentication failed: UID mismatch. Client UID: {uid}, Server UID: {os.getuid()}. PID: {pid}"
      )
      return False

    try:
      client_exe_path = os.path.realpath(f"/proc/{pid}/exe")
    except FileNotFoundError:
      self.logger.error(f"Authentication failed: Could not read /proc/{pid}/exe. PID might have terminated.")
      return False

    # --- THE FIX: We now check for membership in the list ---
    trusted_paths = LEGITIMATE_CLI_PATHS
    if not trusted_paths:
      self.logger.critical(
        "Authentication failed: LEGITIMATE_CLI_PATHS is not configured. This is a fatal installation error."
      )
      return False

    if client_exe_path not in trusted_paths:
      self.logger.error(
        "CRITICAL: AUTHENTICATION FAILED DUE TO EXECUTABLE PATH MISMATCH.\n"
        f"  - Client PID: {pid}\n"
        f"  - Client Executable (from kernel): '{client_exe_path}'\n"
        f"  - List of Trusted Executables: {trusted_paths}"
      )
      return False

    self.logger.info(f"Client authenticated successfully (PID: {pid}, Path: '{client_exe_path}')")
    return True

  def _handle_client(self, conn: socket.socket, addr: Any) -> None:
    """
    Handles a new client connection.

    The protocol is simple:
      1. Authenticate the client using its process credentials.
      2. If authentic, immediately send the Session Encryption Key (SEK).
      3. Close the connection.
    """
    try:
      # 1. AUTHENTICATE. This is the only gate.
      if not self._is_client_authentic(conn):
        return

      # This should never happen if initialization succeeded.
      if not self.session_encryption_key:
        self.logger.error("Vending failed: Session Encryption Key is not available.")
        return

      # 2. VEND THE KEY. No request needed from the client.
      # The protocol is now: connect, get authenticated, receive key.
      conn.sendall(self.session_encryption_key)
      self.logger.info("Vended Session Encryption Key to authenticated client.")

    except Exception as e:
      self.logger.error(f"Error handling client connection: {e}", exc_info=True)
    finally:
      conn.close()

  def _initialize(self) -> None:
    """Pre Run"""
    if self.socket:
      # Set a timeout on the accept call so we can periodically
      # check the self.running flag for graceful shutdown.
      self.socket.settimeout(1.0)

  def _run(self) -> None:
    """Main daemon loop."""
    if not self.socket:
      self.logger.critical("Socket is not initialized. Cannot run.")
      raise KeyMasterError("Socket is not initialized. Cannot run.")
    try:
      conn, addr = self.socket.accept()
      self.logger.debug(f"Accepted connection from {addr}")
      self._handle_client(conn, addr)
    except socket.timeout:
      return  # Loop back and check self.running
    except Exception as e:
      self.logger.warning(f"Error in accept loop: {e}", exc_info=True)

  def _cleanup(self) -> None:
    """Close the socket and remove its file."""
    self.logger.info("Key Master cleaning up...")
    if self.socket:
      self.socket.close()
    if self.socket_path.exists():
      self.socket_path.unlink()
    self.logger.info("Key Master shutdown complete.")
    super()._cleanup()


def main() -> None:
  """Main entry point for Key Master."""
  # This main entry is primarily for direct testing.
  # In production, it's launched by the Supervisor.
  key_master = KeyMaster()
  try:
    key_master.start(sleep=0.0)
  except KeyboardInterrupt:
    print("\nKey Master interrupted.")
    key_master.running = False
  except Exception as e:
    print(f"FATAL: Key Master error: {e}", file=sys.stderr)
    sys.exit(1)


if __name__ == "__main__":
  main()
