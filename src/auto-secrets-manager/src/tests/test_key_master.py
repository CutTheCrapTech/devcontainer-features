"""
Unit tests for KeyMaster class.
"""

import os
import signal
import socket
import tempfile
import threading
import time
from collections.abc import Generator
from pathlib import Path
from unittest.mock import MagicMock, Mock, mock_open, patch

import pytest
from pytest import MonkeyPatch

from auto_secrets import key_master
from auto_secrets.key_master import KeyMaster


class TestKeyMaster:
  """Comprehensive test suite for KeyMaster class."""

  @pytest.fixture
  def mock_dependencies(self) -> Generator[dict[str, Mock], None, None]:
    """Mock all external dependencies."""
    with patch.multiple(
      "auto_secrets.key_master",
      ProcessUtils=MagicMock(),
      AutoSecretsLogger=MagicMock(),
      AppManager=MagicMock(),
      LEGITIMATE_CLI_PATHS=["/usr/bin/auto-secrets", "/opt/auto-secrets/bin/cli"],
    ) as mocks:
      # Setup logger mock
      logger_mock = MagicMock()
      mocks["AutoSecretsLogger"].return_value.get_logger.return_value = logger_mock

      # Setup AppManager mock
      app_mock = MagicMock()
      crypto_utils_mock = MagicMock()
      cache_manager_mock = MagicMock()

      app_mock.crypto_utils = crypto_utils_mock
      app_mock.cache_manager = cache_manager_mock
      app_mock.get_logger.return_value = logger_mock

      crypto_utils_mock.derive_session_encryption_key.return_value = b"session_key_123"

      # Setup cache manager with temporary directory
      with tempfile.TemporaryDirectory() as temp_dir:
        cache_manager_mock.base_dir = Path(temp_dir)
        mocks["AppManager"].return_value = app_mock

        yield mocks

  @pytest.fixture
  def mock_smk_fd(self, monkeypatch: MonkeyPatch) -> Generator[None, None, None]:
    """Mock SMK file descriptor environment variable and file operations."""
    monkeypatch.setenv("AUTO_SECRETS_SMK_FD", "3")

    mock_file = mock_open(read_data=b"test_session_master_key")

    with patch("os.fdopen", mock_file), patch("builtins.open", mock_file):
      yield

  def test_init_success(self, mock_dependencies: dict[str, Mock], mock_smk_fd: None) -> None:
    """Test successful KeyMaster initialization."""
    with patch("socket.socket") as mock_socket, patch("os.chmod"), patch("signal.signal"):
      socket_instance = MagicMock()
      mock_socket.return_value = socket_instance

      key_master_instance = KeyMaster()

      assert key_master_instance.running is True
      assert key_master_instance.smk == b"test_session_master_key"
      assert key_master_instance.session_encryption_key == b"session_key_123"
      mock_dependencies["ProcessUtils"].set_parent_death_signal.assert_called_once()

  def test_init_missing_smk_fd(self, mock_dependencies: dict[str, Mock]) -> None:
    """Test initialization failure when SMK_FD environment variable is missing."""
    with pytest.raises(SystemExit) as exc_info:
      KeyMaster()

    assert exc_info.value.code == 1

  def test_init_invalid_smk_fd(self, mock_dependencies: dict[str, Mock], monkeypatch: MonkeyPatch) -> None:
    """Test initialization failure with invalid SMK file descriptor."""
    monkeypatch.setenv("AUTO_SECRETS_SMK_FD", "invalid")

    with pytest.raises(SystemExit) as exc_info:
      KeyMaster()

    assert exc_info.value.code == 1

  def test_init_empty_smk(self, mock_dependencies: dict[str, Mock], monkeypatch: MonkeyPatch) -> None:
    """Test initialization failure when SMK is empty."""
    monkeypatch.setenv("AUTO_SECRETS_SMK_FD", "3")

    mock_file = mock_open(read_data=b"")

    with patch("os.fdopen", mock_file), pytest.raises(SystemExit) as exc_info:
      KeyMaster()

    assert exc_info.value.code == 1

  @patch("socket.socket")
  @patch("os.chmod")
  @patch("signal.signal")
  def test_acquire_smk_success(
    self,
    mock_signal: Mock,
    mock_chmod: Mock,
    mock_socket: Mock,
    mock_dependencies: dict[str, Mock],
    monkeypatch: MonkeyPatch,
  ) -> None:
    """Test successful SMK acquisition."""
    monkeypatch.setenv("AUTO_SECRETS_SMK_FD", "3")

    expected_smk = b"test_master_key"
    mock_file = mock_open(read_data=expected_smk)

    with patch("os.fdopen", mock_file):
      key_master_instance = KeyMaster()
      assert key_master_instance.smk == expected_smk

  @patch("socket.socket")
  @patch("os.chmod")
  @patch("signal.signal")
  def test_acquire_smk_file_not_found(
    self,
    mock_signal: Mock,
    mock_chmod: Mock,
    mock_socket: Mock,
    mock_dependencies: dict[str, Mock],
    monkeypatch: MonkeyPatch,
  ) -> None:
    """Test SMK acquisition failure when file descriptor is invalid."""
    monkeypatch.setenv("AUTO_SECRETS_SMK_FD", "999")

    with patch("os.fdopen", side_effect=OSError("Bad file descriptor")), pytest.raises(SystemExit):
      KeyMaster()

  def test_setup_socket(self, mock_dependencies: dict[str, Mock], mock_smk_fd: None) -> None:
    """Test socket setup with existing socket file cleanup."""
    with patch("socket.socket") as mock_socket, patch("os.chmod") as mock_chmod, patch("signal.signal"):
      socket_instance = MagicMock()
      mock_socket.return_value = socket_instance

      # Create a temporary file to simulate existing socket
      with tempfile.TemporaryDirectory() as temp_dir:
        state_dir = Path(temp_dir) / "state"
        state_dir.mkdir()
        socket_path = state_dir / "key_master.sock"
        socket_path.touch()  # Create existing socket file

        mock_dependencies["AppManager"].return_value.cache_manager.base_dir = Path(temp_dir)

        KeyMaster()

        socket_instance.bind.assert_called_once()
        socket_instance.listen.assert_called_once_with(5)
        mock_chmod.assert_called_once_with(socket_path, 0o600)

  def test_setup_signal_handlers(self, mock_dependencies: dict[str, Mock], mock_smk_fd: None) -> None:
    """Test signal handler setup."""
    with patch("socket.socket"), patch("os.chmod"), patch("signal.signal") as mock_signal:
      KeyMaster()

      # Verify signal handlers were set up
      signal_calls = mock_signal.call_args_list
      signal_numbers = [call[0][0] for call in signal_calls]

      assert signal.SIGTERM in signal_numbers
      assert signal.SIGINT in signal_numbers

  def test_signal_handler_functionality(self, mock_dependencies: dict[str, Mock], mock_smk_fd: None) -> None:
    """Test that signal handlers properly set running to False."""
    with patch("socket.socket"), patch("os.chmod"), patch("signal.signal") as mock_signal:
      key_master_instance = KeyMaster()

      # Get the signal handler function
      signal_handler = None
      for call in mock_signal.call_args_list:
        if call[0][0] == signal.SIGTERM:
          signal_handler = call[0][1]
          break

      assert signal_handler is not None

      # Test signal handler
      signal_handler(signal.SIGTERM, None)
      assert key_master_instance.running is False

  @patch("os.getuid", return_value=1000)
  @patch("os.path.realpath", return_value="/usr/bin/auto-secrets")
  def test_is_client_authentic_success(
    self, mock_realpath: Mock, mock_getuid: Mock, mock_dependencies: dict[str, Mock], mock_smk_fd: None
  ) -> None:
    """Test successful client authentication."""
    with patch("socket.socket"), patch("os.chmod"), patch("signal.signal"):
      key_master_instance = KeyMaster()

      # Mock socket connection with peer credentials
      mock_conn = MagicMock()
      # PID=1234, UID=1000, GID=1000 (packed as little-endian bytes)
      creds = (1234).to_bytes(4, "little") + (1000).to_bytes(4, "little") + (1000).to_bytes(4, "little")
      mock_conn.getsockopt.return_value = creds

      result = key_master_instance._is_client_authentic(mock_conn)
      assert result is True

  @patch("os.getuid", return_value=1000)
  def test_is_client_authentic_uid_mismatch(
    self, mock_getuid: Mock, mock_dependencies: dict[str, Mock], mock_smk_fd: None
  ) -> None:
    """Test client authentication failure due to UID mismatch."""
    with patch("socket.socket"), patch("os.chmod"), patch("signal.signal"):
      key_master_instance = KeyMaster()

      mock_conn = MagicMock()
      # PID=1234, UID=1001 (different), GID=1000
      creds = (1234).to_bytes(4, "little") + (1001).to_bytes(4, "little") + (1000).to_bytes(4, "little")
      mock_conn.getsockopt.return_value = creds

      result = key_master_instance._is_client_authentic(mock_conn)
      assert result is False

  @patch("os.getuid", return_value=1000)
  @patch("os.path.realpath", return_value="/malicious/path")
  def test_is_client_authentic_path_mismatch(
    self, mock_realpath: Mock, mock_getuid: Mock, mock_dependencies: dict[str, Mock], mock_smk_fd: None
  ) -> None:
    """Test client authentication failure due to executable path mismatch."""
    with patch("socket.socket"), patch("os.chmod"), patch("signal.signal"):
      key_master_instance = KeyMaster()

      mock_conn = MagicMock()
      creds = (1234).to_bytes(4, "little") + (1000).to_bytes(4, "little") + (1000).to_bytes(4, "little")
      mock_conn.getsockopt.return_value = creds

      result = key_master_instance._is_client_authentic(mock_conn)
      assert result is False

  @patch("os.getuid", return_value=1000)
  @patch("os.path.realpath", side_effect=FileNotFoundError())
  def test_is_client_authentic_proc_not_found(
    self, mock_realpath: Mock, mock_getuid: Mock, mock_dependencies: dict[str, Mock], mock_smk_fd: None
  ) -> None:
    """Test client authentication failure when /proc/PID/exe is not found."""
    with patch("socket.socket"), patch("os.chmod"), patch("signal.signal"):
      key_master_instance = KeyMaster()

      mock_conn = MagicMock()
      creds = (1234).to_bytes(4, "little") + (1000).to_bytes(4, "little") + (1000).to_bytes(4, "little")
      mock_conn.getsockopt.return_value = creds

      result = key_master_instance._is_client_authentic(mock_conn)
      assert result is False

  def test_is_client_authentic_socket_error(self, mock_dependencies: dict[str, Mock], mock_smk_fd: None) -> None:
    """Test client authentication failure due to socket credential error."""
    with patch("socket.socket"), patch("os.chmod"), patch("signal.signal"):
      key_master_instance = KeyMaster()

      mock_conn = MagicMock()
      mock_conn.getsockopt.side_effect = OSError("Socket error")

      result = key_master_instance._is_client_authentic(mock_conn)
      assert result is False

  def test_is_client_authentic_empty_legitimate_paths(self, mock_smk_fd: None) -> None:
    """Test client authentication failure when LEGITIMATE_CLI_PATHS is empty."""
    with (
      patch.multiple(
        "auto_secrets.key_master",
        ProcessUtils=MagicMock(),
        AutoSecretsLogger=MagicMock(),
        AppManager=MagicMock(),
        LEGITIMATE_CLI_PATHS=[],  # Empty list
      ),
      patch("socket.socket"),
      patch("os.chmod"),
      patch("signal.signal"),
      patch("os.getuid", return_value=1000),
    ):
      # Setup mocks similar to mock_dependencies fixture
      logger_mock = MagicMock()
      with patch("auto_secrets.key_master.AutoSecretsLogger") as mock_logger_class:
        mock_logger_class.return_value.get_logger.return_value = logger_mock

        with patch("auto_secrets.key_master.AppManager") as mock_app_class:
          app_mock = MagicMock()
          crypto_utils_mock = MagicMock()
          cache_manager_mock = MagicMock()

          app_mock.crypto_utils = crypto_utils_mock
          app_mock.cache_manager = cache_manager_mock
          app_mock.get_logger.return_value = logger_mock

          crypto_utils_mock.derive_session_encryption_key.return_value = b"session_key_123"

          with tempfile.TemporaryDirectory() as temp_dir:
            cache_manager_mock.base_dir = Path(temp_dir)
            mock_app_class.return_value = app_mock

            key_master_instance = KeyMaster()

            mock_conn = MagicMock()
            creds = (1234).to_bytes(4, "little") + (1000).to_bytes(4, "little") + (1000).to_bytes(4, "little")
            mock_conn.getsockopt.return_value = creds

            result = key_master_instance._is_client_authentic(mock_conn)
            assert result is False

  @patch("os.getuid", return_value=1000)
  @patch("os.path.realpath", return_value="/usr/bin/auto-secrets")
  def test_handle_client_success(
    self, mock_realpath: Mock, mock_getuid: Mock, mock_dependencies: dict[str, Mock], mock_smk_fd: None
  ) -> None:
    """Test successful client handling and key vending."""
    with patch("socket.socket"), patch("os.chmod"), patch("signal.signal"):
      key_master_instance = KeyMaster()

      mock_conn = MagicMock()
      creds = (1234).to_bytes(4, "little") + (1000).to_bytes(4, "little") + (1000).to_bytes(4, "little")
      mock_conn.getsockopt.return_value = creds

      key_master_instance._handle_client(mock_conn, "test_addr")

      mock_conn.sendall.assert_called_once_with(b"session_key_123")
      mock_conn.close.assert_called_once()

  def test_handle_client_authentication_failure(self, mock_dependencies: dict[str, Mock], mock_smk_fd: None) -> None:
    """Test client handling when authentication fails."""
    with patch("socket.socket"), patch("os.chmod"), patch("signal.signal"):
      key_master_instance = KeyMaster()

      mock_conn = MagicMock()
      mock_conn.getsockopt.side_effect = OSError("Socket error")

      key_master_instance._handle_client(mock_conn, "test_addr")

      mock_conn.sendall.assert_not_called()
      mock_conn.close.assert_called_once()

  def test_handle_client_no_session_key(self, mock_dependencies: dict[str, Mock], mock_smk_fd: None) -> None:
    """Test client handling when session encryption key is not available."""
    with patch("socket.socket"), patch("os.chmod"), patch("signal.signal"):
      key_master_instance = KeyMaster()
      key_master_instance.session_encryption_key = None

      mock_conn = MagicMock()

      # Make authentication succeed but session key unavailable
      with patch.object(key_master_instance, "_is_client_authentic", return_value=True):
        key_master_instance._handle_client(mock_conn, "test_addr")

      mock_conn.sendall.assert_not_called()
      mock_conn.close.assert_called_once()

  def test_handle_client_exception(self, mock_dependencies: dict[str, Mock], mock_smk_fd: None) -> None:
    """Test client handling when an exception occurs."""
    with patch("socket.socket"), patch("os.chmod"), patch("signal.signal"):
      key_master_instance = KeyMaster()

      mock_conn = MagicMock()
      mock_conn.sendall.side_effect = Exception("Network error")

      with patch.object(key_master_instance, "_is_client_authentic", return_value=True):
        key_master_instance._handle_client(mock_conn, "test_addr")

      mock_conn.close.assert_called_once()

  def test_run_loop(self, mock_dependencies: dict[str, Mock], mock_smk_fd: None) -> None:
    """Test the main run loop with successful connection handling."""
    with patch("socket.socket") as mock_socket_class, patch("os.chmod"), patch("signal.signal"):
      socket_instance = MagicMock()
      mock_socket_class.return_value = socket_instance

      # Setup mock connection
      mock_conn = MagicMock()
      socket_instance.accept.return_value = (mock_conn, "test_addr")

      key_master_instance = KeyMaster()

      # Run for a short time then stop
      def stop_after_delay() -> None:
        time.sleep(0.1)
        key_master_instance.running = False

      with patch.object(key_master_instance, "_handle_client") as mock_handle:
        stop_thread = threading.Thread(target=stop_after_delay)
        stop_thread.start()

        key_master_instance.run()
        stop_thread.join()

        mock_handle.assert_called()

  def test_run_socket_timeout(self, mock_dependencies: dict[str, Mock], mock_smk_fd: None) -> None:
    """Test run loop handling socket timeouts gracefully."""
    with patch("socket.socket") as mock_socket_class, patch("os.chmod"), patch("signal.signal"):
      socket_instance = MagicMock()
      mock_socket_class.return_value = socket_instance
      socket_instance.accept.side_effect = socket.timeout()

      key_master_instance = KeyMaster()

      def stop_after_delay() -> None:
        time.sleep(0.1)
        key_master_instance.running = False

      stop_thread = threading.Thread(target=stop_after_delay)
      stop_thread.start()

      key_master_instance.run()
      stop_thread.join()

      socket_instance.settimeout.assert_called_with(1.0)

  def test_run_no_socket(self, mock_dependencies: dict[str, Mock], mock_smk_fd: None) -> None:
    """Test run method when socket is not initialized."""
    with patch("socket.socket"), patch("os.chmod"), patch("signal.signal"):
      key_master_instance = KeyMaster()
      key_master_instance.socket = None

      key_master_instance.run()

      # Should return early without error

  def test_cleanup(self, mock_dependencies: dict[str, Mock], mock_smk_fd: None) -> None:
    """Test cleanup method closes socket and removes socket file."""
    with patch("socket.socket") as mock_socket_class, patch("os.chmod"), patch("signal.signal"):
      socket_instance = MagicMock()
      mock_socket_class.return_value = socket_instance

      key_master_instance = KeyMaster()

      # Create socket file for cleanup test
      key_master_instance.socket_path.touch()

      key_master_instance._cleanup()

      socket_instance.close.assert_called_once()
      assert not key_master_instance.socket_path.exists()

  def test_cleanup_no_socket(self, mock_dependencies: dict[str, Mock], mock_smk_fd: None) -> None:
    """Test cleanup when socket is None."""
    with patch("socket.socket"), patch("os.chmod"), patch("signal.signal"):
      key_master_instance = KeyMaster()
      key_master_instance.socket = None

      # Should not raise exception
      key_master_instance._cleanup()

  def test_cleanup_socket_file_not_exists(self, mock_dependencies: dict[str, Mock], mock_smk_fd: None) -> None:
    """Test cleanup when socket file doesn't exist."""
    with patch("socket.socket") as mock_socket_class, patch("os.chmod"), patch("signal.signal"):
      socket_instance = MagicMock()
      mock_socket_class.return_value = socket_instance

      key_master_instance = KeyMaster()

      # Ensure socket file doesn't exist
      if key_master_instance.socket_path.exists():
        key_master_instance.socket_path.unlink()

      # Should not raise exception
      key_master_instance._cleanup()

      socket_instance.close.assert_called_once()


class TestKeyMasterMain:
  """Test the main entry point and module-level functions."""

  def test_main_success(self) -> None:
    """Test successful main function execution."""
    with patch("auto_secrets.key_master.KeyMaster") as mock_keymaster_class:
      mock_instance = MagicMock()
      mock_keymaster_class.return_value = mock_instance

      key_master.main()

      mock_keymaster_class.assert_called_once()
      mock_instance.run.assert_called_once()

  def test_main_keyboard_interrupt(self) -> None:
    """Test main function handling KeyboardInterrupt."""
    with patch("auto_secrets.key_master.KeyMaster") as mock_keymaster_class, patch("builtins.print") as mock_print:
      mock_instance = MagicMock()
      mock_instance.run.side_effect = KeyboardInterrupt()
      mock_keymaster_class.return_value = mock_instance

      key_master.main()

      mock_print.assert_called_with("\nKey Master interrupted.")
      assert mock_instance.running is False

  def test_main_exception(self) -> None:
    """Test main function handling general exceptions."""
    with (
      patch("auto_secrets.key_master.KeyMaster") as mock_keymaster_class,
      patch("builtins.print") as mock_print,
      pytest.raises(SystemExit) as exc_info,
    ):
      mock_instance = MagicMock()
      mock_instance.run.side_effect = Exception("Test error")
      mock_keymaster_class.return_value = mock_instance

      key_master.main()

    assert exc_info.value.code == 1
    mock_print.assert_called()

  def test_main_keymaster_init_exception(self) -> None:
    """Test main function when KeyMaster initialization fails."""
    with (
      patch("auto_secrets.key_master.KeyMaster", side_effect=Exception("Init error")),
      patch("builtins.print") as mock_print,
      pytest.raises(SystemExit) as exc_info,
    ):
      key_master.main()

    assert exc_info.value.code == 1
    mock_print.assert_called()


# Integration test helpers
class TestKeyMasterIntegration:
  """Integration tests for KeyMaster with minimal mocking."""

  def test_signal_integration(self, mock_dependencies: dict[str, Mock], mock_smk_fd: None) -> None:
    """Test that signal handling works end-to-end."""
    with patch("socket.socket"), patch("os.chmod"):
      # Don't mock signal.signal to test real integration
      key_master_instance = KeyMaster()

      assert key_master_instance.running is True

      # Send SIGTERM to ourselves
      original_handler = signal.signal(signal.SIGTERM, signal.SIG_DFL)
      try:
        # The signal handler should have been set by KeyMaster
        os.kill(os.getpid(), signal.SIGTERM)
        # In a real scenario, this would set running=False
        # but since we're in a test, we need to verify the handler was set
        current_handler = signal.signal(signal.SIGTERM, signal.SIG_DFL)
        assert current_handler != signal.SIG_DFL
      finally:
        signal.signal(signal.SIGTERM, original_handler)


if __name__ == "__main__":
  pytest.main([__file__])
