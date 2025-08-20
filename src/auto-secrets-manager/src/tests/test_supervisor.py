"""
Comprehensive unit tests for the Auto Secrets Manager Supervisor module.
Tests cover initialization, process management, signal handling, and cleanup.
"""

import os
import signal
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any, Optional
from unittest.mock import Mock, patch

import pytest

from auto_secrets import supervisor
from auto_secrets.supervisor import Supervisor, SupervisorError, main


class TestSupervisorError:
  """Test cases for SupervisorError exception."""

  def test_supervisor_error_inheritance(self) -> None:
    """Test that SupervisorError inherits from Exception."""
    error = SupervisorError("test error")
    assert isinstance(error, Exception)
    assert str(error) == "test error"

  def test_supervisor_error_without_message(self) -> None:
    """Test SupervisorError without message."""
    error = SupervisorError()
    assert isinstance(error, Exception)


class TestSupervisorInitialization:
  """Test cases for Supervisor initialization."""

  @patch("auto_secrets.supervisor.AppManager")
  @patch("auto_secrets.supervisor.CommonConfig")
  def test_successful_initialization(self, mock_common_config: Mock, mock_app_manager: Mock) -> None:
    """Test successful supervisor initialization."""
    # Setup mocks
    mock_config_instance = Mock()
    mock_config_instance.ssh_agent_key_comment = "test-key"
    mock_common_config.return_value = mock_config_instance

    mock_app = Mock()
    mock_logger = Mock()
    mock_app.get_logger.return_value = mock_logger
    mock_cache_manager = Mock()
    mock_cache_manager.base_dir = Path("/tmp/test")
    mock_app.cache_manager = mock_cache_manager
    mock_app.key_retriever = Mock()

    with patch("auto_secrets.supervisor.app", mock_app):
      supervisor_instance = Supervisor()

      assert supervisor_instance.running is True
      assert supervisor_instance.ssh_agent_key_comment == "test-key"
      assert supervisor_instance.ssh_agent_enabled is True
      assert supervisor_instance.child_pids == {}
      assert supervisor_instance.smk_fd is None
      assert supervisor_instance.logger == mock_logger

  @patch("auto_secrets.supervisor.AppManager")
  @patch("auto_secrets.supervisor.CommonConfig")
  def test_initialization_without_ssh_agent(self, mock_common_config: Mock, mock_app_manager: Mock) -> None:
    """Test initialization when SSH agent is disabled."""
    # Setup mocks
    mock_config_instance = Mock()
    mock_config_instance.ssh_agent_key_comment = ""
    mock_common_config.return_value = mock_config_instance

    mock_app = Mock()
    mock_logger = Mock()
    mock_app.get_logger.return_value = mock_logger
    mock_cache_manager = Mock()
    mock_cache_manager.base_dir = Path("/tmp/test")
    mock_app.cache_manager = mock_cache_manager
    mock_app.key_retriever = Mock()

    with patch("auto_secrets.supervisor.app", mock_app):
      supervisor_instance = Supervisor()

      assert supervisor_instance.ssh_agent_enabled is False
      mock_logger.info.assert_any_call("SSH agent integration DISABLED (ssh_agent_key_comment is not set or empty)")

  @patch("auto_secrets.supervisor.AppManager")
  @patch("auto_secrets.supervisor.CommonConfig")
  @patch("auto_secrets.supervisor.sys.exit")
  def test_initialization_failure(self, mock_exit: Mock, mock_common_config: Mock, mock_app_manager: Mock) -> None:
    """Test supervisor initialization failure."""
    mock_common_config.side_effect = Exception("Config error")

    Supervisor()

    mock_exit.assert_called_once_with(1)

  @patch("auto_secrets.supervisor.AppManager")
  @patch("auto_secrets.supervisor.CommonConfig")
  def test_state_directory_creation(self, mock_common_config: Mock, mock_app_manager: Mock) -> None:
    """Test that state directory is created during initialization."""
    mock_config_instance = Mock()
    mock_config_instance.ssh_agent_key_comment = "test-key"
    mock_common_config.return_value = mock_config_instance

    mock_app = Mock()
    mock_logger = Mock()
    mock_app.get_logger.return_value = mock_logger

    with tempfile.TemporaryDirectory() as temp_dir:
      mock_cache_manager = Mock()
      mock_cache_manager.base_dir = Path(temp_dir)
      mock_app.cache_manager = mock_cache_manager
      mock_app.key_retriever = Mock()

      with patch("auto_secrets.supervisor.app", mock_app):
        supervisor_instance = Supervisor()

        expected_state_dir = Path(temp_dir) / "state"
        assert supervisor_instance.state_dir == expected_state_dir
        assert expected_state_dir.exists()


class TestPidFileManagement:
  """Test cases for PID file management."""

  @patch("auto_secrets.supervisor.AppManager")
  @patch("auto_secrets.supervisor.CommonConfig")
  def test_setup_pid_file_success(self, mock_common_config: Mock, mock_app_manager: Mock) -> None:
    """Test successful PID file creation."""
    mock_config_instance = Mock()
    mock_config_instance.ssh_agent_key_comment = "test-key"
    mock_common_config.return_value = mock_config_instance

    mock_app = Mock()
    mock_logger = Mock()
    mock_app.get_logger.return_value = mock_logger
    mock_app.key_retriever = Mock()

    with tempfile.TemporaryDirectory() as temp_dir:
      mock_cache_manager = Mock()
      mock_cache_manager.base_dir = Path(temp_dir)
      mock_app.cache_manager = mock_cache_manager

      with patch("auto_secrets.supervisor.app", mock_app), patch("os.getpid", return_value=12345):
        supervisor_instance = Supervisor()
        supervisor_instance._setup_pid_file()

        pid_file = supervisor_instance.pid_file
        assert pid_file is not None
        assert pid_file.exists()
        assert pid_file.read_text().strip() == "12345"

  @patch("auto_secrets.supervisor.AppManager")
  @patch("auto_secrets.supervisor.CommonConfig")
  @patch("auto_secrets.supervisor.sys.exit")
  def test_setup_pid_file_already_running(
    self, mock_exit: Mock, mock_common_config: Mock, mock_app_manager: Mock
  ) -> None:
    """Test PID file creation when supervisor is already running."""
    mock_config_instance = Mock()
    mock_config_instance.ssh_agent_key_comment = "test-key"
    mock_common_config.return_value = mock_config_instance

    mock_app = Mock()
    mock_logger = Mock()
    mock_app.get_logger.return_value = mock_logger
    mock_app.key_retriever = Mock()

    with tempfile.TemporaryDirectory() as temp_dir:
      mock_cache_manager = Mock()
      mock_cache_manager.base_dir = Path(temp_dir)
      mock_app.cache_manager = mock_cache_manager

      # Create existing PID file
      pid_file = Path(temp_dir) / "state" / "supervisor.pid"
      pid_file.parent.mkdir(parents=True, exist_ok=True)
      pid_file.write_text("999")

      with patch("auto_secrets.supervisor.app", mock_app), patch("os.kill", return_value=None):  # Process exists
        supervisor_instance = Supervisor()
        supervisor_instance._setup_pid_file()

        mock_exit.assert_called_once_with(1)
        mock_logger.error.assert_called_once_with("Supervisor already running with PID 999.")

  @patch("auto_secrets.supervisor.AppManager")
  @patch("auto_secrets.supervisor.CommonConfig")
  def test_setup_pid_file_stale_removal(self, mock_common_config: Mock, mock_app_manager: Mock) -> None:
    """Test removal of stale PID file."""
    mock_config_instance = Mock()
    mock_config_instance.ssh_agent_key_comment = "test-key"
    mock_common_config.return_value = mock_config_instance

    mock_app = Mock()
    mock_logger = Mock()
    mock_app.get_logger.return_value = mock_logger
    mock_app.key_retriever = Mock()

    with tempfile.TemporaryDirectory() as temp_dir:
      mock_cache_manager = Mock()
      mock_cache_manager.base_dir = Path(temp_dir)
      mock_app.cache_manager = mock_cache_manager

      # Create stale PID file
      pid_file = Path(temp_dir) / "state" / "supervisor.pid"
      pid_file.parent.mkdir(parents=True, exist_ok=True)
      pid_file.write_text("999")

      with (
        patch("auto_secrets.supervisor.app", mock_app),
        patch("os.kill", side_effect=OSError("No such process")),
        patch("os.getpid", return_value=12345),
      ):
        supervisor_instance = Supervisor()
        supervisor_instance._setup_pid_file()

        mock_logger.warning.assert_called_once_with("Removing stale supervisor PID file.")
        assert pid_file.read_text().strip() == "12345"


class TestSignalHandling:
  """Test cases for signal handling."""

  @patch("auto_secrets.supervisor.AppManager")
  @patch("auto_secrets.supervisor.CommonConfig")
  @patch("signal.signal")
  def test_setup_signal_handlers(self, mock_signal: Mock, mock_common_config: Mock, mock_app_manager: Mock) -> None:
    """Test signal handler setup."""
    mock_config_instance = Mock()
    mock_config_instance.ssh_agent_key_comment = "test-key"
    mock_common_config.return_value = mock_config_instance

    mock_app = Mock()
    mock_logger = Mock()
    mock_app.get_logger.return_value = mock_logger
    mock_cache_manager = Mock()
    mock_cache_manager.base_dir = Path("/tmp/test")
    mock_app.cache_manager = mock_cache_manager
    mock_app.key_retriever = Mock()

    with patch("auto_secrets.supervisor.app", mock_app):
      supervisor_instance = Supervisor()
      supervisor_instance._setup_signal_handlers()

      # Verify signal handlers were set up
      assert mock_signal.call_count == 2
      mock_signal.assert_any_call(signal.SIGTERM, unittest.mock.ANY)
      mock_signal.assert_any_call(signal.SIGINT, unittest.mock.ANY)

  @patch("auto_secrets.supervisor.AppManager")
  @patch("auto_secrets.supervisor.CommonConfig")
  def test_signal_handler_function(self, mock_common_config: Mock, mock_app_manager: Mock) -> None:
    """Test signal handler function behavior."""
    mock_config_instance = Mock()
    mock_config_instance.ssh_agent_key_comment = "test-key"
    mock_common_config.return_value = mock_config_instance

    mock_app = Mock()
    mock_logger = Mock()
    mock_app.get_logger.return_value = mock_logger
    mock_cache_manager = Mock()
    mock_cache_manager.base_dir = Path("/tmp/test")
    mock_app.cache_manager = mock_cache_manager
    mock_app.key_retriever = Mock()

    with patch("auto_secrets.supervisor.app", mock_app):
      supervisor_instance = Supervisor()

      # Simulate signal handler call
      with patch("signal.signal") as mock_signal:
        supervisor_instance._setup_signal_handlers()
        signal_handler = mock_signal.call_args_list[0][0][1]

        # Call the signal handler
        signal_handler(signal.SIGTERM, None)

        assert supervisor_instance.running is False
        mock_logger.info.assert_called_with(f"Received signal {signal.SIGTERM}, initiating shutdown...")


class TestSessionMasterKey:
  """Test cases for Session Master Key management."""

  @patch("auto_secrets.supervisor.AppManager")
  @patch("auto_secrets.supervisor.CommonConfig")
  def test_get_session_master_key_success(self, mock_common_config: Mock, mock_app_manager: Mock) -> None:
    """Test successful SMK acquisition."""
    mock_config_instance = Mock()
    mock_config_instance.ssh_agent_key_comment = "test-key"
    mock_common_config.return_value = mock_config_instance

    mock_app = Mock()
    mock_logger = Mock()
    mock_app.get_logger.return_value = mock_logger
    mock_cache_manager = Mock()
    mock_cache_manager.base_dir = Path("/tmp/test")
    mock_app.cache_manager = mock_cache_manager

    mock_key_retriever = Mock()
    mock_key_retriever.derive_smk_from_ssh_agent.return_value = 42
    mock_app.key_retriever = mock_key_retriever

    with patch("auto_secrets.supervisor.app", mock_app):
      supervisor_instance = Supervisor()
      supervisor_instance._get_session_master_key()

      assert supervisor_instance.smk_fd == 42
      mock_logger.info.assert_any_call("Acquiring Session Master Key via KeyRetriever...")
      mock_logger.info.assert_any_call("SMK acquired in memfd descriptor: 42")

  @patch("auto_secrets.supervisor.AppManager")
  @patch("auto_secrets.supervisor.CommonConfig")
  @patch("auto_secrets.supervisor.sys.exit")
  def test_get_session_master_key_failure(
    self, mock_exit: Mock, mock_common_config: Mock, mock_app_manager: Mock
  ) -> None:
    """Test SMK acquisition failure."""
    mock_config_instance = Mock()
    mock_config_instance.ssh_agent_key_comment = "test-key"
    mock_common_config.return_value = mock_config_instance

    mock_app = Mock()
    mock_logger = Mock()
    mock_app.get_logger.return_value = mock_logger
    mock_cache_manager = Mock()
    mock_cache_manager.base_dir = Path("/tmp/test")
    mock_app.cache_manager = mock_cache_manager

    mock_key_retriever = Mock()
    mock_key_retriever.derive_smk_from_ssh_agent.return_value = None
    mock_app.key_retriever = mock_key_retriever

    with patch("auto_secrets.supervisor.app", mock_app):
      supervisor_instance = Supervisor()
      supervisor_instance._get_session_master_key()

      mock_exit.assert_called_once_with(1)
      mock_logger.critical.assert_called_once()

  @patch("auto_secrets.supervisor.AppManager")
  @patch("auto_secrets.supervisor.CommonConfig")
  @patch("auto_secrets.supervisor.sys.exit")
  def test_get_session_master_key_exception(
    self, mock_exit: Mock, mock_common_config: Mock, mock_app_manager: Mock
  ) -> None:
    """Test SMK acquisition with exception."""
    mock_config_instance = Mock()
    mock_config_instance.ssh_agent_key_comment = "test-key"
    mock_common_config.return_value = mock_config_instance

    mock_app = Mock()
    mock_logger = Mock()
    mock_app.get_logger.return_value = mock_logger
    mock_cache_manager = Mock()
    mock_cache_manager.base_dir = Path("/tmp/test")
    mock_app.cache_manager = mock_cache_manager

    mock_key_retriever = Mock()
    mock_key_retriever.derive_smk_from_ssh_agent.side_effect = Exception("SSH error")
    mock_app.key_retriever = mock_key_retriever

    with patch("auto_secrets.supervisor.app", mock_app):
      supervisor_instance = Supervisor()
      supervisor_instance._get_session_master_key()

      mock_exit.assert_called_once_with(1)
      mock_logger.critical.assert_called_once()


class TestChildProcessManagement:
  """Test cases for child process management."""

  @patch("auto_secrets.supervisor.AppManager")
  @patch("auto_secrets.supervisor.CommonConfig")
  @patch("os.fork")
  def test_launch_child_parent_process(self, mock_fork: Mock, mock_common_config: Mock, mock_app_manager: Mock) -> None:
    """Test child launch from parent process perspective."""
    mock_fork.return_value = 123  # Parent gets child PID

    mock_config_instance = Mock()
    mock_config_instance.ssh_agent_key_comment = "test-key"
    mock_common_config.return_value = mock_config_instance

    mock_app = Mock()
    mock_logger = Mock()
    mock_app.get_logger.return_value = mock_logger
    mock_cache_manager = Mock()
    mock_cache_manager.base_dir = Path("/tmp/test")
    mock_app.cache_manager = mock_cache_manager
    mock_app.key_retriever = Mock()

    with patch("auto_secrets.supervisor.app", mock_app):
      supervisor_instance = Supervisor()
      mock_target_class = Mock()

      supervisor_instance._launch_child("TestChild", mock_target_class)

      assert supervisor_instance.child_pids["TestChild"] == 123
      mock_logger.info.assert_any_call("Forking to launch child process: TestChild")
      mock_logger.info.assert_any_call("Launched TestChild with PID: 123")

  @patch("auto_secrets.supervisor.AppManager")
  @patch("auto_secrets.supervisor.CommonConfig")
  @patch("os.fork")
  @patch("sys.exit")
  def test_launch_child_child_process_success(
    self, mock_exit: Mock, mock_fork: Mock, mock_common_config: Mock, mock_app_manager: Mock
  ) -> None:
    """Test child process execution path."""
    mock_fork.return_value = 0  # Child process

    mock_config_instance = Mock()
    mock_config_instance.ssh_agent_key_comment = "test-key"
    mock_common_config.return_value = mock_config_instance

    mock_app = Mock()
    mock_logger = Mock()
    mock_app.get_logger.return_value = mock_logger
    mock_cache_manager = Mock()
    mock_cache_manager.base_dir = Path("/tmp/test")
    mock_app.cache_manager = mock_cache_manager
    mock_app.key_retriever = Mock()

    with patch("auto_secrets.supervisor.app", mock_app):
      supervisor_instance = Supervisor()

      mock_instance = Mock()
      mock_target_class = Mock(return_value=mock_instance)

      supervisor_instance._launch_child("TestChild", mock_target_class)

      mock_target_class.assert_called_once()
      mock_instance.run.assert_called_once()
      mock_exit.assert_called_once_with(0)

  @patch("auto_secrets.supervisor.AppManager")
  @patch("auto_secrets.supervisor.CommonConfig")
  @patch("os.fork")
  @patch("sys.exit")
  @patch("builtins.print")
  def test_launch_child_child_process_failure(
    self, mock_print: Mock, mock_exit: Mock, mock_fork: Mock, mock_common_config: Mock, mock_app_manager: Mock
  ) -> None:
    """Test child process failure handling."""
    mock_fork.return_value = 0  # Child process

    mock_config_instance = Mock()
    mock_config_instance.ssh_agent_key_comment = "test-key"
    mock_common_config.return_value = mock_config_instance

    mock_app = Mock()
    mock_logger = Mock()
    mock_app.get_logger.return_value = mock_logger
    mock_cache_manager = Mock()
    mock_cache_manager.base_dir = Path("/tmp/test")
    mock_app.cache_manager = mock_cache_manager
    mock_app.key_retriever = Mock()

    with patch("auto_secrets.supervisor.app", mock_app):
      supervisor_instance = Supervisor()

      mock_target_class = Mock(side_effect=Exception("Child error"))

      supervisor_instance._launch_child("TestChild", mock_target_class)

      mock_print.assert_called_once_with("FATAL ERROR in child process 'TestChild': Child error", file=sys.stderr)
      mock_exit.assert_called_once_with(1)


class TestMainRunLoop:
  """Test cases for the main run loop."""

  @patch("auto_secrets.supervisor.AppManager")
  @patch("auto_secrets.supervisor.CommonConfig")
  @patch("time.sleep")
  @patch("os.waitpid")
  def test_run_ssh_enabled_flow(
    self, mock_waitpid: Mock, mock_sleep: Mock, mock_common_config: Mock, mock_app_manager: Mock
  ) -> None:
    """Test main run loop with SSH agent enabled."""
    mock_config_instance = Mock()
    mock_config_instance.ssh_agent_key_comment = "test-key"
    mock_common_config.return_value = mock_config_instance

    mock_app = Mock()
    mock_logger = Mock()
    mock_app.get_logger.return_value = mock_logger
    mock_cache_manager = Mock()
    mock_cache_manager.base_dir = Path("/tmp/test")
    mock_app.cache_manager = mock_cache_manager

    mock_key_retriever = Mock()
    mock_key_retriever.derive_smk_from_ssh_agent.return_value = 42
    mock_app.key_retriever = mock_key_retriever

    # Mock waitpid to return no dead children initially
    mock_waitpid.return_value = (0, 0)

    with (
      patch("auto_secrets.supervisor.app", mock_app),
      patch.object(Supervisor, "_setup_pid_file"),
      patch.object(Supervisor, "_setup_signal_handlers"),
      patch.object(Supervisor, "_launch_child") as mock_launch,
      patch.object(Supervisor, "_cleanup"),
      patch("os.getpid", return_value=123),
      patch("os.environ", {}),
    ):
      supervisor_instance = Supervisor()

      # Set up to exit after one iteration
      def stop_after_one(*args: Any) -> None:
        supervisor_instance.running = False

      mock_sleep.side_effect = stop_after_one

      supervisor_instance.run()

      # Verify SMK environment variable was set
      assert os.environ.get("AUTO_SECRETS_SMK_FD") == "42"

      # Verify both children were launched
      assert mock_launch.call_count == 2
      mock_launch.assert_any_call("KeyMaster", supervisor.KeyMaster)
      mock_launch.assert_any_call("Daemon", supervisor.SecretsDaemon)

  @patch("auto_secrets.supervisor.AppManager")
  @patch("auto_secrets.supervisor.CommonConfig")
  @patch("time.sleep")
  @patch("os.waitpid")
  def test_run_ssh_disabled_flow(
    self, mock_waitpid: Mock, mock_sleep: Mock, mock_common_config: Mock, mock_app_manager: Mock
  ) -> None:
    """Test main run loop with SSH agent disabled."""
    mock_config_instance = Mock()
    mock_config_instance.ssh_agent_key_comment = ""
    mock_common_config.return_value = mock_config_instance

    mock_app = Mock()
    mock_logger = Mock()
    mock_app.get_logger.return_value = mock_logger
    mock_cache_manager = Mock()
    mock_cache_manager.base_dir = Path("/tmp/test")
    mock_app.cache_manager = mock_cache_manager
    mock_app.key_retriever = Mock()

    # Mock waitpid to return no dead children initially
    mock_waitpid.return_value = (0, 0)

    with (
      patch("auto_secrets.supervisor.app", mock_app),
      patch.object(Supervisor, "_setup_pid_file"),
      patch.object(Supervisor, "_setup_signal_handlers"),
      patch.object(Supervisor, "_launch_child") as mock_launch,
      patch.object(Supervisor, "_cleanup"),
      patch("os.getpid", return_value=123),
    ):
      supervisor_instance = Supervisor()

      # Set up to exit after one iteration
      def stop_after_one(*args: Any) -> None:
        supervisor_instance.running = False

      mock_sleep.side_effect = stop_after_one

      supervisor_instance.run()

      # Verify only Daemon was launched (no KeyMaster)
      mock_launch.assert_called_once_with("Daemon", supervisor.SecretsDaemon)

  @patch("auto_secrets.supervisor.AppManager")
  @patch("auto_secrets.supervisor.CommonConfig")
  @patch("time.sleep")
  @patch("os.waitpid")
  def test_run_child_restart(
    self, mock_waitpid: Mock, mock_sleep: Mock, mock_common_config: Mock, mock_app_manager: Mock
  ) -> None:
    """Test child process restart when it dies."""
    mock_config_instance = Mock()
    mock_config_instance.ssh_agent_key_comment = ""
    mock_common_config.return_value = mock_config_instance

    mock_app = Mock()
    mock_logger = Mock()
    mock_app.get_logger.return_value = mock_logger
    mock_cache_manager = Mock()
    mock_cache_manager.base_dir = Path("/tmp/test")
    mock_app.cache_manager = mock_cache_manager
    mock_app.key_retriever = Mock()

    call_count = 0

    def waitpid_side_effect(*args: Any) -> tuple[int, int]:
      nonlocal call_count
      call_count += 1
      if call_count == 1:
        # First call: child died
        return (999, 1)
      else:
        # Subsequent calls: no dead children
        return (0, 0)

    mock_waitpid.side_effect = waitpid_side_effect

    with (
      patch("auto_secrets.supervisor.app", mock_app),
      patch.object(Supervisor, "_setup_pid_file"),
      patch.object(Supervisor, "_setup_signal_handlers"),
      patch.object(Supervisor, "_launch_child") as mock_launch,
      patch.object(Supervisor, "_cleanup"),
      patch("os.getpid", return_value=123),
    ):
      supervisor_instance = Supervisor()
      supervisor_instance.child_pids["Daemon"] = 999

      # Set up to exit after one iteration
      iteration_count = 0

      def stop_after_two(*args: Any) -> None:
        nonlocal iteration_count
        iteration_count += 1
        if iteration_count >= 2:
          supervisor_instance.running = False

      mock_sleep.side_effect = stop_after_two

      supervisor_instance.run()

      # Verify child was restarted
      assert mock_launch.call_count == 2  # Initial + restart
      mock_logger.warning.assert_called_once()


class TestCleanup:
  """Test cases for cleanup functionality."""

  @patch("auto_secrets.supervisor.AppManager")
  @patch("auto_secrets.supervisor.CommonConfig")
  @patch("time.sleep")
  @patch("os.kill")
  @patch("os.close")
  def test_cleanup_success(
    self, mock_close: Mock, mock_kill: Mock, mock_sleep: Mock, mock_common_config: Mock, mock_app_manager: Mock
  ) -> None:
    """Test successful cleanup process."""
    mock_config_instance = Mock()
    mock_config_instance.ssh_agent_key_comment = "test-key"
    mock_common_config.return_value = mock_config_instance

    mock_app = Mock()
    mock_logger = Mock()
    mock_app.get_logger.return_value = mock_logger
    mock_cache_manager = Mock()
    mock_cache_manager.base_dir = Path("/tmp/test")
    mock_app.cache_manager = mock_cache_manager
    mock_app.key_retriever = Mock()

    with patch("auto_secrets.supervisor.app", mock_app), tempfile.TemporaryDirectory() as temp_dir:
      supervisor_instance = Supervisor()
      supervisor_instance.child_pids = {"TestChild": 123, "TestChild2": 456}
      supervisor_instance.smk_fd = 42

      # Create a fake PID file
      pid_file = Path(temp_dir) / "test.pid"
      pid_file.write_text("123")
      supervisor_instance.pid_file = pid_file

      supervisor_instance._cleanup()

      # Verify children were terminated
      mock_kill.assert_any_call(123, signal.SIGTERM)
      mock_kill.assert_any_call(456, signal.SIGTERM)

      # Verify SMK fd was closed
      mock_close.assert_called_once_with(42)

      # Verify PID file was removed
      assert not pid_file.exists()

      # Verify logger messages
      mock_logger.info.assert_any_call("Supervisor cleaning up...")
      mock_logger.info.assert_any_call("Sent SIGTERM to TestChild (PID: 123).")
      mock_logger.info.assert_any_call("Sent SIGTERM to TestChild2 (PID: 456).")
      mock_logger.info.assert_any_call("SMK file descriptor closed.")
      mock_logger.info.assert_any_call("Supervisor PID file removed.")
      mock_logger.info.assert_any_call("Supervisor shutdown complete.")

  @patch("auto_secrets.supervisor.AppManager")
  @patch("auto_secrets.supervisor.CommonConfig")
  @patch("time.sleep")
  @patch("os.kill")
  @patch("os.close")
  def test_cleanup_process_already_dead(
    self, mock_close: Mock, mock_kill: Mock, mock_sleep: Mock, mock_common_config: Mock, mock_app_manager: Mock
  ) -> None:
    """Test cleanup when child process is already dead."""
    mock_config_instance = Mock()
    mock_config_instance.ssh_agent_key_comment = "test-key"
    mock_common_config.return_value = mock_config_instance

    mock_app = Mock()
    mock_logger = Mock()
    mock_app.get_logger.return_value = mock_logger
    mock_cache_manager = Mock()
    mock_cache_manager.base_dir = Path("/tmp/test")
    mock_app.cache_manager = mock_cache_manager
    mock_app.key_retriever = Mock()

    # Mock ProcessLookupError when trying to kill already dead process
    mock_kill.side_effect = ProcessLookupError("No such process")

    with patch("auto_secrets.supervisor.app", mock_app):
      supervisor_instance = Supervisor()
      supervisor_instance.child_pids = {"TestChild": 123}
      supervisor_instance.smk_fd = 42

      supervisor_instance._cleanup()

      mock_logger.info.assert_any_call("TestChild (PID: 123) already terminated.")

  @patch("auto_secrets.supervisor.AppManager")
  @patch("auto_secrets.supervisor.CommonConfig")
  @patch("time.sleep")
  @patch("os.kill")
  @patch("os.close")
  def test_cleanup_kill_error(
    self, mock_close: Mock, mock_kill: Mock, mock_sleep: Mock, mock_common_config: Mock, mock_app_manager: Mock
  ) -> None:
    """Test cleanup when kill operation fails."""
    mock_config_instance = Mock()
    mock_config_instance.ssh_agent_key_comment = "test-key"
    mock_common_config.return_value = mock_config_instance

    mock_app = Mock()
    mock_logger = Mock()
    mock_app.get_logger.return_value = mock_logger
    mock_cache_manager = Mock()
    mock_cache_manager.base_dir = Path("/tmp/test")
    mock_app.cache_manager = mock_cache_manager
    mock_app.key_retriever = Mock()

    # Mock generic exception when trying to kill process
    mock_kill.side_effect = Exception("Permission denied")

    with patch("auto_secrets.supervisor.app", mock_app):
      supervisor_instance = Supervisor()
      supervisor_instance.child_pids = {"TestChild": 123}
      supervisor_instance.smk_fd = 42

      supervisor_instance._cleanup()

      mock_logger.error.assert_called_once_with("Error terminating TestChild: Permission denied")

  @patch("auto_secrets.supervisor.AppManager")
  @patch("auto_secrets.supervisor.CommonConfig")
  @patch("time.sleep")
  @patch("os.kill")
  @patch("os.close")
  def test_cleanup_no_smk_fd(
    self, mock_close: Mock, mock_kill: Mock, mock_sleep: Mock, mock_common_config: Mock, mock_app_manager: Mock
  ) -> None:
    """Test cleanup when SMK fd is None."""
    mock_config_instance = Mock()
    mock_config_instance.ssh_agent_key_comment = "test-key"
    mock_common_config.return_value = mock_config_instance

    mock_app = Mock()
    mock_logger = Mock()
    mock_app.get_logger.return_value = mock_logger
    mock_cache_manager = Mock()
    mock_cache_manager.base_dir = Path("/tmp/test")
    mock_app.cache_manager = mock_cache_manager
    mock_app.key_retriever = Mock()

    with patch("auto_secrets.supervisor.app", mock_app):
      supervisor_instance = Supervisor()
      supervisor_instance.child_pids = {}
      supervisor_instance.smk_fd = None
      supervisor_instance.pid_file = None

      supervisor_instance._cleanup()

      # Verify close was not called
      mock_close.assert_not_called()

      # Should still log cleanup messages
      mock_logger.info.assert_any_call("Supervisor cleaning up...")
      mock_logger.info.assert_any_call("Supervisor shutdown complete.")

  @patch("auto_secrets.supervisor.AppManager")
  @patch("auto_secrets.supervisor.CommonConfig")
  @patch("time.sleep")
  @patch("os.kill")
  @patch("os.close")
  def test_cleanup_no_pid_file(
    self, mock_close: Mock, mock_kill: Mock, mock_sleep: Mock, mock_common_config: Mock, mock_app_manager: Mock
  ) -> None:
    """Test cleanup when PID file doesn't exist."""
    mock_config_instance = Mock()
    mock_config_instance.ssh_agent_key_comment = "test-key"
    mock_common_config.return_value = mock_config_instance

    mock_app = Mock()
    mock_logger = Mock()
    mock_app.get_logger.return_value = mock_logger
    mock_cache_manager = Mock()
    mock_cache_manager.base_dir = Path("/tmp/test")
    mock_app.cache_manager = mock_cache_manager
    mock_app.key_retriever = Mock()

    with patch("auto_secrets.supervisor.app", mock_app), tempfile.TemporaryDirectory() as temp_dir:
      supervisor_instance = Supervisor()
      supervisor_instance.child_pids = {}
      supervisor_instance.smk_fd = None

      # Set PID file that doesn't exist
      pid_file = Path(temp_dir) / "nonexistent.pid"
      supervisor_instance.pid_file = pid_file

      supervisor_instance._cleanup()

      # Should not try to remove non-existent file
      mock_logger.info.assert_any_call("Supervisor cleaning up...")
      mock_logger.info.assert_any_call("Supervisor shutdown complete.")
      # Should not have message about PID file removal


class TestMainFunction:
  """Test cases for the main() function."""

  @patch("auto_secrets.supervisor.AppManager")
  @patch("builtins.print")
  def test_main_success(self, mock_print: Mock, mock_app_manager: Mock) -> None:
    """Test successful main function execution."""
    mock_app = Mock()
    mock_app_manager.return_value = mock_app

    mock_supervisor = Mock()

    with (
      patch("auto_secrets.supervisor.Supervisor", return_value=mock_supervisor),
      patch("auto_secrets.supervisor.app", mock_app),
    ):
      main()

      mock_print.assert_called_once_with("Starting Auto Secrets Supervisor daemon...")
      mock_supervisor.run.assert_called_once()

  @patch("auto_secrets.supervisor.AppManager")
  @patch("builtins.print")
  @patch("auto_secrets.supervisor.sys.exit")
  def test_main_keyboard_interrupt(self, mock_exit: Mock, mock_print: Mock, mock_app_manager: Mock) -> None:
    """Test main function with KeyboardInterrupt."""
    mock_app = Mock()
    mock_app_manager.return_value = mock_app

    mock_supervisor = Mock()
    mock_supervisor.run.side_effect = KeyboardInterrupt()

    with (
      patch("auto_secrets.supervisor.Supervisor", return_value=mock_supervisor),
      patch("auto_secrets.supervisor.app", mock_app),
    ):
      main()

      mock_print.assert_any_call("Starting Auto Secrets Supervisor daemon...")
      mock_print.assert_any_call("\nSupervisor startup interrupted by user. Exiting.")
      mock_exit.assert_called_once_with(0)

  @patch("auto_secrets.supervisor.AppManager")
  @patch("builtins.print")
  @patch("auto_secrets.supervisor.sys.exit")
  def test_main_exception(self, mock_exit: Mock, mock_print: Mock, mock_app_manager: Mock) -> None:
    """Test main function with general exception."""
    mock_app = Mock()
    mock_app_manager.return_value = mock_app

    mock_supervisor = Mock()
    mock_supervisor.run.side_effect = Exception("Critical error")

    with (
      patch("auto_secrets.supervisor.Supervisor", return_value=mock_supervisor),
      patch("auto_secrets.supervisor.app", mock_app),
    ):
      main()

      mock_print.assert_any_call("Starting Auto Secrets Supervisor daemon...")
      mock_print.assert_any_call("FATAL SUPERVISOR ERROR: Critical error", file=sys.stderr)
      mock_exit.assert_called_once_with(1)

  @patch("auto_secrets.supervisor.AppManager")
  @patch("builtins.print")
  @patch("auto_secrets.supervisor.sys.exit")
  def test_main_supervisor_init_failure(self, mock_exit: Mock, mock_print: Mock, mock_app_manager: Mock) -> None:
    """Test main function when Supervisor initialization fails."""
    mock_app = Mock()
    mock_app_manager.return_value = mock_app

    with (
      patch("auto_secrets.supervisor.Supervisor", side_effect=Exception("Init error")),
      patch("auto_secrets.supervisor.app", mock_app),
    ):
      main()

      mock_print.assert_any_call("Starting Auto Secrets Supervisor daemon...")
      mock_print.assert_any_call("FATAL SUPERVISOR ERROR: Init error", file=sys.stderr)
      mock_exit.assert_called_once_with(1)


class TestIntegrationScenarios:
  """Integration test scenarios combining multiple components."""

  @patch("auto_secrets.supervisor.AppManager")
  @patch("auto_secrets.supervisor.CommonConfig")
  @patch("time.sleep")
  @patch("os.waitpid")
  @patch("os.fork")
  @patch("os.kill")
  @patch("os.close")
  @patch("signal.signal")
  def test_full_lifecycle_ssh_enabled(
    self,
    mock_signal: Mock,
    mock_close: Mock,
    mock_kill: Mock,
    mock_fork: Mock,
    mock_waitpid: Mock,
    mock_sleep: Mock,
    mock_common_config: Mock,
    mock_app_manager: Mock,
  ) -> None:
    """Test full supervisor lifecycle with SSH enabled."""
    # Setup configuration
    mock_config_instance = Mock()
    mock_config_instance.ssh_agent_key_comment = "test-key"
    mock_common_config.return_value = mock_config_instance

    # Setup app mock
    mock_app = Mock()
    mock_logger = Mock()
    mock_app.get_logger.return_value = mock_logger

    mock_cache_manager = Mock()
    mock_cache_manager.base_dir = Path("/tmp/test")
    mock_app.cache_manager = mock_cache_manager

    mock_key_retriever = Mock()
    mock_key_retriever.derive_smk_from_ssh_agent.return_value = 42
    mock_app.key_retriever = mock_key_retriever

    # Setup fork to return child PIDs
    fork_calls = [123, 456]  # KeyMaster, Daemon
    mock_fork.side_effect = fork_calls

    # Setup waitpid to simulate no dead children
    mock_waitpid.return_value = (0, 0)

    with (
      patch("auto_secrets.supervisor.app", mock_app),
      patch("os.getpid", return_value=999),
      patch("os.environ", {}),
      tempfile.TemporaryDirectory(),
    ):
      # Create supervisor and run one iteration
      supervisor_instance = Supervisor()

      def stop_after_one(*args: Any) -> None:
        supervisor_instance.running = False

      mock_sleep.side_effect = stop_after_one

      # Mock PID file creation
      with patch.object(supervisor_instance, "_setup_pid_file"), patch.object(supervisor_instance, "_cleanup"):
        supervisor_instance.run()

      # Verify environment variable was set
      assert os.environ["AUTO_SECRETS_SMK_FD"] == "42"

      # Verify both children were forked
      assert mock_fork.call_count == 2

      # Verify child PIDs were tracked
      assert supervisor_instance.child_pids["KeyMaster"] == 123
      assert supervisor_instance.child_pids["Daemon"] == 456

  @patch("auto_secrets.supervisor.AppManager")
  @patch("auto_secrets.supervisor.CommonConfig")
  @patch("time.sleep")
  @patch("os.waitpid")
  @patch("os.fork")
  def test_child_restart_scenario(
    self, mock_fork: Mock, mock_waitpid: Mock, mock_sleep: Mock, mock_common_config: Mock, mock_app_manager: Mock
  ) -> None:
    """Test child process restart scenario."""
    # Setup configuration
    mock_config_instance = Mock()
    mock_config_instance.ssh_agent_key_comment = ""  # SSH disabled
    mock_common_config.return_value = mock_config_instance

    # Setup app mock
    mock_app = Mock()
    mock_logger = Mock()
    mock_app.get_logger.return_value = mock_logger

    mock_cache_manager = Mock()
    mock_cache_manager.base_dir = Path("/tmp/test")
    mock_app.cache_manager = mock_cache_manager
    mock_app.key_retriever = Mock()

    # Setup fork to return child PIDs
    fork_calls = [123, 456]  # Initial daemon, restarted daemon
    mock_fork.side_effect = fork_calls

    # Setup waitpid to simulate child death then no more deaths
    waitpid_calls = [(123, 1), (0, 0), (0, 0)]  # Child died, then no more deaths
    call_count = 0

    def waitpid_side_effect(*args: Any) -> tuple[int, int]:
      nonlocal call_count
      result = waitpid_calls[call_count] if call_count < len(waitpid_calls) else (0, 0)
      call_count += 1
      return result

    mock_waitpid.side_effect = waitpid_side_effect

    with patch("auto_secrets.supervisor.app", mock_app), patch("os.getpid", return_value=999):
      supervisor_instance = Supervisor()

      # Set up to exit after two iterations
      iteration_count = 0

      def stop_after_two(*args: Any) -> None:
        nonlocal iteration_count
        iteration_count += 1
        if iteration_count >= 2:
          supervisor_instance.running = False

      mock_sleep.side_effect = stop_after_two

      with (
        patch.object(supervisor_instance, "_setup_pid_file"),
        patch.object(supervisor_instance, "_setup_signal_handlers"),
        patch.object(supervisor_instance, "_cleanup"),
      ):
        supervisor_instance.run()

      # Verify daemon was launched twice (initial + restart)
      assert mock_fork.call_count == 2

      # Verify restart was logged
      mock_logger.warning.assert_called_once()
      warning_call = mock_logger.warning.call_args[0][0]
      assert "Daemon (PID: 123) terminated with status 1. Restarting..." in warning_call


class TestEdgeCases:
  """Test edge cases and error conditions."""

  @patch("auto_secrets.supervisor.AppManager")
  @patch("auto_secrets.supervisor.CommonConfig")
  def test_smk_fd_none_with_ssh_enabled(self, mock_common_config: Mock, mock_app_manager: Mock) -> None:
    """Test behavior when SMK FD is None but SSH is enabled."""
    mock_config_instance = Mock()
    mock_config_instance.ssh_agent_key_comment = "test-key"
    mock_common_config.return_value = mock_config_instance

    mock_app = Mock()
    mock_logger = Mock()
    mock_app.get_logger.return_value = mock_logger

    mock_cache_manager = Mock()
    mock_cache_manager.base_dir = Path("/tmp/test")
    mock_app.cache_manager = mock_cache_manager

    mock_key_retriever = Mock()
    mock_key_retriever.derive_smk_from_ssh_agent.return_value = None
    mock_app.key_retriever = mock_key_retriever

    with (
      patch("auto_secrets.supervisor.app", mock_app),
      patch("time.sleep"),
      patch("os.waitpid", return_value=(0, 0)),
      patch("os.fork", return_value=123),
    ):
      supervisor_instance = Supervisor()

      # Set up to exit after one iteration
      def stop_after_one(*args: Any) -> None:
        supervisor_instance.running = False

      with (
        patch("time.sleep", side_effect=stop_after_one),
        patch.object(supervisor_instance, "_setup_pid_file"),
        patch.object(supervisor_instance, "_setup_signal_handlers"),
        patch.object(supervisor_instance, "_get_session_master_key") as mock_get_smk,
        patch.object(supervisor_instance, "_launch_child") as mock_launch,
        patch.object(supervisor_instance, "_cleanup"),
      ):
        # Simulate SMK acquisition returning None
        def set_smk_none() -> None:
          supervisor_instance.smk_fd = None

        mock_get_smk.side_effect = set_smk_none

        supervisor_instance.run()

        # Verify KeyMaster was not launched due to None SMK FD
        mock_launch.assert_called_once_with("Daemon", supervisor.SecretsDaemon)
        mock_logger.error.assert_called_once_with("Failed to get a valid SMK_FD, KeyMaster will not be launched.")

  @patch("auto_secrets.supervisor.AppManager")
  @patch("auto_secrets.supervisor.CommonConfig")
  def test_empty_child_pids_monitoring(self, mock_common_config: Mock, mock_app_manager: Mock) -> None:
    """Test monitoring loop with no child processes."""
    mock_config_instance = Mock()
    mock_config_instance.ssh_agent_key_comment = ""
    mock_common_config.return_value = mock_config_instance

    mock_app = Mock()
    mock_logger = Mock()
    mock_app.get_logger.return_value = mock_logger

    mock_cache_manager = Mock()
    mock_cache_manager.base_dir = Path("/tmp/test")
    mock_app.cache_manager = mock_cache_manager
    mock_app.key_retriever = Mock()

    with patch("auto_secrets.supervisor.app", mock_app), patch("os.waitpid") as mock_waitpid:
      supervisor_instance = Supervisor()
      supervisor_instance.child_pids = {}  # No children

      def stop_after_one(*args: Any) -> None:
        supervisor_instance.running = False

      with (
        patch("time.sleep", side_effect=stop_after_one),
        patch.object(supervisor_instance, "_setup_pid_file"),
        patch.object(supervisor_instance, "_setup_signal_handlers"),
        patch.object(supervisor_instance, "_launch_child"),
        patch.object(supervisor_instance, "_cleanup"),
      ):
        supervisor_instance.run()

        # waitpid should not be called when there are no children
        mock_waitpid.assert_not_called()

  @patch("auto_secrets.supervisor.AppManager")
  @patch("auto_secrets.supervisor.CommonConfig")
  def test_multiple_signal_handling(self, mock_common_config: Mock, mock_app_manager: Mock) -> None:
    """Test handling multiple signals."""
    mock_config_instance = Mock()
    mock_config_instance.ssh_agent_key_comment = ""
    mock_common_config.return_value = mock_config_instance

    mock_app = Mock()
    mock_logger = Mock()
    mock_app.get_logger.return_value = mock_logger

    mock_cache_manager = Mock()
    mock_cache_manager.base_dir = Path("/tmp/test")
    mock_app.cache_manager = mock_cache_manager
    mock_app.key_retriever = Mock()

    with patch("auto_secrets.supervisor.app", mock_app), patch("signal.signal") as mock_signal_setup:
      supervisor_instance = Supervisor()
      supervisor_instance._setup_signal_handlers()

      # Get the signal handler function
      signal_handler = mock_signal_setup.call_args_list[0][0][1]

      # Test multiple signal calls
      assert supervisor_instance.running is True

      signal_handler(signal.SIGTERM, None)
      assert supervisor_instance.running is False

      # Reset running state and test SIGINT
      supervisor_instance.running = True  # type: ignore[unreachable]
      signal_handler(signal.SIGINT, None)
      assert supervisor_instance.running is False


class TestTypeAnnotations:
  """Test type annotation compatibility and mypy compliance."""

  def test_supervisor_error_types(self) -> None:
    """Test SupervisorError type annotations."""
    error: SupervisorError = SupervisorError("test")
    assert isinstance(error, Exception)

    error_no_msg: SupervisorError = SupervisorError()
    assert isinstance(error_no_msg, Exception)

  def test_supervisor_instance_types(self) -> None:
    """Test Supervisor instance type annotations."""
    with (
      patch("auto_secrets.supervisor.AppManager"),
      patch("auto_secrets.supervisor.CommonConfig") as mock_config,
      patch("auto_secrets.supervisor.app"),
    ):
      mock_config.return_value.ssh_agent_key_comment = "test"
      supervisor_instance: Supervisor = Supervisor()

      # Test type annotations
      running: bool = supervisor_instance.running
      child_pids: dict[str, int] = supervisor_instance.child_pids
      smk_fd: Optional[int] = supervisor_instance.smk_fd
      pid_file: Optional[Path] = supervisor_instance.pid_file
      ssh_agent_enabled: bool = supervisor_instance.ssh_agent_enabled
      ssh_agent_key_comment: str = supervisor_instance.ssh_agent_key_comment

      assert isinstance(running, bool)
      assert isinstance(child_pids, dict)
      assert smk_fd is None or isinstance(smk_fd, int)
      assert pid_file is None or isinstance(pid_file, Path)
      assert isinstance(ssh_agent_enabled, bool)
      assert isinstance(ssh_agent_key_comment, str)


if __name__ == "__main__":
  pytest.main([__file__, "-v", "--tb=short"])
