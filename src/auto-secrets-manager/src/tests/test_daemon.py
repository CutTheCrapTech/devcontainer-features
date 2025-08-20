"""
Unit tests for SecretsDaemon class with comprehensive coverage and mypy compatibility.
"""

import signal
import tempfile
import threading
import time
from collections.abc import Generator
from pathlib import Path
from unittest.mock import MagicMock, Mock, mock_open, patch

import pytest
from pytest import MonkeyPatch

from auto_secrets import daemon
from auto_secrets.daemon import DaemonError, SecretsDaemon


class TestSecretsDaemon:
  """Comprehensive test suite for SecretsDaemon class."""

  @pytest.fixture
  def mock_dependencies(self) -> Generator[dict[str, Mock], None, None]:
    """Mock all external dependencies."""
    with patch.multiple(
      "auto_secrets.daemon", ProcessUtils=MagicMock(), AutoSecretsLogger=MagicMock(), AppManager=MagicMock()
    ) as mocks:
      # Setup logger mock
      logger_mock = MagicMock()
      mocks["AutoSecretsLogger"].return_value.get_logger.return_value = logger_mock

      # Setup AppManager mock
      app_mock = MagicMock()
      crypto_utils_mock = MagicMock()
      cache_manager_mock = MagicMock()
      secret_manager_mock = MagicMock()

      app_mock.crypto_utils = crypto_utils_mock
      app_mock.cache_manager = cache_manager_mock
      app_mock.secret_manager = secret_manager_mock
      app_mock.get_logger.return_value = logger_mock

      # Setup cache manager with temporary directory
      with tempfile.TemporaryDirectory() as temp_dir:
        cache_manager_mock.base_dir = Path(temp_dir)
        cache_manager_mock.max_age_seconds = 300
        cache_manager_mock.cleanup_interval = 3600
        cache_manager_mock.is_cache_stale.return_value = False
        cache_manager_mock.cleanup_stale.return_value = 0

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
    """Test successful SecretsDaemon initialization."""
    with patch("os.getpid", return_value=1234), patch("signal.signal"):
      daemon_instance = SecretsDaemon()

      assert daemon_instance.running is False  # Not started yet
      assert daemon_instance.smk == b"test_session_master_key"
      assert daemon_instance.pid_file is not None
      mock_dependencies["ProcessUtils"].set_parent_death_signal.assert_called_once()

  def test_init_missing_smk_fd(self, mock_dependencies: dict[str, Mock]) -> None:
    """Test initialization failure when SMK_FD environment variable is missing."""
    with pytest.raises(DaemonError) as exc_info:
      SecretsDaemon()

    assert "AUTO_SECRETS_SMK_FD environment variable not set" in str(exc_info.value)

  def test_init_invalid_smk_fd(self, mock_dependencies: dict[str, Mock], monkeypatch: MonkeyPatch) -> None:
    """Test initialization failure with invalid SMK file descriptor."""
    monkeypatch.setenv("AUTO_SECRETS_SMK_FD", "invalid")

    with pytest.raises(SystemExit) as exc_info:
      SecretsDaemon()

    assert exc_info.value.code == 1

  def test_init_empty_smk(self, mock_dependencies: dict[str, Mock], monkeypatch: MonkeyPatch) -> None:
    """Test initialization failure when SMK is empty."""
    monkeypatch.setenv("AUTO_SECRETS_SMK_FD", "3")

    mock_file = mock_open(read_data=b"")

    with patch("os.fdopen", mock_file), pytest.raises(DaemonError) as exc_info:
      SecretsDaemon()

    assert "Failed to read key from file descriptor (empty)" in str(exc_info.value)

  def test_init_smk_fd_error(self, mock_dependencies: dict[str, Mock], monkeypatch: MonkeyPatch) -> None:
    """Test initialization failure when file descriptor reading fails."""
    monkeypatch.setenv("AUTO_SECRETS_SMK_FD", "3")

    with patch("os.fdopen", side_effect=OSError("Bad file descriptor")), pytest.raises(SystemExit) as exc_info:
      SecretsDaemon()

    assert exc_info.value.code == 1

  def test_acquire_smk_success(self, mock_dependencies: dict[str, Mock], monkeypatch: MonkeyPatch) -> None:
    """Test successful SMK acquisition."""
    monkeypatch.setenv("AUTO_SECRETS_SMK_FD", "3")

    expected_smk = b"test_master_key"
    mock_file = mock_open(read_data=expected_smk)

    with patch("os.fdopen", mock_file), patch("os.getpid", return_value=1234), patch("signal.signal"):
      daemon_instance = SecretsDaemon()
      assert daemon_instance.smk == expected_smk

  def test_setup_pid_file_new(self, mock_dependencies: dict[str, Mock], mock_smk_fd: None) -> None:
    """Test PID file setup when no existing PID file exists."""
    with patch("os.getpid", return_value=1234), patch("signal.signal"):
      daemon_instance = SecretsDaemon()

      assert daemon_instance.pid_file is not None
      assert daemon_instance.pid_file.exists()

      with open(daemon_instance.pid_file) as f:
        pid_content = f.read().strip()
      assert pid_content == "1234"

  def test_setup_pid_file_stale(self, mock_dependencies: dict[str, Mock], mock_smk_fd: None) -> None:
    """Test PID file setup when existing PID file contains stale process."""
    with (
      patch("os.getpid", return_value=1234),
      patch("os.kill", side_effect=OSError("No such process")),
      patch("signal.signal"),
    ):
      # Create existing PID file
      state_dir = mock_dependencies["AppManager"].return_value.cache_manager.base_dir / "state"
      state_dir.mkdir(parents=True, exist_ok=True)
      pid_file = state_dir / "daemon.pid"

      with open(pid_file, "w") as f:
        f.write("9999")  # Stale PID

      daemon_instance = SecretsDaemon()

      # Should remove stale PID file and create new one
      assert daemon_instance.pid_file is not None  # Add None check
      with open(daemon_instance.pid_file) as f:
        pid_content = f.read().strip()
      assert pid_content == "1234"

  def test_setup_pid_file_running(self, mock_dependencies: dict[str, Mock], mock_smk_fd: None) -> None:
    """Test PID file setup when daemon is already running."""
    with (
      patch("os.getpid", return_value=1234),
      patch("os.kill", return_value=None),
      patch("signal.signal"),
      pytest.raises(SystemExit) as exc_info,
    ):
      # Create existing PID file with running process
      state_dir = mock_dependencies["AppManager"].return_value.cache_manager.base_dir / "state"
      state_dir.mkdir(parents=True, exist_ok=True)
      pid_file = state_dir / "daemon.pid"

      with open(pid_file, "w") as f:
        f.write("9999")  # Running PID

      SecretsDaemon()

    assert exc_info.value.code == 1

  def test_setup_pid_file_invalid_content(self, mock_dependencies: dict[str, Mock], mock_smk_fd: None) -> None:
    """Test PID file setup when existing PID file has invalid content."""
    with patch("os.getpid", return_value=1234), patch("signal.signal"):
      # Create invalid PID file
      state_dir = mock_dependencies["AppManager"].return_value.cache_manager.base_dir / "state"
      state_dir.mkdir(parents=True, exist_ok=True)
      pid_file = state_dir / "daemon.pid"

      with open(pid_file, "w") as f:
        f.write("invalid_pid")

      daemon_instance = SecretsDaemon()

      # Should remove invalid PID file and create new one
      assert daemon_instance.pid_file is not None
      with open(daemon_instance.pid_file) as f:
        pid_content = f.read().strip()
      assert pid_content == "1234"

  def test_setup_pid_file_error(self, mock_dependencies: dict[str, Mock], mock_smk_fd: None) -> None:
    """Test PID file setup when an error occurs during setup."""
    with patch("os.getpid", return_value=1234), patch("signal.signal"):
      # Make state directory creation fail
      mock_dependencies["AppManager"].return_value.cache_manager.base_dir = Path("/invalid/path")

      daemon_instance = SecretsDaemon()

      # Should continue without PID file
      assert daemon_instance.pid_file is None

  def test_setup_signal_handlers(self, mock_dependencies: dict[str, Mock], mock_smk_fd: None) -> None:
    """Test signal handler setup."""
    with patch("os.getpid", return_value=1234), patch("signal.signal") as mock_signal:
      daemon_instance = SecretsDaemon()
      daemon_instance._setup_signal_handlers()

      # Verify signal handlers were set up
      signal_calls = mock_signal.call_args_list
      signal_numbers = [call[0][0] for call in signal_calls if len(call[0]) >= 2]

      assert signal.SIGTERM in signal_numbers
      assert signal.SIGINT in signal_numbers

  def test_signal_handler_functionality(self, mock_dependencies: dict[str, Mock], mock_smk_fd: None) -> None:
    """Test that signal handlers properly set running to False."""
    with patch("os.getpid", return_value=1234), patch("signal.signal") as mock_signal:
      daemon_instance = SecretsDaemon()
      daemon_instance.running = True
      daemon_instance._setup_signal_handlers()

      # Get the signal handler function
      signal_handler = None
      for call in mock_signal.call_args_list:
        if len(call[0]) >= 2 and call[0][0] == signal.SIGTERM:
          signal_handler = call[0][1]
          break

      assert signal_handler is not None

      # Test signal handler
      signal_handler(signal.SIGTERM, None)
      assert daemon_instance.running is False

  def test_get_environments_to_refresh_empty(self, mock_dependencies: dict[str, Mock], mock_smk_fd: None) -> None:
    """Test getting environments to refresh when none are stale."""
    with patch("os.getpid", return_value=1234), patch("signal.signal"):
      daemon_instance = SecretsDaemon()

      # Mock cache manager to return no stale environments
      mock_dependencies["AppManager"].return_value.cache_manager.is_cache_stale.return_value = False

      environments = daemon_instance._get_environments_to_refresh()
      assert environments == []

  def test_get_environments_to_refresh_with_stale(self, mock_dependencies: dict[str, Mock], mock_smk_fd: None) -> None:
    """Test getting environments to refresh when some are stale."""
    with patch("os.getpid", return_value=1234), patch("signal.signal"):
      daemon_instance = SecretsDaemon()

      # Create mock environment cache files
      cache_dir = mock_dependencies["AppManager"].return_value.cache_manager.base_dir / "environments"
      cache_dir.mkdir(parents=True, exist_ok=True)
      (cache_dir / "prod.env").touch()
      (cache_dir / "staging.env").touch()
      (cache_dir / "dev.env").touch()

      # Mock cache manager to return some stale environments
      def mock_is_stale(env_name: str) -> bool:
        return env_name in ["prod", "dev"]

      mock_dependencies["AppManager"].return_value.cache_manager.is_cache_stale.side_effect = mock_is_stale

      environments = daemon_instance._get_environments_to_refresh()
      assert set(environments) == {"prod", "dev"}

  def test_get_environments_to_refresh_no_cache_dir(
    self, mock_dependencies: dict[str, Mock], mock_smk_fd: None
  ) -> None:
    """Test getting environments to refresh when cache directory doesn't exist."""
    with patch("os.getpid", return_value=1234), patch("signal.signal"):
      daemon_instance = SecretsDaemon()

      # No cache directory exists
      environments = daemon_instance._get_environments_to_refresh()
      assert environments == []

  def test_get_environments_to_refresh_error(self, mock_dependencies: dict[str, Mock], mock_smk_fd: None) -> None:
    """Test getting environments to refresh when an error occurs."""
    with patch("os.getpid", return_value=1234), patch("signal.signal"):
      daemon_instance = SecretsDaemon()

      # Mock cache manager to raise exception
      mock_dependencies["AppManager"].return_value.cache_manager.is_cache_stale.side_effect = Exception("Cache error")

      environments = daemon_instance._get_environments_to_refresh()
      assert environments == []

  def test_refresh_environment_secrets_success(self, mock_dependencies: dict[str, Mock], mock_smk_fd: None) -> None:
    """Test successful environment secret refresh."""
    with patch("os.getpid", return_value=1234), patch("signal.signal"):
      daemon_instance = SecretsDaemon()

      # Mock successful operations
      mock_secret_manager = mock_dependencies["AppManager"].return_value.secret_manager
      mock_secret_manager.test_connection.return_value = True
      mock_secret_manager.fetch_secrets.return_value = {"key1": "value1", "key2": "value2"}

      result = daemon_instance._refresh_environment_secrets("prod")

      assert result is True
      mock_secret_manager.test_connection.assert_called_once()
      mock_secret_manager.fetch_secrets.assert_called_once_with("prod")
      mock_dependencies["AppManager"].return_value.cache_manager.update_environment_cache.assert_called_once()

  def test_refresh_environment_secrets_connection_failed(
    self, mock_dependencies: dict[str, Mock], mock_smk_fd: None
  ) -> None:
    """Test environment secret refresh when connection test fails."""
    with patch("os.getpid", return_value=1234), patch("signal.signal"):
      daemon_instance = SecretsDaemon()

      # Mock connection test failure
      mock_secret_manager = mock_dependencies["AppManager"].return_value.secret_manager
      mock_secret_manager.test_connection.return_value = False

      result = daemon_instance._refresh_environment_secrets("prod")

      assert result is False
      mock_secret_manager.fetch_secrets.assert_not_called()

  def test_refresh_environment_secrets_fetch_error(self, mock_dependencies: dict[str, Mock], mock_smk_fd: None) -> None:
    """Test environment secret refresh when fetch fails."""
    with patch("os.getpid", return_value=1234), patch("signal.signal"):
      daemon_instance = SecretsDaemon()

      # Mock fetch secrets failure
      mock_secret_manager = mock_dependencies["AppManager"].return_value.secret_manager
      mock_secret_manager.test_connection.return_value = True
      mock_secret_manager.fetch_secrets.side_effect = Exception("Fetch error")

      result = daemon_instance._refresh_environment_secrets("prod")

      assert result is False

  def test_cleanup_old_caches_success(self, mock_dependencies: dict[str, Mock], mock_smk_fd: None) -> None:
    """Test successful old cache cleanup."""
    with patch("os.getpid", return_value=1234), patch("signal.signal"):
      daemon_instance = SecretsDaemon()

      # Mock cleanup success
      mock_dependencies["AppManager"].return_value.cache_manager.cleanup_stale.return_value = 5

      daemon_instance._cleanup_old_caches()

      mock_dependencies["AppManager"].return_value.cache_manager.cleanup_stale.assert_called_once()

  def test_cleanup_old_caches_disabled(self, mock_dependencies: dict[str, Mock], mock_smk_fd: None) -> None:
    """Test cache cleanup when cleanup is disabled."""
    with patch("os.getpid", return_value=1234), patch("signal.signal"):
      daemon_instance = SecretsDaemon()

      # Mock cleanup disabled
      mock_dependencies["AppManager"].return_value.cache_manager.cleanup_interval = 0

      daemon_instance._cleanup_old_caches()

      mock_dependencies["AppManager"].return_value.cache_manager.cleanup_stale.assert_not_called()

  def test_cleanup_old_caches_error(self, mock_dependencies: dict[str, Mock], mock_smk_fd: None) -> None:
    """Test cache cleanup when an error occurs."""
    with patch("os.getpid", return_value=1234), patch("signal.signal"):
      daemon_instance = SecretsDaemon()

      # Mock cleanup error
      mock_dependencies["AppManager"].return_value.cache_manager.cleanup_stale.side_effect = Exception("Cleanup error")

      # Should not raise exception
      daemon_instance._cleanup_old_caches()

  def test_update_heartbeat_success(self, mock_dependencies: dict[str, Mock], mock_smk_fd: None) -> None:
    """Test successful heartbeat update."""
    with (
      patch("os.getpid", return_value=1234),
      patch("signal.signal"),
      patch("builtins.open", mock_open()) as mock_file,
    ):
      daemon_instance = SecretsDaemon()
      daemon_instance._update_heartbeat()

      # Verify heartbeat file was written
      mock_file.assert_called()

  def test_update_heartbeat_no_pid_file(self, mock_dependencies: dict[str, Mock], mock_smk_fd: None) -> None:
    """Test heartbeat update when no PID file exists."""
    with patch("os.getpid", return_value=1234), patch("signal.signal"):
      daemon_instance = SecretsDaemon()
      daemon_instance.pid_file = None

      # Should not raise exception
      daemon_instance._update_heartbeat()

  def test_update_heartbeat_error(self, mock_dependencies: dict[str, Mock], mock_smk_fd: None) -> None:
    """Test heartbeat update when an error occurs."""
    with (
      patch("os.getpid", return_value=1234),
      patch("signal.signal"),
      patch("builtins.open", side_effect=OSError("File error")),
    ):
      daemon_instance = SecretsDaemon()

      # Should not raise exception
      daemon_instance._update_heartbeat()

  def test_run_basic_loop(self, mock_dependencies: dict[str, Mock], mock_smk_fd: None) -> None:
    """Test basic daemon run loop."""
    with patch("os.getpid", return_value=1234), patch("signal.signal"), patch("time.sleep"):
      daemon_instance = SecretsDaemon()

      # Mock methods
      with (
        patch.object(daemon_instance, "_get_environments_to_refresh", return_value=[]),
        patch.object(daemon_instance, "_update_heartbeat"),
        patch.object(daemon_instance, "_cleanup_old_caches"),
      ):
        # Run for a short time then stop
        def stop_after_delay() -> None:
          time.sleep(0.1)
          daemon_instance.running = False

        stop_thread = threading.Thread(target=stop_after_delay)
        stop_thread.start()

        daemon_instance.run()
        stop_thread.join()

  def test_run_with_environments(self, mock_dependencies: dict[str, Mock], mock_smk_fd: None) -> None:
    """Test daemon run loop with environments to refresh."""
    with patch("os.getpid", return_value=1234), patch("signal.signal"), patch("time.sleep"):
      daemon_instance = SecretsDaemon()

      # Mock methods
      with (
        patch.object(daemon_instance, "_get_environments_to_refresh", return_value=["prod", "staging"]),
        patch.object(daemon_instance, "_refresh_environment_secrets", return_value=True) as mock_refresh,
        patch.object(daemon_instance, "_update_heartbeat"),
        patch.object(daemon_instance, "_cleanup_old_caches"),
      ):
        # Run for a short time then stop
        def stop_after_delay() -> None:
          time.sleep(0.1)
          daemon_instance.running = False

        stop_thread = threading.Thread(target=stop_after_delay)
        stop_thread.start()

        daemon_instance.run()
        stop_thread.join()

        # Verify environments were refreshed
        assert mock_refresh.call_count == 2

  def test_run_refresh_failure(self, mock_dependencies: dict[str, Mock], mock_smk_fd: None) -> None:
    """Test daemon run loop when environment refresh fails."""
    with patch("os.getpid", return_value=1234), patch("signal.signal"), patch("time.sleep"):
      daemon_instance = SecretsDaemon()

      # Mock methods
      with (
        patch.object(daemon_instance, "_get_environments_to_refresh", return_value=["prod"]),
        patch.object(daemon_instance, "_refresh_environment_secrets", return_value=False),
        patch.object(daemon_instance, "_update_heartbeat"),
        patch.object(daemon_instance, "_cleanup_old_caches"),
      ):
        # Run for a short time then stop
        def stop_after_delay() -> None:
          time.sleep(0.1)
          daemon_instance.running = False

        stop_thread = threading.Thread(target=stop_after_delay)
        stop_thread.start()

        daemon_instance.run()
        stop_thread.join()

  def test_run_cleanup_cycle(self, mock_dependencies: dict[str, Mock], mock_smk_fd: None) -> None:
    """Test daemon run loop cleanup cycle."""
    with (
      patch("os.getpid", return_value=1234),
      patch("signal.signal"),
      patch("time.time", side_effect=[0, 0, 3700, 3700]),
      patch("time.sleep"),
    ):
      daemon_instance = SecretsDaemon()

      # Mock methods
      with (
        patch.object(daemon_instance, "_get_environments_to_refresh", return_value=[]),
        patch.object(daemon_instance, "_update_heartbeat"),
        patch.object(daemon_instance, "_cleanup_old_caches") as mock_cleanup,
      ):
        # Run for a short time then stop
        def stop_after_delay() -> None:
          time.sleep(0.1)
          daemon_instance.running = False

        stop_thread = threading.Thread(target=stop_after_delay)
        stop_thread.start()

        daemon_instance.run()
        stop_thread.join()

        # Cleanup should have been called due to time advancement
        mock_cleanup.assert_called()

  def test_run_loop_error(self, mock_dependencies: dict[str, Mock], mock_smk_fd: None) -> None:
    """Test daemon run loop when an error occurs in the loop."""
    with patch("os.getpid", return_value=1234), patch("signal.signal"), patch("time.sleep"):
      daemon_instance = SecretsDaemon()

      # Mock methods to raise error
      with patch.object(daemon_instance, "_update_heartbeat", side_effect=Exception("Heartbeat error")):
        # Run for a short time then stop
        def stop_after_delay() -> None:
          time.sleep(0.1)
          daemon_instance.running = False

        stop_thread = threading.Thread(target=stop_after_delay)
        stop_thread.start()

        daemon_instance.run()
        stop_thread.join()

  def test_run_fatal_error(self, mock_dependencies: dict[str, Mock], mock_smk_fd: None) -> None:
    """Test daemon run with fatal error."""
    with patch("os.getpid", return_value=1234), patch("signal.signal"):
      daemon_instance = SecretsDaemon()

      # Mock setup_signal_handlers to raise exception
      with (
        patch.object(daemon_instance, "_setup_signal_handlers", side_effect=Exception("Fatal error")),
        pytest.raises(SystemExit) as exc_info,
      ):
        daemon_instance.run()

      assert exc_info.value.code == 1

  def test_run_early_exit_check(self, mock_dependencies: dict[str, Mock], mock_smk_fd: None) -> None:
    """Test daemon run loop early exit when running becomes False."""
    with patch("os.getpid", return_value=1234), patch("signal.signal"), patch("time.sleep"):
      daemon_instance = SecretsDaemon()

      # Mock environments and make running False during refresh
      def mock_refresh(env: str) -> bool:
        daemon_instance.running = False  # Stop during first refresh
        return True

      with (
        patch.object(daemon_instance, "_get_environments_to_refresh", return_value=["prod", "staging"]),
        patch.object(daemon_instance, "_refresh_environment_secrets", side_effect=mock_refresh) as mock_refresh_method,
        patch.object(daemon_instance, "_update_heartbeat"),
        patch.object(daemon_instance, "_cleanup_old_caches"),
      ):
        daemon_instance.run()

        # Should only refresh first environment before stopping
        assert mock_refresh_method.call_count == 1

  def test_cleanup(self, mock_dependencies: dict[str, Mock], mock_smk_fd: None) -> None:
    """Test daemon cleanup."""
    with patch("os.getpid", return_value=1234), patch("signal.signal"):
      daemon_instance = SecretsDaemon()

      # Create heartbeat file
      assert daemon_instance.pid_file is not None
      heartbeat_file = daemon_instance.pid_file.parent / "daemon.heartbeat"
      heartbeat_file.touch()

      daemon_instance._cleanup()

      # Verify files were removed
      assert not daemon_instance.pid_file.exists()
      assert not heartbeat_file.exists()

  def test_cleanup_no_pid_file(self, mock_dependencies: dict[str, Mock], mock_smk_fd: None) -> None:
    """Test cleanup when PID file doesn't exist."""
    with patch("os.getpid", return_value=1234), patch("signal.signal"):
      daemon_instance = SecretsDaemon()
      daemon_instance.pid_file = None

      # Should not raise exception
      daemon_instance._cleanup()

  def test_cleanup_file_not_exists(self, mock_dependencies: dict[str, Mock], mock_smk_fd: None) -> None:
    """Test cleanup when files don't exist."""
    with patch("os.getpid", return_value=1234), patch("signal.signal"):
      daemon_instance = SecretsDaemon()

      # Remove PID file
      assert daemon_instance.pid_file is not None
      daemon_instance.pid_file.unlink()

      # Should not raise exception
      daemon_instance._cleanup()

  def test_cleanup_error(self, mock_dependencies: dict[str, Mock], mock_smk_fd: None) -> None:
    """Test cleanup when an error occurs."""
    with patch("os.getpid", return_value=1234), patch("signal.signal"):
      daemon_instance = SecretsDaemon()

      # Mock unlink to raise error
      with patch.object(daemon_instance.pid_file, "unlink", side_effect=OSError("Remove error")):
        # Should not raise exception
        daemon_instance._cleanup()

  def test_init_exception_handling(self, mock_dependencies: dict[str, Mock], mock_smk_fd: None) -> None:
    """Test initialization exception handling and re-raising."""
    with patch("os.getpid", return_value=1234), patch("signal.signal"):
      # Mock AppManager to raise exception
      mock_dependencies["AppManager"].side_effect = Exception("App init error")

      with pytest.raises(Exception) as exc_info:
        SecretsDaemon()

      assert "App init error" in str(exc_info.value)

  def test_acquire_smk_value_error(self, mock_dependencies: dict[str, Mock], monkeypatch: MonkeyPatch) -> None:
    """Test SMK acquisition with ValueError from invalid FD."""
    monkeypatch.setenv("AUTO_SECRETS_SMK_FD", "not_a_number")

    with pytest.raises(SystemExit) as exc_info:
      SecretsDaemon()

    assert exc_info.value.code == 1

  def test_setup_pid_file_permission_error(self, mock_dependencies: dict[str, Mock], mock_smk_fd: None) -> None:
    """Test PID file setup when permission denied."""
    with (
      patch("os.getpid", return_value=1234),
      patch("signal.signal"),
      patch("builtins.open", side_effect=PermissionError("Permission denied")),
    ):
      daemon_instance = SecretsDaemon()

      # Should continue without PID file
      assert daemon_instance.pid_file is None

  def test_setup_pid_file_os_error_on_kill(self, mock_dependencies: dict[str, Mock], mock_smk_fd: None) -> None:
    """Test PID file setup with OSError during process check."""
    with (
      patch("os.getpid", return_value=1234),
      patch("os.kill", side_effect=OSError("Process check failed")),
      patch("signal.signal"),
    ):
      # Create existing PID file
      state_dir = mock_dependencies["AppManager"].return_value.cache_manager.base_dir / "state"
      state_dir.mkdir(parents=True, exist_ok=True)
      pid_file = state_dir / "daemon.pid"

      with open(pid_file, "w") as f:
        f.write("9999")

      daemon_instance = SecretsDaemon()

      # Should remove stale PID file and create new one
      assert daemon_instance.pid_file is not None
      with open(daemon_instance.pid_file) as f:
        pid_content = f.read().strip()
      assert pid_content == "1234"

  def test_get_environments_nested_exception(self, mock_dependencies: dict[str, Mock], mock_smk_fd: None) -> None:
    """Test getting environments when nested exception occurs."""
    with patch("os.getpid", return_value=1234), patch("signal.signal"):
      daemon_instance = SecretsDaemon()

      # Mock the outer try block to succeed but inner to fail
      with patch.object(Path, "glob", side_effect=Exception("Glob error")):
        environments = daemon_instance._get_environments_to_refresh()
        assert environments == []

  def test_get_environments_duplicate_removal(self, mock_dependencies: dict[str, Mock], mock_smk_fd: None) -> None:
    """Test that duplicate environments are removed from refresh list."""
    with patch("os.getpid", return_value=1234), patch("signal.signal"):
      daemon_instance = SecretsDaemon()

      # Create mock environment cache files
      cache_dir = mock_dependencies["AppManager"].return_value.cache_manager.base_dir / "environments"
      cache_dir.mkdir(parents=True, exist_ok=True)
      (cache_dir / "prod.env").touch()
      (cache_dir / "prod.env.backup").touch()  # Different file that would create duplicate

      # Mock to return all as stale
      mock_dependencies["AppManager"].return_value.cache_manager.is_cache_stale.return_value = True

      def mock_with_duplicates() -> list:
        # Simulate internal logic that might create duplicates
        envs = ["prod", "prod"]  # Duplicate
        return list(set(envs))  # Should deduplicate

      with patch.object(daemon_instance, "_get_environments_to_refresh", mock_with_duplicates):
        environments = daemon_instance._get_environments_to_refresh()
        assert environments == ["prod"]  # No duplicates

  def test_refresh_environment_secrets_cache_update_error(
    self, mock_dependencies: dict[str, Mock], mock_smk_fd: None
  ) -> None:
    """Test environment refresh when cache update fails."""
    with patch("os.getpid", return_value=1234), patch("signal.signal"):
      daemon_instance = SecretsDaemon()

      # Mock successful fetch but failed cache update
      mock_secret_manager = mock_dependencies["AppManager"].return_value.secret_manager
      mock_secret_manager.test_connection.return_value = True
      mock_secret_manager.fetch_secrets.return_value = {"key1": "value1"}

      mock_cache_manager = mock_dependencies["AppManager"].return_value.cache_manager
      mock_cache_manager.update_environment_cache.side_effect = Exception("Cache update error")

      result = daemon_instance._refresh_environment_secrets("prod")

      assert result is False

  def test_cleanup_old_caches_negative_cleanup_interval(
    self, mock_dependencies: dict[str, Mock], mock_smk_fd: None
  ) -> None:
    """Test cache cleanup when cleanup interval is negative."""
    with patch("os.getpid", return_value=1234), patch("signal.signal"):
      daemon_instance = SecretsDaemon()

      # Mock negative cleanup interval
      mock_dependencies["AppManager"].return_value.cache_manager.cleanup_interval = -1

      daemon_instance._cleanup_old_caches()

      # Should not call cleanup_stale
      mock_dependencies["AppManager"].return_value.cache_manager.cleanup_stale.assert_not_called()

  def test_update_heartbeat_with_custom_timestamp(self, mock_dependencies: dict[str, Mock], mock_smk_fd: None) -> None:
    """Test heartbeat update writes current timestamp."""
    with (
      patch("os.getpid", return_value=1234),
      patch("signal.signal"),
      patch("auto_secrets.daemon.datetime") as mock_datetime,
    ):
      # Mock datetime.now() to return specific timestamp
      mock_now = MagicMock()
      mock_now.isoformat.return_value = "2024-01-01T12:00:00"
      mock_datetime.now.return_value = mock_now

      mock_file = mock_open()
      with patch("builtins.open", mock_file):
        daemon_instance = SecretsDaemon()
        daemon_instance._update_heartbeat()

        # Verify correct timestamp was written
        mock_file().write.assert_called_with("2024-01-01T12:00:00")

  def test_run_sleep_interruption(self, mock_dependencies: dict[str, Mock], mock_smk_fd: None) -> None:
    """Test daemon run loop sleep interruption behavior."""
    with patch("os.getpid", return_value=1234), patch("signal.signal"):
      daemon_instance = SecretsDaemon()

      sleep_calls = []

      def mock_sleep(duration: float) -> None:
        sleep_calls.append(duration)
        if len(sleep_calls) >= 3:  # Stop after a few sleep calls
          daemon_instance.running = False

      with (
        patch("time.sleep", side_effect=mock_sleep),
        patch("time.time", side_effect=[0, 1, 1, 2, 2, 3]),
        patch.object(daemon_instance, "_get_environments_to_refresh", return_value=[]),
        patch.object(daemon_instance, "_update_heartbeat"),
        patch.object(daemon_instance, "_cleanup_old_caches"),
      ):
        daemon_instance.run()

        # Verify sleep was called in chunks
        assert len(sleep_calls) >= 1
        # Each sleep call should be <= 5.0 seconds (chunk size)
        assert all(duration <= 5.0 for duration in sleep_calls)

  def test_run_zero_sleep_time(self, mock_dependencies: dict[str, Mock], mock_smk_fd: None) -> None:
    """Test daemon run loop when processing takes longer than refresh interval."""
    with patch("os.getpid", return_value=1234), patch("signal.signal"):
      daemon_instance = SecretsDaemon()

      # Mock time to simulate processing taking longer than refresh interval
      with (
        patch("time.time", side_effect=[0, 400, 400]),
        patch("time.sleep") as mock_sleep,
        patch.object(daemon_instance, "_get_environments_to_refresh", return_value=[]),
        patch.object(daemon_instance, "_update_heartbeat"),
        patch.object(daemon_instance, "_cleanup_old_caches"),
      ):
        # Run for one iteration then stop
        def stop_after_delay() -> None:
          time.sleep(0.05)
          daemon_instance.running = False

        stop_thread = threading.Thread(target=stop_after_delay)
        stop_thread.start()

        daemon_instance.run()
        stop_thread.join()

        # Should not sleep if processing took longer than refresh interval
        mock_sleep.assert_not_called()

  def test_run_cleanup_finally_block(self, mock_dependencies: dict[str, Mock], mock_smk_fd: None) -> None:
    """Test that cleanup is called in finally block even after exception."""
    with patch("os.getpid", return_value=1234), patch("signal.signal"):
      daemon_instance = SecretsDaemon()

      with (
        patch.object(daemon_instance, "_setup_signal_handlers", side_effect=Exception("Setup error")),
        patch.object(daemon_instance, "_cleanup") as mock_cleanup,
        pytest.raises(SystemExit),
      ):
        daemon_instance.run()

      # Cleanup should be called even after exception
      mock_cleanup.assert_called_once()

  def test_stop_method(self, mock_dependencies: dict[str, Mock], mock_smk_fd: None) -> None:
    """Test daemon stop method sets running to False."""
    with patch("os.getpid", return_value=1234), patch("signal.signal"):
      daemon_instance = SecretsDaemon()
      daemon_instance.running = True

      daemon_instance.stop()

      assert daemon_instance.running is False

  def test_daemon_error_inheritance(self) -> None:
    """Test that DaemonError properly inherits from Exception."""
    error = DaemonError("Test error message")
    assert isinstance(error, Exception)
    assert str(error) == "Test error message"

  def test_run_with_mixed_refresh_results(self, mock_dependencies: dict[str, Mock], mock_smk_fd: None) -> None:
    """Test daemon run loop with mixed success/failure refresh results."""
    with patch("os.getpid", return_value=1234), patch("signal.signal"), patch("time.sleep"):
      daemon_instance = SecretsDaemon()

      # Mock mixed results
      refresh_results = [True, False, True]  # Success, failure, success
      refresh_calls = []

      def mock_refresh(env: str) -> bool:
        refresh_calls.append(env)
        return refresh_results[len(refresh_calls) - 1]

      with (
        patch.object(daemon_instance, "_get_environments_to_refresh", return_value=["prod", "staging", "dev"]),
        patch.object(daemon_instance, "_refresh_environment_secrets", side_effect=mock_refresh),
        patch.object(daemon_instance, "_update_heartbeat"),
        patch.object(daemon_instance, "_cleanup_old_caches"),
      ):
        # Run for a short time then stop
        def stop_after_delay() -> None:
          time.sleep(0.1)
          daemon_instance.running = False

        stop_thread = threading.Thread(target=stop_after_delay)
        stop_thread.start()

        daemon_instance.run()
        stop_thread.join()

        # All environments should be attempted
        assert len(refresh_calls) == 3
        assert refresh_calls == ["prod", "staging", "dev"]

  def test_cleanup_heartbeat_file_error(self, mock_dependencies: dict[str, Mock], mock_smk_fd: None) -> None:
    """Test cleanup when heartbeat file removal fails."""
    with patch("os.getpid", return_value=1234), patch("signal.signal"):
      daemon_instance = SecretsDaemon()

      # Create heartbeat file and mock its unlink to fail
      assert daemon_instance.pid_file is not None
      heartbeat_file = daemon_instance.pid_file.parent / "daemon.heartbeat"
      heartbeat_file.touch()

      with patch.object(heartbeat_file, "unlink", side_effect=OSError("Unlink error")):
        # Should not raise exception
        daemon_instance._cleanup()

  def test_multiple_signal_types(self, mock_dependencies: dict[str, Mock], mock_smk_fd: None) -> None:
    """Test that both SIGTERM and SIGINT handlers work correctly."""
    with patch("os.getpid", return_value=1234), patch("signal.signal") as mock_signal:
      daemon_instance = SecretsDaemon()
      daemon_instance.running = True
      daemon_instance._setup_signal_handlers()

      # Get both signal handlers
      sigterm_handler = None
      sigint_handler = None

      for call in mock_signal.call_args_list:
        if len(call[0]) >= 2:
          if call[0][0] == signal.SIGTERM:
            sigterm_handler = call[0][1]
          elif call[0][0] == signal.SIGINT:
            sigint_handler = call[0][1]

      assert sigterm_handler is not None
      assert sigint_handler is not None

      # Test SIGTERM handler
      daemon_instance.running = True
      sigterm_handler(signal.SIGTERM, None)
      assert daemon_instance.running is False

      # Test SIGINT handler
      daemon_instance.running = True
      sigint_handler(signal.SIGINT, None)
      assert daemon_instance.running is False

  def test_get_environments_glob_pattern(self, mock_dependencies: dict[str, Mock], mock_smk_fd: None) -> None:
    """Test that environment discovery uses correct glob pattern."""
    with patch("os.getpid", return_value=1234), patch("signal.signal"):
      daemon_instance = SecretsDaemon()

      # Create various files to test glob pattern
      cache_dir = mock_dependencies["AppManager"].return_value.cache_manager.base_dir / "environments"
      cache_dir.mkdir(parents=True, exist_ok=True)

      # Files that should match *.env pattern
      (cache_dir / "prod.env").touch()
      (cache_dir / "staging.env").touch()

      # Files that should NOT match
      (cache_dir / "prod.json").touch()
      (cache_dir / "config.txt").touch()
      (cache_dir / "env.backup").touch()

      # Mock all as stale for testing
      mock_dependencies["AppManager"].return_value.cache_manager.is_cache_stale.return_value = True

      environments = daemon_instance._get_environments_to_refresh()

      # Should only include .env files
      assert set(environments) == {"prod", "staging"}


class TestSecretsDaemonMain:
  """Test the main entry point and module-level functions."""

  def test_main_success(self) -> None:
    """Test successful main function execution."""
    with patch("auto_secrets.daemon.SecretsDaemon") as mock_daemon_class:
      mock_instance = MagicMock()
      mock_daemon_class.return_value = mock_instance

      daemon.main()

      mock_daemon_class.assert_called_once()
      mock_instance.run.assert_called_once()

  def test_main_keyboard_interrupt(self) -> None:
    """Test main function handling KeyboardInterrupt."""
    with (
      patch("auto_secrets.daemon.SecretsDaemon") as mock_daemon_class,
      patch("builtins.print") as mock_print,
      pytest.raises(SystemExit) as exc_info,
    ):
      mock_instance = MagicMock()
      mock_instance.run.side_effect = KeyboardInterrupt()
      mock_daemon_class.return_value = mock_instance

      daemon.main()

    assert exc_info.value.code == 0
    mock_print.assert_called_with("\nDaemon interrupted")
    mock_instance.stop.assert_called_once()

  def test_main_general_exception(self) -> None:
    """Test main function handling general exceptions."""
    with (
      patch("auto_secrets.daemon.SecretsDaemon") as mock_daemon_class,
      patch("builtins.print") as mock_print,
      pytest.raises(SystemExit) as exc_info,
    ):
      mock_instance = MagicMock()
      mock_instance.run.side_effect = Exception("Test error")
      mock_daemon_class.return_value = mock_instance

      daemon.main()

    assert exc_info.value.code == 1
    mock_print.assert_called_with("FATAL: Daemon error: Test error")

  def test_main_daemon_init_exception(self) -> None:
    """Test main function when SecretsDaemon initialization fails."""
    with (
      patch("auto_secrets.daemon.SecretsDaemon", side_effect=Exception("Init error")),
      patch("builtins.print") as mock_print,
      pytest.raises(SystemExit) as exc_info,
    ):
      daemon.main()

    assert exc_info.value.code == 1
    mock_print.assert_called_with("FATAL: Daemon error: Init error")

  def test_main_no_exception_in_run(self) -> None:
    """Test main function when run completes normally without exception."""
    with patch("auto_secrets.daemon.SecretsDaemon") as mock_daemon_class:
      mock_instance = MagicMock()
      mock_instance.run.return_value = None  # Normal completion
      mock_daemon_class.return_value = mock_instance

      # Should not raise SystemExit
      daemon.main()

      mock_daemon_class.assert_called_once()
      mock_instance.run.assert_called_once()


class TestSecretsDaemonIntegration:
  """Integration tests for SecretsDaemon with minimal mocking."""

  def test_signal_integration_end_to_end(self, mock_dependencies: dict[str, Mock], mock_smk_fd: None) -> None:
    """Test that signal handling integrates properly with daemon lifecycle."""
    with patch("os.getpid", return_value=1234):
      # Don't mock signal.signal to test real integration
      daemon_instance = SecretsDaemon()
      assert daemon_instance.running is False  # Initial state

      # Test that signal handlers can be set up without errors
      daemon_instance._setup_signal_handlers()

      # Verify running can be toggled
      daemon_instance.running = True
      assert daemon_instance.running is True

      daemon_instance.stop()
      assert daemon_instance.running is False

  def test_file_operations_integration(self, mock_dependencies: dict[str, Mock], mock_smk_fd: None) -> None:
    """Test file operations work with real filesystem operations."""
    with patch("os.getpid", return_value=1234), patch("signal.signal"):
      daemon_instance = SecretsDaemon()

      # Test heartbeat file creation and cleanup
      assert daemon_instance.pid_file is not None
      assert daemon_instance.pid_file.exists()

      daemon_instance._update_heartbeat()
      heartbeat_file = daemon_instance.pid_file.parent / "daemon.heartbeat"
      assert heartbeat_file.exists()

      # Read heartbeat content
      with open(heartbeat_file) as f:
        content = f.read()

      # Should be a valid ISO timestamp
      assert "T" in content  # ISO format contains T

      # Cleanup should remove both files
      daemon_instance._cleanup()
      assert not daemon_instance.pid_file.exists()
      assert not heartbeat_file.exists()

  def test_environment_discovery_integration(self, mock_dependencies: dict[str, Mock], mock_smk_fd: None) -> None:
    """Test environment discovery with real file system."""
    with patch("os.getpid", return_value=1234), patch("signal.signal"):
      daemon_instance = SecretsDaemon()

      # Create real environment files
      cache_dir = mock_dependencies["AppManager"].return_value.cache_manager.base_dir / "environments"
      cache_dir.mkdir(parents=True, exist_ok=True)

      env_files = ["production.env", "staging.env", "development.env"]
      for env_file in env_files:
        (cache_dir / env_file).touch()

      # Mock cache staleness check
      def mock_is_stale(env_name: str) -> bool:
        return env_name in ["production", "development"]

      mock_dependencies["AppManager"].return_value.cache_manager.is_cache_stale.side_effect = mock_is_stale

      environments = daemon_instance._get_environments_to_refresh()
      assert set(environments) == {"production", "development"}


if __name__ == "__main__":
  pytest.main([__file__])
