"""
Comprehensive unit tests for Auto Secrets Manager logging configuration.

Tests all functionality including logger setup, component adapters, configuration,
file handling, and error scenarios.
"""

import logging
import logging.handlers
import os
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any, Optional
from unittest.mock import MagicMock, Mock, patch

from auto_secrets.managers.log_manager import (
  AutoSecretsLogger,
  AutoSecretsLoggerConfig,
  ComponentLoggerAdapter,
)


class TestAutoSecretsLoggerConfig(unittest.TestCase):
  """Test cases for AutoSecretsLoggerConfig dataclass."""

  def setUp(self) -> None:
    """Set up test environment."""
    # Store original env vars for cleanup
    self.original_env: dict[str, Optional[str]] = {}
    for var in ["AUTO_SECRETS_LOG_DIR", "AUTO_SECRETS_LOG_LEVEL"]:
      self.original_env[var] = os.environ.get(var)

  def tearDown(self) -> None:
    """Clean up test environment."""
    # Restore original env vars
    for var, value in self.original_env.items():
      if value is None:
        os.environ.pop(var, None)
      else:
        os.environ[var] = value

  def test_config_default_values(self) -> None:
    """Test config with default values."""
    config = AutoSecretsLoggerConfig(log_dir="/default/log", log_level="INFO", log_file="test.log")

    self.assertEqual(config.log_dir, "/default/log")
    self.assertEqual(config.log_level, "INFO")
    self.assertEqual(config.log_file, "test.log")

  def test_config_environment_override(self) -> None:
    """Test config overrides from environment variables."""
    os.environ["AUTO_SECRETS_LOG_DIR"] = "/env/log"
    os.environ["AUTO_SECRETS_LOG_LEVEL"] = "DEBUG"

    config = AutoSecretsLoggerConfig(log_dir="/default/log", log_level="INFO", log_file="test.log")

    self.assertEqual(config.log_dir, "/env/log")
    self.assertEqual(config.log_level, "DEBUG")
    self.assertEqual(config.log_file, "test.log")  # Not overridden

  def test_config_partial_environment_override(self) -> None:
    """Test config with only some env vars set."""
    os.environ["AUTO_SECRETS_LOG_LEVEL"] = "WARNING"
    # Don't set AUTO_SECRETS_LOG_DIR

    config = AutoSecretsLoggerConfig(log_dir="/default/log", log_level="INFO", log_file="test.log")

    self.assertEqual(config.log_dir, "/default/log")
    self.assertEqual(config.log_level, "WARNING")
    self.assertEqual(config.log_file, "test.log")


class TestComponentLoggerAdapter(unittest.TestCase):
  """Test cases for ComponentLoggerAdapter."""

  def setUp(self) -> None:
    """Set up test fixtures."""
    self.mock_logger = Mock(spec=logging.Logger)
    self.component = "test-component"
    self.adapter = ComponentLoggerAdapter(self.mock_logger, self.component)

  def test_adapter_initialization(self) -> None:
    """Test adapter initialization."""
    self.assertEqual(self.adapter.component, self.component)
    self.assertEqual(self.adapter.logger, self.mock_logger)

    # Handle the case where extra might be None
    assert self.adapter.extra is not None
    self.assertEqual(self.adapter.extra["component"], self.component)

  def test_process_method_adds_component(self) -> None:
    """Test that process method adds component to extra data."""
    msg = "Test message"
    kwargs: dict[str, Any] = {}

    processed_msg, processed_kwargs = self.adapter.process(msg, kwargs)

    self.assertEqual(processed_msg, msg)
    self.assertIn("extra", processed_kwargs)
    self.assertEqual(processed_kwargs["extra"]["component"], self.component)

  def test_process_method_preserves_existing_extra(self) -> None:
    """Test that process method preserves existing extra data."""
    msg = "Test message"
    kwargs: dict[str, Any] = {"extra": {"existing_key": "existing_value"}}

    processed_msg, processed_kwargs = self.adapter.process(msg, kwargs)

    self.assertEqual(processed_msg, msg)
    self.assertEqual(processed_kwargs["extra"]["existing_key"], "existing_value")
    self.assertEqual(processed_kwargs["extra"]["component"], self.component)

  def test_process_method_overwrites_component(self) -> None:
    """Test that process method overwrites existing component in extra."""
    msg = "Test message"
    kwargs: dict[str, Any] = {"extra": {"component": "old-component"}}

    processed_msg, processed_kwargs = self.adapter.process(msg, kwargs)

    self.assertEqual(processed_kwargs["extra"]["component"], self.component)


class TestAutoSecretsLogger(unittest.TestCase):
  """Test cases for AutoSecretsLogger."""

  def setUp(self) -> None:
    """Set up test fixtures."""
    self.temp_dir = tempfile.mkdtemp()
    self.temp_log_path = Path(self.temp_dir)

    # Store original env vars
    self.original_env: dict[str, Optional[str]] = {}
    env_vars = ["AUTO_SECRETS_LOG_DIR", "AUTO_SECRETS_LOG_LEVEL"]
    for var in env_vars:
      self.original_env[var] = os.environ.get(var)

  def tearDown(self) -> None:
    """Clean up test fixtures."""
    # Restore env vars
    for var, value in self.original_env.items():
      if value is None:
        os.environ.pop(var, None)
      else:
        os.environ[var] = value

    # Clean up temp directory
    import shutil

    shutil.rmtree(self.temp_dir, ignore_errors=True)

  @patch("pathlib.Path.mkdir")
  @patch("logging.handlers.RotatingFileHandler")
  def test_logger_initialization_default(self, mock_file_handler: Mock, mock_mkdir: Mock) -> None:
    """Test logger initialization with default settings."""
    mock_handler_instance = Mock()
    mock_file_handler.return_value = mock_handler_instance

    logger = AutoSecretsLogger()

    self.assertEqual(logger.log_level, "INFO")
    self.assertEqual(logger.log_dir, "/var/log/auto-secrets")
    self.assertEqual(logger.log_file, "auto-secrets.log")
    self.assertFalse(logger.console_output)
    self.assertIsNotNone(logger._base_logger)

    mock_mkdir.assert_called_once()
    mock_file_handler.assert_called_once()

  def test_logger_initialization_custom_params(self) -> None:
    """Test logger initialization with custom parameters."""
    with patch("pathlib.Path.mkdir"), patch("logging.handlers.RotatingFileHandler"):
      logger = AutoSecretsLogger(log_file="custom.log", console_output=True)

      self.assertEqual(logger.log_file, "custom.log")
      self.assertTrue(logger.console_output)

  @patch("pathlib.Path.mkdir")
  @patch("logging.handlers.RotatingFileHandler")
  def test_logger_initialization_with_env_vars(self, mock_file_handler: Mock, mock_mkdir: Mock) -> None:
    """Test logger initialization with environment variables."""
    os.environ["AUTO_SECRETS_LOG_DIR"] = str(self.temp_log_path)
    os.environ["AUTO_SECRETS_LOG_LEVEL"] = "DEBUG"

    mock_handler_instance = Mock()
    mock_file_handler.return_value = mock_handler_instance

    logger = AutoSecretsLogger()

    self.assertEqual(logger.log_level, "DEBUG")
    self.assertEqual(logger.log_dir, str(self.temp_log_path))

  @patch("pathlib.Path.mkdir", side_effect=PermissionError("Access denied"))
  @patch("logging.StreamHandler")
  @patch("sys.stderr", new_callable=MagicMock)
  def test_logger_file_permission_error_fallback(
    self, mock_stderr: Mock, mock_stream_handler: Mock, mock_mkdir: Mock
  ) -> None:
    """Test logger falls back to console when file permissions fail."""
    mock_handler_instance = Mock()
    mock_stream_handler.return_value = mock_handler_instance
    logger = AutoSecretsLogger()
    # Should fall back to console output
    self.assertTrue(logger.console_output)
    mock_stream_handler.assert_called_once_with(sys.stderr)

  def test_get_logger_default_params(self) -> None:
    """Test get_logger with default parameters."""
    with patch("pathlib.Path.mkdir"), patch("logging.handlers.RotatingFileHandler"):
      logger = AutoSecretsLogger()
      component_logger = logger.get_logger(None, None)

      self.assertIsInstance(component_logger, ComponentLoggerAdapter)
      self.assertEqual(component_logger.component, "system")

  def test_get_logger_custom_params(self) -> None:
    """Test get_logger with custom parameters."""
    with patch("pathlib.Path.mkdir"), patch("logging.handlers.RotatingFileHandler"):
      logger = AutoSecretsLogger()
      component_logger = logger.get_logger("test_module", "test_component")

      self.assertIsInstance(component_logger, ComponentLoggerAdapter)
      self.assertEqual(component_logger.component, "test_component")

  def test_get_logger_caching(self) -> None:
    """Test that get_logger caches logger instances."""
    with patch("pathlib.Path.mkdir"), patch("logging.handlers.RotatingFileHandler"):
      logger = AutoSecretsLogger()

      # Get same logger twice
      logger1 = logger.get_logger("test", "component")
      logger2 = logger.get_logger("test", "component")

      # Should be the same instance due to caching
      self.assertIs(logger1, logger2)

  def test_get_logger_different_cache_keys(self) -> None:
    """Test that different name/component combinations create different loggers."""
    with patch("pathlib.Path.mkdir"), patch("logging.handlers.RotatingFileHandler"):
      logger = AutoSecretsLogger()

      logger1 = logger.get_logger("test1", "component1")
      logger2 = logger.get_logger("test2", "component2")
      logger3 = logger.get_logger("test1", "component2")  # Different component

      self.assertIsNot(logger1, logger2)
      self.assertIsNot(logger1, logger3)
      self.assertIsNot(logger2, logger3)

  def test_logger_name_formatting(self) -> None:
    """Test logger name formatting logic."""
    with (
      patch("pathlib.Path.mkdir"),
      patch("logging.handlers.RotatingFileHandler"),
      patch("logging.getLogger") as mock_get_logger,
    ):
      logger = AutoSecretsLogger()
      # Test different name scenarios
      test_cases = [
        ("auto_secrets", "auto_secrets"),
        ("auto_secrets.module", "auto_secrets.module"),
        ("module", "auto_secrets.module"),
        (None, "auto_secrets"),
      ]

      for input_name, expected_name in test_cases:
        # Clear the logger cache to force new getLogger calls
        logger.clear_cache()
        # Reset the mock before each test case
        mock_get_logger.reset_mock()

        logger.get_logger(input_name, "component")
        mock_get_logger.assert_called_with(expected_name)

  @patch("sys.version", "3.9.0")
  @patch("sys.platform", "linux")
  @patch("os.getcwd")
  @patch.dict(
    os.environ,
    {
      "USER": "testuser",
      "HOME": "/home/testuser",
      "PATH": "/usr/bin",
      "AUTO_SECRETS_DEBUG": "true",
      "AUTO_SECRETS_SECRET_MANAGER": "vault",
      "AUTO_SECRETS_API_KEY": "secret123",
    },
  )
  def test_log_system_info(self, mock_getcwd: Mock) -> None:
    """Test system info logging."""
    mock_getcwd.return_value = "/test/dir"

    with patch("pathlib.Path.mkdir"), patch("logging.handlers.RotatingFileHandler"):
      logger = AutoSecretsLogger()

      # Mock the component logger to capture log calls
      mock_component_logger = Mock()
      with patch.object(logger, "get_logger", return_value=mock_component_logger):
        logger.log_system_info()

      # Verify info method was called multiple times
      self.assertTrue(mock_component_logger.info.called)
      call_args_list = [call[0][0] for call in mock_component_logger.info.call_args_list]

      # Check that system info was logged
      system_info_found = any("Python version: 3.9.0" in arg for arg in call_args_list)
      self.assertTrue(system_info_found)

      # Check that sensitive values are redacted
      redacted_found = any("***REDACTED***" in arg for arg in call_args_list)
      self.assertTrue(redacted_found)

  def test_set_log_level(self) -> None:
    """Test changing log level."""
    with patch("pathlib.Path.mkdir"), patch("logging.handlers.RotatingFileHandler"):
      logger = AutoSecretsLogger()

      # Mock the base logger and its methods
      mock_base_logger = Mock()
      mock_handler = Mock()
      mock_base_logger.handlers = [mock_handler]
      logger._base_logger = mock_base_logger

      logger.set_log_level("DEBUG")

      self.assertEqual(logger.log_level, "DEBUG")
      mock_base_logger.setLevel.assert_called_with(logging.DEBUG)
      mock_handler.setLevel.assert_called_with(logging.DEBUG)

  def test_set_log_level_invalid(self) -> None:
    """Test setting invalid log level falls back to default."""
    with patch("pathlib.Path.mkdir"), patch("logging.handlers.RotatingFileHandler"):
      logger = AutoSecretsLogger()

      # This should not raise an exception
      logger.set_log_level("INVALID_LEVEL")

      # Should fall back to some default behavior
      self.assertIsNotNone(logger.log_level)

  @patch("logging.StreamHandler")
  def test_add_console_output(self, mock_stream_handler: Mock) -> None:
    """Test adding console output."""
    mock_handler_instance = Mock()
    mock_stream_handler.return_value = mock_handler_instance

    with patch("pathlib.Path.mkdir"), patch("logging.handlers.RotatingFileHandler"):
      logger = AutoSecretsLogger(console_output=False)

      # Mock the base logger
      mock_base_logger = Mock()
      logger._base_logger = mock_base_logger

      self.assertFalse(logger.console_output)
      logger.add_console_output()
      self.assertTrue(logger.console_output)

      mock_stream_handler.assert_called_with(sys.stderr)
      mock_base_logger.addHandler.assert_called_with(mock_handler_instance)

  def test_add_console_output_already_enabled(self) -> None:
    """Test adding console output when already enabled."""
    with patch("pathlib.Path.mkdir"), patch("logging.handlers.RotatingFileHandler"), patch("logging.StreamHandler"):
      logger = AutoSecretsLogger(console_output=True)

      # Mock the base logger
      mock_base_logger = Mock()
      mock_base_logger.handlers = [Mock(), Mock()]  # Mock some existing handlers
      logger._base_logger = mock_base_logger

      initial_handler_count = len(mock_base_logger.handlers)
      logger.add_console_output()

      # Should not add another handler
      self.assertEqual(len(mock_base_logger.handlers), initial_handler_count)

  def test_remove_console_output(self) -> None:
    """Test removing console output."""
    with patch("pathlib.Path.mkdir"), patch("logging.handlers.RotatingFileHandler"):
      # Create logger with console output
      logger = AutoSecretsLogger(console_output=True)

      # Mock the base logger and its methods
      mock_base_logger = Mock()
      mock_stream_handler = Mock(spec=logging.StreamHandler)
      mock_stream_handler.stream = sys.stderr
      mock_base_logger.handlers = [mock_stream_handler]
      logger._base_logger = mock_base_logger

      logger.remove_console_output()

      self.assertFalse(logger.console_output)
      mock_base_logger.removeHandler.assert_called()
      mock_stream_handler.close.assert_called_once()

  def test_remove_console_output_not_enabled(self) -> None:
    """Test removing console output when not enabled."""
    with patch("pathlib.Path.mkdir"), patch("logging.handlers.RotatingFileHandler"):
      logger = AutoSecretsLogger(console_output=False)

      # Mock the base logger
      mock_base_logger = Mock()
      mock_base_logger.handlers = [Mock()]  # Mock some existing handlers
      logger._base_logger = mock_base_logger

      initial_handler_count = len(mock_base_logger.handlers)
      logger.remove_console_output()

      # Should not affect handlers
      self.assertEqual(len(mock_base_logger.handlers), initial_handler_count)

  def test_clear_cache(self) -> None:
    """Test clearing the logger cache."""
    with patch("pathlib.Path.mkdir"), patch("logging.handlers.RotatingFileHandler"):
      logger = AutoSecretsLogger()

      # Add some loggers to cache
      logger.get_logger("test1", "comp1")
      logger.get_logger("test2", "comp2")

      self.assertGreater(len(logger._logger_cache), 0)

      logger.clear_cache()

      self.assertEqual(len(logger._logger_cache), 0)

  def test_base_logger_property(self) -> None:
    """Test base_logger property."""
    with patch("pathlib.Path.mkdir"), patch("logging.handlers.RotatingFileHandler"):
      logger = AutoSecretsLogger()
      base_logger = logger.base_logger

      self.assertIsInstance(base_logger, logging.Logger)
      self.assertEqual(base_logger.name, "auto_secrets")

  def test_base_logger_property_not_initialized(self) -> None:
    """Test base_logger property when not initialized."""
    logger = AutoSecretsLogger.__new__(AutoSecretsLogger)  # Create without __init__
    logger._base_logger = None

    with self.assertRaises(RuntimeError) as context:
      _ = logger.base_logger

    self.assertIn("Logger not initialized", str(context.exception))

  def test_log_file_path_property(self) -> None:
    """Test log_file_path property."""
    with patch("pathlib.Path.mkdir"), patch("logging.handlers.RotatingFileHandler"):
      logger = AutoSecretsLogger()
      log_file_path = logger.log_file_path

      expected_path = Path(logger.log_dir) / logger.DEFAULT_LOG_FILE
      self.assertEqual(log_file_path, expected_path)

  def test_is_debug_enabled_property(self) -> None:
    """Test is_debug_enabled property."""
    with patch("pathlib.Path.mkdir"), patch("logging.handlers.RotatingFileHandler"):
      # Test with INFO level (debug disabled)
      logger = AutoSecretsLogger()

      # Mock the base logger
      mock_base_logger = Mock()
      mock_base_logger.level = logging.INFO
      logger._base_logger = mock_base_logger
      self.assertFalse(logger.is_debug_enabled)

      # Test with DEBUG level (debug enabled)
      mock_base_logger.level = logging.DEBUG
      self.assertTrue(logger.is_debug_enabled)

      # Test with uninitialized logger
      logger._base_logger = None
      self.assertFalse(logger.is_debug_enabled)

  def test_constants_defined(self) -> None:
    """Test that class constants are properly defined."""
    self.assertEqual(AutoSecretsLogger.DEFAULT_LOG_DIR, "/var/log/auto-secrets")
    self.assertEqual(AutoSecretsLogger.DEFAULT_LOG_FILE, "auto-secrets.log")
    self.assertEqual(AutoSecretsLogger.DEFAULT_LOG_LEVEL, "INFO")
    self.assertEqual(AutoSecretsLogger.DEFAULT_MAX_BYTES, 10 * 1024 * 1024)
    self.assertEqual(AutoSecretsLogger.DEFAULT_BACKUP_COUNT, 5)
    self.assertIsInstance(AutoSecretsLogger.LOG_FORMAT, str)
    self.assertIsInstance(AutoSecretsLogger.DATE_FORMAT, str)

  def test_log_format_contains_component(self) -> None:
    """Test that log format includes component placeholder."""
    self.assertIn("%(component)s", AutoSecretsLogger.LOG_FORMAT)


class TestAutoSecretsLoggerIntegration(unittest.TestCase):
  """Integration tests for AutoSecretsLogger with real file operations."""

  def setUp(self) -> None:
    """Set up test fixtures."""
    self.temp_dir = tempfile.mkdtemp()
    self.temp_log_path = Path(self.temp_dir)

  def tearDown(self) -> None:
    """Clean up test fixtures."""
    import shutil

    shutil.rmtree(self.temp_dir, ignore_errors=True)

  def test_real_file_logging(self) -> None:
    """Test actual file logging functionality."""
    # Set environment to use temp directory
    with patch.dict(os.environ, {"AUTO_SECRETS_LOG_DIR": str(self.temp_log_path), "AUTO_SECRETS_LOG_LEVEL": "DEBUG"}):
      logger = AutoSecretsLogger()
      component_logger = logger.get_logger("test_module", "integration_test")

      # Log some messages
      component_logger.info("Test info message")
      component_logger.warning("Test warning message")
      component_logger.error("Test error message")

      # Check that log file was created
      log_file = self.temp_log_path / "auto-secrets.log"
      self.assertTrue(log_file.exists())

      # Read and verify log content
      log_content = log_file.read_text()
      self.assertIn("Test info message", log_content)
      self.assertIn("Test warning message", log_content)
      self.assertIn("Test error message", log_content)
      self.assertIn("[integration_test]", log_content)

  def test_log_rotation_setup(self) -> None:
    """Test that log rotation is properly configured."""
    with patch.dict(os.environ, {"AUTO_SECRETS_LOG_DIR": str(self.temp_log_path)}):
      logger = AutoSecretsLogger()

      # Find the RotatingFileHandler
      rotating_handler = None
      for handler in logger.base_logger.handlers:
        if isinstance(handler, logging.handlers.RotatingFileHandler):
          rotating_handler = handler
          break

      self.assertIsNotNone(rotating_handler)
      if rotating_handler:
        self.assertEqual(rotating_handler.maxBytes, AutoSecretsLogger.DEFAULT_MAX_BYTES)
        self.assertEqual(rotating_handler.backupCount, AutoSecretsLogger.DEFAULT_BACKUP_COUNT)


if __name__ == "__main__":
  # Configure test runner
  unittest.main(verbosity=2)
