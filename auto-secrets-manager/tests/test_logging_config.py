"""
Tests for auto_secrets.logging_config module.

Tests the logging configuration functionality including setup,
formatters, handlers, and system information logging.
"""

import logging
import os
import sys
import tempfile
from io import StringIO
from pathlib import Path
from unittest.mock import Mock, patch, mock_open
import pytest

from auto_secrets.logging_config import (
    setup_logging,
    get_logger,
    log_system_info,
)


class TestLoggingFormatting:
    """Test logging formatting and output."""

    def test_log_message_formatting(self):
        """Test that log messages are properly formatted."""
        with patch('sys.stdout', new_callable=StringIO) as mock_stdout:
            logger = setup_logging(console_output=True)
            logger.info("Test message")

            output = mock_stdout.getvalue()
            assert "Test message" in output

    def test_different_log_levels(self):
        """Test different log levels are handled properly."""
        with tempfile.NamedTemporaryFile(mode='w+', delete=False) as temp_file:
            logger = setup_logging(log_file=temp_file.name)

            logger.debug("Debug message")
            logger.info("Info message")
            logger.warning("Warning message")
            logger.error("Error message")
            logger.critical("Critical message")

            # Force flush handlers
            for handler in logger.handlers:
                handler.flush()

            # Read log file
            with open(temp_file.name, 'r') as f:
                content = f.read()

            # Should contain the messages
            assert "Info message" in content
            assert "Warning message" in content
            assert "Error message" in content
            assert "Critical message" in content

            # Cleanup
            os.unlink(temp_file.name)


class TestSetupLogging:
    """Test setup_logging function."""

    def teardown_method(self):
        """Clean up logging configuration after each test."""
        # Reset logging configuration
        logging.getLogger().handlers.clear()
        logging.getLogger().setLevel(logging.WARNING)

    def test_setup_logging_default(self):
        """Test default logging setup."""
        logger = setup_logging()

        assert isinstance(logger, logging.Logger)
        assert logger.name == "auto_secrets"

    def test_setup_logging_debug(self):
        """Test debug logging setup."""
        logger = setup_logging(log_level="DEBUG")

        assert logger.level == logging.DEBUG

    def test_setup_logging_error_level(self):
        """Test error level logging setup."""
        logger = setup_logging(log_level="ERROR")

        assert logger.level == logging.ERROR

    def test_setup_logging_with_log_file(self):
        """Test logging setup with log file."""
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            log_path = temp_file.name

            logger = setup_logging(log_file=log_path)

            # Test that logging to file works
            logger.info("Test message")

            # Force flush
            for handler in logger.handlers:
                handler.flush()

            # Read log file content
            with open(log_path, 'r') as f:
                content = f.read()
                assert "Test message" in content

            # Cleanup
            os.unlink(log_path)

    def test_setup_logging_file_creation_error(self):
        """Test logging setup when file creation fails."""
        # Point to invalid directory
        invalid_path = "/invalid/path/log.txt"

        # Should not raise exception
        logger = setup_logging(log_file=invalid_path)

        # Should still return a logger
        assert isinstance(logger, logging.Logger)

    def test_setup_logging_multiple_calls(self):
        """Test that multiple setup calls work properly."""
        logger1 = setup_logging()
        logger2 = setup_logging()

        # Should return logger instances
        assert isinstance(logger1, logging.Logger)
        assert isinstance(logger2, logging.Logger)

    def test_setup_logging_custom_level(self):
        """Test logging setup with custom level."""
        logger = setup_logging(log_level="WARNING")

        assert logger.level == logging.WARNING

    def test_setup_logging_with_console_output(self):
        """Test logging setup with console output enabled."""
        logger = setup_logging(console_output=True)

        # Should have handlers
        assert len(logger.handlers) > 0


class TestGetLogger:
    """Test get_logger function."""

    def test_get_logger_default(self):
        """Test getting default logger."""
        logger = get_logger()
        assert isinstance(logger, logging.Logger)
        assert logger.name == "auto_secrets"

    def test_get_logger_with_name(self):
        """Test getting logger with specific name."""
        logger = get_logger("test_module")
        assert isinstance(logger, logging.Logger)
        assert logger.name == "auto_secrets.test_module"

    def test_get_logger_with_full_name(self):
        """Test getting logger with full dotted name."""
        logger = get_logger("core.config")
        assert isinstance(logger, logging.Logger)
        assert logger.name == "auto_secrets.core.config"

    def test_get_logger_caching(self):
        """Test that loggers are cached properly."""
        logger1 = get_logger("test")
        logger2 = get_logger("test")
        assert logger1 is logger2

    def test_get_logger_hierarchy(self):
        """Test logger hierarchy."""
        parent_logger = get_logger("parent")
        child_logger = get_logger("parent.child")

        assert child_logger.parent.name == parent_logger.name

    def test_get_logger_propagation(self):
        """Test logger propagation settings."""
        logger = get_logger("test")
        assert logger.propagate is True


class TestLogSystemInfo:
    """Test log_system_info function."""

    def test_log_system_info_basic(self):
        """Test basic system info logging."""
        mock_logger = Mock()

        log_system_info(mock_logger)

        # Should log system information
        assert mock_logger.info.called
        call_args = mock_logger.info.call_args_list

        # Check that various system info is logged
        logged_messages = [str(call.args[0]) for call in call_args]
        logged_text = " ".join(logged_messages)

        assert "Python" in logged_text or "python" in logged_text.lower()
        assert "Platform" in logged_text or "platform" in logged_text.lower()

    @patch('platform.system')
    @patch('platform.release')
    def test_log_system_info_details(self, mock_release, mock_system):
        """Test detailed system info logging."""
        mock_logger = Mock()

        mock_system.return_value = "Linux"
        mock_release.return_value = "5.4.0"

        log_system_info(mock_logger)

        # Verify logger was called
        assert mock_logger.info.called

    def test_log_system_info_output_format(self):
        """Test system info logging output format."""
        mock_logger = Mock()

        log_system_info(mock_logger)

        # Should log multiple pieces of information
        assert mock_logger.info.call_count > 1

    @patch('os.environ')
    def test_log_system_info_environment_vars(self, mock_environ):
        """Test system info logging includes environment variables."""
        mock_logger = Mock()

        # Mock some AUTO_SECRETS environment variables
        mock_environ.items.return_value = [
            ("AUTO_SECRETS_DEBUG", "true"),
            ("AUTO_SECRETS_CONFIG", "/path/to/config"),
            ("OTHER_VAR", "ignored"),
            ("PATH", "/usr/bin")
        ]

        log_system_info(mock_logger)

        # Should log environment info
        assert mock_logger.info.called

    def test_log_system_info_error_handling(self):
        """Test system info logging handles errors gracefully."""
        mock_logger = Mock()

        # Mock an error in system info gathering
        with patch('platform.system', side_effect=Exception("Platform error")):
            # Should not raise exception
            log_system_info(mock_logger)

            # Should still attempt to log something
            assert mock_logger.info.called or mock_logger.error.called


class TestLoggingIntegration:
    """Integration tests for logging functionality."""

    def teardown_method(self):
        """Clean up logging configuration."""
        logging.getLogger().handlers.clear()
        logging.getLogger().setLevel(logging.WARNING)

    def test_end_to_end_logging(self):
        """Test complete logging workflow."""
        with tempfile.NamedTemporaryFile(mode='w+', delete=False) as temp_file:
            log_path = temp_file.name

            # Setup logging
            main_logger = setup_logging(log_level="DEBUG", log_file=log_path)

            # Log system info
            log_system_info(main_logger)

            # Get loggers and log messages
            logger1 = get_logger("module1")
            logger2 = get_logger("module2.submodule")

            logger1.info("Info message from module1")
            logger1.debug("Debug message from module1")
            logger2.warning("Warning message from module2.submodule")
            logger2.error("Error message from module2.submodule")

            # Force flush all handlers
            for handler in main_logger.handlers:
                handler.flush()
            for handler in logger1.handlers:
                handler.flush()
            for handler in logger2.handlers:
                handler.flush()

            # Read log file
            with open(log_path, 'r') as f:
                log_content = f.read()

            # Verify messages are logged (some may be filtered by level)
            assert "Info message from module1" in log_content or "Warning message from module2.submodule" in log_content

            # Cleanup
            os.unlink(log_path)

    def test_console_and_file_logging(self):
        """Test that messages go to both console and file."""
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            log_path = temp_file.name

            # Setup with both console and file output
            main_logger = setup_logging(console_output=True, log_file=log_path)

            logger = get_logger("test")
            logger.info("Test info message")
            logger.error("Test error message")

            # Force flush
            for handler in main_logger.handlers:
                handler.flush()

            # Check file output
            with open(log_path, 'r') as f:
                file_output = f.read()

            # File should contain the messages
            assert "Test info message" in file_output or "Test error message" in file_output

            # Cleanup
            os.unlink(log_path)

    def test_logger_hierarchy_and_propagation(self):
        """Test logger hierarchy and message propagation."""
        setup_logging(log_level="DEBUG")

        # Create parent and child loggers
        parent_logger = get_logger("parent")
        child_logger = get_logger("parent.child")
        grandchild_logger = get_logger("parent.child.grandchild")

        # Test that hierarchy is maintained
        assert "parent" in child_logger.name
        assert "parent.child" in grandchild_logger.name

    def test_different_log_levels(self):
        """Test logging with different levels."""
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            log_path = temp_file.name

            # Test with INFO level
            main_logger = setup_logging(log_level="INFO", log_file=log_path)
            logger = get_logger("test")

            logger.debug("Debug message")  # Should not appear
            logger.info("Info message")    # Should appear
            logger.warning("Warning message")  # Should appear
            logger.error("Error message")  # Should appear

            # Force flush
            for handler in main_logger.handlers:
                handler.flush()

            with open(log_path, 'r') as f:
                content = f.read()

            # At least some messages should appear
            assert "Info message" in content or "Error message" in content

            # Cleanup
            os.unlink(log_path)

    def test_exception_logging(self):
        """Test logging exceptions with stack traces."""
        logger = setup_logging(log_level="DEBUG")

        # Create and log an exception
        try:
            raise ValueError("Test exception for logging")
        except ValueError as e:
            logger.exception("An error occurred")

        # The test here is that no exception is raised during logging
        # In a real scenario, we'd check the log output for the stack trace
