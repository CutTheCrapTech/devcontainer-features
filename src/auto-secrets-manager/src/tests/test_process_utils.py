"""
Comprehensive unit tests for ProcessUtils class.
"""

import ctypes
import signal
from unittest import TestCase
from unittest.mock import Mock, patch

from auto_secrets.core.process_utils import ProcessUtils
from auto_secrets.managers.log_manager import ComponentLoggerAdapter


class TestProcessUtils(TestCase):
  """Test suite for ProcessUtils class."""

  def setUp(self) -> None:
    """Set up test fixtures."""
    self.mock_logger = Mock(spec=ComponentLoggerAdapter)

  def test_class_structure(self) -> None:
    """Test that ProcessUtils has the expected structure."""
    # Verify it's a class with static methods
    assert hasattr(ProcessUtils, "set_parent_death_signal")
    assert callable(ProcessUtils.set_parent_death_signal)

    # Verify method is static
    import inspect

    assert isinstance(inspect.getattr_static(ProcessUtils, "set_parent_death_signal"), staticmethod)

  @patch("sys.platform", "darwin")
  def test_set_parent_death_signal_non_linux_platform(self) -> None:
    """Test that the method skips setup on non-Linux platforms."""
    ProcessUtils.set_parent_death_signal(self.mock_logger)

    # Should log debug message and return early
    self.mock_logger.debug.assert_called_once_with("Skipping parent death signal setup (not on Linux).")
    # Should not call any other logger methods
    self.mock_logger.warning.assert_not_called()
    self.mock_logger.info.assert_not_called()
    self.mock_logger.error.assert_not_called()

  @patch("sys.platform", "win32")
  def test_set_parent_death_signal_windows_platform(self) -> None:
    """Test that the method skips setup on Windows."""
    ProcessUtils.set_parent_death_signal(self.mock_logger)

    self.mock_logger.debug.assert_called_once_with("Skipping parent death signal setup (not on Linux).")

  @patch("sys.platform", "linux")
  @patch("ctypes.CDLL")
  def test_set_parent_death_signal_cdll_oserror(self, mock_cdll: Mock) -> None:
    """Test handling of OSError when getting C library handle."""
    mock_cdll.side_effect = OSError("Library not found")

    ProcessUtils.set_parent_death_signal(self.mock_logger)

    mock_cdll.assert_called_once_with(None)
    self.mock_logger.warning.assert_called_once_with(
      "Could not get handle to C library: Library not found. Parent death signal not set."
    )

  @patch("sys.platform", "linux")
  @patch("ctypes.CDLL")
  def test_set_parent_death_signal_prctl_not_found(self, mock_cdll: Mock) -> None:
    """Test handling when prctl function is not found in C library."""
    mock_libc = Mock()
    mock_cdll.return_value = mock_libc
    # Remove prctl attribute to simulate AttributeError
    del mock_libc.prctl

    ProcessUtils.set_parent_death_signal(self.mock_logger)

    self.mock_logger.warning.assert_called_once_with(
      "'prctl' function not found in C library. Parent death signal not set."
    )

  @patch("sys.platform", "linux")
  @patch("ctypes.CDLL")
  def test_set_parent_death_signal_success(self, mock_cdll: Mock) -> None:
    """Test successful parent death signal setup."""
    mock_libc = Mock()
    mock_prctl = Mock(return_value=0)
    mock_libc.prctl = mock_prctl
    mock_cdll.return_value = mock_libc

    ProcessUtils.set_parent_death_signal(self.mock_logger)

    # Verify C library setup
    mock_cdll.assert_called_once_with(None)

    # Verify prctl function configuration
    expected_argtypes = [ctypes.c_int, ctypes.c_int]
    assert mock_prctl.argtypes == expected_argtypes
    assert mock_prctl.restype == ctypes.c_int

    # Verify prctl call with correct arguments
    mock_prctl.assert_called_once_with(1, signal.SIGTERM)  # PR_SET_PDEATHSIG = 1

    # Verify success logging
    self.mock_logger.info.assert_called_once_with("Successfully set parent death signal (SIGTERM).")

  @patch("sys.platform", "linux")
  @patch("ctypes.CDLL")
  def test_set_parent_death_signal_prctl_failure(self, mock_cdll: Mock) -> None:
    """Test handling when prctl returns non-zero (failure)."""
    mock_libc = Mock()
    mock_prctl = Mock(return_value=1)  # Non-zero indicates failure
    mock_libc.prctl = mock_prctl
    mock_cdll.return_value = mock_libc

    ProcessUtils.set_parent_death_signal(self.mock_logger)

    # Verify prctl was called
    mock_prctl.assert_called_once_with(1, signal.SIGTERM)

    # Verify failure warning
    self.mock_logger.warning.assert_called_once_with("prctl(PR_SET_PDEATHSIG) failed with non-zero result: %d", 1)

  @patch("sys.platform", "linux")
  @patch("ctypes.CDLL")
  def test_set_parent_death_signal_prctl_exception(self, mock_cdll: Mock) -> None:
    """Test handling when prctl call raises an exception."""
    mock_libc = Mock()
    mock_prctl = Mock(side_effect=RuntimeError("Unexpected error"))
    mock_libc.prctl = mock_prctl
    mock_cdll.return_value = mock_libc

    ProcessUtils.set_parent_death_signal(self.mock_logger)

    # Verify exception handling
    self.mock_logger.error.assert_called_once_with("An unexpected error occurred when calling prctl: Unexpected error")

  @patch("sys.platform", "linux")
  @patch("ctypes.CDLL")
  def test_set_parent_death_signal_constants(self, mock_cdll: Mock) -> None:
    """Test that correct constants are used."""
    mock_libc = Mock()
    mock_prctl = Mock(return_value=0)
    mock_libc.prctl = mock_prctl
    mock_cdll.return_value = mock_libc

    ProcessUtils.set_parent_death_signal(self.mock_logger)

    # Verify PR_SET_PDEATHSIG constant value and SIGTERM signal
    mock_prctl.assert_called_once_with(1, signal.SIGTERM)

  def test_logger_parameter_type_annotation(self) -> None:
    """Test that logger parameter accepts ComponentLoggerAdapter type."""
    # This test verifies type compatibility
    logger: ComponentLoggerAdapter = Mock(spec=ComponentLoggerAdapter)

    # This should not raise any type checking errors
    with patch("sys.platform", "darwin"):
      ProcessUtils.set_parent_death_signal(logger)

  @patch("sys.platform", "linux")
  @patch("ctypes.CDLL")
  def test_method_return_type_is_none(self, mock_cdll: Mock) -> None:
    """Test that method returns None (implicit)."""
    mock_libc = Mock()
    mock_prctl = Mock(return_value=0)
    mock_libc.prctl = mock_prctl
    mock_cdll.return_value = mock_libc

    result = ProcessUtils.set_parent_death_signal(self.mock_logger)

    assert result is None

  @patch("sys.platform", "linux")
  @patch("ctypes.CDLL")
  def test_multiple_calls_are_safe(self, mock_cdll: Mock) -> None:
    """Test that multiple calls to the method are safe."""
    mock_libc = Mock()
    mock_prctl = Mock(return_value=0)
    mock_libc.prctl = mock_prctl
    mock_cdll.return_value = mock_libc

    # Call multiple times
    ProcessUtils.set_parent_death_signal(self.mock_logger)
    ProcessUtils.set_parent_death_signal(self.mock_logger)

    # Should have been called twice
    assert mock_prctl.call_count == 2
    assert self.mock_logger.info.call_count == 2

  @patch("sys.platform", "linux")
  @patch("ctypes.CDLL")
  def test_prctl_type_configuration(self, mock_cdll: Mock) -> None:
    """Test that prctl function types are configured correctly."""
    mock_libc = Mock()
    mock_prctl = Mock(return_value=0)
    mock_libc.prctl = mock_prctl
    mock_cdll.return_value = mock_libc

    ProcessUtils.set_parent_death_signal(self.mock_logger)

    # Verify type configuration
    assert mock_prctl.argtypes == [ctypes.c_int, ctypes.c_int]
    assert mock_prctl.restype == ctypes.c_int

  @patch("sys.platform", "linux")
  @patch("ctypes.CDLL")
  def test_edge_case_negative_return_value(self, mock_cdll: Mock) -> None:
    """Test handling of negative return value from prctl."""
    mock_libc = Mock()
    mock_prctl = Mock(return_value=-1)  # Negative return value
    mock_libc.prctl = mock_prctl
    mock_cdll.return_value = mock_libc

    ProcessUtils.set_parent_death_signal(self.mock_logger)

    self.mock_logger.warning.assert_called_once_with("prctl(PR_SET_PDEATHSIG) failed with non-zero result: %d", -1)

  def test_logger_interface_compatibility(self) -> None:
    """Test that all required logger methods are called correctly."""
    # Create a more realistic mock that tracks calls
    logger_mock = Mock(spec=ComponentLoggerAdapter)

    with patch("sys.platform", "darwin"):
      ProcessUtils.set_parent_death_signal(logger_mock)

    # Verify the mock has all expected methods
    assert hasattr(logger_mock, "debug")
    assert hasattr(logger_mock, "info")
    assert hasattr(logger_mock, "warning")
    assert hasattr(logger_mock, "error")


# Type checking tests - these will be caught by mypy
def test_mypy_compatibility() -> None:
  """Test cases specifically for mypy type checking."""

  # Valid logger types
  logger: ComponentLoggerAdapter = Mock(spec=ComponentLoggerAdapter)

  # This should pass type checking
  ProcessUtils.set_parent_death_signal(logger)

  # Test that return type is correctly inferred as None
  result: None = ProcessUtils.set_parent_death_signal(logger)
  assert result is None


# Integration-style tests
class TestProcessUtilsIntegration(TestCase):
  """Integration tests for ProcessUtils."""

  def setUp(self) -> None:
    """Set up integration test fixtures."""
    self.logger = Mock(spec=ComponentLoggerAdapter)

  @patch("sys.platform", "linux")
  def test_full_linux_workflow_success(self) -> None:
    """Test the complete workflow on Linux with successful prctl call."""
    with patch("ctypes.CDLL") as mock_cdll:
      mock_libc = Mock()
      mock_prctl = Mock(return_value=0)
      mock_libc.prctl = mock_prctl
      mock_cdll.return_value = mock_libc

      ProcessUtils.set_parent_death_signal(self.logger)

      # Verify complete workflow
      mock_cdll.assert_called_once_with(None)
      assert mock_prctl.argtypes == [ctypes.c_int, ctypes.c_int]
      assert mock_prctl.restype == ctypes.c_int
      mock_prctl.assert_called_once_with(1, signal.SIGTERM)
      self.logger.info.assert_called_once_with("Successfully set parent death signal (SIGTERM).")

  @patch("sys.platform", "linux")
  def test_full_linux_workflow_with_errors(self) -> None:
    """Test the complete workflow with various error conditions."""
    # Test OSError in CDLL
    with patch("ctypes.CDLL", side_effect=OSError("Test error")):
      ProcessUtils.set_parent_death_signal(self.logger)
      self.logger.warning.assert_called_with(
        "Could not get handle to C library: Test error. Parent death signal not set."
      )

    self.logger.reset_mock()

    # Test AttributeError for missing prctl
    with patch("ctypes.CDLL") as mock_cdll:
      mock_libc = Mock()
      del mock_libc.prctl  # Simulate missing prctl
      mock_cdll.return_value = mock_libc

      ProcessUtils.set_parent_death_signal(self.logger)
      self.logger.warning.assert_called_with("'prctl' function not found in C library. Parent death signal not set.")


if __name__ == "__main__":
  import unittest

  unittest.main()
