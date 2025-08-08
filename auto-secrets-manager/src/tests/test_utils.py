"""
Tests for auto_secrets.secret_managers.base module.

Tests the SecretManagerBase abstract class and related utilities.
"""

import pytest

from auto_secrets.core.utils import CommonUtils


class TestCommonUtils:
  """Test SecretManagerBase abstract class."""

  def test_parse_duration_seconds(self) -> None:
    """Test parsing duration in seconds."""
    test_cases = [
      ("30", 30),
      ("30s", 30),
      ("0", 0),
      ("0s", 0),
    ]

    for duration_str, expected in test_cases:
      assert CommonUtils.parse_duration(duration_str) == expected

  def test_parse_duration_minutes(self) -> None:
    """Test parsing duration in minutes."""
    test_cases = [
      ("5m", 300),
      ("1m", 60),
      ("15m", 900),
    ]

    for duration_str, expected in test_cases:
      assert CommonUtils.parse_duration(duration_str) == expected

  def test_parse_duration_hours(self) -> None:
    """Test parsing duration in hours."""
    test_cases = [
      ("1h", 3600),
      ("2h", 7200),
      ("24h", 86400),
    ]

    for duration_str, expected in test_cases:
      assert CommonUtils.parse_duration(duration_str) == expected

  def test_parse_duration_days(self) -> None:
    """Test parsing duration in days."""
    test_cases = [
      ("1d", 86400),
      ("7d", 604800),
    ]

    for duration_str, expected in test_cases:
      assert CommonUtils.parse_duration(duration_str) == expected

  def test_parse_duration_empty(self) -> None:
    """Test parsing empty duration string."""
    with pytest.raises(ValueError, match="Invalid duration format"):
      CommonUtils.parse_duration("")

  def test_parse_duration_invalid_format(self) -> None:
    """Test parsing invalid duration format."""
    invalid_durations = [
      "invalid",
      "5x",
      "abc",
      "5.5m",
      "-5m",
    ]

    for duration_str in invalid_durations:
      with pytest.raises(ValueError, match="Invalid duration format"):
        CommonUtils.parse_duration(duration_str)
