"""
Auto Secrets Manager - Common Utilities Module

Parse Duration.
"""

import re


class CommonUtils:
  @staticmethod
  def parse_duration(duration_str: str) -> int:
    """
    Parse duration string to seconds.

    Args:
        duration_str: Duration string like "5m", "1h", "30s"

    Returns:
        int: Duration in seconds

    Raises:
        ValueError: If duration format is invalid
    """
    if not duration_str:
      raise ValueError(f"Invalid duration format: {duration_str}")

    duration_str = duration_str.strip().lower()
    match = re.match(r"^(\d+)([smhd]?)$", duration_str)

    if not match:
      raise ValueError(f"Invalid duration format: {duration_str}")

    number, unit = match.groups()
    number = int(number)

    multipliers = {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400}

    return number * multipliers.get(unit, 1)
