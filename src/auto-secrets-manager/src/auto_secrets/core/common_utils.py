import json
import re
from typing import Any


class UtilsError(Exception):
  """Branch config related errors."""

  pass


class CommonUtils:
  """
  Utility class for parsing environment variables and JSON strings.

  Provides methods to parse environment variables and JSON strings
  with error handling.
  """

  @staticmethod
  def parse_json(env_variable: str, json_str: str) -> Any:
    """Parse JSON from environment variable."""
    try:
      return json.loads(json_str)
    except json.JSONDecodeError as e:
      raise UtilsError(f"Invalid {env_variable} JSON: {e}") from None

  @staticmethod
  def get_regex_from_pattern(pattern: str) -> re.Pattern:
    """
    Convert shell-style pattern to regex pattern.

    Args:
        pattern: Shell-style pattern (with *, **, ? wildcards)

    Returns:
      re.Pattern: Compiled regex pattern, or raises UtilsError if conversion fails
    """
    if not pattern or not isinstance(pattern, str):
      raise UtilsError(f"Branch must be a string '{pattern}'")

    # Basic validation
    if len(pattern) < 1 or len(pattern) > 255:
      raise UtilsError(f"Branch length must be > 1 and < 255 '{pattern}'")

    # Check it starts with alpha numeric
    if not re.match(r"^[a-zA-Z0-9]", pattern):
      raise UtilsError(f"Branch pattern does not start with alpha numeric '{pattern}'")

    try:
      # Convert shell-style pattern to regex
      regex_pattern = pattern
      # Replace wildcards with regex equivalents
      # ** matches anything including /
      regex_pattern = regex_pattern.replace("**", "___DOUBLE_STAR___")
      # * matches anything except /
      regex_pattern = regex_pattern.replace("*", "[^/]*")
      # Restore **
      regex_pattern = regex_pattern.replace("___DOUBLE_STAR___", ".*")
      # ? matches single character
      regex_pattern = regex_pattern.replace("?", ".")
      # Anchor the pattern
      regex_pattern = f"^{regex_pattern}$"

      # Test if regex compiles
      return re.compile(regex_pattern)
    except re.error as e:
      raise UtilsError(f"Invalid pattern '{pattern}': {e}") from None

  @staticmethod
  def is_valid_name(environment: str) -> bool:
    """
    Validate environment/command name format.
    Must start with letter, contain only alphanumeric/hyphens/underscores.
    """
    if not environment or not isinstance(environment, str):
      return False

    # Length check
    if len(environment) < 1 or len(environment) > 64:
      return False

    # Must start with letter, contain alphanumeric + hyphens/underscores
    if len(environment) == 1:
      return re.match(r"^[a-zA-Z]$", environment) is not None
    else:
      return re.match(r"^[a-zA-Z][a-zA-Z0-9_-]*$", environment) is not None
