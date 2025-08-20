import re
from typing import Any, Union
from unittest import TestCase

import pytest

from auto_secrets.core.common_utils import CommonUtils, UtilsError


class TestCommonUtils(TestCase):
  """Test cases for CommonUtils class."""

  def test_parse_json_valid_json(self) -> None:
    """Test parsing valid JSON strings."""
    # Simple dictionary
    result: dict[str, str] = CommonUtils.parse_json("TEST_VAR", '{"key": "value"}')
    self.assertEqual(result, {"key": "value"})

    # List
    result_list: list[int] = CommonUtils.parse_json("TEST_VAR", "[1, 2, 3]")
    self.assertEqual(result_list, [1, 2, 3])

    # String
    result_str: str = CommonUtils.parse_json("TEST_VAR", '"hello"')
    self.assertEqual(result_str, "hello")

    # Number
    result_num: int = CommonUtils.parse_json("TEST_VAR", "42")
    self.assertEqual(result_num, 42)

    # Boolean
    result_bool: bool = CommonUtils.parse_json("TEST_VAR", "true")
    self.assertEqual(result_bool, True)

    # Null
    result_null: None = CommonUtils.parse_json("TEST_VAR", "null")
    self.assertIsNone(result_null)

    # Complex nested structure
    complex_json: str = '{"users": [{"name": "John", "age": 30}, {"name": "Jane", "age": 25}]}'
    result_complex: dict[str, list[dict[str, Union[str, int]]]] = CommonUtils.parse_json("TEST_VAR", complex_json)
    expected: dict[str, list[dict[str, Union[str, int]]]] = {
      "users": [{"name": "John", "age": 30}, {"name": "Jane", "age": 25}]
    }
    self.assertEqual(result_complex, expected)

  def test_parse_json_invalid_json(self) -> None:
    """Test parsing invalid JSON strings."""
    # Missing quotes
    with self.assertRaises(UtilsError) as context:
      CommonUtils.parse_json("TEST_VAR", '{key: "value"}')
    self.assertIn("Invalid TEST_VAR JSON", str(context.exception))

    # Trailing comma
    with self.assertRaises(UtilsError) as context:
      CommonUtils.parse_json("TEST_VAR", '{"key": "value",}')
    self.assertIn("Invalid TEST_VAR JSON", str(context.exception))

    # Unclosed brace
    with self.assertRaises(UtilsError) as context:
      CommonUtils.parse_json("TEST_VAR", '{"key": "value"')
    self.assertIn("Invalid TEST_VAR JSON", str(context.exception))

    # Empty string
    with self.assertRaises(UtilsError) as context:
      CommonUtils.parse_json("TEST_VAR", "")
    self.assertIn("Invalid TEST_VAR JSON", str(context.exception))

    # Invalid syntax
    with self.assertRaises(UtilsError) as context:
      CommonUtils.parse_json("TEST_VAR", "not json at all")
    self.assertIn("Invalid TEST_VAR JSON", str(context.exception))

  def test_get_regex_from_pattern_valid_patterns(self) -> None:
    """Test regex conversion with valid patterns."""
    # Simple alphanumeric
    pattern: re.Pattern[str] = re.compile(r"^main$")
    result: re.Pattern[str] = CommonUtils.get_regex_from_pattern("main")
    self.assertEqual(pattern.pattern, result.pattern)

    # Single wildcard
    result = CommonUtils.get_regex_from_pattern("feature*")
    self.assertTrue(result.match("feature123"))
    self.assertTrue(result.match("feature-test"))
    self.assertFalse(result.match("feature/test"))  # * doesn't match /

    # Double wildcard
    result = CommonUtils.get_regex_from_pattern("feature**")
    self.assertTrue(result.match("feature123"))
    self.assertTrue(result.match("feature/test/deep"))

    # Question mark wildcard
    result = CommonUtils.get_regex_from_pattern("test?")
    self.assertTrue(result.match("test1"))
    self.assertTrue(result.match("testa"))
    self.assertFalse(result.match("test"))
    self.assertFalse(result.match("test12"))

    # Complex pattern
    result = CommonUtils.get_regex_from_pattern("feature*/test?/deploy**")
    self.assertTrue(result.match("feature123/testa/deploy/prod"))
    self.assertFalse(result.match("feature/branch/testa/deploy/prod"))  # * doesn't match /

    # Pattern with numbers at start
    result = CommonUtils.get_regex_from_pattern("1main")
    self.assertTrue(result.match("1main"))

  def test_get_regex_from_pattern_invalid_patterns(self) -> None:
    """Test regex conversion with invalid patterns."""
    # Empty string
    with self.assertRaises(UtilsError) as context:
      CommonUtils.get_regex_from_pattern("")
    self.assertIn("Branch must be a string", str(context.exception))

    # None
    with self.assertRaises(UtilsError) as context:
      CommonUtils.get_regex_from_pattern(None)  # type: ignore[arg-type]
    self.assertIn("Branch must be a string", str(context.exception))

    # Non-string type
    with self.assertRaises(UtilsError) as context:
      CommonUtils.get_regex_from_pattern(123)  # type: ignore[arg-type]
    self.assertIn("Branch must be a string", str(context.exception))

    # Too long (> 255 characters)
    long_pattern: str = "a" * 256
    with self.assertRaises(UtilsError) as context:
      CommonUtils.get_regex_from_pattern(long_pattern)
    self.assertIn("Branch length must be > 1 and < 255", str(context.exception))

    # Doesn't start with alphanumeric
    with self.assertRaises(UtilsError) as context:
      CommonUtils.get_regex_from_pattern("_main")
    self.assertIn("Branch pattern does not start with alpha numeric", str(context.exception))

    with self.assertRaises(UtilsError) as context:
      CommonUtils.get_regex_from_pattern("-main")
    self.assertIn("Branch pattern does not start with alpha numeric", str(context.exception))

    with self.assertRaises(UtilsError) as context:
      CommonUtils.get_regex_from_pattern("/main")
    self.assertIn("Branch pattern does not start with alpha numeric", str(context.exception))

  def test_get_regex_from_pattern_edge_cases(self) -> None:
    """Test edge cases for regex pattern conversion."""
    # Single character
    result: re.Pattern[str] = CommonUtils.get_regex_from_pattern("a")
    self.assertTrue(result.match("a"))
    self.assertFalse(result.match("ab"))

    # Maximum length (255 characters)
    max_pattern: str = "a" + "b" * 254
    result = CommonUtils.get_regex_from_pattern(max_pattern)
    self.assertTrue(result.match(max_pattern))

    # Pattern with all types of wildcards
    result = CommonUtils.get_regex_from_pattern("a*b?c**d")
    self.assertTrue(result.match("a123b4c/deep/path/d"))

  def test_is_valid_name_valid_names(self) -> None:
    """Test valid environment/command names."""
    # Single letter
    self.assertTrue(CommonUtils.is_valid_name("a"))
    self.assertTrue(CommonUtils.is_valid_name("Z"))

    # Alphanumeric
    self.assertTrue(CommonUtils.is_valid_name("test123"))
    self.assertTrue(CommonUtils.is_valid_name("Test123"))

    # With hyphens
    self.assertTrue(CommonUtils.is_valid_name("test-env"))
    self.assertTrue(CommonUtils.is_valid_name("my-test-env"))

    # With underscores
    self.assertTrue(CommonUtils.is_valid_name("test_env"))
    self.assertTrue(CommonUtils.is_valid_name("my_test_env"))

    # Mixed hyphens and underscores
    self.assertTrue(CommonUtils.is_valid_name("test-env_name"))
    self.assertTrue(CommonUtils.is_valid_name("test_env-name"))

    # Maximum length (64 characters)
    max_name: str = "a" + "b" * 63
    self.assertTrue(CommonUtils.is_valid_name(max_name))

  def test_is_valid_name_invalid_names(self) -> None:
    """Test invalid environment/command names."""
    # Empty string
    self.assertFalse(CommonUtils.is_valid_name(""))

    # None
    self.assertFalse(CommonUtils.is_valid_name(None))  # type: ignore[arg-type]

    # Non-string type
    self.assertFalse(CommonUtils.is_valid_name(123))  # type: ignore[arg-type]
    self.assertFalse(CommonUtils.is_valid_name([]))  # type: ignore[arg-type]
    self.assertFalse(CommonUtils.is_valid_name({}))  # type: ignore[arg-type]

    # Too long (> 64 characters)
    long_name: str = "a" * 65
    self.assertFalse(CommonUtils.is_valid_name(long_name))

    # Doesn't start with letter
    self.assertFalse(CommonUtils.is_valid_name("1test"))
    self.assertFalse(CommonUtils.is_valid_name("_test"))
    self.assertFalse(CommonUtils.is_valid_name("-test"))
    self.assertFalse(CommonUtils.is_valid_name("*test"))

    # Contains invalid characters
    self.assertFalse(CommonUtils.is_valid_name("test.env"))
    self.assertFalse(CommonUtils.is_valid_name("test env"))
    self.assertFalse(CommonUtils.is_valid_name("test@env"))
    self.assertFalse(CommonUtils.is_valid_name("test#env"))
    self.assertFalse(CommonUtils.is_valid_name("test$env"))
    self.assertFalse(CommonUtils.is_valid_name("test%env"))
    self.assertFalse(CommonUtils.is_valid_name("test/env"))
    self.assertFalse(CommonUtils.is_valid_name("test\\env"))

  def test_is_valid_name_edge_cases(self) -> None:
    """Test edge cases for name validation."""
    # Single character edge cases
    self.assertTrue(CommonUtils.is_valid_name("A"))
    self.assertTrue(CommonUtils.is_valid_name("z"))
    self.assertFalse(CommonUtils.is_valid_name("1"))
    self.assertFalse(CommonUtils.is_valid_name("_"))
    self.assertFalse(CommonUtils.is_valid_name("-"))

    # Boundary length testing
    self.assertTrue(CommonUtils.is_valid_name("a"))  # Length 1
    self.assertTrue(CommonUtils.is_valid_name("a" * 64))  # Length 64
    self.assertFalse(CommonUtils.is_valid_name("a" * 65))  # Length 65


# Additional test cases using pytest fixtures and parametrize if you prefer pytest style
@pytest.mark.parametrize(
  "json_str,expected",
  [
    ('{"key": "value"}', {"key": "value"}),
    ("[1, 2, 3]", [1, 2, 3]),
    ('"hello"', "hello"),
    ("42", 42),
    ("true", True),
    ("null", None),
  ],
)
def test_parse_json_parametrized(json_str: str, expected: Any) -> None:
  """Parametrized test for valid JSON parsing."""
  result: Any = CommonUtils.parse_json("TEST_VAR", json_str)
  assert result == expected


@pytest.mark.parametrize(
  "invalid_json",
  [
    '{key: "value"}',  # Missing quotes
    '{"key": "value",}',  # Trailing comma
    '{"key": "value"',  # Unclosed brace
    "",  # Empty string
    "not json at all",  # Invalid syntax
  ],
)
def test_parse_json_invalid_parametrized(invalid_json: str) -> None:
  """Parametrized test for invalid JSON parsing."""
  with pytest.raises(UtilsError, match="Invalid TEST_VAR JSON"):
    CommonUtils.parse_json("TEST_VAR", invalid_json)


@pytest.mark.parametrize(
  "pattern,test_string,should_match",
  [
    ("main", "main", True),
    ("main", "main2", False),
    ("feature*", "feature123", True),
    ("feature*", "feature/test", False),  # * doesn't match /
    ("feature**", "feature/test/deep", True),
    ("test?", "test1", True),
    ("test?", "test", False),
    ("test?", "test12", False),
  ],
)
def test_regex_pattern_matching(pattern: str, test_string: str, should_match: bool) -> None:
  """Parametrized test for regex pattern matching."""
  regex: re.Pattern[str] = CommonUtils.get_regex_from_pattern(pattern)
  if should_match:
    assert regex.match(test_string) is not None
  else:
    assert regex.match(test_string) is None


@pytest.mark.parametrize(
  "name,is_valid",
  [
    ("a", True),
    ("test123", True),
    ("test-env", True),
    ("test_env", True),
    ("Test_Env-123", True),
    ("1test", False),
    ("_test", False),
    ("-test", False),
    ("test.env", False),
    ("test env", False),
    ("", False),
    ("a" * 64, True),  # Max length
    ("a" * 65, False),  # Over max length
  ],
)
def test_is_valid_name_parametrized(name: str, is_valid: bool) -> None:
  """Parametrized test for name validation."""
  assert CommonUtils.is_valid_name(name) == is_valid


if __name__ == "__main__":
  # Run tests using unittest
  import unittest

  unittest.main()
