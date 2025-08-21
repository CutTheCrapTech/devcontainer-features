import os
from pathlib import Path
from unittest import TestCase
from unittest.mock import MagicMock, patch

import pytest

from auto_secrets.managers.common_config import CommonConfig


class TestCommonConfig(TestCase):
  """Test cases for CommonConfig class."""

  def setUp(self) -> None:
    """Set up test fixtures before each test method."""
    # Clear environment variables before each test
    if "AUTO_SECRETS_SSH_AGENT_KEY_COMMENT" in os.environ:
      del os.environ["AUTO_SECRETS_SSH_AGENT_KEY_COMMENT"]
    if "AUTO_SECRETS_CACHE_DIR" in os.environ:
      del os.environ["AUTO_SECRETS_CACHE_DIR"]

  def tearDown(self) -> None:
    """Clean up after each test method."""
    # Clear environment variables after each test
    if "AUTO_SECRETS_SSH_AGENT_KEY_COMMENT" in os.environ:
      del os.environ["AUTO_SECRETS_SSH_AGENT_KEY_COMMENT"]
    if "AUTO_SECRETS_CACHE_DIR" in os.environ:
      del os.environ["AUTO_SECRETS_CACHE_DIR"]

  def test_default_initialization(self) -> None:
    """Test default initialization without environment variables."""
    config = CommonConfig()

    # Check default values
    self.assertEqual(config.ssh_agent_key_comment, "")
    self.assertEqual(config.cache_base_dir, "")

  def test_post_init_with_environment_variables(self) -> None:
    """Test post_init method with environment variables set."""
    # Set environment variables
    test_ssh_comment: str = "test-ssh-key"
    test_cache_dir: str = "/tmp/test-cache"

    os.environ["AUTO_SECRETS_SSH_AGENT_KEY_COMMENT"] = test_ssh_comment
    os.environ["AUTO_SECRETS_CACHE_DIR"] = test_cache_dir

    config = CommonConfig()
    config.__post_init__()

    # Verify values are read from environment
    self.assertEqual(config.ssh_agent_key_comment, test_ssh_comment)
    self.assertEqual(config.cache_base_dir, test_cache_dir)

  def test_post_init_without_environment_variables(self) -> None:
    """Test post_init method without environment variables."""
    config = CommonConfig()
    config.__post_init__()

    # Should use empty string defaults when env vars are not set
    self.assertEqual(config.ssh_agent_key_comment, "")
    self.assertEqual(config.cache_base_dir, "")

  def test_post_init_with_empty_environment_variables(self) -> None:
    """Test post_init method with empty environment variables."""
    os.environ["AUTO_SECRETS_SSH_AGENT_KEY_COMMENT"] = ""
    os.environ["AUTO_SECRETS_CACHE_DIR"] = ""

    config = CommonConfig()
    config.__post_init__()

    # Should use empty strings when env vars are explicitly empty
    self.assertEqual(config.ssh_agent_key_comment, "")
    self.assertEqual(config.cache_base_dir, "")

  def test_post_init_partial_environment_variables(self) -> None:
    """Test post_init method with only some environment variables set."""
    # Set only one environment variable
    test_ssh_comment: str = "partial-test-key"
    os.environ["AUTO_SECRETS_SSH_AGENT_KEY_COMMENT"] = test_ssh_comment
    # AUTO_SECRETS_CACHE_DIR is not set

    config = CommonConfig()
    config.__post_init__()

    # Should use env var for ssh_agent_key_comment, default for cache_base_dir
    self.assertEqual(config.ssh_agent_key_comment, test_ssh_comment)
    self.assertEqual(config.cache_base_dir, "")

  @patch.dict(
    os.environ, {"AUTO_SECRETS_SSH_AGENT_KEY_COMMENT": "mocked-ssh-key", "AUTO_SECRETS_CACHE_DIR": "/mocked/cache/dir"}
  )
  def test_post_init_with_mock_environment(self) -> None:
    """Test post_init method using mocked environment variables."""
    config = CommonConfig()
    config.__post_init__()

    self.assertEqual(config.ssh_agent_key_comment, "mocked-ssh-key")
    self.assertEqual(config.cache_base_dir, "/mocked/cache/dir")

  def test_get_base_dir_with_valid_path(self) -> None:
    """Test get_base_dir method with a valid path."""
    test_cache_dir: str = "/tmp/test-cache"

    config = CommonConfig()
    config.cache_base_dir = test_cache_dir

    result: Path = config.get_base_dir()
    expected: Path = Path(test_cache_dir)

    self.assertEqual(result, expected)
    self.assertIsInstance(result, Path)

  def test_get_base_dir_with_empty_path(self) -> None:
    """Test get_base_dir method with empty path."""
    config = CommonConfig()
    config.cache_base_dir = ""

    result: Path = config.get_base_dir()
    expected: Path = Path("")

    self.assertEqual(result, expected)
    self.assertIsInstance(result, Path)

  def test_get_base_dir_with_relative_path(self) -> None:
    """Test get_base_dir method with relative path."""
    test_cache_dir: str = "relative/cache/dir"

    config = CommonConfig()
    config.cache_base_dir = test_cache_dir

    result: Path = config.get_base_dir()
    expected: Path = Path(test_cache_dir)

    self.assertEqual(result, expected)
    self.assertIsInstance(result, Path)

  def test_get_base_dir_with_absolute_path(self) -> None:
    """Test get_base_dir method with absolute path."""
    test_cache_dir: str = "/absolute/cache/dir"

    config = CommonConfig()
    config.cache_base_dir = test_cache_dir

    result: Path = config.get_base_dir()
    expected: Path = Path(test_cache_dir)

    self.assertEqual(result, expected)
    self.assertIsInstance(result, Path)
    self.assertTrue(result.is_absolute())

  def test_get_base_dir_with_windows_path(self) -> None:
    """Test get_base_dir method with Windows-style path."""
    test_cache_dir: str = r"C:\Windows\Cache\Dir"

    config = CommonConfig()
    config.cache_base_dir = test_cache_dir

    result: Path = config.get_base_dir()
    expected: Path = Path(test_cache_dir)

    self.assertEqual(result, expected)
    self.assertIsInstance(result, Path)

  def test_get_base_dir_with_tilde_path(self) -> None:
    """Test get_base_dir method with tilde path."""
    test_cache_dir: str = "~/cache/dir"

    config = CommonConfig()
    config.cache_base_dir = test_cache_dir

    result: Path = config.get_base_dir()
    expected: Path = Path(test_cache_dir)

    self.assertEqual(result, expected)
    self.assertIsInstance(result, Path)

  def test_dataclass_field_assignment(self) -> None:
    """Test direct field assignment works correctly."""
    config = CommonConfig()

    # Test direct assignment
    test_ssh_comment: str = "direct-assignment-key"
    test_cache_dir: str = "/direct/assignment/cache"

    config.ssh_agent_key_comment = test_ssh_comment
    config.cache_base_dir = test_cache_dir

    self.assertEqual(config.ssh_agent_key_comment, test_ssh_comment)
    self.assertEqual(config.cache_base_dir, test_cache_dir)

  def test_dataclass_initialization_with_values(self) -> None:
    """Test dataclass initialization with explicit values."""
    test_ssh_comment: str = "init-ssh-key"
    test_cache_dir: str = "/init/cache/dir"
    import os
    from unittest.mock import patch

    with patch.dict(
      os.environ,
      {
        "AUTO_SECRETS_SSH_AGENT_KEY_COMMENT": test_ssh_comment,
        "AUTO_SECRETS_CACHE_DIR": test_cache_dir,  # Changed from AUTO_SECRETS_CACHE_BASE_DIR
      },
    ):
      config = CommonConfig()
      self.assertEqual(config.ssh_agent_key_comment, test_ssh_comment)
      self.assertEqual(config.cache_base_dir, test_cache_dir)

  def test_post_init_overwrites_initialization_values(self) -> None:
    """Test that post_init overwrites values set during initialization."""
    # Initialize with explicit values
    config = CommonConfig(ssh_agent_key_comment="init-value", cache_base_dir="/init/path")

    # Set environment variables
    os.environ["AUTO_SECRETS_SSH_AGENT_KEY_COMMENT"] = "env-value"
    os.environ["AUTO_SECRETS_CACHE_DIR"] = "/env/path"

    # Call post_init - should overwrite initialization values
    config.__post_init__()

    # Should use environment values, not initialization values
    self.assertEqual(config.ssh_agent_key_comment, "env-value")
    self.assertEqual(config.cache_base_dir, "/env/path")

  @patch("os.getenv")
  def test_post_init_with_mocked_getenv(self, mock_getenv: MagicMock) -> None:
    """Test post_init method with mocked os.getenv."""

    # Configure mock to return specific values
    def mock_getenv_side_effect(key: str, default: str = "") -> str:
      if key == "AUTO_SECRETS_SSH_AGENT_KEY_COMMENT":
        return "mocked-ssh-key"
      elif key == "AUTO_SECRETS_CACHE_DIR":
        return "/mocked/cache"
      return default

    mock_getenv.side_effect = mock_getenv_side_effect

    config = CommonConfig()
    config.__post_init__()

    # Verify the mock was called with correct parameters
    mock_getenv.assert_any_call("AUTO_SECRETS_SSH_AGENT_KEY_COMMENT", "")
    mock_getenv.assert_any_call("AUTO_SECRETS_CACHE_DIR", "")

    # Verify the values were set correctly
    self.assertEqual(config.ssh_agent_key_comment, "mocked-ssh-key")
    self.assertEqual(config.cache_base_dir, "/mocked/cache")


# Additional pytest parametrized tests
@pytest.mark.parametrize(
  "ssh_comment,cache_dir",
  [
    ("", ""),
    ("test-key", "/test/cache"),
    ("production-key", "/var/cache/secrets"),
    ("dev-environment-key", "~/dev/cache"),
    ("special-chars-key!@#", "/cache/with/special-chars"),
  ],
)
def test_post_init_parametrized(ssh_comment: str, cache_dir: str) -> None:
  """Parametrized test for post_init with various environment variable values."""
  # Set environment variables
  os.environ["AUTO_SECRETS_SSH_AGENT_KEY_COMMENT"] = ssh_comment
  os.environ["AUTO_SECRETS_CACHE_DIR"] = cache_dir

  try:
    config = CommonConfig()
    config.__post_init__()

    assert config.ssh_agent_key_comment == ssh_comment
    assert config.cache_base_dir == cache_dir
  finally:
    # Clean up environment variables
    if "AUTO_SECRETS_SSH_AGENT_KEY_COMMENT" in os.environ:
      del os.environ["AUTO_SECRETS_SSH_AGENT_KEY_COMMENT"]
    if "AUTO_SECRETS_CACHE_DIR" in os.environ:
      del os.environ["AUTO_SECRETS_CACHE_DIR"]


@pytest.mark.parametrize(
  "cache_dir",
  [
    "/absolute/path",
    "relative/path",
    "~/home/path",
    "",
    ".",
    "..",
    "/",
    r"C:\Windows\Path",
    "path/with/spaces in it",
    "path-with-dashes",
    "path_with_underscores",
  ],
)
def test_get_base_dir_parametrized(cache_dir: str) -> None:
  """Parametrized test for get_base_dir with various path formats."""
  config = CommonConfig()
  config.cache_base_dir = cache_dir

  result: Path = config.get_base_dir()
  expected: Path = Path(cache_dir)

  assert result == expected
  assert isinstance(result, Path)


# Integration tests
class TestCommonConfigIntegration(TestCase):
  """Integration tests for CommonConfig class."""

  def test_full_workflow_with_environment_variables(self) -> None:
    """Test full workflow: initialization -> post_init -> get_base_dir."""
    # Set up environment
    test_ssh_comment: str = "integration-test-key"
    test_cache_dir: str = "/tmp/integration-test-cache"

    os.environ["AUTO_SECRETS_SSH_AGENT_KEY_COMMENT"] = test_ssh_comment
    os.environ["AUTO_SECRETS_CACHE_DIR"] = test_cache_dir

    try:
      # Create and initialize config
      config = CommonConfig()
      config.__post_init__()

      # Verify post_init worked
      self.assertEqual(config.ssh_agent_key_comment, test_ssh_comment)
      self.assertEqual(config.cache_base_dir, test_cache_dir)

      # Verify get_base_dir works
      base_dir: Path = config.get_base_dir()
      expected_path: Path = Path(test_cache_dir)
      self.assertEqual(base_dir, expected_path)

    finally:
      # Clean up
      if "AUTO_SECRETS_SSH_AGENT_KEY_COMMENT" in os.environ:
        del os.environ["AUTO_SECRETS_SSH_AGENT_KEY_COMMENT"]
      if "AUTO_SECRETS_CACHE_DIR" in os.environ:
        del os.environ["AUTO_SECRETS_CACHE_DIR"]

  def test_full_workflow_without_environment_variables(self) -> None:
    """Test full workflow without environment variables."""
    # Ensure no environment variables are set
    if "AUTO_SECRETS_SSH_AGENT_KEY_COMMENT" in os.environ:
      del os.environ["AUTO_SECRETS_SSH_AGENT_KEY_COMMENT"]
    if "AUTO_SECRETS_CACHE_DIR" in os.environ:
      del os.environ["AUTO_SECRETS_CACHE_DIR"]

    # Create and initialize config
    config = CommonConfig()
    config.__post_init__()

    # Verify defaults
    self.assertEqual(config.ssh_agent_key_comment, "")
    self.assertEqual(config.cache_base_dir, "")

    # Verify get_base_dir works with empty string
    base_dir: Path = config.get_base_dir()
    expected_path: Path = Path("")
    self.assertEqual(base_dir, expected_path)


if __name__ == "__main__":
  # Run tests using unittest
  import unittest

  unittest.main()
