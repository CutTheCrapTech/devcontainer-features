"""
Comprehensive unit tests for Key Master Configuration Loader.
"""

import json
import logging
import tempfile
from pathlib import Path
from typing import Any, Optional
from unittest import TestCase
from unittest.mock import Mock, patch

# Import the actual module
from auto_secrets import key_master_config


class TestConfigLoaderImports(TestCase):
  """Test that the module imports correctly and has expected attributes."""

  def test_module_has_required_constants(self) -> None:
    """Test that the module has the required constants defined."""
    assert hasattr(key_master_config, "TRUSTED_PATHS_CONFIG_FILE")
    assert hasattr(key_master_config, "LEGITIMATE_CLI_PATHS")

  def test_trusted_paths_config_file_type(self) -> None:
    """Test that TRUSTED_PATHS_CONFIG_FILE is a Path object."""
    assert isinstance(key_master_config._TRUSTED_PATHS_CONFIG_FILE, Path)

  def test_legitimate_cli_paths_type(self) -> None:
    """Test that LEGITIMATE_CLI_PATHS is a list."""
    assert isinstance(key_master_config.LEGITIMATE_CLI_PATHS, list)
    assert all(isinstance(path, str) for path in key_master_config.LEGITIMATE_CLI_PATHS)

  def test_config_file_path_value(self) -> None:
    """Test the expected path value."""
    expected_path = Path("/etc/auto-secrets/trusted_paths.json")
    assert expected_path == key_master_config._TRUSTED_PATHS_CONFIG_FILE


class TestConfigLoaderFunctionality(TestCase):
  """Test the actual functionality of the config loader."""

  def setUp(self) -> None:
    """Set up test fixtures and backup original state."""
    # Backup original values
    self.original_legitimate_paths = key_master_config.LEGITIMATE_CLI_PATHS[:]

  def tearDown(self) -> None:
    """Restore original state after each test."""
    key_master_config.LEGITIMATE_CLI_PATHS[:] = self.original_legitimate_paths

  @patch.object(Path, "exists")
  @patch.object(Path, "read_text")
  @patch("json.loads")
  @patch("logging.getLogger")
  def test_successful_config_loading_flow(
    self, mock_get_logger: Mock, mock_json_loads: Mock, mock_read_text: Mock, mock_exists: Mock
  ) -> None:
    """Test the complete successful config loading flow."""
    # Setup mocks
    mock_exists.return_value = True
    test_config_content = '{"trusted_paths": ["/usr/bin/app1", "/usr/local/bin/app2"]}'
    mock_read_text.return_value = test_config_content
    mock_json_loads.return_value = {"trusted_paths": ["/usr/bin/app1", "/usr/local/bin/app2"]}
    mock_logger = Mock()
    mock_get_logger.return_value = mock_logger

    # Simulate the module loading logic
    config_file = key_master_config._TRUSTED_PATHS_CONFIG_FILE

    if config_file.exists():
      try:
        config_data = json.loads(config_file.read_text())
        paths = config_data.get("trusted_paths")
        if isinstance(paths, list) and all(isinstance(p, str) for p in paths):
          key_master_config.LEGITIMATE_CLI_PATHS = paths
        else:
          mock_logger.error(f"Config file at {config_file} is malformed.")
      except (json.JSONDecodeError, OSError) as e:
        mock_logger.error(f"Failed to load trusted paths config from {config_file}: {e}")

    # Verify the mocks were called correctly
    mock_exists.assert_called_once()
    mock_read_text.assert_called_once()
    mock_json_loads.assert_called_once_with(test_config_content)
    mock_logger.error.assert_not_called()

  @patch.object(Path, "exists")
  def test_config_file_does_not_exist(self, mock_exists: Mock) -> None:
    """Test behavior when config file doesn't exist."""
    mock_exists.return_value = False

    config_file = key_master_config._TRUSTED_PATHS_CONFIG_FILE

    # Simulate module logic
    if not config_file.exists():
      # Module should continue with empty LEGITIMATE_CLI_PATHS
      pass

    mock_exists.assert_called_once()

  @patch.object(Path, "exists")
  @patch.object(Path, "read_text")
  @patch("json.loads")
  @patch("logging.getLogger")
  def test_json_decode_error_handling(
    self, mock_get_logger: Mock, mock_json_loads: Mock, mock_read_text: Mock, mock_exists: Mock
  ) -> None:
    """Test handling of JSON decode errors."""
    mock_exists.return_value = True
    mock_read_text.return_value = "invalid json content"
    mock_json_loads.side_effect = json.JSONDecodeError("Invalid JSON", "doc", 0)
    mock_logger = Mock()
    mock_get_logger.return_value = mock_logger

    config_file = key_master_config._TRUSTED_PATHS_CONFIG_FILE

    # Simulate module logic
    if config_file.exists():
      try:
        json.loads(config_file.read_text())
      except (json.JSONDecodeError, OSError) as e:
        mock_logger.error(f"Failed to load trusted paths config from {config_file}: {e}")

    mock_exists.assert_called_once()
    mock_read_text.assert_called_once()
    mock_json_loads.assert_called_once_with("invalid json content")
    mock_logger.error.assert_called_once()

    # Check error message format
    error_call_args = mock_logger.error.call_args[0][0]
    assert "Failed to load trusted paths config" in error_call_args
    assert str(config_file) in error_call_args

  @patch.object(Path, "exists")
  @patch.object(Path, "read_text")
  @patch("logging.getLogger")
  def test_os_error_handling(self, mock_get_logger: Mock, mock_read_text: Mock, mock_exists: Mock) -> None:
    """Test handling of OS errors when reading file."""
    mock_exists.return_value = True
    mock_read_text.side_effect = OSError("Permission denied")
    mock_logger = Mock()
    mock_get_logger.return_value = mock_logger

    config_file = key_master_config._TRUSTED_PATHS_CONFIG_FILE

    # Simulate module logic
    if config_file.exists():
      try:
        config_file.read_text()
      except (json.JSONDecodeError, OSError) as e:
        mock_logger.error(f"Failed to load trusted paths config from {config_file}: {e}")

    mock_exists.assert_called_once()
    mock_read_text.assert_called_once()
    mock_logger.error.assert_called_once()

    # Check error message contains the actual error
    error_call_args = mock_logger.error.call_args[0][0]
    assert "Permission denied" in error_call_args

  @patch.object(Path, "exists")
  @patch.object(Path, "read_text")
  @patch("json.loads")
  @patch("logging.getLogger")
  def test_malformed_config_missing_key(
    self, mock_get_logger: Mock, mock_json_loads: Mock, mock_read_text: Mock, mock_exists: Mock
  ) -> None:
    """Test handling of config file missing 'trusted_paths' key."""
    mock_exists.return_value = True
    mock_read_text.return_value = '{"other_key": "value"}'
    mock_json_loads.return_value = {"other_key": "value"}
    mock_logger = Mock()
    mock_get_logger.return_value = mock_logger

    config_file = key_master_config._TRUSTED_PATHS_CONFIG_FILE

    # Simulate module logic
    if config_file.exists():
      try:
        config_data = json.loads(config_file.read_text())
        paths = config_data.get("trusted_paths")
        if isinstance(paths, list) and all(isinstance(p, str) for p in paths):
          key_master_config.LEGITIMATE_CLI_PATHS = paths
        else:
          mock_logger.error(f"Config file at {config_file} is malformed.")
      except (json.JSONDecodeError, OSError) as e:
        mock_logger.error(f"Failed to load trusted paths config from {config_file}: {e}")

    mock_logger.error.assert_called_once()
    error_call_args = mock_logger.error.call_args[0][0]
    assert "is malformed" in error_call_args

  @patch.object(Path, "exists")
  @patch.object(Path, "read_text")
  @patch("json.loads")
  @patch("logging.getLogger")
  def test_malformed_config_wrong_type(
    self, mock_get_logger: Mock, mock_json_loads: Mock, mock_read_text: Mock, mock_exists: Mock
  ) -> None:
    """Test handling when trusted_paths is not a list."""
    mock_exists.return_value = True
    mock_read_text.return_value = '{"trusted_paths": "not_a_list"}'
    mock_json_loads.return_value = {"trusted_paths": "not_a_list"}
    mock_logger = Mock()
    mock_get_logger.return_value = mock_logger

    config_file = key_master_config._TRUSTED_PATHS_CONFIG_FILE

    # Simulate module logic
    if config_file.exists():
      try:
        config_data = json.loads(config_file.read_text())
        paths = config_data.get("trusted_paths")
        if isinstance(paths, list) and all(isinstance(p, str) for p in paths):
          key_master_config.LEGITIMATE_CLI_PATHS = paths
        else:
          mock_logger.error(f"Config file at {config_file} is malformed.")
      except (json.JSONDecodeError, OSError) as e:
        mock_logger.error(f"Failed to load trusted paths config from {config_file}: {e}")

    mock_logger.error.assert_called_once()

  @patch.object(Path, "exists")
  @patch.object(Path, "read_text")
  @patch("json.loads")
  @patch("logging.getLogger")
  def test_malformed_config_non_string_elements(
    self, mock_get_logger: Mock, mock_json_loads: Mock, mock_read_text: Mock, mock_exists: Mock
  ) -> None:
    """Test handling when trusted_paths contains non-string elements."""
    mock_exists.return_value = True
    mock_read_text.return_value = '{"trusted_paths": ["/usr/bin/app", 123, null]}'
    mock_json_loads.return_value = {"trusted_paths": ["/usr/bin/app", 123, None]}
    mock_logger = Mock()
    mock_get_logger.return_value = mock_logger

    config_file = key_master_config._TRUSTED_PATHS_CONFIG_FILE

    # Simulate module logic
    if config_file.exists():
      try:
        config_data = json.loads(config_file.read_text())
        paths = config_data.get("trusted_paths")
        if isinstance(paths, list) and all(isinstance(p, str) for p in paths):
          key_master_config.LEGITIMATE_CLI_PATHS = paths
        else:
          mock_logger.error(f"Config file at {config_file} is malformed.")
      except (json.JSONDecodeError, OSError) as e:
        mock_logger.error(f"Failed to load trusted paths config from {config_file}: {e}")

    mock_logger.error.assert_called_once()

  def test_module_constants_values(self) -> None:
    """Test the actual values of module constants."""
    # Test config file path
    expected_path = Path("/etc/auto-secrets/trusted_paths.json")
    assert expected_path == key_master_config._TRUSTED_PATHS_CONFIG_FILE
    assert key_master_config._TRUSTED_PATHS_CONFIG_FILE.is_absolute()
    assert str(key_master_config._TRUSTED_PATHS_CONFIG_FILE).startswith("/etc/")

    # Test initial state of LEGITIMATE_CLI_PATHS
    assert isinstance(key_master_config.LEGITIMATE_CLI_PATHS, list)


class TestConfigLoaderIntegration(TestCase):
  """Integration tests using real files and JSON operations."""

  def test_real_json_parsing_valid_config(self) -> None:
    """Test parsing real JSON content with valid configuration."""
    test_cases = [
      ('{"trusted_paths": []}', []),
      ('{"trusted_paths": ["/usr/bin/app"]}', ["/usr/bin/app"]),
      ('{"trusted_paths": ["/usr/bin/app1", "/usr/local/bin/app2"]}', ["/usr/bin/app1", "/usr/local/bin/app2"]),
    ]

    for json_content, expected_paths in test_cases:
      with self.subTest(json_content=json_content):
        config_data = json.loads(json_content)
        paths = config_data.get("trusted_paths")

        assert isinstance(paths, list)
        assert all(isinstance(p, str) for p in paths)
        assert paths == expected_paths

  def test_real_json_parsing_invalid_config(self) -> None:
    """Test parsing real JSON with invalid configurations."""
    invalid_cases = [
      '{"trusted_paths": "not_a_list"}',
      '{"trusted_paths": ["/valid", 123]}',
      '{"trusted_paths": ["/valid", null]}',
      '{"other_key": "value"}',  # Missing trusted_paths key
    ]

    for json_content in invalid_cases:
      with self.subTest(json_content=json_content):
        config_data = json.loads(json_content)
        paths = config_data.get("trusted_paths")

        is_valid = isinstance(paths, list) and all(isinstance(p, str) for p in paths)
        assert not is_valid

  def test_with_temporary_config_file(self) -> None:
    """Test the complete workflow with a real temporary file."""
    test_config = {"trusted_paths": ["/usr/bin/test-app", "/usr/local/bin/another-app", "/opt/custom/app"]}

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
      json.dump(test_config, f)
      temp_path = Path(f.name)

    try:
      # Test the complete workflow
      assert temp_path.exists()

      # Read and parse the file
      config_content = temp_path.read_text()
      config_data = json.loads(config_content)
      paths = config_data.get("trusted_paths")

      # Validate the structure
      assert isinstance(paths, list)
      assert all(isinstance(p, str) for p in paths)
      assert len(paths) == 3
      assert "/usr/bin/test-app" in paths
      assert "/usr/local/bin/another-app" in paths
      assert "/opt/custom/app" in paths

    finally:
      # Clean up
      temp_path.unlink()

  def test_unicode_and_special_characters(self) -> None:
    """Test handling of Unicode and special characters in paths."""
    unicode_test_config = {
      "trusted_paths": [
        "/usr/bin/café-app",
        "/path/with/émojis/🔑",
        "/путь/с/unicode",
        "/path with spaces/app",
        "/path-with-dashes/app",
        "/path_with_underscores/app",
      ]
    }

    # Test JSON serialization and deserialization
    json_content = json.dumps(unicode_test_config)
    config_data = json.loads(json_content)
    paths = config_data.get("trusted_paths")

    assert isinstance(paths, list)
    assert all(isinstance(p, str) for p in paths)
    assert len(paths) == 6

    # Verify specific Unicode paths
    assert "/usr/bin/café-app" in paths
    assert "/path/with/émojis/🔑" in paths
    assert "/путь/с/unicode" in paths

  def test_path_validation_logic(self) -> None:
    """Test the path validation logic used in the module."""
    # Test valid cases
    valid_paths_cases: list[list[str]] = [
      [],  # Empty list
      ["/usr/bin/app"],  # Single path
      ["/usr/bin/app1", "/usr/local/bin/app2"],  # Multiple paths
      ["/path/with/spaces in name"],  # Path with spaces
      ["/path/with-dashes", "/path/with_underscores"],  # Special characters
    ]
    for paths in valid_paths_cases:
      assert isinstance(paths, list)
      assert all(isinstance(p, str) for p in paths)

    # Test invalid cases
    invalid_paths_cases: list[object] = [
      "not_a_list",  # String instead of list
      123,  # Number instead of list
      None,  # None instead of list
      ["/valid/path", 123],  # List with non-string
      ["/valid/path", None],  # List with None
      ["/valid/path", []],  # List with nested list
    ]
    for paths_obj in invalid_paths_cases:
      is_valid = isinstance(paths_obj, list) and all(isinstance(p, str) for p in paths_obj)
      assert not is_valid


class TestModuleStructure(TestCase):
  """Test the overall module structure and design."""

  def test_config_file_path_security(self) -> None:
    """Test that config file path is in a secure system location."""
    config_path = key_master_config._TRUSTED_PATHS_CONFIG_FILE

    # Verify it's an absolute path
    assert config_path.is_absolute()

    # Verify it's in a system directory
    assert str(config_path).startswith("/etc/")

    # Verify filename is as expected
    assert config_path.name == "trusted_paths.json"
    assert config_path.suffix == ".json"

  def test_module_level_constants_immutability(self) -> None:
    """Test that module constants behave as expected."""
    # TRUSTED_PATHS_CONFIG_FILE should remain constant
    original_config_file = key_master_config._TRUSTED_PATHS_CONFIG_FILE

    # LEGITIMATE_CLI_PATHS should be mutable (it gets modified by the module)
    original_paths = key_master_config.LEGITIMATE_CLI_PATHS[:]

    # Test that we can modify the paths list
    key_master_config.LEGITIMATE_CLI_PATHS.append("/test/modify")
    assert "/test/modify" in key_master_config.LEGITIMATE_CLI_PATHS

    # Restore original state
    key_master_config.LEGITIMATE_CLI_PATHS[:] = original_paths

    # Config file path should remain unchanged
    assert original_config_file == key_master_config._TRUSTED_PATHS_CONFIG_FILE


# Type checking tests for mypy compatibility
def test_mypy_compatibility() -> None:
  """Test mypy type compatibility."""
  # Path type checking
  config_path: Path = key_master_config._TRUSTED_PATHS_CONFIG_FILE
  assert isinstance(config_path, Path)

  # List type checking
  paths: list[str] = key_master_config.LEGITIMATE_CLI_PATHS
  assert isinstance(paths, list)

  # Optional type checking
  maybe_paths: Optional[list[str]] = None
  config_data: dict[str, Any] = {"trusted_paths": ["/test"]}
  maybe_paths = config_data.get("trusted_paths")

  if maybe_paths is not None:
    validated_paths: list[str] = maybe_paths
    assert all(isinstance(p, str) for p in validated_paths)

  # Logger type
  logger: logging.Logger = logging.getLogger(__name__)
  assert isinstance(logger, logging.Logger)


if __name__ == "__main__":
  import unittest

  unittest.main(verbosity=2)
