"""
Unit tests for the Auto Secrets Manager CLI interface.

Comprehensive test suite with proper mypy compatibility and type annotations.
"""

import argparse
import json
import sys
from typing import Any
from unittest import TestCase
from unittest.mock import Mock, call, patch

from auto_secrets.cli import (
  _refresh_secrets,
  handle_branch_change,
  handle_cleanup,
  handle_debug_env,
  handle_exec_command,
  handle_inspect_secrets,
  handle_output_env,
  handle_refresh_secrets,
  main,
  set_sm_secret,
)


class TestCLIBase(TestCase):
  """Base test class with common setup."""

  def setUp(self) -> None:
    """Set up test fixtures."""
    self.mock_app = Mock()
    self.mock_logger = Mock()
    self.mock_branch_manager = Mock()
    self.mock_cache_manager = Mock()
    self.mock_secret_manager = Mock()
    self.mock_key_retriever = Mock()

    # Configure mock app
    self.mock_app.get_logger.return_value = self.mock_logger
    self.mock_app.branch_manager = self.mock_branch_manager
    self.mock_app.cache_manager = self.mock_cache_manager
    self.mock_app.secret_manager = self.mock_secret_manager
    self.mock_app.key_retriever = self.mock_key_retriever

  def create_args(self, **kwargs: Any) -> argparse.Namespace:
    """Create an argparse.Namespace with default values."""
    defaults = {
      "branch": "main",
      "repopath": "/path/to/repo",
      "environment": "dev",
      "paths": None,
      "quiet": False,
      "format": "table",
      "show_values": False,
      "command": ["echo", "test"],
      "all": False,
    }
    defaults.update(kwargs)
    return argparse.Namespace(**defaults)


class TestHandleBranchChange(TestCLIBase):
  """Test cases for handle_branch_change function."""

  @patch("auto_secrets.cli.app", create=True)
  @patch("auto_secrets.cli._refresh_secrets")
  def test_handle_branch_change_success(self, mock_refresh: Mock, mock_app: Mock) -> None:
    """Test successful branch change handling."""
    mock_app.get_logger.return_value = self.mock_logger
    mock_app.branch_manager = self.mock_branch_manager

    self.mock_branch_manager.map_branch_to_environment.return_value = "staging"

    args = self.create_args(branch="feature/new-feature", repopath="/repo")

    handle_branch_change(args)

    self.mock_branch_manager.map_branch_to_environment.assert_called_once_with("feature/new-feature", "/repo")
    mock_refresh.assert_called_once_with("staging", "feature/new-feature", "/repo")

  @patch("auto_secrets.cli.app", create=True)
  @patch("auto_secrets.cli.sys.exit")
  def test_handle_branch_change_exception(self, mock_exit: Mock, mock_app: Mock) -> None:
    """Test branch change handling with exception."""
    mock_app.get_logger.return_value = self.mock_logger
    mock_app.branch_manager = self.mock_branch_manager

    self.mock_branch_manager.map_branch_to_environment.side_effect = Exception("Test error")

    args = self.create_args()

    handle_branch_change(args)

    self.mock_logger.error.assert_called()
    mock_exit.assert_called_once_with(1)


class TestHandleRefreshSecrets(TestCLIBase):
  """Test cases for handle_refresh_secrets function."""

  @patch("builtins.print")
  @patch("auto_secrets.cli._refresh_secrets")
  @patch("auto_secrets.cli.app", create=True)
  def test_handle_refresh_secrets_success(self, mock_app: Mock, mock_refresh: Mock, mock_print: Mock) -> None:
    """Test successful secrets refresh."""
    mock_app.get_logger.return_value = self.mock_logger
    args = self.create_args(environment="production")
    handle_refresh_secrets(args)
    mock_refresh.assert_called_once_with("production")  # Should expect "production", not "test"
    mock_print.assert_called_once_with("✅ Refreshed secrets for environment: production")

  @patch("auto_secrets.cli.app", create=True)
  @patch("auto_secrets.cli._refresh_secrets")
  @patch("auto_secrets.cli.sys.exit")
  @patch("builtins.print")
  def test_handle_refresh_secrets_exception(
    self, mock_print: Mock, mock_exit: Mock, mock_refresh: Mock, mock_app: Mock
  ) -> None:
    """Test refresh secrets with exception."""
    mock_app.get_logger.return_value = self.mock_logger
    mock_refresh.side_effect = Exception("Refresh failed")

    args = self.create_args(environment="dev")

    handle_refresh_secrets(args)

    self.mock_logger.error.assert_called()
    assert mock_exit.call_count >= 1

  @patch("builtins.print")
  @patch("auto_secrets.cli._refresh_secrets")
  @patch("auto_secrets.cli.app", create=True)
  def test_handle_refresh_secrets_quiet_mode(self, mock_app: Mock, mock_refresh: Mock, mock_print: Mock) -> None:
    """Test refresh secrets in quiet mode."""
    mock_app.get_logger.return_value = self.mock_logger
    args = self.create_args(environment="test", quiet=True)
    handle_refresh_secrets(args)
    mock_refresh.assert_called_once_with("test")
    # In quiet mode, no print should be called
    mock_print.assert_not_called()


class TestHandleInspectSecrets(TestCLIBase):
  """Test cases for handle_inspect_secrets function."""

  @patch("auto_secrets.cli.app", create=True)
  @patch("builtins.print")
  def test_handle_inspect_secrets_table_format(self, mock_print: Mock, mock_app: Mock) -> None:
    """Test inspect secrets with table format."""
    mock_app.get_logger.return_value = self.mock_logger
    mock_app.cache_manager = self.mock_cache_manager

    test_secrets = {"API_KEY": "secret123", "DB_PASSWORD": "dbpass456"}
    self.mock_cache_manager.get_cached_secrets.return_value = test_secrets
    self.mock_cache_manager.is_cache_stale.return_value = False

    args = self.create_args(environment="dev", format="table", show_values=False)

    handle_inspect_secrets(args)

    # Verify the output contains expected elements
    call_args = mock_print.call_args[0][0]
    self.assertIn("Environment: dev", call_args)
    self.assertIn("Secrets Count: 2", call_args)
    self.assertIn("API_KEY=***REDACTED***", call_args)
    self.assertIn("DB_PASSWORD=***REDACTED***", call_args)

  @patch("auto_secrets.cli.app", create=True)
  @patch("builtins.print")
  def test_handle_inspect_secrets_json_format(self, mock_print: Mock, mock_app: Mock) -> None:
    """Test inspect secrets with JSON format."""
    mock_app.get_logger.return_value = self.mock_logger
    mock_app.cache_manager = self.mock_cache_manager

    test_secrets = {"API_KEY": "secret123"}
    self.mock_cache_manager.get_cached_secrets.return_value = test_secrets

    args = self.create_args(environment="dev", format="json")

    handle_inspect_secrets(args)

    expected_output = json.dumps(test_secrets, indent=2)
    mock_print.assert_called_once_with(expected_output)

  @patch("auto_secrets.cli.app", create=True)
  @patch("builtins.print")
  def test_handle_inspect_secrets_env_format(self, mock_print: Mock, mock_app: Mock) -> None:
    """Test inspect secrets with env format."""
    mock_app.get_logger.return_value = self.mock_logger
    mock_app.cache_manager = self.mock_cache_manager

    test_secrets = {"API_KEY": "secret123", "DB_HOST": "localhost"}
    self.mock_cache_manager.get_cached_secrets.return_value = test_secrets

    args = self.create_args(environment="dev", format="env")

    handle_inspect_secrets(args)

    expected_output = 'API_KEY="secret123"\nDB_HOST="localhost"'
    mock_print.assert_called_once_with(expected_output)

  @patch("auto_secrets.cli.app", create=True)
  @patch("builtins.print")
  def test_handle_inspect_secrets_keys_format(self, mock_print: Mock, mock_app: Mock) -> None:
    """Test inspect secrets with keys format."""
    mock_app.get_logger.return_value = self.mock_logger
    mock_app.cache_manager = self.mock_cache_manager

    test_secrets = {"API_KEY": "secret123", "DB_HOST": "localhost"}
    self.mock_cache_manager.get_cached_secrets.return_value = test_secrets

    args = self.create_args(environment="dev", format="keys")

    handle_inspect_secrets(args)

    expected_output = "API_KEY\nDB_HOST"
    mock_print.assert_called_once_with(expected_output)

  @patch("auto_secrets.cli.app", create=True)
  @patch("auto_secrets.cli.sys.exit")
  def test_handle_inspect_secrets_exception(self, mock_exit: Mock, mock_app: Mock) -> None:
    """Test inspect secrets without environment specified."""
    mock_app.get_logger.return_value = self.mock_logger

    args = self.create_args(environment=None)

    handle_inspect_secrets(args)

    self.mock_logger.error.assert_called()
    assert mock_exit.call_count >= 1

  @patch("auto_secrets.cli.app", create=True)
  @patch("builtins.print")
  def test_handle_inspect_secrets_no_secrets(self, mock_print: Mock, mock_app: Mock) -> None:
    """Test inspect secrets when no secrets found."""
    mock_app.get_logger.return_value = self.mock_logger
    mock_app.cache_manager = self.mock_cache_manager

    self.mock_cache_manager.get_cached_secrets.return_value = {}

    args = self.create_args(environment="dev")

    handle_inspect_secrets(args)

    mock_print.assert_called_once_with("No cached secrets found for environment: dev")


class TestHandleExecCommand(TestCLIBase):
  """Test cases for handle_exec_command function."""

  @patch("auto_secrets.cli.app", create=True)
  @patch("auto_secrets.cli.subprocess.run")
  @patch("auto_secrets.cli.sys.exit")
  @patch.dict("os.environ", {"HOME": "/home/user"})
  def test_handle_exec_command_success(self, mock_exit: Mock, mock_run: Mock, mock_app: Mock) -> None:
    """Test successful command execution with secrets."""
    mock_app.get_logger.return_value = self.mock_logger
    mock_app.cache_manager = self.mock_cache_manager
    mock_app.key_retriever = self.mock_key_retriever

    test_secrets = {"API_KEY": "secret123"}
    self.mock_cache_manager.get_cached_secrets.return_value = test_secrets

    mock_result = Mock()
    mock_result.returncode = 0
    mock_run.return_value = mock_result

    args = self.create_args(environment="dev", command=["python", "script.py"])

    handle_exec_command(args)

    # Verify subprocess.run was called with correct environment
    mock_run.assert_called_once()
    call_kwargs = mock_run.call_args[1]
    expected_env = {"HOME": "/home/user", "API_KEY": "secret123", "AUTO_SECRETS_CURRENT_ENV": "dev"}
    self.assertEqual(call_kwargs["env"]["API_KEY"], expected_env["API_KEY"])
    self.assertEqual(call_kwargs["env"]["AUTO_SECRETS_CURRENT_ENV"], expected_env["AUTO_SECRETS_CURRENT_ENV"])
    mock_exit.assert_called_once_with(0)

  @patch("auto_secrets.cli.app", create=True)
  @patch("auto_secrets.cli.subprocess.run")
  @patch("auto_secrets.cli.sys.exit")
  def test_handle_exec_command_file_not_found(self, mock_exit: Mock, mock_run: Mock, mock_app: Mock) -> None:
    """Test command execution with FileNotFoundError."""
    mock_app.get_logger.return_value = self.mock_logger
    mock_app.cache_manager = self.mock_cache_manager
    mock_app.key_retriever = self.mock_key_retriever

    self.mock_cache_manager.get_cached_secrets.return_value = {}
    mock_run.side_effect = FileNotFoundError()

    args = self.create_args(environment="dev", command=["nonexistent"])

    handle_exec_command(args)

    self.mock_logger.error.assert_called_with("Command not found: nonexistent")
    mock_exit.assert_called_once_with(127)


class TestHandleOutputEnv(TestCLIBase):
  """Test cases for handle_output_env function."""

  @patch("auto_secrets.cli.app", create=True)
  @patch("builtins.print")
  def test_handle_output_env_success(self, mock_print: Mock, mock_app: Mock) -> None:
    """Test successful environment output."""
    mock_app.get_logger.return_value = self.mock_logger
    mock_app.branch_manager = self.mock_branch_manager
    mock_app.cache_manager = self.mock_cache_manager

    self.mock_branch_manager.map_branch_to_environment.return_value = "dev"
    self.mock_cache_manager.get_auto_command_paths.return_value = ["/app/secrets"]
    self.mock_cache_manager.get_cached_secrets.return_value = {"API_KEY": "secret123", "DB_PASSWORD": "dbpass"}

    args = self.create_args(branch="main", repopath="/repo", command="python")

    handle_output_env(args)

    expected_calls = [
      call('export API_KEY="secret123"'),
      call('export DB_PASSWORD="dbpass"'),
      call("export AUTO_SECRETS_CURRENT_ENV='dev'"),
    ]
    mock_print.assert_has_calls(expected_calls, any_order=True)

  @patch("auto_secrets.cli.app", create=True)
  @patch("builtins.print")
  def test_handle_output_env_terraform_prefix(self, mock_print: Mock, mock_app: Mock) -> None:
    """Test environment output with Terraform variable prefixing."""
    mock_app.get_logger.return_value = self.mock_logger
    mock_app.branch_manager = self.mock_branch_manager
    mock_app.cache_manager = self.mock_cache_manager

    self.mock_branch_manager.map_branch_to_environment.return_value = "dev"
    self.mock_cache_manager.get_auto_command_paths.return_value = []
    self.mock_cache_manager.get_cached_secrets.return_value = {
      "region": "us-east-1",
      "TF_VAR_existing": "already_prefixed",
    }

    args = self.create_args(branch="main", repopath="/repo", command="terraform")

    handle_output_env(args)

    expected_calls = [
      call('export TF_VAR_region="us-east-1"'),
      call('export TF_VAR_existing="already_prefixed"'),
      call("export AUTO_SECRETS_CURRENT_ENV='dev'"),
    ]
    mock_print.assert_has_calls(expected_calls, any_order=True)


class TestHandleDebugEnv(TestCLIBase):
  """Test cases for handle_debug_env function."""

  @patch("auto_secrets.cli.app", create=True)
  @patch("builtins.print")
  @patch("os.getcwd")
  @patch("os.getenv")
  def test_handle_debug_env_success(
    self, mock_getenv: Mock, mock_getcwd: Mock, mock_print: Mock, mock_app: Mock
  ) -> None:
    """Test successful debug environment output."""
    mock_app.get_logger.return_value = self.mock_logger
    mock_app.cache_manager = self.mock_cache_manager
    mock_app.secret_manager = self.mock_secret_manager

    mock_getcwd.return_value = "/current/dir"
    mock_getenv.side_effect = lambda key, default="unknown": {
      "USER": "testuser",
      "AUTO_SECRETS_CONFIG": "/config/path",
    }.get(key, default)

    # Mock cache manager
    mock_cache_dir = Mock()
    mock_cache_dir.exists.return_value = True
    mock_cache_file1 = Mock()
    mock_cache_file1.stem = "dev"
    mock_cache_file2 = Mock()
    mock_cache_file2.stem = "staging"
    mock_cache_dir.glob.return_value = [mock_cache_file1, mock_cache_file2]
    self.mock_cache_manager.base_dir = mock_cache_dir
    self.mock_cache_manager.is_cache_stale.side_effect = lambda env: env == "staging"

    # Mock secret manager
    self.mock_secret_manager.test_connection.return_value = True

    with patch.dict("os.environ", {"AUTO_SECRETS_CONFIG": "/config/path"}):
      handle_debug_env()

    # Verify debug information was printed
    print_calls = [call[0][0] for call in mock_print.call_args_list]
    debug_output = "\n".join(print_calls)

    self.assertIn("=== Auto Secrets Manager Debug Information ===", debug_output)
    self.assertIn("Working Directory: /current/dir", debug_output)
    self.assertIn("User: testuser", debug_output)
    self.assertIn("Cache Files: 2", debug_output)
    self.assertIn("Connection: OK", debug_output)


class TestHandleCleanup(TestCLIBase):
  """Test cases for handle_cleanup function."""

  @patch("auto_secrets.cli.app", create=True)
  @patch("builtins.print")
  def test_handle_cleanup_all(self, mock_print: Mock, mock_app: Mock) -> None:
    """Test cleanup with --all flag."""
    mock_app.get_logger.return_value = self.mock_logger
    mock_app.cache_manager = self.mock_cache_manager

    args = self.create_args(all=True)

    handle_cleanup(args)

    self.mock_cache_manager.cleanup_all.assert_called_once()
    mock_print.assert_called_once_with("✅ All cache and temporary files cleaned up")

  @patch("auto_secrets.cli.app", create=True)
  @patch("builtins.print")
  def test_handle_cleanup_stale(self, mock_print: Mock, mock_app: Mock) -> None:
    """Test cleanup of stale files only."""
    mock_app.get_logger.return_value = self.mock_logger
    mock_app.cache_manager = self.mock_cache_manager

    args = self.create_args(all=False)

    handle_cleanup(args)

    self.mock_cache_manager.cleanup_stale.assert_called_once()
    mock_print.assert_called_once_with("✅ Stale cache files cleaned up")


class TestRefreshSecrets(TestCLIBase):
  """Test cases for _refresh_secrets function."""

  @patch("auto_secrets.cli.app", create=True)
  def test_refresh_secrets_success(self, mock_app: Mock) -> None:
    """Test successful secrets refresh."""
    mock_app.get_logger.return_value = self.mock_logger
    mock_app.secret_manager = self.mock_secret_manager
    mock_app.cache_manager = self.mock_cache_manager

    self.mock_secret_manager.test_connection.return_value = True
    self.mock_secret_manager.fetch_secrets.return_value = {"key": "value"}

    _refresh_secrets("dev", "main", "/repo")

    self.mock_secret_manager.fetch_secrets.assert_called_once_with("dev")
    self.mock_cache_manager.update_environment_cache.assert_called_once_with("dev", {"key": "value"}, "main", "/repo")

  @patch("auto_secrets.cli.app", create=True)
  @patch("auto_secrets.cli.sys.exit")
  def test_set_sm_secret_exception(self, mock_exit: Mock, mock_app: Mock) -> None:
    """Test refresh secrets without environment."""
    mock_app.get_logger.return_value = self.mock_logger

    _refresh_secrets(None)

    self.mock_logger.error.assert_called_with("No environment specified for background refresh")
    mock_exit.assert_called_once_with(1)


class TestMainFunction(TestCLIBase):
  """Test cases for the main CLI function."""

  @patch("auto_secrets.cli.sys.version_info", (3, 8))
  @patch("builtins.print")
  @patch("auto_secrets.cli.sys.exit")
  def test_main_python_version_check_fails(self, mock_exit: Mock, mock_print: Mock) -> None:
    """Test main function with insufficient Python version."""
    import sys
    from collections import namedtuple

    VersionInfo = namedtuple("VersionInfo", ["major", "minor", "micro", "releaselevel", "serial"])
    sys.version_info = VersionInfo(3, 8, 0, "final", 0)  # type: ignore[assignment]
    main()

    mock_print.assert_any_call("❌ Auto Secrets Manager requires Python 3.9+, found Python 3.8")
    assert mock_exit.call_count >= 1

  @patch("auto_secrets.cli.AppManager")
  @patch("auto_secrets.cli.argparse.ArgumentParser.parse_args")
  @patch("auto_secrets.cli.argparse.ArgumentParser.print_help")
  @patch("auto_secrets.cli.sys.exit")
  def test_main_no_command_specified(
    self, mock_exit: Mock, mock_print_help: Mock, mock_parse_args: Mock, mock_app_manager: Mock
  ) -> None:
    """Test main function when no command is specified."""
    mock_args = Mock()
    # Simulate no func attribute (no command specified)
    del mock_args.func
    mock_parse_args.return_value = mock_args

    main()

    mock_print_help.assert_called_once()
    mock_exit.assert_called_once_with(1)


class TestArgumentParsing(TestCase):
  """Test cases for argument parsing and subcommand setup."""

  def setUp(self) -> None:
    """Set up test fixtures."""
    self.parser = argparse.ArgumentParser(
      prog="auto-secrets", description="Auto Secrets Manager - Automatic environment secrets management"
    )
    self._setup_parser()

  def _setup_parser(self) -> None:
    """Set up the argument parser as in main()."""
    # Global options
    self.parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    self.parser.add_argument("--quiet", action="store_true", help="Suppress output messages")
    self.parser.add_argument(
      "--log-level",
      choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
      help="Set log level",
    )

    # Subcommands
    self.subparsers = self.parser.add_subparsers(dest="command", help="Available commands")

    # Branch change command
    branch_parser = self.subparsers.add_parser("branch-changed", help="Handle branch change notification")
    branch_parser.add_argument("--branch", help="New branch name")
    branch_parser.add_argument("--repopath", help="Repository path")

    # Refresh secrets command
    refresh_parser = self.subparsers.add_parser("refresh", help="Refresh secrets cache")
    refresh_parser.add_argument("--environment", help="Specific environment to refresh")
    refresh_parser.add_argument("--paths", nargs="*", help="Specific secret paths to refresh")

    # Inspect secrets command
    inspect_parser = self.subparsers.add_parser("inspect", help="Inspect cached secrets")
    inspect_parser.add_argument("--environment", help="Specific environment to inspect")
    inspect_parser.add_argument("--paths", nargs="*", help="Specific secret paths to inspect")
    inspect_parser.add_argument(
      "--format",
      choices=["table", "json", "env", "keys"],
      default="table",
      help="Output format",
    )
    inspect_parser.add_argument(
      "--show-values",
      action="store_true",
      help="Show actual secret values (security risk)",
    )

    # Execute command
    exec_parser = self.subparsers.add_parser("exec", help="Execute command with secrets loaded")
    exec_parser.add_argument("--environment", help="Specific environment to use")
    exec_parser.add_argument("--paths", nargs="*", help="Specific secret paths to load")
    exec_parser.add_argument("command", nargs="+", help="Command to execute")

    # Output environment
    output_env_parser = self.subparsers.add_parser("output-env", help="Output environment variables for shell sourcing")
    output_env_parser.add_argument("--branch", help="Current branch")
    output_env_parser.add_argument("--repopath", help="Repository path")
    output_env_parser.add_argument("--command", help="Command to fetch secrets for")

    # Debug command
    self.subparsers.add_parser("debug", help="Show debug information")

    # Cleanup command
    cleanup_parser = self.subparsers.add_parser("cleanup", help="Clean up cache files")
    cleanup_parser.add_argument("--all", action="store_true", help="Clean up all cache files")

  def test_branch_changed_parsing(self) -> None:
    """Test parsing of branch-changed command."""
    args = self.parser.parse_args(["branch-changed", "--branch", "feature/test", "--repopath", "/path/to/repo"])

    self.assertEqual(args.command, "branch-changed")
    self.assertEqual(args.branch, "feature/test")
    self.assertEqual(args.repopath, "/path/to/repo")

  def test_refresh_parsing(self) -> None:
    """Test parsing of refresh command."""
    args = self.parser.parse_args(["refresh", "--environment", "staging", "--paths", "secret1", "secret2"])

    self.assertEqual(args.command, "refresh")
    self.assertEqual(args.environment, "staging")
    self.assertEqual(args.paths, ["secret1", "secret2"])

  def test_inspect_parsing_with_format(self) -> None:
    """Test parsing of inspect command with format options."""
    args = self.parser.parse_args(["inspect", "--environment", "dev", "--format", "json", "--show-values"])

    self.assertEqual(args.command, "inspect")
    self.assertEqual(args.environment, "dev")
    self.assertEqual(args.format, "json")
    self.assertTrue(args.show_values)

  def test_debug_parsing(self) -> None:
    """Test parsing of debug command."""
    args = self.parser.parse_args(["debug"])

    self.assertEqual(args.command, "debug")

  def test_cleanup_parsing_with_all(self) -> None:
    """Test parsing of cleanup command with --all flag."""
    args = self.parser.parse_args(["cleanup", "--all"])

    self.assertEqual(args.command, "cleanup")
    self.assertTrue(args.all)

  def test_global_options_parsing(self) -> None:
    """Test parsing of global options."""
    args = self.parser.parse_args(["--debug", "--quiet", "--log-level", "WARNING", "debug"])

    self.assertTrue(args.debug)
    self.assertTrue(args.quiet)
    self.assertEqual(args.log_level, "WARNING")
    self.assertEqual(args.command, "debug")


class TestIntegrationScenarios(TestCLIBase):
  """Integration test scenarios combining multiple components."""

  @patch("auto_secrets.cli.app", create=True)
  @patch("auto_secrets.cli._refresh_secrets")
  def test_branch_change_workflow(self, mock_refresh: Mock, mock_app: Mock) -> None:
    """Test complete branch change workflow."""
    mock_app.get_logger.return_value = self.mock_logger
    mock_app.branch_manager = self.mock_branch_manager

    # Setup branch mapping
    self.mock_branch_manager.map_branch_to_environment.return_value = "feature-env"

    args = argparse.Namespace(branch="feature/auth-system", repopath="/projects/myapp")

    handle_branch_change(args)

    # Verify the complete workflow
    self.mock_branch_manager.map_branch_to_environment.assert_called_once_with("feature/auth-system", "/projects/myapp")
    mock_refresh.assert_called_once_with("feature-env", "feature/auth-system", "/projects/myapp")
    self.mock_logger.debug.assert_called()

  @patch("auto_secrets.cli.app", create=True)
  @patch("builtins.print")
  def test_inspect_and_exec_workflow(self, mock_print: Mock, mock_app: Mock) -> None:
    """Test workflow of inspecting secrets then executing command."""
    mock_app.get_logger.return_value = self.mock_logger
    mock_app.cache_manager = self.mock_cache_manager
    mock_app.key_retriever = self.mock_key_retriever

    test_secrets = {"DATABASE_URL": "postgresql://localhost:5432/myapp", "API_KEY": "secret-api-key-123"}
    self.mock_cache_manager.get_cached_secrets.return_value = test_secrets
    self.mock_cache_manager.is_cache_stale.return_value = False

    # First inspect
    inspect_args = argparse.Namespace(environment="staging", paths=None, format="keys", show_values=False, quiet=False)

    handle_inspect_secrets(inspect_args)

    expected_keys_output = "DATABASE_URL\nAPI_KEY"
    mock_print.assert_called_with(expected_keys_output)

    # Then execute with same environment
    with patch("auto_secrets.cli.subprocess.run") as mock_run:
      mock_result = Mock()
      mock_result.returncode = 0
      mock_run.return_value = mock_result

      exec_args = argparse.Namespace(environment="staging", paths=None, command=["python", "manage.py", "test"])

      with patch("auto_secrets.cli.sys.exit"):
        handle_exec_command(exec_args)

      # Verify secrets were loaded in environment
      call_args = mock_run.call_args
      executed_env = call_args[1]["env"]
      self.assertIn("DATABASE_URL", executed_env)
      self.assertIn("API_KEY", executed_env)
      self.assertEqual(executed_env["DATABASE_URL"], "postgresql://localhost:5432/myapp")

  @patch("auto_secrets.cli.app", create=True)
  @patch("builtins.print")
  def test_terraform_environment_setup(self, mock_print: Mock, mock_app: Mock) -> None:
    """Test complete Terraform environment setup workflow."""
    mock_app.get_logger.return_value = self.mock_logger
    mock_app.branch_manager = self.mock_branch_manager
    mock_app.cache_manager = self.mock_cache_manager

    # Setup environment mapping and secrets
    self.mock_branch_manager.map_branch_to_environment.return_value = "production"
    self.mock_cache_manager.get_auto_command_paths.return_value = ["/terraform/secrets"]

    terraform_secrets = {
      "aws_access_key": "AKIA...",
      "aws_secret_key": "secret...",
      "region": "us-west-2",
      "TF_VAR_existing_var": "already_prefixed",
    }
    self.mock_cache_manager.get_cached_secrets.return_value = terraform_secrets

    args = argparse.Namespace(branch="production", repopath="/infrastructure", command="terraform")

    handle_output_env(args)

    # Verify Terraform-specific variable prefixing
    print_calls = [call[0][0] for call in mock_print.call_args_list]

    expected_exports = [
      'export TF_VAR_aws_access_key="AKIA..."',
      'export TF_VAR_aws_secret_key="secret..."',
      'export TF_VAR_region="us-west-2"',
      'export TF_VAR_existing_var="already_prefixed"',
      "export AUTO_SECRETS_CURRENT_ENV='production'",
    ]

    for expected_export in expected_exports:
      self.assertIn(expected_export, print_calls)

  @patch("auto_secrets.cli.app", create=True)
  @patch("auto_secrets.cli._refresh_secrets")
  @patch("builtins.print")
  def test_full_refresh_and_inspect_cycle(self, mock_print: Mock, mock_refresh: Mock, mock_app: Mock) -> None:
    """Test full cycle of refresh then inspect."""
    mock_app.get_logger.return_value = self.mock_logger
    mock_app.cache_manager = self.mock_cache_manager

    # First refresh
    refresh_args = self.create_args(environment="production", quiet=False)
    handle_refresh_secrets(refresh_args)

    mock_refresh.assert_called_once_with("production")

    # Then inspect the refreshed secrets
    test_secrets = {"SECRET_KEY": "refreshed_value"}
    self.mock_cache_manager.get_cached_secrets.return_value = test_secrets
    self.mock_cache_manager.is_cache_stale.return_value = False

    inspect_args = self.create_args(environment="production", format="env", show_values=False)

    handle_inspect_secrets(inspect_args)

    expected_output = 'SECRET_KEY="refreshed_value"'
    mock_print.assert_any_call(expected_output)


class TestSetSmSecret(TestCLIBase):
  """Test cases for set_sm_secret function."""

  @patch("auto_secrets.cli.app", create=True)
  def test_set_sm_secret_success(self, mock_app: Mock) -> None:
    """Test successful secret setting."""
    mock_app.get_logger.return_value = self.mock_logger
    mock_app.secret_manager = self.mock_secret_manager

    args = self.create_args()

    set_sm_secret(args)

    self.mock_secret_manager.set_secret.assert_called_once()

  @patch("auto_secrets.cli.app", create=True)
  @patch("builtins.print")
  @patch("auto_secrets.cli.sys.exit")
  def test_set_sm_secret_exception(self, mock_exit: Mock, mock_print: Mock, mock_app: Mock) -> None:
    """Test secret setting with exception."""
    mock_app.get_logger.return_value = self.mock_logger
    mock_app.secret_manager = self.mock_secret_manager

    self.mock_secret_manager.set_secret.side_effect = Exception("Set secret failed")

    args = self.create_args()

    set_sm_secret(args)

    self.mock_logger.error.assert_called()
    mock_print.assert_called_with("❌ set_secret failed: Set secret failed", file=sys.stderr)
    mock_exit.assert_called_once_with(1)


class TestErrorHandlingAndEdgeCases(TestCLIBase):
  """Test error handling and edge cases."""

  @patch("auto_secrets.cli.app", create=True)
  @patch("builtins.print")
  def test_inspect_secrets_with_empty_values(self, mock_print: Mock, mock_app: Mock) -> None:
    """Test inspect secrets with empty or None values."""
    mock_app.get_logger.return_value = self.mock_logger
    mock_app.cache_manager = self.mock_cache_manager

    test_secrets = {"EMPTY_SECRET": "", "SHORT_SECRET": "ab"}
    self.mock_cache_manager.get_cached_secrets.return_value = test_secrets
    self.mock_cache_manager.is_cache_stale.return_value = False

    args = self.create_args(environment="test", paths=None, format="table", show_values=True, quiet=False)

    handle_inspect_secrets(args)

    # Verify output handles edge cases properly
    call_args = mock_print.call_args[0][0]
    self.assertIn("EMPTY_SECRET=***", call_args)
    self.assertIn("SHORT_SECRET=a***", call_args)

  @patch("auto_secrets.cli.app", create=True)
  @patch("auto_secrets.cli.subprocess.run")
  @patch("auto_secrets.cli.sys.exit")
  def test_exec_command_with_complex_command_args(self, mock_exit: Mock, mock_run: Mock, mock_app: Mock) -> None:
    """Test exec command with complex command arguments."""
    mock_app.get_logger.return_value = self.mock_logger
    mock_app.cache_manager = self.mock_cache_manager
    mock_app.key_retriever = self.mock_key_retriever

    self.mock_cache_manager.get_cached_secrets.return_value = {"SECRET": "value"}

    mock_result = Mock()
    mock_result.returncode = 42
    mock_run.return_value = mock_result

    args = self.create_args(environment="dev", paths=None, command=["bash", "-c", 'echo "Hello $SECRET"'])

    handle_exec_command(args)

    # Verify complex command was executed correctly
    mock_run.assert_called_once()
    executed_command = mock_run.call_args[0][0]
    self.assertEqual(executed_command, ["bash", "-c", 'echo "Hello $SECRET"'])

    # Verify exit code was propagated
    mock_exit.assert_called_once_with(42)

  @patch("auto_secrets.cli.app", create=True)
  def test_refresh_secrets_with_large_secret_set(self, mock_app: Mock) -> None:
    """Test refresh secrets with large number of secrets."""
    mock_app.get_logger.return_value = self.mock_logger
    mock_app.secret_manager = self.mock_secret_manager
    mock_app.cache_manager = self.mock_cache_manager

    # Generate large secret set
    large_secrets = {f"SECRET_{i}": f"value_{i}" for i in range(1000)}

    self.mock_secret_manager.test_connection.return_value = True
    self.mock_secret_manager.fetch_secrets.return_value = large_secrets

    _refresh_secrets("load-test-env", "main", "/repo")

    # Verify all secrets were processed
    self.mock_cache_manager.update_environment_cache.assert_called_once_with(
      "load-test-env", large_secrets, "main", "/repo"
    )

    # Verify logging included count
    log_calls = [call[0][0] for call in self.mock_logger.info.call_args_list]
    self.assertTrue(any("1000 secrets" in call for call in log_calls))

  @patch("auto_secrets.cli.app", create=True)
  @patch("builtins.print")
  def test_output_env_with_special_characters(self, mock_print: Mock, mock_app: Mock) -> None:
    """Test output env with secrets containing special characters."""
    mock_app.get_logger.return_value = self.mock_logger
    mock_app.branch_manager = self.mock_branch_manager
    mock_app.cache_manager = self.mock_cache_manager

    self.mock_branch_manager.map_branch_to_environment.return_value = "dev"
    self.mock_cache_manager.get_auto_command_paths.return_value = []

    # Secrets with special characters
    special_secrets = {
      "PASSWORD_WITH_QUOTES": "pass\"word's",
      "PASSWORD_WITH_SPACES": "pass word",
      "PASSWORD_WITH_SYMBOLS": "pass@#$%^&*()",
    }
    self.mock_cache_manager.get_cached_secrets.return_value = special_secrets

    args = self.create_args(branch="main", repopath="/repo", command="python")

    handle_output_env(args)

    # Verify proper escaping in shell exports
    print_calls = [call[0][0] for call in mock_print.call_args_list]

    expected_exports = [
      'export PASSWORD_WITH_QUOTES="pass"word\'s"',
      'export PASSWORD_WITH_SPACES="pass word"',
      'export PASSWORD_WITH_SYMBOLS="pass@#$%^&*()"',
    ]

    for expected_export in expected_exports:
      self.assertIn(expected_export, print_calls)

  @patch("auto_secrets.cli.app", create=True)
  @patch("builtins.print")
  def test_debug_env_with_exceptions(self, mock_print: Mock, mock_app: Mock) -> None:
    """Test debug environment with various component failures."""
    mock_app.get_logger.return_value = self.mock_logger
    mock_app.cache_manager = self.mock_cache_manager
    mock_app.secret_manager = self.mock_secret_manager

    # Mock cache manager to raise exception
    self.mock_cache_manager.base_dir.side_effect = Exception("Cache directory error")

    # Mock secret manager to raise exception
    self.mock_secret_manager.test_connection.side_effect = Exception("Connection error")

    with (
      patch("os.getcwd", return_value="/test/dir"),
      patch("os.getenv", side_effect=lambda k, d="unknown": {"USER": "testuser"}.get(k, d)),
    ):
      handle_debug_env()

    # Verify error handling in debug output
    print_calls = [call[0][0] for call in mock_print.call_args_list]
    debug_output = "\n".join(print_calls)

    self.assertIn("=== Auto Secrets Manager Debug Information ===", debug_output)
    self.assertIn("Working Directory: /test/dir", debug_output)
    self.assertIn("Error checking cache:", debug_output)
    self.assertIn("Error testing secret manager:", debug_output)

  @patch("auto_secrets.cli.sys.exit")
  @patch("auto_secrets.cli.app", create=True)
  def test_refresh_secrets_exception(self, mock_app: Mock, mock_exit: Mock) -> None:
    """Test refresh secrets with connection timeout."""
    mock_app.get_logger.return_value = self.mock_logger

    # Make sure secret_manager exists but connection fails
    mock_app.secret_manager = self.mock_secret_manager
    mock_app.secret_manager.test_connection.return_value = False

    _refresh_secrets("timeout-env")

    self.mock_logger.warning.assert_called_with("Secret manager not available for background refresh")
    # Since sys.exit might be called multiple times, just verify it was called with 1
    mock_exit.assert_called_with(1)

  @patch("auto_secrets.cli.app", create=True)
  @patch("builtins.print")
  def test_inspect_secrets_with_path_filtering(self, mock_print: Mock, mock_app: Mock) -> None:
    """Test inspect secrets with path filtering."""
    mock_app.get_logger.return_value = self.mock_logger
    mock_app.cache_manager = self.mock_cache_manager

    filtered_secrets = {"DB_HOST": "localhost", "DB_PASSWORD": "secret"}

    self.mock_cache_manager.get_cached_secrets.return_value = filtered_secrets

    args = self.create_args(environment="dev", paths=["db/*"], format="keys")

    handle_inspect_secrets(args)

    # Verify path filtering was applied
    self.mock_cache_manager.get_cached_secrets.assert_called_once_with("dev", ["db/*"])

    expected_output = "DB_HOST\nDB_PASSWORD"
    mock_print.assert_called_with(expected_output)


class TestComplexScenarios(TestCLIBase):
  """Test complex real-world scenarios."""

  @patch("auto_secrets.cli.app", create=True)
  @patch("builtins.print")
  def test_multi_environment_terraform_workflow(self, mock_print: Mock, mock_app: Mock) -> None:
    """Test Terraform workflow across multiple environments."""
    mock_app.get_logger.return_value = self.mock_logger
    mock_app.branch_manager = self.mock_branch_manager
    mock_app.cache_manager = self.mock_cache_manager

    # Test dev environment
    self.mock_branch_manager.map_branch_to_environment.return_value = "dev"
    self.mock_cache_manager.get_auto_command_paths.return_value = []
    self.mock_cache_manager.get_cached_secrets.return_value = {"instance_type": "t3.micro", "region": "us-east-1"}

    dev_args = self.create_args(branch="develop", repopath="/infra", command="terraform")
    handle_output_env(dev_args)

    # Test production environment
    self.mock_branch_manager.map_branch_to_environment.return_value = "production"
    self.mock_cache_manager.get_cached_secrets.return_value = {"instance_type": "t3.large", "region": "us-west-2"}

    prod_args = self.create_args(branch="main", repopath="/infra", command="terraform")
    handle_output_env(prod_args)

    # Verify different configurations for different environments
    print_calls = [call[0][0] for call in mock_print.call_args_list]

    # Should have both dev and prod variables
    self.assertIn('export TF_VAR_instance_type="t3.micro"', print_calls)
    self.assertIn('export TF_VAR_instance_type="t3.large"', print_calls)
    self.assertIn('export TF_VAR_region="us-east-1"', print_calls)
    self.assertIn('export TF_VAR_region="us-west-2"', print_calls)

  @patch("auto_secrets.cli.app", create=True)
  @patch("auto_secrets.cli.subprocess.run")
  @patch("auto_secrets.cli.sys.exit")
  def test_exec_command_environment_isolation(self, mock_exit: Mock, mock_run: Mock, mock_app: Mock) -> None:
    """Test that different exec commands have isolated environments."""
    mock_app.get_logger.return_value = self.mock_logger
    mock_app.cache_manager = self.mock_cache_manager
    mock_app.key_retriever = self.mock_key_retriever

    # First execution with dev secrets
    dev_secrets = {"ENV": "development", "DEBUG": "true"}
    self.mock_cache_manager.get_cached_secrets.return_value = dev_secrets

    mock_result = Mock()
    mock_result.returncode = 0
    mock_run.return_value = mock_result

    dev_args = self.create_args(environment="dev", command=["echo", "dev"])
    handle_exec_command(dev_args)

    # Verify dev environment
    first_call_env = mock_run.call_args[1]["env"]
    self.assertEqual(first_call_env["ENV"], "development")
    self.assertEqual(first_call_env["DEBUG"], "true")

    # Reset mock
    mock_run.reset_mock()

    # Second execution with prod secrets
    prod_secrets = {"ENV": "production", "DEBUG": "false"}
    self.mock_cache_manager.get_cached_secrets.return_value = prod_secrets

    prod_args = self.create_args(environment="prod", command=["echo", "prod"])
    handle_exec_command(prod_args)

    # Verify prod environment
    second_call_env = mock_run.call_args[1]["env"]
    self.assertEqual(second_call_env["ENV"], "production")
    self.assertEqual(second_call_env["DEBUG"], "false")


class TestTypeAnnotationCompliance(TestCase):
  """Test type annotation compliance and mypy compatibility."""

  def test_create_args_return_type(self) -> None:
    """Test that create_args returns proper type."""
    base_test = TestCLIBase()
    base_test.setUp()

    args = base_test.create_args(environment="test")

    # Verify it's the correct type
    self.assertIsInstance(args, argparse.Namespace)
    self.assertEqual(args.environment, "test")

  def test_mock_type_specifications(self) -> None:
    """Test that mocks are properly typed."""
    base_test = TestCLIBase()
    base_test.setUp()

    # Verify mock types
    self.assertIsInstance(base_test.mock_app, Mock)
    self.assertIsInstance(base_test.mock_logger, Mock)
    self.assertIsInstance(base_test.mock_cache_manager, Mock)


if __name__ == "__main__":
  # Run the tests
  import unittest

  unittest.main(verbosity=2)
