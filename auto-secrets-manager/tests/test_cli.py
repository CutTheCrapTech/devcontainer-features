"""
Tests for auto_secrets.cli module.

Tests the command-line interface functionality including argument parsing,
command execution, and integration with other modules.
"""

import os
from io import StringIO
from typing import Any, Dict
from unittest.mock import Mock, patch

import pytest
from auto_secrets.cli import handle_branch_change  # type: ignore
from auto_secrets.cli import (
    _background_refresh_secrets,
    handle_cleanup,
    handle_debug_env,
    handle_exec_command,
    handle_exec_for_shell,
    handle_inspect_secrets,
    handle_refresh_secrets,
    main,
)
from auto_secrets.core.config import ConfigError  # type: ignore
from auto_secrets.secret_managers.base import ConnectionTestResult, SecretManagerError  # type: ignore


class TestHandleBranchChange:
    """Test handle_branch_change function."""

    def setup_method(self) -> None:
        """Set up test fixtures."""
        self.mock_args = Mock()
        self.mock_args.branch = "main"
        self.mock_args.repo_path = "/path/to/repo"

        self.mock_config: Dict[str, Any] = {
            "branch_mappings": {
                "main": "production",
                "develop": "staging",
                "default": "development",
            }
        }

    @patch("auto_secrets.cli.ConfigManager.load_config")
    @patch("auto_secrets.cli.BranchManager")
    @patch("auto_secrets.cli.CacheManager")
    @patch("auto_secrets.cli.create_secret_manager")
    def test_handle_branch_change_new_environment(
        self,
        mock_create_manager,
        mock_cache_manager,
        mock_branch_manager,
        mock_load_config,
    ):
        """Test handling branch change to new environment."""
        mock_load_config.return_value = self.mock_config

        mock_branch_instance = Mock()
        mock_branch_instance.map_branch_to_environment.return_value = "production"
        mock_branch_manager.return_value = mock_branch_instance

        mock_manager = Mock()
        mock_manager.fetch_secrets.return_value = {"key": "value"}
        mock_create_manager.return_value = mock_manager

        mock_cache_instance = Mock()
        mock_cache_manager.return_value = mock_cache_instance

        with patch("time.time", return_value=1234567890):
            handle_branch_change(self.mock_args)

        mock_cache_instance.update_environment_cache.assert_called_once_with(
            "production", {"key": "value"}, 'main', '/path/to/repo'
        )

    @patch("auto_secrets.cli.ConfigManager.load_config")
    @patch("auto_secrets.cli.BranchManager")
    def test_handle_branch_change_no_mapping(
        self, mock_branch_manager, mock_load_config
    ):
        """Test handling branch change with no mapping found."""
        self.mock_config["cache_base_dir"] = "/tmp"
        mock_load_config.return_value = self.mock_config

        mock_branch_instance = Mock()
        mock_branch_instance.map_branch_to_environment.return_value = None
        mock_branch_manager.return_value = mock_branch_instance

        with pytest.raises(SystemExit):
            handle_branch_change(self.mock_args)

    @patch("auto_secrets.cli.ConfigManager.load_config")
    def test_handle_branch_change_error(self, mock_load_config):
        """Test handling branch change with error."""
        mock_load_config.side_effect = Exception("Config error")

        with pytest.raises(SystemExit):
            handle_branch_change(self.mock_args)


class TestHandleRefreshSecrets:
    """Test handle_refresh_secrets function."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_args = Mock()
        self.mock_args.environment = "production"

    @patch("auto_secrets.cli.ConfigManager.load_config")
    @patch("auto_secrets.cli.CacheManager")
    @patch("auto_secrets.cli.create_secret_manager")
    def test_handle_refresh_secrets_specified_env(
        self, mock_create_manager, mock_cache_manager, mock_load_config
    ):
        """Test refreshing secrets for specified environment."""
        mock_config = {"secret_manager": {"type": "infisical"}}
        mock_load_config.return_value = mock_config

        mock_cache_instance = Mock()
        mock_cache_manager.return_value = mock_cache_instance

        mock_manager = Mock()
        mock_manager.fetch_secrets.return_value = {"key": "value"}
        mock_create_manager.return_value = mock_manager

        handle_refresh_secrets(self.mock_args)

        mock_manager.fetch_secrets.assert_called_once_with("production")
        mock_cache_instance.update_environment_cache.assert_called_once()


class TestHandleInspectSecrets:
    """Test handle_inspect_secrets function."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_args = Mock()
        self.mock_args.environment = "production"
        self.mock_args.format = "table"

    @patch("auto_secrets.cli.ConfigManager.load_config")
    @patch("auto_secrets.cli.CacheManager")
    def test_handle_inspect_secrets_with_cache(
        self, mock_cache_manager, mock_load_config
    ):
        """Test inspecting cached secrets."""
        mock_config = {}
        mock_load_config.return_value = mock_config

        mock_cache_instance = Mock()
        mock_cache_instance.get_cached_secrets.return_value = {
            "API_KEY": "secret123",
            "DB_PASSWORD": "dbpass456",
        }
        mock_cache_manager.return_value = mock_cache_instance

        with patch("sys.stdout", new_callable=StringIO) as mock_stdout:
            handle_inspect_secrets(self.mock_args)

            output = mock_stdout.getvalue()
            assert "API_KEY" in output
            assert "DB_PASSWORD" in output

    @patch("auto_secrets.cli.ConfigManager.load_config")
    @patch("auto_secrets.cli.CacheManager")
    def test_handle_inspect_secrets_no_cache(
        self, mock_cache_manager, mock_load_config
    ):
        """Test inspecting secrets with no cache."""
        mock_config = {}
        mock_load_config.return_value = mock_config

        mock_cache_instance = Mock()
        mock_cache_instance.get_cached_secrets.return_value = {}
        mock_cache_manager.return_value = mock_cache_instance

        with patch("sys.stdout", new_callable=StringIO) as mock_stdout:
            handle_inspect_secrets(self.mock_args)

            output = mock_stdout.getvalue()
            assert "No cached secrets found" in output or output == ""


class TestHandleExecCommand:
    """Test handle_exec_command function."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_args = Mock()
        self.mock_args.environment = "production"
        self.mock_args.command = ["echo", "test"]

    @patch("auto_secrets.cli.ConfigManager.load_config")
    @patch("auto_secrets.cli.CacheManager")
    @patch("subprocess.run")
    def test_handle_exec_command_success(
        self, mock_subprocess, mock_cache_manager, mock_load_config
    ):
        """Test executing command with secrets."""
        mock_config = {}
        mock_load_config.return_value = mock_config

        mock_cache_instance = Mock()
        mock_cache_instance.get_cached_secrets.return_value = {
            "API_KEY": "secret123",
            "DB_PASSWORD": "dbpass456",
        }
        mock_cache_manager.return_value = mock_cache_instance

        mock_result = Mock()
        mock_result.returncode = 0
        mock_subprocess.return_value = mock_result

        with pytest.raises(SystemExit) as e:
            handle_exec_command(self.mock_args)

        assert e.value.code == 0

        mock_subprocess.assert_called_once()
        # Check that environment was modified
        call_args = mock_subprocess.call_args
        env_arg = call_args[1]["env"]
        assert "API_KEY" in env_arg
        assert "DB_PASSWORD" in env_arg

    @patch("auto_secrets.cli.ConfigManager.load_config")
    @patch("auto_secrets.cli.CacheManager")
    def test_handle_exec_command_no_secrets(self, mock_cache_manager, mock_load_config):
        """Test executing command with no secrets available."""
        mock_config = {}
        mock_load_config.return_value = mock_config

        mock_cache_instance = Mock()
        mock_cache_instance.get_cached_secrets.return_value = {}
        mock_cache_manager.return_value = mock_cache_instance

        with pytest.raises(SystemExit):
            handle_exec_command(self.mock_args)


class TestHandleExecForShell:
    """Test handle_exec_for_shell function."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_args = Mock()
        self.mock_args.environment = "production"
        self.mock_args.shell = "bash"

    @patch("auto_secrets.cli.ConfigManager.load_config")
    @patch("auto_secrets.cli.CacheManager")
    def test_handle_exec_for_shell_bash(self, mock_cache_manager, mock_load_config):
        """Test generating bash script."""
        self.mock_args.shell = "bash"

        mock_config = {}
        mock_load_config.return_value = mock_config

        mock_cache_instance = Mock()
        mock_cache_instance.get_cached_secrets.return_value = {
            "API_KEY": "secret123",
            "DB_PASSWORD": "dbpass456",
        }
        mock_cache_manager.return_value = mock_cache_instance

        with patch("sys.stdout", new_callable=StringIO) as mock_stdout:
            handle_exec_for_shell(self.mock_args)

            output = mock_stdout.getvalue()
            assert 'export API_KEY="secret123"' in output
            assert 'export DB_PASSWORD="dbpass456"' in output

    @patch("auto_secrets.cli.ConfigManager.load_config")
    @patch("auto_secrets.cli.CacheManager")
    def test_handle_exec_for_shell_zsh(self, mock_cache_manager, mock_load_config):
        """Test generating zsh script."""
        self.mock_args.shell = "zsh"

        mock_config = {}
        mock_load_config.return_value = mock_config

        mock_cache_instance = Mock()
        mock_cache_instance.get_cached_secrets.return_value = {
            "API_KEY": "secret123",
            "DB_PASSWORD": "dbpass456",
        }
        mock_cache_manager.return_value = mock_cache_instance

        with patch("sys.stdout", new_callable=StringIO) as mock_stdout:
            handle_exec_for_shell(self.mock_args)

            output = mock_stdout.getvalue()
            assert 'export API_KEY="secret123"' in output
            assert 'export DB_PASSWORD="dbpass456"' in output


class TestHandleDebugEnv:
    """Test handle_debug_env function."""

    @patch("auto_secrets.cli.ConfigManager.load_config")
    def test_handle_debug_env(self, mock_load_config):
        """Test debug environment information."""
        mock_config = {
            "secret_manager": {"type": "infisical"},
            "branch_mappings": {"main": "production"},
        }
        mock_load_config.return_value = mock_config

        with patch("sys.stdout", new_callable=StringIO) as mock_stdout, patch(
            "auto_secrets.cli.BranchManager"
        ) as mock_branch_manager, patch(
            "auto_secrets.cli.CacheManager"
        ) as mock_cache_manager:

            mock_branch_instance = Mock()
            mock_branch_instance.get_mapping_status.return_value = {
                "current_branch": "main",
                "current_environment": "production",
            }
            mock_branch_manager.return_value = mock_branch_instance

            mock_cache_instance = Mock()
            mock_cache_instance.get_cache_info.return_value = {
                "total_environments": 1,
                "environments": {"production": {"status": "ok"}},
            }
            mock_cache_manager.return_value = mock_cache_instance

            handle_debug_env()

            output = mock_stdout.getvalue()
            assert "Auto Secrets Manager Debug Information" in output
            assert "System Information" in output
            assert "Configuration" in output


class TestHandleCleanup:
    """Test handle_cleanup function."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_args = Mock()
        self.mock_args.all = False
        self.mock_args.stale = False

    @patch("auto_secrets.cli.ConfigManager.load_config")
    @patch("auto_secrets.cli.CacheManager")
    def test_handle_cleanup_all(self, mock_cache_manager, mock_load_config):
        """Test cleanup all caches."""
        self.mock_args.all = True

        mock_config = {}
        mock_load_config.return_value = mock_config

        mock_cache_instance = Mock()
        mock_cache_instance.cleanup_all.return_value = {"removed": 3}
        mock_cache_manager.return_value = mock_cache_instance

        handle_cleanup(self.mock_args)

        mock_cache_instance.cleanup_all.assert_called_once()

    @patch("auto_secrets.cli.ConfigManager.load_config")
    @patch("auto_secrets.cli.CacheManager")
    def test_handle_cleanup_stale(self, mock_cache_manager, mock_load_config):
        """Test cleanup stale caches."""
        self.mock_args.stale = True

        mock_config = {}
        mock_load_config.return_value = mock_config

        mock_cache_instance = Mock()
        mock_cache_instance.cleanup_stale.return_value = {"removed": 2, "kept": 1}
        mock_cache_manager.return_value = mock_cache_instance

        handle_cleanup(self.mock_args)

        mock_cache_instance.cleanup_stale.assert_called_once()


class TestBackgroundRefreshSecrets:
    """Test _background_refresh_secrets function."""

    @patch("auto_secrets.cli.create_secret_manager")
    @patch("auto_secrets.cli.CacheManager")
    def test_background_refresh_success(self, mock_cache_manager, mock_create_manager):
        """Test successful background refresh."""
        environment = "production"
        config = {"secret_manager": {"type": "infisical"}}

        mock_manager = Mock()
        mock_manager.test_connection.return_value = ConnectionTestResult(
            success=True, message="OK", details={}, authenticated=True
        )
        mock_manager.fetch_secrets.return_value = {"key": "value"}
        mock_create_manager.return_value = mock_manager

        mock_cache_instance = Mock()
        mock_cache_manager.return_value = mock_cache_instance

        # Should not raise exception
        _background_refresh_secrets(environment, config)

        mock_manager.fetch_secrets.assert_called_once_with(environment)

    @patch("auto_secrets.cli.create_secret_manager")
    def test_background_refresh_no_manager(self, mock_create_manager):
        """Test background refresh with no secret manager."""
        environment = "production"
        config = {}

        mock_create_manager.return_value = None

        with pytest.raises(SystemExit):
            _background_refresh_secrets(environment, config)


class TestMainFunction:
    """Test main CLI function."""

    @patch("auto_secrets.cli.ConfigManager.load_config")
    @patch("auto_secrets.cli.setup_logging")
    @patch("argparse.ArgumentParser.parse_args")
    def test_main_branch_change_command(
        self, mock_parse_args, mock_setup_logging, mock_load_config
    ):
        """Test main function with branch-change command."""
        mock_load_config.return_value = {
            "cache_base_dir": "/tmp",
            "secret_manager": "infisical",
            "log_dir": "/tmp",
        }
        mock_args = Mock()
        mock_args.debug = False
        mock_args.quiet = False
        mock_args.command = "branch-changed"
        mock_args.branch = "main"
        mock_args.repo_path = "/repo"
        mock_parse_args.return_value = mock_args

        with patch("auto_secrets.cli.handle_branch_change") as mock_handle, patch.dict(
            os.environ,
            {
                "AUTO_SECRETS_SECRET_MANAGER": "infisical",
                "AUTO_SECRETS_SHELLS": "bash",
                "AUTO_SECRETS_BRANCH_MAPPINGS": '{"main": "production", "default": "development"}',
            },
        ):
            mock_args.func = mock_handle
            main()

            mock_setup_logging.assert_called_once()
            mock_handle.assert_called_once_with(mock_args)

    @patch("auto_secrets.cli.ConfigManager.load_config")
    @patch("auto_secrets.cli.setup_logging")
    @patch("argparse.ArgumentParser.parse_args")
    def test_main_refresh_command(
        self, mock_parse_args, mock_setup_logging, mock_load_config
    ):
        """Test main function with refresh command."""
        mock_load_config.return_value = {
            "cache_base_dir": "/tmp",
            "secret_manager": "infisical",
            "log_dir": "/tmp",
        }
        mock_args = Mock()
        mock_args.debug = False
        mock_args.quiet = False
        mock_args.command = "refresh"
        mock_args.environment = "production"
        mock_args.paths = None
        mock_parse_args.return_value = mock_args

        with patch(
            "auto_secrets.cli.handle_refresh_secrets"
        ) as mock_handle, patch.dict(
            os.environ,
            {
                "AUTO_SECRETS_SECRET_MANAGER": "infisical",
                "AUTO_SECRETS_SHELLS": "bash",
                "AUTO_SECRETS_BRANCH_MAPPINGS": '{"main": "production", "default": "development"}',
            },
        ):
            mock_args.func = mock_handle
            main()

            mock_setup_logging.assert_called_once()
            mock_handle.assert_called_once_with(mock_args)

    @patch("auto_secrets.cli.ConfigManager.load_config")
    @patch("auto_secrets.cli.setup_logging")
    @patch("argparse.ArgumentParser.parse_args")
    def test_main_inspect_command(
        self, mock_parse_args, mock_setup_logging, mock_load_config
    ):
        """Test main function with inspect command."""
        mock_load_config.return_value = {
            "cache_base_dir": "/tmp",
            "secret_manager": "infisical",
            "log_dir": "/tmp",
        }
        mock_args = Mock()
        mock_args.debug = False
        mock_args.quiet = False
        mock_args.command = "inspect"
        mock_args.environment = "production"
        mock_args.paths = None
        mock_args.shell = "bash"
        mock_parse_args.return_value = mock_args

        with patch(
            "auto_secrets.cli.handle_inspect_secrets"
        ) as mock_handle, patch.dict(
            os.environ,
            {
                "AUTO_SECRETS_SECRET_MANAGER": "infisical",
                "AUTO_SECRETS_SHELLS": "bash",
                "AUTO_SECRETS_BRANCH_MAPPINGS": '{"main": "production", "default": "development"}',
            },
        ):
            mock_args.func = mock_handle
            main()

            mock_setup_logging.assert_called_once()
            mock_handle.assert_called_once_with(mock_args)

    @patch("auto_secrets.cli.ConfigManager.load_config")
    @patch("auto_secrets.cli.setup_logging")
    @patch("argparse.ArgumentParser.parse_args")
    def test_main_exec_command(
        self, mock_parse_args, mock_setup_logging, mock_load_config
    ):
        """Test main function with exec command."""
        mock_load_config.return_value = {
            "cache_base_dir": "/tmp",
            "secret_manager": "infisical",
            "log_dir": "/tmp",
        }
        mock_args = Mock()
        mock_args.debug = False
        mock_args.quiet = False
        mock_args.command = "exec"
        mock_args.environment = "production"
        mock_args.command = ["echo", "test"]
        mock_parse_args.return_value = mock_args

        with patch("auto_secrets.cli.handle_exec_command") as mock_handle, patch.dict(
            os.environ,
            {
                "AUTO_SECRETS_SECRET_MANAGER": "infisical",
                "AUTO_SECRETS_SHELLS": "bash",
                "AUTO_SECRETS_BRANCH_MAPPINGS": '{"main": "production", "default": "development"}',
            },
        ):
            mock_args.func = mock_handle
            main()

            mock_setup_logging.assert_called_once()
            mock_handle.assert_called_once_with(mock_args)

    @patch("auto_secrets.cli.ConfigManager.load_config")
    @patch("auto_secrets.cli.setup_logging")
    @patch("argparse.ArgumentParser.parse_args")
    def test_main_shell_command(
        self, mock_parse_args, mock_setup_logging, mock_load_config
    ):
        """Test main function with shell command."""
        mock_load_config.return_value = {
            "cache_base_dir": "/tmp",
            "secret_manager": "infisical",
            "log_dir": "/tmp",
        }
        mock_args = Mock()
        mock_args.debug = False
        mock_args.quiet = False
        mock_args.command = "output-env"
        mock_args.environment = "production"
        mock_args.paths = None
        mock_parse_args.return_value = mock_args

        with patch("auto_secrets.cli.handle_exec_for_shell") as mock_handle, patch.dict(
            os.environ,
            {
                "AUTO_SECRETS_SECRET_MANAGER": "infisical",
                "AUTO_SECRETS_SHELLS": "bash",
                "AUTO_SECRETS_BRANCH_MAPPINGS": '{"main": "production", "default": "development"}',
            },
        ):
            mock_args.func = mock_handle
            main()

            mock_setup_logging.assert_called_once()
            mock_handle.assert_called_once_with(mock_args)

    @patch("auto_secrets.cli.ConfigManager.load_config")
    @patch("auto_secrets.cli.setup_logging")
    @patch("argparse.ArgumentParser.parse_args")
    def test_main_debug_command(
        self, mock_parse_args, mock_setup_logging, mock_load_config
    ):
        """Test main function with debug command."""
        mock_load_config.return_value = {
            "cache_base_dir": "/tmp",
            "secret_manager": "infisical",
            "log_dir": "/tmp",
        }
        mock_args = Mock()
        mock_args.debug = False
        mock_args.quiet = False
        mock_args.command = "debug"
        mock_parse_args.return_value = mock_args

        with patch("auto_secrets.cli.handle_debug_env") as mock_handle, patch.dict(
            os.environ,
            {
                "AUTO_SECRETS_SECRET_MANAGER": "infisical",
                "AUTO_SECRETS_SHELLS": "bash",
                "AUTO_SECRETS_BRANCH_MAPPINGS": '{"main": "production", "default": "development"}',
            },
        ):
            mock_args.func = mock_handle
            main()

            mock_setup_logging.assert_called_once()
            mock_handle.assert_called_once()

    @patch("auto_secrets.cli.ConfigManager.load_config")
    @patch("auto_secrets.cli.setup_logging")
    @patch("argparse.ArgumentParser.parse_args")
    def test_main_cleanup_command(
        self, mock_parse_args, mock_setup_logging, mock_load_config
    ):
        """Test main function with cleanup command."""
        mock_load_config.return_value = {
            "cache_base_dir": "/tmp",
            "secret_manager": "infisical",
            "log_dir": "/tmp",
        }
        mock_args = Mock()
        mock_args.debug = False
        mock_args.quiet = False
        mock_args.command = "cleanup"
        mock_args.all = True
        mock_parse_args.return_value = mock_args

        with patch("auto_secrets.cli.handle_cleanup") as mock_handle, patch.dict(
            os.environ,
            {
                "AUTO_SECRETS_SECRET_MANAGER": "infisical",
                "AUTO_SECRETS_SHELLS": "bash",
                "AUTO_SECRETS_BRANCH_MAPPINGS": '{"main": "production", "default": "development"}',
            },
        ):
            mock_args.func = mock_handle
            main()

            mock_setup_logging.assert_called_once()
            mock_handle.assert_called_once_with(mock_args)

    @patch("auto_secrets.cli.ConfigManager.load_config")
    @patch("auto_secrets.cli.setup_logging")
    def test_main_unknown_command(self, mock_setup_logging, mock_load_config):
        """Test main function with unknown command."""
        mock_load_config.return_value = {
            "cache_base_dir": "/tmp",
            "secret_manager": "infisical",
            "log_dir": "/tmp",
        }
        # Use spec to limit mock attributes - explicitly exclude 'func'
        mock_args = Mock(spec=["debug", "quiet", "command"])
        mock_args.debug = False
        mock_args.quiet = False
        mock_args.command = "unknown"
        # Don't set func attribute to simulate unknown command

        with patch("sys.exit") as mock_exit, patch.dict(
            os.environ,
            {
                "AUTO_SECRETS_SECRET_MANAGER": "infisical",
                "AUTO_SECRETS_SHELLS": "bash",
                "AUTO_SECRETS_BRANCH_MAPPINGS": '{"main": "production", "default": "development"}',
            },
        ):
            with patch("auto_secrets.cli.argparse.ArgumentParser") as MockParser:
                mock_parser_instance = Mock()
                MockParser.return_value = mock_parser_instance
                mock_parser_instance.parse_args.return_value = mock_args

                main()

                mock_parser_instance.print_help.assert_called_once()
                mock_exit.assert_called_once_with(1)

    @patch("auto_secrets.cli.ConfigManager.load_config")
    @patch("auto_secrets.cli.setup_logging")
    @patch("argparse.ArgumentParser.parse_args")
    def test_main_debug_logging(
        self, mock_parse_args, mock_setup_logging, mock_load_config
    ):
        """Test main function with debug logging enabled."""
        mock_load_config.return_value = {
            "cache_base_dir": "/tmp",
            "secret_manager": "infisical",
            "log_dir": "/tmp",
            "debug": True,
        }
        mock_args = Mock()
        mock_args.debug = True
        mock_args.quiet = False
        mock_args.command = "debug"
        mock_parse_args.return_value = mock_args

        with patch("auto_secrets.cli.handle_debug_env") as mock_handle, patch.dict(
            os.environ,
            {
                "AUTO_SECRETS_SECRET_MANAGER": "infisical",
                "AUTO_SECRETS_SHELLS": "bash",
                "AUTO_SECRETS_BRANCH_MAPPINGS": '{"main": "production", "default": "development"}',
            },
        ):
            mock_args.func = mock_handle
            main()

            mock_setup_logging.assert_called_once_with(
                log_level="DEBUG", log_dir="/tmp", log_file="cli.log"
            )

    @patch("auto_secrets.cli.ConfigManager.load_config")
    @patch("auto_secrets.cli.setup_logging")
    @patch("argparse.ArgumentParser.parse_args")
    def test_main_quiet_logging(
        self, mock_parse_args, mock_setup_logging, mock_load_config
    ):
        """Test main function with quiet logging enabled."""
        mock_load_config.return_value = {
            "cache_base_dir": "/tmp",
            "secret_manager": "infisical",
            "log_dir": "/tmp",
        }
        mock_args = Mock()
        mock_args.debug = False
        mock_args.quiet = True
        mock_args.command = "debug"
        mock_parse_args.return_value = mock_args

        with patch("auto_secrets.cli.handle_debug_env"), patch.dict(
            os.environ,
            {
                "AUTO_SECRETS_SECRET_MANAGER": "infisical",
                "AUTO_SECRETS_SHELLS": "bash",
                "AUTO_SECRETS_BRANCH_MAPPINGS": '{"main": "production", "default": "development"}',
            },
        ):
            main()

            mock_setup_logging.assert_called_once_with(
                log_level="INFO", log_dir="/tmp", log_file="cli.log"
            )


class TestCLIIntegration:
    """Integration tests for CLI functionality."""

    @patch("auto_secrets.cli.ConfigManager.load_config")
    @patch("auto_secrets.cli.CacheManager")
    @patch("auto_secrets.cli.BranchManager")
    @patch("auto_secrets.cli.create_secret_manager")
    def test_complete_workflow(
        self,
        mock_create_manager,
        mock_branch_manager,
        mock_cache_manager,
        mock_load_config,
    ):
        """Test complete CLI workflow."""
        # Setup config
        mock_config = {
            "secret_manager": {"type": "infisical", "project_id": "test"},
            "branch_mappings": {"main": "production", "default": "development"},
        }
        mock_load_config.return_value = mock_config

        # Setup managers
        mock_manager = Mock()
        mock_manager.fetch_secrets.return_value = {"/api/key": "secret123"}
        mock_create_manager.return_value = mock_manager

        mock_cache_instance = Mock()
        mock_cache_manager.return_value = mock_cache_instance

        mock_branch_instance = Mock()
        mock_branch_instance.map_branch_to_environment.return_value = "production"
        mock_branch_manager.return_value = mock_branch_instance

        # Test branch change workflow
        branch_args = Mock()
        branch_args.branch = "main"
        branch_args.repo_path = "/repo"

        # Test refresh secrets
        refresh_args = Mock()
        refresh_args.environment = "production"
        refresh_args.paths = None

        handle_refresh_secrets(refresh_args)

        # Should fetch and cache secrets
        mock_manager.fetch_secrets.assert_called_with("production")
        mock_cache_instance.update_environment_cache.assert_called()

    def test_error_handling_workflow(self):
        """Test error handling across CLI functions."""
        # Test config loading error
        with patch(
            "auto_secrets.cli.ConfigManager.load_config",
            side_effect=ConfigError("Config error"),
        ):
            args = Mock()
            args.environment = "production"

            with pytest.raises(SystemExit):
                handle_refresh_secrets(args)

        # Test secret manager error
        with patch(
            "auto_secrets.cli.ConfigManager.load_config", return_value={}
        ), patch(
            "auto_secrets.cli.create_secret_manager",
            side_effect=SecretManagerError("Manager error"),
        ):

            args = Mock()
            args.environment = "production"

            with pytest.raises(SystemExit):
                handle_refresh_secrets(args)
