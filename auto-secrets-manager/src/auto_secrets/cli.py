"""
Auto Secrets Manager - CLI Interface

Main CLI entry point for the auto-secrets-py command.
Provides all user-facing commands and integrates Python components.
"""

import argparse
import json
import os
import subprocess
import sys
import time

from .logging_config import setup_logging, get_logger, log_system_info
from .core.config import load_config
from .core.cache_manager import CacheManager
from .core.branch_manager import BranchManager
from .core.environment import get_current_environment, EnvironmentState
from .secret_managers import create_secret_manager


def handle_branch_change(args) -> None:
    """Handle branch change notification from shell."""
    logger = get_logger("cli.branch_change")

    try:
        logger.debug(f"Branch change detected: {args.branch} in {args.repo_path}")

        config = load_config()
        branch_manager = BranchManager(config)
        cache_manager = CacheManager(config)

        branch = args.branch
        repo_path = args.repo_path

        # Map branch to environment
        environment = branch_manager.map_branch_to_environment(branch, repo_path)

        if not environment:
            logger.debug(f"No environment mapping found for branch: {branch}")
            return

        logger.info(f"Branch '{branch}' mapped to environment '{environment}'")

        # Check if environment changed
        current_state = get_current_environment()
        if current_state.environment == environment and current_state.branch == branch:
            logger.debug("Environment unchanged, skipping refresh")
            return

        # Update current state
        new_state = EnvironmentState(
            environment=environment,
            branch=branch,
            repo_path=repo_path,
            timestamp=int(time.time())
        )

        # Save new state
        cache_manager.save_current_state(new_state)
        logger.info(f"Environment state updated: {environment}")

        # Mark cache as potentially stale for background refresh
        cache_manager.mark_environment_stale(environment)

        # Optional: Prefetch secrets in background if configured
        if config.get('prefetch_on_branch_change', False):
            logger.debug("Starting background prefetch")
            _background_refresh_secrets(environment, config)

    except Exception as e:
        logger.error(f"Error handling branch change: {e}", exc_info=True)
        sys.exit(1)


def handle_refresh_secrets(args) -> None:
    """Refresh secrets for current or specified environment."""
    logger = get_logger("cli.refresh")

    try:
        config = load_config()
        cache_manager = CacheManager(config)

        # Determine environment
        if args.environment:
            environment = args.environment
            logger.info(f"Refreshing secrets for specified environment: {environment}")
        else:
            current_state = get_current_environment()
            environment = current_state.environment
            if not environment:
                logger.error("No current environment found. Use --environment to specify.")
                sys.exit(1)
            logger.info(f"Refreshing secrets for current environment: {environment}")

        # Create secret manager
        secret_manager = create_secret_manager(config)
        if not secret_manager:
            logger.error("No secret manager configured")
            sys.exit(1)

        # Test connection first
        if not secret_manager.test_connection():
            logger.error(f"Cannot connect to secret manager: {config['secret_manager']}")
            sys.exit(1)

        # Fetch secrets
        logger.info("Fetching secrets...")
        paths = args.paths if hasattr(args, 'paths') and args.paths else None
        secrets = secret_manager.fetch_secrets(environment, paths)

        if not secrets:
            logger.warning(f"No secrets found for environment: {environment}")
            return

        # Update cache atomically
        cache_manager.update_environment_cache(environment, secrets)
        logger.info(f"Successfully refreshed {len(secrets)} secrets for environment: {environment}")

        # Output success message
        if not args.quiet:
            print(f"✅ Refreshed {len(secrets)} secrets for environment: {environment}")

    except Exception as e:
        logger.error(f"Error refreshing secrets: {e}", exc_info=True)
        if not args.quiet:
            print(f"❌ Failed to refresh secrets: {e}", file=sys.stderr)
        sys.exit(1)


def handle_inspect_secrets(args) -> None:
    """Inspect cached secrets for current or specified environment."""
    logger = get_logger("cli.inspect")

    try:
        config = load_config()
        cache_manager = CacheManager(config)

        # Determine environment
        if args.environment:
            environment = args.environment
        else:
            current_state = get_current_environment()
            environment = current_state.environment
            if not environment:
                logger.error("No current environment found. Use --environment to specify.")
                sys.exit(1)

        logger.debug(f"Inspecting secrets for environment: {environment}")

        # Get cached secrets
        secrets = cache_manager.get_cached_secrets(environment, args.paths)

        if not secrets:
            if not args.quiet:
                print(f"No cached secrets found for environment: {environment}")
            logger.info(f"No cached secrets for environment: {environment}")
            return

        # Format output
        if args.format == 'json':
            output = json.dumps(secrets, indent=2)
        elif args.format == 'env':
            output = '\n'.join([f"{k}={v}" for k, v in secrets.items()])
        elif args.format == 'keys':
            output = '\n'.join(secrets.keys())
        else:  # table format (default)
            output = f"Environment: {environment}\n"
            output += f"Secrets Count: {len(secrets)}\n"
            output += f"Cache Status: {'Fresh' if not cache_manager.is_cache_stale(environment) else 'Stale'}\n"
            output += "-" * 50 + "\n"
            for key, value in secrets.items():
                # Redact sensitive values unless --show-values is specified
                if args.show_values:
                    output += f"{key}={value}\n"
                else:
                    output += f"{key}=***REDACTED***\n"

        print(output)
        logger.info(f"Inspected {len(secrets)} secrets for environment: {environment}")

    except Exception as e:
        logger.error(f"Error inspecting secrets: {e}", exc_info=True)
        if not args.quiet:
            print(f"❌ Failed to inspect secrets: {e}", file=sys.stderr)
        sys.exit(1)


def handle_exec_command(args) -> None:
    """Execute command with environment secrets loaded."""
    logger = get_logger("cli.exec")

    try:
        config = load_config()
        cache_manager = CacheManager(config)

        # Determine environment
        if args.environment:
            environment = args.environment
        else:
            current_state = get_current_environment()
            environment = current_state.environment
            if not environment:
                logger.error("No current environment found. Use --environment to specify.")
                sys.exit(1)

        logger.debug(f"Executing command with environment: {environment}")

        # Check path filtering if specified
        if args.paths:
            logger.debug(f"Path filtering enabled: {args.paths}")

        # Get cached secrets
        secrets = cache_manager.get_cached_secrets(environment, args.paths)

        if not secrets:
            logger.warning(f"No cached secrets found for environment: {environment}")
            if config.get('require_secrets_for_exec', False):
                logger.error("No secrets available and require_secrets_for_exec is enabled")
                sys.exit(1)

        # Prepare environment
        env = os.environ.copy()
        env.update(secrets)

        # Add environment indicator
        env['AUTO_SECRETS_CURRENT_ENV'] = environment

        logger.info(f"Executing command with {len(secrets)} secrets loaded")

        # Execute command
        try:
            result = subprocess.run(args.command, env=env, shell=False)
            sys.exit(result.returncode)
        except FileNotFoundError:
            logger.error(f"Command not found: {args.command[0]}")
            sys.exit(127)

    except Exception as e:
        logger.error(f"Error executing command: {e}", exc_info=True)
        print(f"❌ Failed to execute command: {e}", file=sys.stderr)
        sys.exit(1)


def handle_exec_for_shell(args) -> None:
    """Generate shell script for sourcing environment variables."""
    logger = get_logger("cli.exec_shell")

    try:
        config = load_config()
        cache_manager = CacheManager(config)

        # Determine environment
        if args.environment:
            environment = args.environment
        else:
            current_state = get_current_environment()
            environment = current_state.environment
            if not environment:
                logger.debug("No current environment found for shell exec")
                return

        logger.debug(f"Generating shell environment for: {environment}")

        # Get cached secrets
        secrets = cache_manager.get_cached_secrets(environment, args.paths)

        if not secrets:
            logger.debug(f"No cached secrets found for environment: {environment}")
            return

        # Generate shell export statements
        for key, value in secrets.items():
            # Escape single quotes in values
            escaped_value = value.replace("'", "'\"'\"'")
            print(f"export {key}='{escaped_value}'")

        # Add environment indicator
        print(f"export AUTO_SECRETS_CURRENT_ENV='{environment}'")

        logger.debug(f"Generated shell exports for {len(secrets)} secrets")

    except Exception as e:
        logger.error(f"Error generating shell environment: {e}", exc_info=True)
        # Don't output error to stdout as it would interfere with shell sourcing
        pass


def handle_current_env(args) -> None:
    """Display current environment information."""
    logger = get_logger("cli.current_env")

    try:
        current_state = get_current_environment()

        if args.prompt_format:
            # Format for shell prompt
            if current_state.environment:
                print(f"[{current_state.environment}]")
            else:
                print("")
        elif args.json:
            # JSON format
            output = {
                "environment": current_state.environment,
                "branch": current_state.branch,
                "repo_path": current_state.repo_path,
                "timestamp": current_state.timestamp
            }
            print(json.dumps(output, indent=2))
        else:
            # Human readable format
            if current_state.environment:
                print(f"Current Environment: {current_state.environment}")
                print(f"Branch: {current_state.branch}")
                print(f"Repository: {current_state.repo_path}")
                print(f"Last Updated: {time.ctime(current_state.timestamp) if current_state.timestamp else 'Unknown'}")
            else:
                print("No current environment set")

        logger.debug(f"Current environment: {current_state.environment}")

    except Exception as e:
        logger.error(f"Error getting current environment: {e}", exc_info=True)
        if not args.prompt_format:  # Don't show errors in prompt format
            print(f"❌ Failed to get current environment: {e}", file=sys.stderr)
        sys.exit(1)


def handle_debug_env() -> None:
    """Comprehensive environment debugging information."""
    logger = get_logger("cli.debug")

    try:
        print("=== Auto Secrets Manager Debug Information ===")

        # System information
        print("\n--- System Information ---")
        print(f"Python: {sys.version}")
        print(f"Platform: {sys.platform}")
        print(f"Working Directory: {os.getcwd()}")
        print(f"User: {os.getenv('USER', 'unknown')}")

        # Configuration
        print("\n--- Configuration ---")
        try:
            config = load_config()
            config_dict = dict(config)
            # Redact sensitive information
            for key in config_dict:
                if any(sensitive in key.lower() for sensitive in ['token', 'secret', 'key', 'password']):
                    config_dict[key] = "***REDACTED***"
            print(json.dumps(config_dict, indent=2))
        except Exception as e:
            print(f"Error loading config: {e}")

        # Current state
        print("\n--- Current State ---")
        try:
            current_state = get_current_environment()
            print(f"Environment: {current_state.environment}")
            print(f"Branch: {current_state.branch}")
            print(f"Repository: {current_state.repo_path}")
            print(f"Timestamp: {time.ctime(current_state.timestamp) if current_state.timestamp else 'None'}")
        except Exception as e:
            print(f"Error getting current state: {e}")

        # Cache status
        print("\n--- Cache Status ---")
        try:
            config = load_config()
            cache_manager = CacheManager(config)
            cache_dir = cache_manager.cache_dir
            print(f"Cache Directory: {cache_dir}")
            print(f"Cache Directory Exists: {cache_dir.exists()}")

            if cache_dir.exists():
                cache_files = list(cache_dir.glob("*.env"))
                print(f"Cache Files: {len(cache_files)}")
                for cache_file in cache_files:
                    env_name = cache_file.stem
                    is_stale = cache_manager.is_cache_stale(env_name)
                    print(f"  {env_name}: {'Stale' if is_stale else 'Fresh'}")

        except Exception as e:
            print(f"Error checking cache: {e}")

        # Secret Manager status
        print("\n--- Secret Manager Status ---")
        try:
            config = load_config()
            secret_manager = create_secret_manager(config)
            if secret_manager:
                print(f"Type: {type(secret_manager).__name__}")
                connection_ok = secret_manager.test_connection()
                print(f"Connection: {'OK' if connection_ok else 'FAILED'}")
            else:
                print("No secret manager configured")
        except Exception as e:
            print(f"Error testing secret manager: {e}")

        # Environment variables
        print("\n--- Environment Variables ---")
        env_vars = [var for var in os.environ.keys() if var.startswith('AUTO_SECRETS_')]
        if env_vars:
            for var in sorted(env_vars):
                value = os.getenv(var)
                # Redact sensitive values
                if any(sensitive in var.lower() for sensitive in ['token', 'secret', 'key', 'password']):
                    value = "***REDACTED***"
                print(f"{var}: {value}")
        else:
            print("No AUTO_SECRETS_* environment variables found")

        print("\n=== End Debug Information ===")

        logger.info("Debug information displayed")

    except Exception as e:
        logger.error(f"Error in debug command: {e}", exc_info=True)
        print(f"❌ Error generating debug information: {e}", file=sys.stderr)
        sys.exit(1)


def handle_cleanup(args) -> None:
    """Clean up cache and temporary files."""
    logger = get_logger("cli.cleanup")

    try:
        config = load_config()
        cache_manager = CacheManager(config)

        if args.all:
            logger.info("Performing full cleanup")
            cache_manager.cleanup_all()
            print("✅ All cache and temporary files cleaned up")
        else:
            logger.info("Performing partial cleanup")
            cache_manager.cleanup_stale()
            print("✅ Stale cache files cleaned up")

    except Exception as e:
        logger.error(f"Error during cleanup: {e}", exc_info=True)
        print(f"❌ Cleanup failed: {e}", file=sys.stderr)
        sys.exit(1)


def _background_refresh_secrets(environment: str, config: dict) -> None:
    """Background refresh of secrets (non-blocking)."""
    logger = get_logger("cli.background_refresh")

    try:
        logger.debug(f"Starting background refresh for environment: {environment}")

        # Create secret manager
        secret_manager = create_secret_manager(config)
        if not secret_manager or not secret_manager.test_connection():
            logger.warning("Secret manager not available for background refresh")
            return

        # Fetch and cache secrets
        cache_manager = CacheManager(config)
        secrets = secret_manager.fetch_secrets(environment)

        if secrets:
            cache_manager.update_environment_cache(environment, secrets)
            logger.info(f"Background refresh completed for {environment}: {len(secrets)} secrets")
        else:
            logger.warning(f"No secrets found during background refresh for {environment}")

    except Exception as e:
        logger.error(f"Error in background refresh: {e}", exc_info=True)


def main() -> None:
    """Main CLI entry point."""
    # Set up argument parser
    parser = argparse.ArgumentParser(
        prog='auto-secrets-py',
        description='Auto Secrets Manager - Automatic environment secrets management'
    )

    # Global options
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')
    parser.add_argument('--quiet', action='store_true', help='Suppress output messages')
    parser.add_argument('--log-level', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
                       help='Set log level')

    # Subcommands
    subparsers = parser.add_subparsers(dest='command', help='Available commands')

    # Branch change command (called from shell)
    branch_parser = subparsers.add_parser('branch-changed', help='Handle branch change notification')
    branch_parser.add_argument('branch', help='New branch name')
    branch_parser.add_argument('repo_path', help='Repository path')
    branch_parser.set_defaults(func=handle_branch_change)

    # Refresh secrets command
    refresh_parser = subparsers.add_parser('refresh', help='Refresh secrets cache')
    refresh_parser.add_argument('--environment', help='Specific environment to refresh')
    refresh_parser.add_argument('--paths', nargs='*', help='Specific secret paths to refresh')
    refresh_parser.set_defaults(func=handle_refresh_secrets)

    # Inspect secrets command
    inspect_parser = subparsers.add_parser('inspect', help='Inspect cached secrets')
    inspect_parser.add_argument('--environment', help='Specific environment to inspect')
    inspect_parser.add_argument('--paths', nargs='*', help='Specific secret paths to inspect')
    inspect_parser.add_argument('--format', choices=['table', 'json', 'env', 'keys'],
                               default='table', help='Output format')
    inspect_parser.add_argument('--show-values', action='store_true',
                               help='Show actual secret values (security risk)')
    inspect_parser.set_defaults(func=handle_inspect_secrets)

    # Execute command with secrets
    exec_parser = subparsers.add_parser('exec', help='Execute command with secrets loaded')
    exec_parser.add_argument('--environment', help='Specific environment to use')
    exec_parser.add_argument('--paths', nargs='*', help='Specific secret paths to load')
    exec_parser.add_argument('command', nargs='+', help='Command to execute')
    exec_parser.set_defaults(func=handle_exec_command)

    # Output environment for shell sourcing
    output_env_parser = subparsers.add_parser('output-env', help='Output environment variables for shell sourcing')
    output_env_parser.add_argument('--environment', help='Specific environment to use')
    output_env_parser.add_argument('--paths', nargs='*', help='Specific secret paths to load')
    output_env_parser.set_defaults(func=handle_exec_for_shell)

    # Current environment command
    current_parser = subparsers.add_parser('current-env', help='Show current environment')
    current_parser.add_argument('--prompt-format', action='store_true',
                               help='Format for shell prompt')
    current_parser.add_argument('--json', action='store_true', help='JSON output format')
    current_parser.set_defaults(func=handle_current_env)

    # Debug command
    debug_parser = subparsers.add_parser('debug', help='Show debug information')
    debug_parser.set_defaults(func=handle_debug_env)

    # Cleanup command
    cleanup_parser = subparsers.add_parser('cleanup', help='Clean up cache files')
    cleanup_parser.add_argument('--all', action='store_true', help='Clean up all cache files')
    cleanup_parser.set_defaults(func=handle_cleanup)

    # Parse arguments
    args = parser.parse_args()

    # Set up logging
    debug_mode = args.debug or os.getenv('AUTO_SECRETS_DEBUG', '').lower() == 'true'
    log_level = args.log_level or os.getenv('AUTO_SECRETS_LOG_LEVEL', 'INFO')

    logger = setup_logging(
        log_level=log_level,
        debug=debug_mode,
        console_output=debug_mode
    )

    if debug_mode:
        log_system_info(logger)

    # Execute command
    if hasattr(args, 'func'):
        args.func(args)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == '__main__':
    main()
