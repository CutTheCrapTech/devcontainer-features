"""
Auto Secrets Manager - CLI Interface

Main CLI entry point for the auto-secrets command.
Provides all user-facing commands and integrates Python components.
"""

import argparse
import json
import os
import subprocess
import sys
from typing import Optional

from .managers.app_manager import AppManager


def handle_branch_change(args: argparse.Namespace) -> None:
  """Handle branch change notification from shell."""
  logger = app.get_logger("cli", "cli.branch_change")

  try:
    logger.debug(f"Branch change detected: {args.branch} in {args.repopath}")

    branch_manager = app.branch_manager

    branch = args.branch
    repo_path = args.repopath

    # Map branch to environment
    environment = branch_manager.map_branch_to_environment(branch, repo_path)
    _refresh_secrets(environment, branch, repo_path)

  except Exception as e:
    logger.error(f"Error handling branch change: {e}", exc_info=True)
    sys.exit(1)


def handle_refresh_secrets(args: argparse.Namespace) -> None:
  """Refresh secrets for current or specified environment."""
  logger = app.get_logger("cli", "cli.refresh")

  try:
    _refresh_secrets(args.environment)

    # Output success message
    if not args.quiet:
      print(f"✅ Refreshed secrets for environment: {args.environment}")

  except Exception as e:
    logger.error(f"Error refreshing secrets: {e}", exc_info=True)
    if not args.quiet:
      print(f"❌ Failed to refresh secrets: {e}", file=sys.stderr)
    sys.exit(1)


def handle_inspect_secrets(args: argparse.Namespace) -> None:
  """Inspect cached secrets for current or specified environment."""
  logger = app.get_logger("cli", "cli.inspect")

  try:
    cache_manager = app.cache_manager

    # Determine environment
    if args.environment:
      environment = args.environment
    else:
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
    if args.format == "json":
      output = json.dumps(secrets, indent=2)
    elif args.format == "env":
      output = "\n".join([f'{k}="{v}"' for k, v in secrets.items()])
    elif args.format == "keys":
      output = "\n".join(secrets.keys())
    else:  # table format (default)
      output = f"Environment: {environment}\n"
      output += f"Secrets Count: {len(secrets)}\n"
      output += f"Cache Status: {'Fresh' if not cache_manager.is_cache_stale(environment) else 'Stale'}\n"
      output += "-" * 50 + "\n"
      for key, value in secrets.items():
        # Redact sensitive values unless --show-values is specified
        if args.show_values:
          # Show half the value, but max 10 chars
          half_length = len(value) // 2
          chars_to_show = min(half_length, 10)
          if chars_to_show > 0:
            partial_value = value[:chars_to_show] + "***"
            output += f"{key}={partial_value}\n"
          else:
            output += f"{key}=***\n"
        else:
          output += f"{key}=***REDACTED***\n"

    print(output)
    logger.info(f"Inspected {len(secrets)} secrets for environment: {environment}")

  except Exception as e:
    logger.error(f"Error inspecting secrets: {e}", exc_info=True)
    if not args.quiet:
      print(f"❌ Failed to inspect secrets: {e}", file=sys.stderr)
    sys.exit(1)


def handle_exec_command(args: argparse.Namespace) -> None:
  """Execute command with environment secrets loaded."""
  logger = app.get_logger("cli", "cli.exec")

  try:
    cache_manager = app.cache_manager

    # Determine environment
    if args.environment:
      environment = args.environment
    else:
      logger.error("No current environment found. Use --environment to specify.")
      sys.exit(1)

    logger.debug(f"Executing command with environment: {environment}")

    # Check path filtering if specified
    if args.paths:
      logger.debug(f"Path filtering enabled: {args.paths}")

    # Get cached secrets
    secrets = cache_manager.get_cached_secrets(environment, args.paths)

    if not secrets:
      logger.warning(f"No cached secrets found for environment: {environment}Continuing execution without secrets.")

    # Prepare environment
    env = os.environ.copy()
    env.update(secrets)

    # Add environment indicator
    env["AUTO_SECRETS_CURRENT_ENV"] = environment

    logger.info(f"Executing command with {len(secrets)} secrets loaded")

    # Execute command
    try:
      # Prompt for SSH agent biometric if configured
      app.key_retriever.prompt_ssh_agent_biometric()
      # Execute the command
      result = subprocess.run(args.command, env=env, shell=False)
      sys.exit(result.returncode)
    except FileNotFoundError:
      logger.error(f"Command not found: {args.command[0]}")
      sys.exit(127)

  except Exception as e:
    logger.error(f"Error executing command: {e}", exc_info=True)
    print(f"❌ Failed to execute command: {e}", file=sys.stderr)
    sys.exit(1)


def handle_output_env(args: argparse.Namespace) -> None:
  """Generate shell script for sourcing environment variables."""
  logger = app.get_logger("cli", "cli.output_env")

  try:
    cache_manager = app.cache_manager

    # Determine branch
    if not (args.branch or args.repopath or args.command):
      logger.error("Branch, repopath and command are required.")
      sys.exit(1)

    branch = args.branch
    repo_path = args.repopath
    command = args.command

    branch_manager = app.branch_manager
    environment = branch_manager.map_branch_to_environment(branch, repo_path)

    if not environment:
      logger.error("Could not get environment.")
      sys.exit(1)

    paths = cache_manager.get_auto_command_paths(command)
    # Get cached secrets
    secrets = cache_manager.get_cached_secrets(environment, paths)

    if not secrets:
      logger.debug(f"No cached secrets found for environment: {environment}")
      return

    def should_prefix_terraform_var(key: str, command: str) -> bool:
      return command in ["terraform", "tofu"] and not key.startswith("TF_VAR_")

    secrets = {
      (f"TF_VAR_{key}" if should_prefix_terraform_var(key, command) else key): value for key, value in secrets.items()
    }

    # Generate shell export statements
    for key, value in secrets.items():
      print(f'export {key}="{value}"')

    # Add environment indicator
    print(f"export AUTO_SECRETS_CURRENT_ENV='{environment}'")

    logger.debug(f"Generated shell exports for {len(secrets)} secrets")

  except Exception as e:
    logger.error(f"Error generating shell environment: {e}", exc_info=True)
    # Don't output error to stdout as it would interfere with shell sourcing
    pass


def handle_debug_env() -> None:
  """Comprehensive environment debugging information."""
  logger = app.get_logger("cli", "cli.debug")

  try:
    print("=== Auto Secrets Manager Debug Information ===")

    # System information
    print("\n--- System Information ---")
    print(f"Python: {sys.version}")
    print(f"Platform: {sys.platform}")
    print(f"Working Directory: {os.getcwd()}")
    print(f"User: {os.getenv('USER', 'unknown')}")

    # Environment
    print("\n--- Environment (minus sensitive values) ---")
    try:
      safe_vars = {
        k: v
        for k, v in os.environ.items()
        if not any(sensitive in k.upper() for sensitive in ["PASSWORD", "SECRET", "KEY", "TOKEN"])
      }
      print(json.dumps(safe_vars, indent=2))
    except Exception as e:
      print(f"Error loading config: {e}")

    # Cache status
    print("\n--- Cache Status ---")
    try:
      cache_manager = app.cache_manager
      base_dir = cache_manager.base_dir
      print(f"Cache Directory: {base_dir}")
      print(f"Cache Directory Exists: {base_dir.exists()}")

      if base_dir.exists():
        cache_files = list(base_dir.glob("*.env"))
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
      secret_manager = app.secret_manager
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
    env_vars = [var for var in os.environ if var.startswith("AUTO_SECRETS_")]
    if env_vars:
      for var in sorted(env_vars):
        value = os.getenv(var)
        # Redact sensitive values
        if any(sensitive in var.lower() for sensitive in ["token", "secret", "key", "password"]):
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


def handle_cleanup(args: argparse.Namespace) -> None:
  """Clean up cache and temporary files."""
  logger = app.get_logger("cli", "cli.cleanup")

  try:
    cache_manager = app.cache_manager

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


def set_sm_secret(args: argparse.Namespace) -> None:
  """Sets the secret for the configured secret manager."""
  logger = app.get_logger("cli", "cli.set_secret")

  try:
    app.secret_manager.set_secret()
  except Exception as e:
    logger.error(f"Error during set_secret: {e}", exc_info=True)
    print(f"❌ set_secret failed: {e}", file=sys.stderr)
    sys.exit(1)


def _refresh_secrets(
  environment: Optional[str],
  branch: Optional[str] = None,
  repo_path: Optional[str] = None,
) -> None:
  """
  Synchronously refreshes secrets for a given environment.

  NOTE: This function is blocking and is designed to be invoked
  as a non-blocking background process from its calling shell script branch-detection.sh
  (e.g., using `&`) which it currently is
  and a blocking foreground process when calling refresh-secrets.
  """
  logger = app.get_logger("cli", "cli.background_refresh")

  try:
    logger.debug(f"Starting background refresh for environment: {environment}")

    if not environment:
      logger.error("No environment specified for background refresh")
      sys.exit(1)

    # Get secret manager
    secret_manager = app.secret_manager
    if not secret_manager or not secret_manager.test_connection():
      logger.warning("Secret manager not available for background refresh")
      sys.exit(1)

    # Fetch and cache secrets
    cache_manager = app.cache_manager
    secrets = secret_manager.fetch_secrets(environment)

    if secrets:
      cache_manager.update_environment_cache(environment, secrets, branch, repo_path)
      logger.info(f"Background refresh completed for {environment}: {len(secrets)} secrets")
    else:
      logger.warning(f"No secrets found during background refresh for {environment}")

  except Exception as e:
    logger.error(f"Error in background refresh: {e}", exc_info=True)
    sys.exit(1)


def main() -> None:
  """Main CLI entry point."""

  if sys.version_info < (3, 9):  # noqa: UP036
    print(
      f"❌ Auto Secrets Manager requires Python 3.9+, found Python {sys.version_info.major}.{sys.version_info.minor}"
    )
    print("💡 Your Python was downgraded after installation. Please use Python 3.9+ or reinstall the feature.")
    sys.exit(1)

  # Set up argument parser
  parser = argparse.ArgumentParser(
    prog="auto-secrets",
    description="Auto Secrets Manager - Automatic environment secrets management",
  )

  # Global options
  parser.add_argument("--debug", action="store_true", help="Enable debug logging")
  parser.add_argument("--quiet", action="store_true", help="Suppress output messages")
  parser.add_argument(
    "--log-level",
    choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
    help="Set log level",
  )

  # Subcommands
  subparsers = parser.add_subparsers(dest="command", help="Available commands")

  # Branch change command (called from shell)
  branch_parser = subparsers.add_parser("branch-changed", help="Handle branch change notification")
  branch_parser.add_argument("--branch", help="New branch name")
  branch_parser.add_argument("--repopath", help="Repository path")
  branch_parser.set_defaults(func=handle_branch_change)

  # Refresh secrets command
  refresh_parser = subparsers.add_parser("refresh", help="Refresh secrets cache")
  refresh_parser.add_argument("--environment", help="Specific environment to refresh")
  refresh_parser.add_argument("--paths", nargs="*", help="Specific secret paths to refresh")
  refresh_parser.set_defaults(func=handle_refresh_secrets)

  # Inspect secrets command
  inspect_parser = subparsers.add_parser("inspect", help="Inspect cached secrets")
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
  inspect_parser.set_defaults(func=handle_inspect_secrets)

  # Execute command with secrets
  exec_parser = subparsers.add_parser("exec", help="Execute command with secrets loaded")
  exec_parser.add_argument("--environment", help="Specific environment to use")
  exec_parser.add_argument("--paths", nargs="*", help="Specific secret paths to load")
  exec_parser.add_argument("command", nargs="+", help="Command to execute")
  exec_parser.set_defaults(func=handle_exec_command)

  # Output environment for shell sourcing
  output_env_parser = subparsers.add_parser("output-env", help="Output environment variables for shell sourcing")
  output_env_parser.add_argument("--branch", help="Current branch")
  output_env_parser.add_argument("--repopath", help="Repository path")
  output_env_parser.add_argument("--command", help="Command to fetch secrets for")
  output_env_parser.set_defaults(func=handle_output_env)

  # Debug command
  debug_parser = subparsers.add_parser("debug", help="Show debug information")
  debug_parser.set_defaults(func=handle_debug_env)

  # Cleanup command
  cleanup_parser = subparsers.add_parser("cleanup", help="Clean up cache files")
  cleanup_parser.add_argument("--all", action="store_true", help="Clean up all cache files")
  cleanup_parser.set_defaults(func=handle_cleanup)

  # Set secret command
  cleanup_parser = subparsers.add_parser("set-sm-secret", help="Set SM secret")
  cleanup_parser.set_defaults(func=set_sm_secret)

  # Parse arguments
  args = parser.parse_args()

  # Execute command
  if hasattr(args, "func"):
    args.func(args)
  else:
    parser.print_help()
    sys.exit(1)


if __name__ == "__main__":
  app = AppManager(log_file="cli.log")
  main()
