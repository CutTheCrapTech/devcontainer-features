"""
Auto Secrets Manager - Class-Based Logging Configuration

Centralized logging configuration for the auto-secrets-manager.
Provides file-based logging with proper rotation, formatting, and component identification.
"""

import logging
import logging.handlers
import os
import sys
from collections.abc import MutableMapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional


@dataclass
class AutoSecretsLoggerConfig:
  """Logger settings."""

  log_dir: str
  log_level: str
  log_file: str

  def __post_init__(self) -> None:
    """Initialize from environment variables after dataclass creation."""
    # Read from environment
    self.log_dir = os.getenv("AUTO_SECRETS_LOG_DIR", self.log_dir)
    self.log_level = os.getenv("AUTO_SECRETS_LOG_LEVEL", self.log_level)


class ComponentLoggerAdapter(logging.LoggerAdapter):
  """
  Logger adapter that adds component information to log records.

  This allows us to identify which part of the system generated each log message.
  """

  def __init__(self, logger: logging.Logger, component: str) -> None:
    """
    Initialize the adapter with a component name.

    Args:
        logger: The underlying logger instance
        component: Component identifier (e.g., 'config', 'cache', 'vault-client')
    """
    super().__init__(logger, {"component": component})
    self.component = component

  def process(self, msg: Any, kwargs: MutableMapping[str, Any]) -> tuple[Any, MutableMapping[str, Any]]:
    """Process the log record to include component information."""
    # Ensure component is in extra data for the formatter
    if "extra" not in kwargs:
      kwargs["extra"] = {}
    kwargs["extra"]["component"] = self.component
    return msg, kwargs


class AutoSecretsLogger:
  """
  Centralized logging manager for Auto Secrets Manager.

  Handles setup, configuration, and creation of component-aware loggers.
  """

  # Class-level constants
  DEFAULT_LOG_DIR = "/var/log/auto-secrets"
  DEFAULT_LOG_FILE = "auto-secrets.log"
  DEFAULT_LOG_LEVEL = "INFO"
  DEFAULT_MAX_BYTES = 10 * 1024 * 1024  # 10MB
  DEFAULT_BACKUP_COUNT = 5

  # Enhanced log format with component support
  LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - [%(component)s] - [%(filename)s:%(lineno)d] - %(message)s"
  DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

  def __init__(
    self,
    log_file: Optional[str] = None,
    console_output: bool = False,
  ):
    """
    Initialize the logging manager.

    Args:
        log_file: File name for log files (default: auto-secrets.log)
        console_output: Whether to also output to console
    """
    config = AutoSecretsLoggerConfig(
      log_dir=self.DEFAULT_LOG_DIR,
      log_level=self.DEFAULT_LOG_LEVEL,
      log_file=log_file or self.DEFAULT_LOG_FILE,
    )
    self.log_level = config.log_level
    self.log_dir = config.log_dir
    self.log_file = config.log_file
    self.console_output = console_output
    self._base_logger: Optional[logging.Logger] = None
    self._logger_cache: dict[str, ComponentLoggerAdapter] = {}

    # Setup logging on initialization
    self._setup_logging()

  def _setup_logging(self) -> None:
    """Set up the base logging configuration."""
    # Determine log level
    level = getattr(logging, self.log_level.upper())

    # Determine log file path
    log_path = Path(self.log_dir) / self.DEFAULT_LOG_FILE

    # Create formatter
    formatter = logging.Formatter(self.LOG_FORMAT, self.DATE_FORMAT)

    # Get or create base logger
    self._base_logger = logging.getLogger("auto_secrets")
    self._base_logger.setLevel(level)

    # Clear existing handlers to avoid duplicates
    self._base_logger.handlers.clear()

    # Create rotating file handler
    try:
      # Ensure log directory exists
      Path(self.log_dir).mkdir(parents=True, exist_ok=True, mode=0o755)

      file_handler = logging.handlers.RotatingFileHandler(
        log_path,
        maxBytes=self.DEFAULT_MAX_BYTES,
        backupCount=self.DEFAULT_BACKUP_COUNT,
        mode="a",
      )
      file_handler.setLevel(level)
      file_handler.setFormatter(formatter)
      self._base_logger.addHandler(file_handler)
    except (PermissionError, OSError) as e:
      print(f"Error setting up file logging: {e}", file=sys.stderr)
      # Fall back to console only
      self.console_output = True

    # Add console handler if requested or if file logging failed
    if self.console_output:
      console_handler = logging.StreamHandler(sys.stderr)
      console_handler.setLevel(level)
      console_handler.setFormatter(formatter)
      self._base_logger.addHandler(console_handler)

    # Prevent propagation to root logger
    self._base_logger.propagate = False

  def get_logger(self, name: Optional[str], component: Optional[str]) -> ComponentLoggerAdapter:
    """
    Get a logger instance with the specified name and component.

    Args:
        name: Logger name (will be prefixed with auto_secrets if not already)
        component: Component identifier (default: 'system')

    Returns:
        ComponentLoggerAdapter instance
    """
    if not name:
      name = "auto_secrets"
    if not component:
      component = "system"

    # Create cache key
    cache_key = f"{name}:{component}"

    # Return cached logger if exists
    if cache_key in self._logger_cache:
      return self._logger_cache[cache_key]

    # Determine logger name
    logger_name = name if name == "auto_secrets" or name.startswith("auto_secrets.") else f"auto_secrets.{name}"

    # Get the underlying logger
    logger = logging.getLogger(logger_name)

    # Create component adapter
    component_logger = ComponentLoggerAdapter(logger, component)

    # Cache and return
    self._logger_cache[cache_key] = component_logger
    return component_logger

  def log_system_info(self, name: str = "auto_secrets", component: str = "system") -> None:
    """
    Log system information for debugging purposes.

    Args:
        component: Component identifier for these log messages
    """
    logger = self.get_logger(name=name, component=component)

    logger.info("=== Auto Secrets Manager System Info ===")
    logger.info(f"Python version: {sys.version}")
    logger.info(f"Platform: {sys.platform}")
    logger.info(f"Working directory: {os.getcwd()}")
    logger.info(f"User: {os.getenv('USER', 'unknown')}")
    logger.info(f"HOME: {os.getenv('HOME', 'unknown')}")
    logger.info(f"PATH: {os.getenv('PATH', 'unknown')}")

    # Log environment variables related to auto-secrets
    env_vars = [
      "AUTO_SECRETS_DEBUG",
      "AUTO_SECRETS_CONFIG_PATH",
      "AUTO_SECRETS_LOG_LEVEL",
      "AUTO_SECRETS_SECRET_MANAGER",
      "AUTO_SECRETS_BRANCH_MAPPINGS",
    ]

    for var in env_vars:
      value = os.getenv(var)
      if value:
        # Don't log sensitive values in full
        if "token" in var.lower() or "secret" in var.lower() or "key" in var.lower():
          logger.info(f"{var}: ***REDACTED***")
        else:
          logger.info(f"{var}: {value}")

    logger.info("==========================================")

  def set_log_level(self, log_level: str) -> None:
    """
    Change the log level for all handlers.

    Args:
        log_level: New log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
    """
    level = getattr(logging, log_level.upper(), self.DEFAULT_LOG_LEVEL)

    if self._base_logger:
      self._base_logger.setLevel(level)
      for handler in self._base_logger.handlers:
        handler.setLevel(level)

    self.log_level = log_level.upper()

  def add_console_output(self) -> None:
    """Add console output to the logger if not already present."""
    if not self.console_output and self._base_logger:
      console_handler = logging.StreamHandler(sys.stderr)
      formatter = logging.Formatter(self.LOG_FORMAT, self.DATE_FORMAT)
      console_handler.setFormatter(formatter)
      console_handler.setLevel(self._base_logger.level)
      self._base_logger.addHandler(console_handler)
      self.console_output = True

  def remove_console_output(self) -> None:
    """Remove console output from the logger."""
    if self.console_output and self._base_logger:
      # Remove StreamHandler instances
      handlers_to_remove = [
        h
        for h in self._base_logger.handlers
        if isinstance(h, logging.StreamHandler) and h.stream in (sys.stdout, sys.stderr)
      ]
      for handler in handlers_to_remove:
        self._base_logger.removeHandler(handler)
        handler.close()
      self.console_output = False

  def clear_cache(self) -> None:
    """Clear the logger cache."""
    self._logger_cache.clear()

  @property
  def base_logger(self) -> logging.Logger:
    """Get the base logger instance."""
    if self._base_logger is None:
      raise RuntimeError("Logger not initialized")
    return self._base_logger

  @property
  def log_file_path(self) -> Path:
    """Get the current log file path."""
    return Path(self.log_dir) / self.DEFAULT_LOG_FILE

  @property
  def is_debug_enabled(self) -> bool:
    """Check if debug logging is enabled."""
    return self._base_logger is not None and self._base_logger.level <= logging.DEBUG
