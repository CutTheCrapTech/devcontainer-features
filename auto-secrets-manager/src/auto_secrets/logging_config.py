"""
Auto Secrets Manager - Logging Configuration

Centralized logging configuration for the auto-secrets-manager.
Provides file-based logging with proper rotation and formatting.
"""

import logging
import logging.handlers
import os
import sys
from pathlib import Path
from typing import Optional


# Default log configuration
DEFAULT_LOG_DIR = "/var/log/auto-secrets"
DEFAULT_LOG_FILE = "auto-secrets.log"
DEFAULT_LOG_LEVEL = logging.INFO
DEFAULT_MAX_BYTES = 10 * 1024 * 1024  # 10MB
DEFAULT_BACKUP_COUNT = 5

# Log format
LOG_FORMAT = (
    "%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s"
)
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"


def setup_logging(
    log_level: Optional[str] = None,
    log_dir: Optional[str] = None,
    log_file: Optional[str] = None,
    console_output: bool = False,
) -> logging.Logger:
    """
    Set up logging configuration for auto-secrets-manager.

    Args:
        log_level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_dir: Directory for log files (default: /var/log/auto-secrets)
        log_file: Log file name (default: auto-secrets.log)
        console_output: Whether to also output to console
        debug: Enable debug mode (sets log level to DEBUG)

    Returns:
        Configured logger instance
    """
    # Determine log level
    if log_level:
        level = getattr(logging, log_level.upper(), DEFAULT_LOG_LEVEL)
    else:
        level = DEFAULT_LOG_LEVEL

    # Determine log directory and file
    log_dir = log_dir or DEFAULT_LOG_DIR
    log_file = log_file or DEFAULT_LOG_FILE
    log_path = Path(log_dir) / log_file

    # Create formatter
    formatter = logging.Formatter(LOG_FORMAT, DATE_FORMAT)

    # Get or create logger
    logger = logging.getLogger("auto_secrets")
    logger.setLevel(level)

    # Clear existing handlers to avoid duplicates
    logger.handlers.clear()

    # Create rotating file handler
    try:
        file_handler = logging.handlers.RotatingFileHandler(
            log_path,
            maxBytes=DEFAULT_MAX_BYTES,
            backupCount=DEFAULT_BACKUP_COUNT,
            mode="a",
        )
        file_handler.setLevel(level)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    except (PermissionError, OSError) as e:
        print(f"Error setting up file logging: {e}", file=sys.stderr)
        # Fall back to console only
        console_output = True

    # Add console handler if requested or if file logging failed
    if console_output:
        console_handler = logging.StreamHandler(sys.stderr)
        console_handler.setLevel(level)
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)

    # Prevent propagation to root logger
    logger.propagate = False

    return logger


def get_logger(name: str = "auto_secrets") -> logging.Logger:
    """
    Get a logger instance with the specified name.

    Args:
        name: Logger name (will be prefixed with auto_secrets if not already)

    Returns:
        Logger instance
    """
    if name == "auto_secrets" or name.startswith("auto_secrets."):
        return logging.getLogger(name)
    else:
        return logging.getLogger(f"auto_secrets.{name}")


def log_system_info(logger: logging.Logger) -> None:
    """
    Log system information for debugging purposes.

    Args:
        logger: Logger instance to use
    """
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
            if (
                "token" in var.lower()
                or "secret" in var.lower()
                or "key" in var.lower()
            ):
                logger.info(f"{var}: ***REDACTED***")
            else:
                logger.info(f"{var}: {value}")

    logger.info("==========================================")


# Initialize default logger on import
_default_logger = None


def init_default_logger(debug: bool = False) -> None:
    """Initialize the default logger for the package."""
    global _default_logger
    if _default_logger is None:
        _default_logger = setup_logging()
