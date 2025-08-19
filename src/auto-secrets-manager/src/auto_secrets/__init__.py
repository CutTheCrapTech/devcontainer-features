"""
Auto Secrets Manager - Python Package

A hybrid Python/Shell solution for automatic environment secrets management
based on git branches with enterprise-grade security.
"""

__version__ = "1.0.0"
__author__ = "Auto Secrets Manager Team"
__description__ = "Automatic environment secrets management based on git branches"

# Core imports for external use
from .cli import main as cli_main

__all__ = [
  "cli_main",
  "__version__",
]
