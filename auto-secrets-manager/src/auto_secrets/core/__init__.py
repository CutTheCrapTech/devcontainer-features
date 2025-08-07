"""
Auto Secrets Manager - Core Module

Contains core functionality for branch management, caching, environment handling,
and configuration management.
"""

from .branch_manager import BranchManager
from .cache_manager import CacheManager
from .environment import (
    get_current_environment,
    save_environment_state,
    clear_environment_state,
    is_valid_environment_name,
    get_environment_debug_info
)
from .config import load_config
from .utils import CommonUtils

__all__ = [
    "BranchManager",
    "CacheManager",
    "get_current_environment",
    "save_environment_state",
    "clear_environment_state",
    "is_valid_environment_name",
    "get_environment_debug_info",
    "load_config",
    "CommonUtils",
]
