"""
Auto Secrets Manager - Environment State Management

Manages current environment state, branch tracking, and state persistence.
Provides atomic state updates and proper state caching.
"""

import json
import os
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Dict, Optional, Any

from ..logging_config import get_logger
from .config import get_state_dir


@dataclass
class EnvironmentState:
    """
    Current environment state information.

    This represents the complete state of the auto-secrets manager
    including current environment, branch, and repository information.
    """
    environment: Optional[str] = None
    branch: Optional[str] = None
    repo_path: Optional[str] = None
    timestamp: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'EnvironmentState':
        """Create from dictionary loaded from JSON."""
        return cls(
            environment=data.get('environment'),
            branch=data.get('branch'),
            repo_path=data.get('repo_path'),
            timestamp=data.get('timestamp')
        )

    def is_valid(self) -> bool:
        """Check if the state has valid environment information."""
        return bool(self.environment and self.branch)

    def age_seconds(self) -> Optional[int]:
        """Get the age of this state in seconds."""
        if not self.timestamp:
            return None
        return int(time.time() - self.timestamp)


class EnvironmentStateManager:
    """
    Manages environment state persistence and retrieval.

    Handles atomic state updates and provides caching for performance.
    """

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = get_logger("environment_state")
        self.state_file = get_state_dir(config) / "current.json"
        self._cached_state: Optional[EnvironmentState] = None
        self._cache_time: Optional[float] = None
        self._cache_ttl = 5.0  # Cache for 5 seconds

    def get_current_state(self, use_cache: bool = True) -> EnvironmentState:
        """
        Get the current environment state.

        Args:
            use_cache: Whether to use cached state if available

        Returns:
            EnvironmentState: Current state (may be empty if no state set)
        """
        current_time = time.time()

        # Check cache first
        if (use_cache and self._cached_state and self._cache_time and
            current_time - self._cache_time < self._cache_ttl):
            self.logger.debug("Using cached environment state")
            return self._cached_state

        # Load from file
        state = self._load_state_from_file()

        # Update cache
        self._cached_state = state
        self._cache_time = current_time

        return state

    def save_state(self, state: EnvironmentState) -> None:
        """
        Save environment state atomically.

        Args:
            state: State to save
        """
        self.logger.debug(f"Saving environment state: {state.environment}")

        # Ensure state directory exists
        self.state_file.parent.mkdir(parents=True, exist_ok=True, mode=0o755)

        # Add timestamp if not present
        if not state.timestamp:
            state.timestamp = int(time.time())

        try:
            # Atomic write using temporary file
            temp_file = self.state_file.with_suffix('.tmp')

            with open(temp_file, 'w') as f:
                json.dump(state.to_dict(), f, indent=2)
                f.flush()
                os.fsync(f.fileno())

            # Atomic rename
            temp_file.rename(self.state_file)

            # Set proper permissions
            self.state_file.chmod(0o600)

            # Update cache
            self._cached_state = state
            self._cache_time = time.time()

            self.logger.info(f"Environment state saved: {state.environment}")

        except (OSError, IOError) as e:
            self.logger.error(f"Failed to save environment state: {e}")
            raise

    def _load_state_from_file(self) -> EnvironmentState:
        """
        Load environment state from file.

        Returns:
            EnvironmentState: Loaded state or empty state if file doesn't exist
        """
        if not self.state_file.exists():
            self.logger.debug("No environment state file found")
            return EnvironmentState()

        try:
            with open(self.state_file, 'r') as f:
                data = json.load(f)

            state = EnvironmentState.from_dict(data)
            self.logger.debug(f"Loaded environment state: {state.environment}")
            return state

        except (OSError, IOError, json.JSONDecodeError) as e:
            self.logger.error(f"Failed to load environment state: {e}")
            # Return empty state on error
            return EnvironmentState()

    def clear_state(self) -> None:
        """Clear the current environment state."""
        try:
            if self.state_file.exists():
                self.state_file.unlink()
                self.logger.info("Environment state cleared")

            # Clear cache
            self._cached_state = None
            self._cache_time = None

        except OSError as e:
            self.logger.error(f"Failed to clear environment state: {e}")

    def get_state_info(self) -> Dict[str, Any]:
        """
        Get information about the current state for debugging.

        Returns:
            Dict[str, Any]: State information
        """
        state = self.get_current_state()

        return {
            "state_file": str(self.state_file),
            "state_file_exists": self.state_file.exists(),
            "current_state": state.to_dict(),
            "state_valid": state.is_valid(),
            "state_age_seconds": state.age_seconds(),
            "cache_active": self._cached_state is not None,
            "cache_age_seconds": (time.time() - self._cache_time) if self._cache_time else None
        }


def get_current_environment(config: Optional[Dict[str, Any]] = None) -> EnvironmentState:
    """
    Get the current environment state.

    This is the main entry point for getting environment information.

    Args:
        config: Optional configuration dictionary

    Returns:
        EnvironmentState: Current environment state
    """
    if config is None:
        from .config import load_config
        config = load_config()

    manager = EnvironmentStateManager(config)
    return manager.get_current_state()


def save_environment_state(state: EnvironmentState, config: Optional[Dict[str, Any]] = None) -> None:
    """
    Save environment state.

    Args:
        state: Environment state to save
        config: Optional configuration dictionary
    """
    if config is None:
        from .config import load_config
        config = load_config()

    manager = EnvironmentStateManager(config)
    manager.save_state(state)


def clear_environment_state(config: Optional[Dict[str, Any]] = None) -> None:
    """
    Clear the current environment state.

    Args:
        config: Optional configuration dictionary
    """
    if config is None:
        from .config import load_config
        config = load_config()

    manager = EnvironmentStateManager(config)
    manager.clear_state()


def is_valid_environment_name(environment: str) -> bool:
    """
    Validate environment name format.

    Args:
        environment: Environment name to validate

    Returns:
        bool: True if environment name is valid
    """
    import re

    if not environment or not isinstance(environment, str):
        return False

    # Length check
    if len(environment) < 1 or len(environment) > 64:
        return False

    # Must be alphanumeric with hyphens/underscores
    # Can't start or end with special characters
    if len(environment) == 1:
        return re.match(r'^[a-zA-Z0-9]$', environment) is not None
    else:
        return re.match(r'^[a-zA-Z0-9][a-zA-Z0-9_-]*[a-zA-Z0-9]$', environment) is not None


def get_environment_debug_info(config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Get comprehensive environment debug information.

    Args:
        config: Optional configuration dictionary

    Returns:
        Dict[str, Any]: Debug information
    """
    if config is None:
        from .config import load_config
        config = load_config()

    manager = EnvironmentStateManager(config)
    state_info = manager.get_state_info()

    # Add additional debug information
    debug_info = {
        "state_manager": state_info,
        "working_directory": os.getcwd(),
        "user_id": os.getuid(),
        "environment_variables": {
            key: value for key, value in os.environ.items()
            if key.startswith('AUTO_SECRETS_')
        }
    }

    return debug_info
