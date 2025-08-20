import os
from dataclasses import dataclass
from pathlib import Path


@dataclass
class CommonConfig:
  """Common configuration settings."""

  ssh_agent_key_comment: str = ""
  cache_base_dir: str = ""

  def __post_init__(self) -> None:
    """Initialize from environment variables after dataclass creation."""
    # Read from environment
    self.ssh_agent_key_comment = os.getenv("AUTO_SECRETS_SSH_AGENT_KEY_COMMENT", "")
    self.cache_base_dir = os.getenv("AUTO_SECRETS_CACHE_DIR", "")

  def get_base_dir(self) -> Path:
    """
    Get the base directory path.
    Returns:
        Path: Base directory path
    """
    return Path(self.cache_base_dir)
