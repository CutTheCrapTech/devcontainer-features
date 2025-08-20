"""
Auto Secrets Manager - Branch Manager

Handles git branch detection and branch-to-environment mapping.
Provides pattern matching for branch names and proper logging.
"""

import os
import re
from dataclasses import dataclass, field
from typing import Any, Optional

from ..core.common_utils import CommonUtils
from .log_manager import AutoSecretsLogger


class BranchConfigError(Exception):
  """Branch config related errors."""

  pass


class BranchManagerError(Exception):
  """Branch manager related errors."""

  pass


@dataclass
class BranchConfig:
  """
  Data class for branch configuration.

  Attributes:
      mappings (dict): Dictionary mapping branch names to environment names.
  """

  mappings: dict[str, str] = field(default_factory=dict)
  pattern_cache: dict[str, re.Pattern] = field(default_factory=dict)

  def __post_init__(self) -> None:
    """Validate branch mappings after initialization."""
    self.mappings = CommonUtils.parse_json(
      "AUTO_SECRETS_BRANCH_MAPPINGS", os.getenv("AUTO_SECRETS_BRANCH_MAPPINGS", "{}")
    )

    if not isinstance(self.mappings, dict):
      raise BranchConfigError("Branch mappings must be a dictionary")

    if "default" not in self.mappings:
      raise BranchConfigError("Branch mappings must contain a 'default' key")

    # Validation of keys and values
    for key, value in self.mappings.items():
      # Validate all keys and values are strings
      if not isinstance(key, str) or not isinstance(value, str):
        raise BranchConfigError(f"Branch mapping keys and values must be strings: {key} -> {value}")

      # Validate none of keys and values can be empty
      if not key.strip() or not value.strip():
        raise BranchConfigError(f"Branch mapping keys and values cannot be empty: '{key}' -> '{value}'")

      self.pattern_cache[key] = CommonUtils.get_regex_from_pattern(key)

      if not CommonUtils.is_valid_name(value):
        raise BranchConfigError(f"Invalid environment name: '{value}'")

  @classmethod
  def from_dict(cls, data: dict[str, str]) -> "BranchConfig":
    return cls(mappings=data)


class BranchManager:
  """
  Manages git branch detection and branch-to-environment mapping.

  Handles pattern matching for branch names and provides caching
  for performance optimization.
  """

  def __init__(self, log_manager: AutoSecretsLogger) -> None:
    self.logger = log_manager.get_logger(name="branch_manager", component="branch_manager")
    branch_config = BranchConfig()
    self.branch_mappings = branch_config.mappings
    self.branch_pattern_cache = branch_config.pattern_cache

  def map_branch_to_environment(self, branch: str, repo_path: Optional[str] = None) -> Optional[str]:
    """
    Map a git branch to an environment using configuration rules.

    Args:
        branch: Git branch name to map
        repo_path: Repository path (for context, currently unused)

    Returns:
        str: Environment name or None if no mapping found

    Raises:
        BranchManagerError: If branch mappings are invalid
    """
    if not branch:
      self.logger.warning("Empty branch name provided")
      return self._get_default_environment()

    self.logger.debug(f"Mapping branch '{branch}' to environment")

    if not self.branch_mappings:
      raise BranchManagerError("No branch mappings configured")

    # Handle special cases first
    if branch in ["detached", "no-git", ""]:
      self.logger.debug(f"Special branch state: {branch}")
      return self._get_default_environment()

    # Check for exact match first (fast path)
    if branch in self.branch_mappings:
      environment = self.branch_mappings.get(branch)
      self.logger.info(f"Exact match: {branch} -> {environment}")
      return environment

    # Check for pattern matches
    for pattern, environment in self.branch_mappings.items():
      if pattern == "default":
        continue  # Skip default, handle separately

      if self._branch_matches_pattern(branch, pattern):
        self.logger.info(f"Pattern match: {branch} matches {pattern} -> {environment}")
        return environment

    # Use default if no matches found
    default_env = self._get_default_environment()
    if default_env:
      self.logger.info(f"No match found for '{branch}', using default: {default_env}")
      return default_env

    self.logger.error(f"No mapping found for branch '{branch}' and no default configured")
    return None

  def _get_default_environment(self) -> Optional[str]:
    """Get the default environment from configuration."""
    if isinstance(self.branch_mappings, dict):
      default_env = self.branch_mappings.get("default")
      return default_env if isinstance(default_env, str) else None

  def _branch_matches_pattern(self, branch_name: str, pattern: str) -> bool:
    """
    Check if branch name matches a pattern.

    Supports patterns like:
    - feature/* (matches feature/auth, feature/ui, etc.)
    - release/** (matches release/v1.0, release/hotfix/security, etc.)
    - hotfix-* (matches hotfix-login, hotfix-payment, etc.)

    Args:
        branch_name: Branch name to test
        pattern: Pattern to match against

    Returns:
        bool: True if branch matches pattern
    """
    # Skip patterns without wildcards
    if "*" not in pattern and "?" not in pattern:
      return False
    self.logger.debug(f"Testing pattern '{pattern}' against branch '{branch_name}'")
    try:
      # Add safety check for pattern cache
      if pattern not in self.branch_pattern_cache:
        self.logger.warning(f"Pattern not found in cache: '{pattern}'")
        return False
      match_result = bool(self.branch_pattern_cache[pattern].match(branch_name))
      self.logger.debug(f"Pattern '{pattern}' -> branch '{branch_name}' -> {match_result}")
      return match_result
    except re.error as e:
      self.logger.warning(f"Invalid regex pattern '{pattern}' when matching against branch {branch_name}: {e}")
      return False

  def get_available_environments(self) -> list[str]:
    """
    Get list of all configured environments.

    Returns:
        List[str]: List of environment names
    """
    environments = set(self.branch_mappings.values())
    # Remove 'default' if it's used as a key
    environments.discard("default")
    return sorted(environments)

  def test_branch_mapping(self, test_cases: list[tuple[str, str]]) -> dict[str, Any]:
    """
    Test branch mapping functionality with provided test cases.

    Args:
        test_cases: List of (branch_name, expected_environment) tuples

    Returns:
        Dict[str, Any]: Test results including successes and failures
    """
    results: dict[str, Any] = {
      "total": len(test_cases),
      "passed": 0,
      "failed": 0,
      "details": [],
    }

    for branch, expected_env in test_cases:
      try:
        actual_env = self.map_branch_to_environment(branch)
        success = actual_env == expected_env

        if success:
          results["passed"] += 1
        else:
          results["failed"] += 1

        results["details"].append(
          {
            "branch": branch,
            "expected": expected_env,
            "actual": actual_env,
            "success": success,
          }
        )

      except Exception as e:
        results["failed"] += 1
        results["details"].append(
          {
            "branch": branch,
            "expected": expected_env,
            "actual": f"ERROR: {e}",
            "success": False,
          }
        )

    self.logger.info(f"Branch mapping test: {results['passed']}/{results['total']} passed")
    return results

  def validate_configuration(self) -> list[str]:
    """
    Validate branch mapping configuration.

    Returns:
        List[str]: List of validation errors (empty if valid)
    """
    errors = []
    if not self.branch_mappings:
      errors.append("No branch mappings configured")
      return errors

    if "default" not in self.branch_mappings:
      errors.append("No 'default' environment mapping configured")

    # Check for invalid pattern syntax
    for pattern in self.branch_mappings:
      if pattern == "default":
        continue

      try:
        # Test the pattern conversion - validate all patterns, not just wildcards
        test_pattern = pattern.replace("**", ".*").replace("*", "[^/]*").replace("?", ".")
        re.compile(f"^{test_pattern}$")
      except re.error:
        errors.append(f"Invalid pattern syntax: {pattern}")

    # Check for duplicate environment names (might be intentional, so just warn)
    environments = list(self.branch_mappings.values())
    duplicates = {env for env in environments if environments.count(env) > 1}
    if duplicates:
      self.logger.warning(f"Duplicate environment mappings: {duplicates}")

    return errors

  def __repr__(self) -> str:
    """String representation of BranchManager."""
    return f"BranchManager(mappings={len(self.branch_mappings)})"
