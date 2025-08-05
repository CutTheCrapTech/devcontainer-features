"""
Auto Secrets Manager - Branch Manager

Handles git branch detection and branch-to-environment mapping.
Provides pattern matching for branch names and proper logging.
"""

import os
import re
import subprocess
import time
from typing import Dict, Any, Optional, List

from ..logging_config import get_logger


class BranchManagerError(Exception):
    """Branch manager related errors."""
    pass


class BranchManager:
    """
    Manages git branch detection and branch-to-environment mapping.

    Handles pattern matching for branch names and provides caching
    for performance optimization.
    """

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = get_logger("branch_manager")
        self._branch_cache: Optional[tuple] = None
        self._cache_ttl = 5.0  # Cache branch detection for 5 seconds

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

        branch_mappings = self.config.get("branch_mappings", {})
        if not branch_mappings:
            raise BranchManagerError("No branch mappings configured")

        # Handle special cases first
        if branch in ["detached", "no-git", ""]:
            self.logger.debug(f"Special branch state: {branch}")
            return self._get_default_environment()

        # Check for exact match first (fast path)
        if branch in branch_mappings:
            environment = branch_mappings[branch]
            self.logger.info(f"Exact match: {branch} -> {environment}")
            return environment

        # Check for pattern matches
        for pattern, environment in branch_mappings.items():
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
        return self.config.get("branch_mappings", {}).get("default")

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
        if '*' not in pattern and '?' not in pattern:
            return False

        self.logger.debug(f"Testing pattern '{pattern}' against branch '{branch_name}'")

        try:
            # Convert shell-style pattern to regex
            regex_pattern = pattern

            # Replace wildcards with regex equivalents
            # ** matches anything including /
            regex_pattern = regex_pattern.replace('**', '___DOUBLE_STAR___')
            # * matches anything except /
            regex_pattern = regex_pattern.replace('*', '[^/]*')
            # Restore **
            regex_pattern = regex_pattern.replace('___DOUBLE_STAR___', '.*')
            # ? matches single character
            regex_pattern = regex_pattern.replace('?', '.')

            # Anchor the pattern
            regex_pattern = f"^{regex_pattern}$"

            match_result = bool(re.match(regex_pattern, branch_name))
            self.logger.debug(f"Pattern '{pattern}' -> regex '{regex_pattern}' -> {match_result}")
            return match_result

        except re.error as e:
            self.logger.warning(f"Invalid regex pattern '{pattern}': {e}")
            return False

    def get_current_branch(self, repo_path: Optional[str] = None, use_cache: bool = True) -> Optional[str]:
        """
        Get the current git branch name.

        Args:
            repo_path: Optional repository path to check (defaults to current directory)
            use_cache: Whether to use cached result if available

        Returns:
            str: Current branch name or None if not in a git repository
        """
        current_time = time.time()
        current_dir = repo_path or os.getcwd()

        # Check cache if enabled
        if use_cache and self._branch_cache:
            cached_dir, cached_time, cached_branch = self._branch_cache
            if (
              cached_dir == current_dir
              and current_time - cached_time < self._cache_ttl
            ):
                self.logger.debug(f"Using cached branch: {cached_branch}")
                return cached_branch

        # Get fresh branch information
        branch = self._detect_current_branch(repo_path)

        # Update cache
        self._branch_cache = (current_dir, current_time, branch)

        return branch

    def _detect_current_branch(self, repo_path: Optional[str] = None) -> Optional[str]:
        """
        Detect the current git branch name.

        Args:
            repo_path: Optional repository path to check

        Returns:
            str: Branch name or None if not in a git repository
        """
        original_cwd = None

        try:
            # Change to target directory if specified
            if repo_path and repo_path != os.getcwd():
                original_cwd = os.getcwd()
                os.chdir(repo_path)

            # Check if we're in a git repository
            if not self._is_git_repository():
                self.logger.debug("Not in a git repository")
                return None

            # Try to get current branch name
            result = subprocess.run(
                ["git", "branch", "--show-current"],
                capture_output=True,
                text=True,
                timeout=5
            )

            if result.returncode == 0 and result.stdout.strip():
                branch_name = result.stdout.strip()
                self.logger.debug(f"Detected branch: {branch_name}")
                return branch_name

            # Handle detached HEAD or other cases
            return self._handle_detached_head()

        except (subprocess.TimeoutExpired, subprocess.SubprocessError, FileNotFoundError) as e:
            self.logger.warning(f"Git command failed: {e}")
            return None

        finally:
            # Restore original directory
            if original_cwd:
                try:
                    os.chdir(original_cwd)
                except OSError as e:
                    self.logger.warning(f"Failed to restore directory: {e}")

    def _handle_detached_head(self) -> Optional[str]:
        """
        Handle detached HEAD state and try to get meaningful reference.

        Returns:
            str: Branch name, tag name, or 'detached' if no meaningful reference found
        """
        try:
            # Try to get a symbolic reference
            result = subprocess.run(
                ["git", "symbolic-ref", "HEAD"],
                capture_output=True,
                text=True,
                timeout=5
            )

            if result.returncode == 0:
                ref = result.stdout.strip()
                branch_name = ref.replace("refs/heads/", "")
                self.logger.debug(f"Found symbolic ref: {branch_name}")
                return branch_name

            # Try to get tag name
            result = subprocess.run(
                ["git", "describe", "--tags", "--exact-match"],
                capture_output=True,
                text=True,
                timeout=5
            )

            if result.returncode == 0:
                tag_name = result.stdout.strip()
                self.logger.debug(f"Found tag: {tag_name}")
                return tag_name

            # Default to detached
            self.logger.debug("In detached HEAD state")
            return "detached"

        except (subprocess.TimeoutExpired, subprocess.SubprocessError) as e:
            self.logger.debug(f"Failed to resolve detached HEAD: {e}")
            return "detached"

    def _is_git_repository(self) -> bool:
        """
        Check if current directory is in a git repository.

        Returns:
            bool: True if in a git repository
        """
        try:
            result = subprocess.run(
                ["git", "rev-parse", "--is-inside-work-tree"],
                capture_output=True,
                text=True,
                timeout=5
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, subprocess.SubprocessError, FileNotFoundError):
            return False

    def clear_cache(self) -> None:
        """Clear the branch detection cache."""
        self._branch_cache = None
        self.logger.debug("Branch cache cleared")

    def get_available_environments(self) -> List[str]:
        """
        Get list of all configured environments.

        Returns:
            List[str]: List of environment names
        """
        branch_mappings = self.config.get("branch_mappings", {})
        environments = set(branch_mappings.values())
        # Remove 'default' if it's used as a key
        environments.discard("default")
        return sorted(list(environments))

    def test_branch_mapping(self, test_cases: List[tuple]) -> Dict[str, Any]:
        """
        Test branch mapping functionality with provided test cases.

        Args:
            test_cases: List of (branch_name, expected_environment) tuples

        Returns:
            Dict[str, Any]: Test results including successes and failures
        """
        results: Dict[str, Any] = {
            "total": len(test_cases),
            "passed": 0,
            "failed": 0,
            "details": []
        }

        for branch, expected_env in test_cases:
            try:
                actual_env = self.map_branch_to_environment(branch)
                success = actual_env == expected_env

                if success:
                    results["passed"] += 1
                else:
                    results["failed"] += 1

                results["details"].append({
                    "branch": branch,
                    "expected": expected_env,
                    "actual": actual_env,
                    "success": success
                })

            except Exception as e:
                results["failed"] += 1
                results["details"].append({
                    "branch": branch,
                    "expected": expected_env,
                    "actual": f"ERROR: {e}",
                    "success": False
                })

        self.logger.info(f"Branch mapping test: {results['passed']}/{results['total']} passed")
        return results

    def get_mapping_status(self) -> Dict[str, Any]:
        """
        Get current branch mapping status for debugging.

        Returns:
            Dict[str, Any]: Status information
        """
        current_branch = self.get_current_branch()
        current_env = None

        if current_branch:
            try:
                current_env = self.map_branch_to_environment(current_branch)
            except Exception as e:
                current_env = f"ERROR: {e}"

        return {
            "current_branch": current_branch,
            "current_environment": current_env,
            "working_directory": os.getcwd(),
            "is_git_repo": self._is_git_repository(),
            "branch_mappings": self.config.get("branch_mappings", {}),
            "available_environments": self.get_available_environments(),
            "cache_status": "active" if self._branch_cache else "empty"
        }

    def validate_configuration(self) -> List[str]:
        """
        Validate branch mapping configuration.

        Returns:
            List[str]: List of validation errors (empty if valid)
        """
        errors = []
        branch_mappings = self.config.get("branch_mappings", {})

        if not branch_mappings:
            errors.append("No branch mappings configured")
            return errors

        if "default" not in branch_mappings:
            errors.append("No 'default' environment mapping configured")

        # Check for invalid pattern syntax
        for pattern in branch_mappings.keys():
            if pattern == "default":
                continue

            if '*' in pattern or '?' in pattern:
                try:
                    # Test the pattern conversion
                    test_pattern = pattern.replace('**', '.*').replace('*', '[^/]*').replace('?', '.')
                    re.compile(f"^{test_pattern}$")
                except re.error:
                    errors.append(f"Invalid pattern syntax: {pattern}")

        # Check for duplicate environment names (might be intentional, so just warn)
        environments = list(branch_mappings.values())
        duplicates = set([env for env in environments if environments.count(env) > 1])
        if duplicates:
            self.logger.warning(f"Duplicate environment mappings: {duplicates}")

        return errors

    def __repr__(self) -> str:
        """String representation of BranchManager."""
        current_branch = self.get_current_branch() if self._branch_cache else "unknown"
        return f"BranchManager(branch={current_branch}, mappings={len(self.config.get('branch_mappings', {}))})"
