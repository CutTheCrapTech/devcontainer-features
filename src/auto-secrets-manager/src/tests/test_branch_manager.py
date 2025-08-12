"""
Test suite for auto_secrets.core.branch_manager module.

This file is MISSING from your test suite - that's why coverage is 10%!
"""

from typing import Any
from unittest.mock import patch

import pytest

from auto_secrets.core.branch_manager import BranchManager, BranchManagerError


class TestBranchManager:
  """Test BranchManager functionality."""

  def setup_method(self) -> None:
    """Set up test configuration."""
    self.config = {
      "branch_mappings": {
        "main": "production",
        "develop": "staging",
        "feature/*": "development",
        "release/**": "staging",
        "hotfix-*": "production",
        "default": "development",
      }
    }
    self.branch_manager = BranchManager(self.config)

  def test_exact_branch_match(self) -> None:
    """Test exact branch name matching."""
    result = self.branch_manager.map_branch_to_environment("main")
    assert result == "production"

    result = self.branch_manager.map_branch_to_environment("develop")
    assert result == "staging"

  def test_pattern_matching(self) -> None:
    """Test pattern matching for branch names."""
    # Test feature/* pattern
    result = self.branch_manager.map_branch_to_environment("feature/auth")
    assert result == "development"

    result = self.branch_manager.map_branch_to_environment("feature/ui-update")
    assert result == "development"

    # Test release/** pattern
    result = self.branch_manager.map_branch_to_environment("release/v1.0")
    assert result == "staging"

    result = self.branch_manager.map_branch_to_environment("release/hotfix/security")
    assert result == "staging"

    # Test hotfix-* pattern
    result = self.branch_manager.map_branch_to_environment("hotfix-login")
    assert result == "production"

  def test_default_fallback(self) -> None:
    """Test fallback to default environment."""
    result = self.branch_manager.map_branch_to_environment("unknown-branch")
    assert result == "development"

  def test_special_branch_states(self) -> None:
    """Test special branch states (detached, no-git, empty)."""
    for special_branch in ["detached", "no-git", ""]:
      result = self.branch_manager.map_branch_to_environment(special_branch)
      assert result == "development"

  def test_empty_branch_name(self) -> None:
    """Test handling of empty branch name."""
    with patch.object(self.branch_manager.logger, "warning") as mock_warning:
      result = self.branch_manager.map_branch_to_environment("")
      assert result == "development"
      mock_warning.assert_called_once()

  def test_no_branch_mappings_configured(self) -> None:
    """Test error when no branch mappings are configured."""
    empty_config: dict[str, Any] = {"branch_mappings": {}}
    branch_manager = BranchManager(empty_config)

    with pytest.raises(BranchManagerError, match="No branch mappings configured"):
      branch_manager.map_branch_to_environment("main")

  def test_get_default_environment(self) -> None:
    """Test getting default environment."""
    result = self.branch_manager._get_default_environment()
    assert result == "development"

    # Test with no default
    no_default_config = {"branch_mappings": {"main": "prod"}}
    branch_manager = BranchManager(no_default_config)
    result = branch_manager._get_default_environment()
    assert result is None

  def test_branch_pattern_matching_logic(self) -> None:
    """Test the pattern matching logic in detail."""
    # Test patterns without wildcards (should return False)
    assert not self.branch_manager._branch_matches_pattern("main", "main")

    # Test single wildcard
    assert self.branch_manager._branch_matches_pattern("feature/auth", "feature/*")
    assert not self.branch_manager._branch_matches_pattern("feature/sub/auth", "feature/*")

    # Test double wildcard
    assert self.branch_manager._branch_matches_pattern("release/v1.0", "release/**")
    assert self.branch_manager._branch_matches_pattern("release/hotfix/security", "release/**")

    # Test question mark wildcard
    config_with_question = {"branch_mappings": {"test-?": "testing", "default": "dev"}}
    bm = BranchManager(config_with_question)
    assert bm._branch_matches_pattern("test-1", "test-?")
    assert bm._branch_matches_pattern("test-a", "test-?")
    assert not bm._branch_matches_pattern("test-ab", "test-?")

  def test_invalid_regex_pattern(self) -> None:
    """Test handling of invalid regex patterns."""
    with patch.object(self.branch_manager.logger, "warning") as mock_warning:
      # Use a pattern with wildcards that creates invalid regex after conversion
      result = self.branch_manager._branch_matches_pattern("test", "*(?P<")

      # Should not raise exception (handled gracefully)
      assert result is False
      # Should log warning about invalid pattern
      mock_warning.assert_called_once()

      # Verify warning message contains expected content
      call_args = mock_warning.call_args[0][0]
      assert "Invalid regex pattern" in call_args
      assert "*(?P<" in call_args

  def test_pattern_without_wildcards_returns_early(self) -> None:
    """Test that patterns without wildcards return False immediately."""
    with patch.object(self.branch_manager.logger, "debug") as mock_debug:
      # Pattern without wildcards should return False without attempting regex
      result = self.branch_manager._branch_matches_pattern("main", "main")
      assert result is False

      # Should not attempt pattern conversion or regex matching
      # No debug log should be called for pattern testing
      mock_debug.assert_not_called()

    # Test other patterns without wildcards
    assert not self.branch_manager._branch_matches_pattern("develop", "develop")
    assert not self.branch_manager._branch_matches_pattern("feature/auth", "exact-branch-name")
    assert not self.branch_manager._branch_matches_pattern("test", "production")

  def test_get_available_environments(self) -> None:
    """Test getting list of available environments."""
    environments = self.branch_manager.get_available_environments()
    expected = ["development", "production", "staging"]
    assert sorted(environments) == expected

  def test_test_branch_mapping(self) -> None:
    """Test the branch mapping test functionality."""
    test_cases = [
      ("main", "production"),
      ("develop", "staging"),
      ("feature/auth", "development"),
      ("unknown", "development"),
    ]

    results = self.branch_manager.test_branch_mapping(test_cases)

    assert results["total"] == 4
    assert results["passed"] == 4
    assert results["failed"] == 0
    assert all(detail["success"] for detail in results["details"])

  def test_test_branch_mapping_with_failures(self) -> None:
    """Test branch mapping test with some failures."""
    test_cases = [
      ("main", "wrong-env"),  # This will fail
      ("develop", "staging"),  # This will pass
    ]

    results = self.branch_manager.test_branch_mapping(test_cases)

    assert results["total"] == 2
    assert results["passed"] == 1
    assert results["failed"] == 1

  def test_test_branch_mapping_with_exceptions(self) -> None:
    """Test branch mapping test when exceptions occur."""
    # Create a branch manager that will raise an exception
    bad_config: dict[str, Any] = {"branch_mappings": {}}  # No mappings = will raise error
    bad_manager = BranchManager(bad_config)

    test_cases = [("main", "production")]
    results = bad_manager.test_branch_mapping(test_cases)

    assert results["failed"] == 1
    assert "ERROR:" in results["details"][0]["actual"]

  def test_validate_configuration_valid(self) -> None:
    """Test configuration validation with valid config."""
    errors = self.branch_manager.validate_configuration()
    assert errors == []

  def test_validate_configuration_no_mappings(self) -> None:
    """Test validation with no branch mappings."""
    empty_config: dict[str, Any] = {"branch_mappings": {}}
    branch_manager = BranchManager(empty_config)

    errors = branch_manager.validate_configuration()
    assert "No branch mappings configured" in errors

  def test_validate_configuration_no_default(self) -> None:
    """Test validation without default mapping."""
    no_default_config = {"branch_mappings": {"main": "production"}}
    branch_manager = BranchManager(no_default_config)

    errors = branch_manager.validate_configuration()
    assert any("default" in error for error in errors)

  def test_validate_configuration_invalid_pattern(self) -> None:
    """Test validation with invalid regex pattern."""
    bad_pattern_config = {
      "branch_mappings": {
        "[invalid": "production",  # Invalid regex
        "default": "development",
      }
    }
    branch_manager = BranchManager(bad_pattern_config)

    errors = branch_manager.validate_configuration()
    assert any("Invalid pattern syntax" in error for error in errors)

  def test_validate_configuration_duplicate_environments(self) -> None:
    """Test validation logs warning for duplicate environments."""
    duplicate_config = {
      "branch_mappings": {
        "main": "production",
        "master": "production",  # Duplicate
        "default": "development",
      }
    }
    branch_manager = BranchManager(duplicate_config)

    with patch.object(branch_manager.logger, "warning") as mock_warning:
      branch_manager.validate_configuration()
      mock_warning.assert_called_once()

  def test_repr(self) -> None:
    """Test string representation."""
    repr_str = repr(self.branch_manager)
    assert "BranchManager" in repr_str
    assert "mappings=6" in repr_str  # 5 mappings + default

  def test_no_match_no_default_returns_none(self) -> None:
    """Test that None is returned when no match and no default."""
    no_default_config = {"branch_mappings": {"main": "production"}}
    branch_manager = BranchManager(no_default_config)

    with patch.object(branch_manager.logger, "error") as mock_error:
      result = branch_manager.map_branch_to_environment("unknown")
      assert result is None
      mock_error.assert_called_once()


if __name__ == "__main__":
  pytest.main([__file__])
