"""
Test suite for auto_secrets.core.branch_manager module.

Comprehensive tests for git branch detection and branch-to-environment mapping.
"""

import pytest
from auto_secrets.core.branch_manager import BranchManager, BranchManagerError  # type: ignore


class TestBranchManager:
    """Test the BranchManager class functionality."""

    def setup_method(self) -> None:
        """Set up test configuration."""
        self.config = {
            "branch_mappings": {
                "main": "production",
                "staging": "staging",
                "develop": "development",
                "feature/*": "development",
                "release/*": "staging",
                "hotfix/*": "production",
                "hotfix-*": "production",
                "release/**": "staging",
                "default": "development",
            },
            "debug": False,
        }
        self.branch_manager = BranchManager(self.config)

    def test_init(self) -> None:
        """Test BranchManager initialization."""
        manager = BranchManager(self.config)
        assert manager.config == self.config

    def test_map_branch_to_environment_exact_match(self) -> None:
        """Test exact branch name matching."""
        # Test exact matches
        assert self.branch_manager.map_branch_to_environment("main") == "production"
        assert self.branch_manager.map_branch_to_environment("staging") == "staging"
        assert self.branch_manager.map_branch_to_environment("develop") == "development"

    def test_map_branch_to_environment_pattern_match(self) -> None:
        """Test pattern-based branch matching."""
        # Test feature/* pattern
        assert (
            self.branch_manager.map_branch_to_environment("feature/auth")
            == "development"
        )
        assert (
            self.branch_manager.map_branch_to_environment("feature/new-ui")
            == "development"
        )
        assert (
            self.branch_manager.map_branch_to_environment("feature/payment-system")
            == "development"
        )

        # Test release/* pattern
        assert (
            self.branch_manager.map_branch_to_environment("release/v1.0") == "staging"
        )
        assert (
            self.branch_manager.map_branch_to_environment("release/v2.1-beta")
            == "staging"
        )

        # Test hotfix/* pattern
        assert (
            self.branch_manager.map_branch_to_environment("hotfix/security")
            == "production"
        )
        assert (
            self.branch_manager.map_branch_to_environment("hotfix/login-bug")
            == "production"
        )

        # Test hotfix-* pattern (different from hotfix/*)
        assert (
            self.branch_manager.map_branch_to_environment("hotfix-login")
            == "production"
        )
        assert (
            self.branch_manager.map_branch_to_environment("hotfix-payment")
            == "production"
        )

    def test_map_branch_to_environment_double_star_pattern(self) -> None:
        """Test double star pattern matching."""
        # Test release/** pattern (should match nested paths)
        assert (
            self.branch_manager.map_branch_to_environment("release/v1.0/hotfix")
            == "staging"
        )
        assert (
            self.branch_manager.map_branch_to_environment("release/feature/auth")
            == "staging"
        )

    def test_map_branch_to_environment_default(self) -> None:
        """Test default environment mapping."""
        # Test branches that don't match any pattern
        assert (
            self.branch_manager.map_branch_to_environment("random-branch")
            == "development"
        )
        assert (
            self.branch_manager.map_branch_to_environment("experimental")
            == "development"
        )
        assert (
            self.branch_manager.map_branch_to_environment("test-123") == "development"
        )

    def test_map_branch_to_environment_special_cases(self) -> None:
        """Test special branch cases."""
        # Test special branch states
        assert (
            self.branch_manager.map_branch_to_environment("detached") == "development"
        )
        assert self.branch_manager.map_branch_to_environment("no-git") == "development"
        assert self.branch_manager.map_branch_to_environment("") == "development"

    def test_map_branch_to_environment_empty_branch(self) -> None:
        """Test handling of empty branch name."""
        result = self.branch_manager.map_branch_to_environment("")
        assert result == "development"  # Should use default

    def test_map_branch_to_environment_no_mappings(self) -> None:
        """Test error when no branch mappings configured."""
        config_no_mappings = {"branch_mappings": {}}
        manager = BranchManager(config_no_mappings)

        with pytest.raises(BranchManagerError) as exc_info:
            manager.map_branch_to_environment("main")
        assert "No branch mappings configured" in str(exc_info.value)

    def test_map_branch_to_environment_no_default(self) -> None:
        """Test behavior when no default mapping exists."""
        config_no_default = {
            "branch_mappings": {"main": "production", "staging": "staging"}
        }
        manager = BranchManager(config_no_default)

        # Should return None when no default exists
        result = manager.map_branch_to_environment("unknown-branch")
        assert result is None

    def test_branch_matches_pattern_simple_wildcards(self) -> None:
        """Test simple wildcard pattern matching."""
        # Test single * (doesn't match /)
        assert self.branch_manager._branch_matches_pattern("feature/auth", "feature/*")
        assert self.branch_manager._branch_matches_pattern("hotfix-login", "hotfix-*")
        assert not self.branch_manager._branch_matches_pattern(
            "feature/auth/sub", "feature/*"
        )

    def test_branch_matches_pattern_double_wildcards(self) -> None:
        """Test double wildcard pattern matching."""
        # Test ** (matches everything including /)
        assert self.branch_manager._branch_matches_pattern("release/v1.0", "release/**")
        assert self.branch_manager._branch_matches_pattern(
            "release/v1.0/hotfix", "release/**"
        )
        assert self.branch_manager._branch_matches_pattern(
            "release/feature/auth/sub", "release/**"
        )

    def test_branch_matches_pattern_question_mark(self) -> None:
        """Test question mark pattern matching."""
        config_with_question = {
            "branch_mappings": {"test?": "development", "default": "development"}
        }
        manager = BranchManager(config_with_question)

        assert manager._branch_matches_pattern("test1", "test?")
        assert manager._branch_matches_pattern("testa", "test?")
        assert not manager._branch_matches_pattern("test12", "test?")
        assert not manager._branch_matches_pattern("test", "test?")

    def test_branch_matches_pattern_no_wildcards(self) -> None:
        """Test that patterns without wildcards are skipped."""
        # Patterns without wildcards should return False from _branch_matches_pattern
        assert not self.branch_manager._branch_matches_pattern("main", "main")
        assert not self.branch_manager._branch_matches_pattern("feature", "feature")

    def test_branch_matches_pattern_invalid_regex(self) -> None:
        """Test handling of invalid regex patterns."""
        # This should not crash, just return False
        result = self.branch_manager._branch_matches_pattern("test", "[invalid")
        assert result is False

    def test_get_available_environments(self) -> None:
        """Test getting list of available environments."""
        environments = self.branch_manager.get_available_environments()

        expected = ["development", "production", "staging"]
        assert sorted(environments) == expected

    def test_get_available_environments_empty_config(self) -> None:
        """Test getting environments with empty configuration."""
        config = {"branch_mappings": {}}
        manager = BranchManager(config)

        environments = manager.get_available_environments()
        assert environments == []

    def test_test_branch_mapping(self) -> None:
        """Test branch mapping testing functionality."""
        test_cases = [
            ("main", "production"),
            ("feature/auth", "development"),
            ("release/v1.0", "staging"),
            ("unknown-branch", "development"),
        ]

        results = self.branch_manager.test_branch_mapping(test_cases)

        assert results["total"] == 4
        assert results["passed"] == 4
        assert results["failed"] == 0
        assert len(results["details"]) == 4

        for detail in results["details"]:
            assert detail["success"] is True

    def test_test_branch_mapping_with_failures(self) -> None:
        """Test branch mapping testing with failed cases."""
        test_cases = [
            ("main", "production"),  # Should pass
            ("main", "staging"),  # Should fail
            ("feature/auth", "production"),  # Should fail
        ]

        results = self.branch_manager.test_branch_mapping(test_cases)

        assert results["total"] == 3
        assert results["passed"] == 1
        assert results["failed"] == 2

    def test_validate_configuration_valid(self) -> None:
        """Test configuration validation with valid config."""
        errors = self.branch_manager.validate_configuration()
        assert errors == []

    def test_validate_configuration_no_mappings(self) -> None:
        """Test configuration validation with no mappings."""
        config = {"branch_mappings": {}}
        manager = BranchManager(config)

        errors = manager.validate_configuration()
        assert "No branch mappings configured" in errors

    def test_validate_configuration_no_default(self) -> None:
        """Test configuration validation with no default."""
        config = {"branch_mappings": {"main": "production", "staging": "staging"}}
        manager = BranchManager(config)

        errors = manager.validate_configuration()
        assert "No 'default' environment mapping configured" in errors

    def test_validate_configuration_invalid_pattern(self) -> None:
        """Test configuration validation with invalid pattern."""
        config = {"branch_mappings": {"[": "production", "default": "development"}}
        manager = BranchManager(config)

        errors = manager.validate_configuration()
        assert any("Invalid pattern syntax" in error for error in errors)

    def test_repr(self) -> None:
        """Test string representation."""
        repr_str = repr(self.branch_manager)
        assert "BranchManager" in repr_str
        assert "mappings=" in repr_str


class TestBranchManagerIntegration:
    """Integration tests for BranchManager with real git operations."""

    def test_pattern_matching_edge_cases(self) -> None:
        """Test pattern matching with edge cases."""
        config = {
            "branch_mappings": {
                "feature/**": "development",
                "release/v*": "staging",
                "hotfix-?": "production",
                "test*test": "testing",
                "default": "development",
            }
        }
        manager = BranchManager(config)

        test_cases = [
            ("feature/a/b/c/d", "development"),  # ** should match multiple levels
            ("release/v1", "staging"),  # * should match single level
            ("hotfix-a", "production"),  # ? should match single char
            ("hotfix-ab", "development"),  # ? should not match multiple chars
            ("testabctest", "testing"),  # * in middle
            ("test/test", "development"),  # * should not match /
        ]

        for branch, expected in test_cases:
            actual = manager.map_branch_to_environment(branch)
            assert (
                actual == expected
            ), f"Branch '{branch}' expected '{expected}', got '{actual}'"


if __name__ == "__main__":
    pytest.main([__file__])
