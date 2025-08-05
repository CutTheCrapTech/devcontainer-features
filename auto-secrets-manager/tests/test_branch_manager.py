"""
Test suite for auto_secrets.core.branch_manager module.

Comprehensive tests for git branch detection and branch-to-environment mapping.
"""

import pytest
import subprocess
from unittest.mock import patch, MagicMock

from auto_secrets.core.branch_manager import BranchManager, BranchManagerError # type: ignore


class TestBranchManager:
    """Test the BranchManager class functionality."""

    def setup_method(self):
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
                "default": "development"
            },
            "debug": False
        }
        self.branch_manager = BranchManager(self.config)

    def test_init(self):
        """Test BranchManager initialization."""
        manager = BranchManager(self.config)
        assert manager.config == self.config
        assert manager._branch_cache is None
        assert manager._cache_ttl == 5.0

    def test_map_branch_to_environment_exact_match(self):
        """Test exact branch name matching."""
        # Test exact matches
        assert self.branch_manager.map_branch_to_environment("main") == "production"
        assert self.branch_manager.map_branch_to_environment("staging") == "staging"
        assert self.branch_manager.map_branch_to_environment("develop") == "development"

    def test_map_branch_to_environment_pattern_match(self):
        """Test pattern-based branch matching."""
        # Test feature/* pattern
        assert self.branch_manager.map_branch_to_environment("feature/auth") == "development"
        assert self.branch_manager.map_branch_to_environment("feature/new-ui") == "development"
        assert self.branch_manager.map_branch_to_environment("feature/payment-system") == "development"

        # Test release/* pattern
        assert self.branch_manager.map_branch_to_environment("release/v1.0") == "staging"
        assert self.branch_manager.map_branch_to_environment("release/v2.1-beta") == "staging"

        # Test hotfix/* pattern
        assert self.branch_manager.map_branch_to_environment("hotfix/security") == "production"
        assert self.branch_manager.map_branch_to_environment("hotfix/login-bug") == "production"

        # Test hotfix-* pattern (different from hotfix/*)
        assert self.branch_manager.map_branch_to_environment("hotfix-login") == "production"
        assert self.branch_manager.map_branch_to_environment("hotfix-payment") == "production"

    def test_map_branch_to_environment_double_star_pattern(self):
        """Test double star pattern matching."""
        # Test release/** pattern (should match nested paths)
        assert self.branch_manager.map_branch_to_environment("release/v1.0/hotfix") == "staging"
        assert self.branch_manager.map_branch_to_environment("release/feature/auth") == "staging"

    def test_map_branch_to_environment_default(self):
        """Test default environment mapping."""
        # Test branches that don't match any pattern
        assert self.branch_manager.map_branch_to_environment("random-branch") == "development"
        assert self.branch_manager.map_branch_to_environment("experimental") == "development"
        assert self.branch_manager.map_branch_to_environment("test-123") == "development"

    def test_map_branch_to_environment_special_cases(self):
        """Test special branch cases."""
        # Test special branch states
        assert self.branch_manager.map_branch_to_environment("detached") == "development"
        assert self.branch_manager.map_branch_to_environment("no-git") == "development"
        assert self.branch_manager.map_branch_to_environment("") == "development"

    def test_map_branch_to_environment_empty_branch(self):
        """Test handling of empty branch name."""
        result = self.branch_manager.map_branch_to_environment("")
        assert result == "development"  # Should use default

    def test_map_branch_to_environment_no_mappings(self):
        """Test error when no branch mappings configured."""
        config_no_mappings = {"branch_mappings": {}}
        manager = BranchManager(config_no_mappings)

        with pytest.raises(BranchManagerError) as exc_info:
            manager.map_branch_to_environment("main")
        assert "No branch mappings configured" in str(exc_info.value)

    def test_map_branch_to_environment_no_default(self):
        """Test behavior when no default mapping exists."""
        config_no_default = {
            "branch_mappings": {
                "main": "production",
                "staging": "staging"
            }
        }
        manager = BranchManager(config_no_default)

        # Should return None when no default exists
        result = manager.map_branch_to_environment("unknown-branch")
        assert result is None

    def test_branch_matches_pattern_simple_wildcards(self):
        """Test simple wildcard pattern matching."""
        # Test single * (doesn't match /)
        assert self.branch_manager._branch_matches_pattern("feature/auth", "feature/*")
        assert self.branch_manager._branch_matches_pattern("hotfix-login", "hotfix-*")
        assert not self.branch_manager._branch_matches_pattern("feature/auth/sub", "feature/*")

    def test_branch_matches_pattern_double_wildcards(self):
        """Test double wildcard pattern matching."""
        # Test ** (matches everything including /)
        assert self.branch_manager._branch_matches_pattern("release/v1.0", "release/**")
        assert self.branch_manager._branch_matches_pattern("release/v1.0/hotfix", "release/**")
        assert self.branch_manager._branch_matches_pattern("release/feature/auth/sub", "release/**")

    def test_branch_matches_pattern_question_mark(self):
        """Test question mark pattern matching."""
        config_with_question = {
            "branch_mappings": {
                "test?": "development",
                "default": "development"
            }
        }
        manager = BranchManager(config_with_question)

        assert manager._branch_matches_pattern("test1", "test?")
        assert manager._branch_matches_pattern("testa", "test?")
        assert not manager._branch_matches_pattern("test12", "test?")
        assert not manager._branch_matches_pattern("test", "test?")

    def test_branch_matches_pattern_no_wildcards(self):
        """Test that patterns without wildcards are skipped."""
        # Patterns without wildcards should return False from _branch_matches_pattern
        assert not self.branch_manager._branch_matches_pattern("main", "main")
        assert not self.branch_manager._branch_matches_pattern("feature", "feature")

    def test_branch_matches_pattern_invalid_regex(self):
        """Test handling of invalid regex patterns."""
        # This should not crash, just return False
        result = self.branch_manager._branch_matches_pattern("test", "[invalid")
        assert result is False

    @patch('subprocess.run')
    def test_get_current_branch_success(self, mock_run):
        """Test successful branch detection."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="feature/auth\n"
        )

        branch = self.branch_manager.get_current_branch(use_cache=False)
        assert branch == "feature/auth"

        mock_run.assert_called_once_with(
            ["git", "branch", "--show-current"],
            capture_output=True,
            text=True,
            timeout=5
        )

    @patch('subprocess.run')
    @patch.object(BranchManager, '_is_git_repository')
    def test_get_current_branch_not_git_repo(self, mock_is_git, mock_run):
        """Test branch detection when not in git repository."""
        mock_is_git.return_value = False

        branch = self.branch_manager.get_current_branch(use_cache=False)
        assert branch is None

        # subprocess.run should not be called
        mock_run.assert_not_called()

    @patch('subprocess.run')
    @patch.object(BranchManager, '_is_git_repository')
    @patch.object(BranchManager, '_handle_detached_head')
    def test_get_current_branch_detached_head(self, mock_detached, mock_is_git, mock_run):
        """Test branch detection in detached HEAD state."""
        mock_is_git.return_value = True
        mock_run.return_value = MagicMock(returncode=1, stdout="")
        mock_detached.return_value = "detached"

        branch = self.branch_manager.get_current_branch(use_cache=False)
        assert branch == "detached"

        mock_detached.assert_called_once()

    @patch('subprocess.run')
    def test_get_current_branch_timeout(self, mock_run):
        """Test branch detection with timeout."""
        mock_run.side_effect = subprocess.TimeoutExpired(["git"], 5)

        branch = self.branch_manager.get_current_branch(use_cache=False)
        assert branch is None

    @patch('subprocess.run')
    def test_get_current_branch_git_not_found(self, mock_run):
        """Test branch detection when git command is not found."""
        mock_run.side_effect = FileNotFoundError("git not found")

        branch = self.branch_manager.get_current_branch(use_cache=False)
        assert branch is None

    def test_get_current_branch_caching(self):
        """Test branch detection caching behavior."""
        with patch.object(self.branch_manager, '_detect_current_branch') as mock_detect:
            mock_detect.return_value = "main"

            # First call should detect
            branch1 = self.branch_manager.get_current_branch()
            assert branch1 == "main"
            assert mock_detect.call_count == 1

            # Second call should use cache
            branch2 = self.branch_manager.get_current_branch()
            assert branch2 == "main"
            assert mock_detect.call_count == 1  # Should not be called again

            # Third call with use_cache=False should detect again
            branch3 = self.branch_manager.get_current_branch(use_cache=False)
            assert branch3 == "main"
            assert mock_detect.call_count == 2

    @patch('os.chdir')
    def test_get_current_branch_different_repo_path(self, mock_chdir):
        """Test branch detection with different repository path."""
        with patch.object(self.branch_manager, '_detect_current_branch') as mock_detect:
            mock_detect.return_value = "feature/test"

            branch = self.branch_manager.get_current_branch(repo_path="/other/repo")
            assert branch == "feature/test"

            # Should change to target directory and back
            assert mock_chdir.call_count == 2

    @patch('subprocess.run')
    def test_handle_detached_head_symbolic_ref(self, mock_run):
        """Test detached HEAD handling with symbolic reference."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="refs/heads/main\n"
        )

        result = self.branch_manager._handle_detached_head()
        assert result == "main"

    @patch('subprocess.run')
    def test_handle_detached_head_tag(self, mock_run):
        """Test detached HEAD handling with tag."""
        # First call (symbolic-ref) fails
        # Second call (describe --tags) succeeds
        mock_run.side_effect = [
            MagicMock(returncode=1, stdout=""),
            MagicMock(returncode=0, stdout="v1.0.0\n")
        ]

        result = self.branch_manager._handle_detached_head()
        assert result == "v1.0.0"

    @patch('subprocess.run')
    def test_handle_detached_head_fallback(self, mock_run):
        """Test detached HEAD handling fallback."""
        # All git commands fail
        mock_run.return_value = MagicMock(returncode=1, stdout="")

        result = self.branch_manager._handle_detached_head()
        assert result == "detached"

    @patch('subprocess.run')
    def test_is_git_repository_true(self, mock_run):
        """Test git repository detection when in git repo."""
        mock_run.return_value = MagicMock(returncode=0)

        result = self.branch_manager._is_git_repository()
        assert result is True

        mock_run.assert_called_once_with(
            ["git", "rev-parse", "--is-inside-work-tree"],
            capture_output=True,
            text=True,
            timeout=5
        )

    @patch('subprocess.run')
    def test_is_git_repository_false(self, mock_run):
        """Test git repository detection when not in git repo."""
        mock_run.return_value = MagicMock(returncode=1)

        result = self.branch_manager._is_git_repository()
        assert result is False

    @patch('subprocess.run')
    def test_is_git_repository_git_not_found(self, mock_run):
        """Test git repository detection when git is not found."""
        mock_run.side_effect = FileNotFoundError("git not found")

        result = self.branch_manager._is_git_repository()
        assert result is False

    def test_clear_cache(self):
        """Test cache clearing."""
        # Set up cache
        self.branch_manager._branch_cache = ("test", 123.0, "main")

        # Clear cache
        self.branch_manager.clear_cache()

        assert self.branch_manager._branch_cache is None

    def test_get_available_environments(self):
        """Test getting list of available environments."""
        environments = self.branch_manager.get_available_environments()

        expected = ["development", "production", "staging"]
        assert sorted(environments) == expected

    def test_get_available_environments_empty_config(self):
        """Test getting environments with empty configuration."""
        config = {"branch_mappings": {}}
        manager = BranchManager(config)

        environments = manager.get_available_environments()
        assert environments == []

    def test_test_branch_mapping(self):
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

    def test_test_branch_mapping_with_failures(self):
        """Test branch mapping testing with failed cases."""
        test_cases = [
            ("main", "production"),     # Should pass
            ("main", "staging"),        # Should fail
            ("feature/auth", "production"),  # Should fail
        ]

        results = self.branch_manager.test_branch_mapping(test_cases)

        assert results["total"] == 3
        assert results["passed"] == 1
        assert results["failed"] == 2

    def test_get_mapping_status(self):
        """Test getting mapping status."""
        with patch.object(self.branch_manager, 'get_current_branch') as mock_branch:
            with patch.object(self.branch_manager, '_is_git_repository') as mock_git:
                mock_branch.return_value = "main"
                mock_git.return_value = True

                status = self.branch_manager.get_mapping_status()

                assert status["current_branch"] == "main"
                assert status["current_environment"] == "production"
                assert status["is_git_repo"] is True
                assert "branch_mappings" in status
                assert "available_environments" in status

    def test_validate_configuration_valid(self):
        """Test configuration validation with valid config."""
        errors = self.branch_manager.validate_configuration()
        assert errors == []

    def test_validate_configuration_no_mappings(self):
        """Test configuration validation with no mappings."""
        config = {"branch_mappings": {}}
        manager = BranchManager(config)

        errors = manager.validate_configuration()
        assert "No branch mappings configured" in errors

    def test_validate_configuration_no_default(self):
        """Test configuration validation with no default."""
        config = {
            "branch_mappings": {
                "main": "production",
                "staging": "staging"
            }
        }
        manager = BranchManager(config)

        errors = manager.validate_configuration()
        assert "No 'default' environment mapping configured" in errors

    def test_validate_configuration_invalid_pattern(self):
        """Test configuration validation with invalid pattern."""
        config = {
            "branch_mappings": {
                "[invalid": "production",
                "default": "development"
            }
        }
        manager = BranchManager(config)

        errors = manager.validate_configuration()
        assert any("Invalid pattern syntax" in error for error in errors)

    def test_repr(self):
        """Test string representation."""
        repr_str = repr(self.branch_manager)
        assert "BranchManager" in repr_str
        assert "mappings=" in repr_str


class TestBranchManagerIntegration:
    """Integration tests for BranchManager with real git operations."""

    def test_real_git_repository_detection(self):
        """Test with a real git repository."""
        config = {
            "branch_mappings": {
                "main": "production",
                "default": "development"
            }
        }
        manager = BranchManager(config)

        # This will depend on whether the test is run in a git repository
        # Just test that it doesn't crash
        try:
            is_git = manager._is_git_repository()
            assert isinstance(is_git, bool)
        except Exception as e:
            pytest.fail(f"Git repository detection failed: {e}")

    def test_pattern_matching_edge_cases(self):
        """Test pattern matching with edge cases."""
        config = {
            "branch_mappings": {
                "feature/**": "development",
                "release/v*": "staging",
                "hotfix-?": "production",
                "test*test": "testing",
                "default": "development"
            }
        }
        manager = BranchManager(config)

        test_cases = [
            ("feature/a/b/c/d", "development"),  # ** should match multiple levels
            ("release/v1", "staging"),           # * should match single level
            ("hotfix-a", "production"),          # ? should match single char
            ("hotfix-ab", "development"),        # ? should not match multiple chars
            ("testabctest", "testing"),          # * in middle
            ("test/test", "development"),        # * should not match /
        ]

        for branch, expected in test_cases:
            actual = manager.map_branch_to_environment(branch)
            assert actual == expected, f"Branch '{branch}' expected '{expected}', got '{actual}'"


if __name__ == '__main__':
    pytest.main([__file__])
