"""Comprehensive unit tests for KeyRetriever class."""

import os
from typing import Any, Union
from unittest.mock import Mock, patch

import paramiko
import pytest

from auto_secrets.core.key_retriever import HAS_MEMFD, MFD_CLOEXEC, KeyRetriever, KeyRetrieverError
from auto_secrets.managers.common_config import CommonConfig
from auto_secrets.managers.log_manager import AutoSecretsLogger


class MockSSHAgentKey:
  """Mock SSH Agent Key for testing."""

  def __init__(self, comment: str = "test-key", name: str = "ssh-rsa") -> None:
    self.comment = comment
    self._name = name
    self._signature_data = b"mock_signature_data_for_testing"

  def get_name(self) -> str:
    """Return the key type name."""
    return self._name

  def sign_ssh_data(self, key: Any, data: Union[str, bytes]) -> bytes:
    """Mock SSH signing operation."""
    if isinstance(data, str):
      data = data.encode("utf-8")
    return self._signature_data


class TestKeyRetriever:
  """Test suite for KeyRetriever class."""

  @pytest.fixture
  def mock_logger(self) -> Mock:
    """Create a mock logger."""
    logger_instance = Mock()
    logger_manager = Mock(spec=AutoSecretsLogger)
    logger_manager.get_logger.return_value = logger_instance
    return logger_manager

  @pytest.fixture
  def mock_common_config(self) -> Mock:
    """Create a mock common config."""
    config = Mock(spec=CommonConfig)
    config.ssh_agent_key_comment = "test-key-comment"
    return config

  @pytest.fixture
  def key_retriever(self, mock_logger: Mock) -> KeyRetriever:
    """Create a KeyRetriever instance with mocked dependencies."""
    with (
      patch.object(CommonConfig, "__init__", return_value=None),
      patch.object(CommonConfig, "ssh_agent_key_comment", "test-key-comment"),
    ):
      return KeyRetriever(log_manager=mock_logger)

  @pytest.fixture
  def mock_agent_keys(self) -> list[MockSSHAgentKey]:
    """Create mock SSH agent keys."""
    return [
      MockSSHAgentKey(comment="other-key", name="ssh-ed25519"),
      MockSSHAgentKey(comment="test-key-comment", name="ssh-rsa"),
      MockSSHAgentKey(comment="another-key", name="ssh-dss"),
    ]

  def test_init_success(self, mock_logger: Mock) -> None:
    """Test successful initialization of KeyRetriever."""
    with (
      patch.object(CommonConfig, "__init__", return_value=None),
      patch.object(CommonConfig, "ssh_agent_key_comment", "test-comment"),
    ):
      retriever = KeyRetriever(log_manager=mock_logger)

      assert retriever.ssh_agent_key_comment == "test-comment"
      mock_logger.get_logger.assert_called_once_with(name="key_retriever", component="key_retriever")

  def test_init_with_none_comment(self, mock_logger: Mock) -> None:
    """Test initialization with None SSH agent key comment."""
    with (
      patch.object(CommonConfig, "__init__", return_value=None),
      patch.object(CommonConfig, "ssh_agent_key_comment", None),
    ):
      retriever = KeyRetriever(log_manager=mock_logger)

      assert retriever.ssh_agent_key_comment is None

  @patch("paramiko.Agent")
  def test_derive_smk_from_ssh_agent_success(
    self, mock_agent_class: Mock, key_retriever: KeyRetriever, mock_agent_keys: list[MockSSHAgentKey]
  ) -> None:
    """Test successful SMK derivation from SSH agent."""
    # Setup mock agent
    mock_agent = Mock()
    mock_agent.get_keys.return_value = mock_agent_keys
    mock_agent_class.return_value = mock_agent

    # Mock memfd_create and file operations
    mock_fd = 5
    expected_signature = b"mock_signature_data_for_testing"

    with (
      patch("auto_secrets.core.key_retriever.memfd_create", return_value=mock_fd) as mock_memfd,
      patch("os.fdopen") as mock_fdopen,
    ):
      mock_file = Mock()
      mock_fdopen.return_value.__enter__.return_value = mock_file

      result_fd = key_retriever.derive_smk_from_ssh_agent()

      assert result_fd == mock_fd
      mock_memfd.assert_called_once_with(b"session-master-key", MFD_CLOEXEC)
      mock_file.write.assert_called_once_with(expected_signature)

  @patch("paramiko.Agent")
  def test_derive_smk_no_keys_in_agent(self, mock_agent_class: Mock, key_retriever: KeyRetriever) -> None:
    """Test SMK derivation when no keys are found in SSH agent."""
    mock_agent = Mock()
    mock_agent.get_keys.return_value = []
    mock_agent_class.return_value = mock_agent

    with pytest.raises(KeyRetrieverError, match="No keys found in the SSH agent"):
      key_retriever.derive_smk_from_ssh_agent()

  @patch("paramiko.Agent")
  def test_derive_smk_target_key_not_found(self, mock_agent_class: Mock, key_retriever: KeyRetriever) -> None:
    """Test SMK derivation when target key comment is not found."""
    mock_agent = Mock()
    # Keys without the target comment
    mock_keys = [MockSSHAgentKey(comment="wrong-comment-1"), MockSSHAgentKey(comment="wrong-comment-2")]
    mock_agent.get_keys.return_value = mock_keys
    mock_agent_class.return_value = mock_agent

    with pytest.raises(KeyRetrieverError, match="Could not find key with comment 'test-key-comment'"):
      key_retriever.derive_smk_from_ssh_agent()

  @patch("paramiko.Agent")
  def test_derive_smk_signing_failure(
    self, mock_agent_class: Mock, key_retriever: KeyRetriever, mock_agent_keys: list[MockSSHAgentKey]
  ) -> None:
    """Test SMK derivation when SSH signing fails."""
    mock_agent = Mock()
    mock_agent.get_keys.return_value = mock_agent_keys
    mock_agent_class.return_value = mock_agent

    # Make the target key's signing method raise an exception
    target_key = next(key for key in mock_agent_keys if key.comment == "test-key-comment")
    with (
      patch.object(target_key, "sign_ssh_data", side_effect=Exception("Signing failed")),
      pytest.raises(KeyRetrieverError, match="Agent signing operation failed or was canceled"),
    ):
      key_retriever.derive_smk_from_ssh_agent()

  @patch("paramiko.Agent")
  def test_derive_smk_memfd_failure(
    self, mock_agent_class: Mock, key_retriever: KeyRetriever, mock_agent_keys: list[MockSSHAgentKey]
  ) -> None:
    """Test SMK derivation when memfd_create fails."""
    mock_agent = Mock()
    mock_agent.get_keys.return_value = mock_agent_keys
    mock_agent_class.return_value = mock_agent

    with (
      patch("auto_secrets.core.key_retriever.memfd_create", return_value=-1),
      patch("ctypes.get_errno", return_value=12) as mock_errno,
      patch("os.strerror", return_value="Cannot allocate memory") as mock_strerror,
    ):
      with pytest.raises(OSError, match="memfd_create failed: Cannot allocate memory"):
        key_retriever.derive_smk_from_ssh_agent()

      mock_errno.assert_called_once()
      mock_strerror.assert_called_once_with(12)

  @patch("paramiko.Agent")
  def test_derive_smk_file_write_error(
    self, mock_agent_class: Mock, key_retriever: KeyRetriever, mock_agent_keys: list[MockSSHAgentKey]
  ) -> None:
    """Test SMK derivation when file writing fails."""
    mock_agent = Mock()
    mock_agent.get_keys.return_value = mock_agent_keys
    mock_agent_class.return_value = mock_agent

    mock_fd = 5

    with patch("auto_secrets.core.key_retriever.memfd_create", return_value=mock_fd), patch("os.fdopen") as mock_fdopen:
      # Make fdopen raise an exception
      mock_fdopen.side_effect = OSError("File descriptor error")

      with pytest.raises(OSError, match="File descriptor error"):
        key_retriever.derive_smk_from_ssh_agent()

  def test_derive_smk_different_key_types(self, key_retriever: KeyRetriever) -> None:
    """Test SMK derivation with different SSH key types."""
    key_types = ["ssh-rsa", "ssh-ed25519", "ssh-dss", "ecdsa-sha2-nistp256"]

    for key_type in key_types:
      with patch("paramiko.Agent") as mock_agent_class:
        mock_agent = Mock()
        mock_keys = [MockSSHAgentKey(comment="test-key-comment", name=key_type)]
        mock_agent.get_keys.return_value = mock_keys
        mock_agent_class.return_value = mock_agent

        with patch("auto_secrets.core.key_retriever.memfd_create", return_value=5), patch("os.fdopen") as mock_fdopen:
          mock_file = Mock()
          mock_fdopen.return_value.__enter__.return_value = mock_file

          fd = key_retriever.derive_smk_from_ssh_agent()
          assert fd == 5

  @patch("paramiko.Agent")
  def test_prompt_ssh_agent_biometric_success(self, mock_agent_class: Mock, key_retriever: KeyRetriever) -> None:
    """Test successful biometric prompt."""
    mock_agent = Mock()
    mock_agent.get_keys.return_value = []
    mock_agent_class.return_value = mock_agent

    # Should not raise an exception
    key_retriever.prompt_ssh_agent_biometric()

    mock_agent_class.assert_called_once()
    mock_agent.get_keys.assert_called_once()

  @patch("paramiko.Agent")
  def test_prompt_ssh_agent_biometric_failure(self, mock_agent_class: Mock, key_retriever: KeyRetriever) -> None:
    """Test biometric prompt failure."""
    mock_agent_class.side_effect = Exception("SSH agent connection failed")

    with pytest.raises(KeyRetrieverError, match="SSH agent biometric prompt failed"):
      key_retriever.prompt_ssh_agent_biometric()

  def test_prompt_ssh_agent_biometric_no_comment(self, mock_logger: Mock) -> None:
    """Test biometric prompt when ssh_agent_key_comment is None - should not call Agent."""
    with (
      patch.object(CommonConfig, "__init__", return_value=None),
      patch.object(CommonConfig, "ssh_agent_key_comment", None),
      patch("auto_secrets.core.key_retriever.paramiko.Agent") as mock_agent_class,  # Mock the import path
    ):
      retriever = KeyRetriever(log_manager=mock_logger)
      # Should NOT call Agent when comment is None
      retriever.prompt_ssh_agent_biometric()
      mock_agent_class.assert_not_called()

  def test_prompt_ssh_agent_biometric_none_comment_no_call(self, mock_logger: Mock) -> None:
    """Test biometric prompt when ssh_agent_key_comment is None - should not call Agent."""
    with (
      patch.object(CommonConfig, "__init__", return_value=None),
      patch.object(CommonConfig, "ssh_agent_key_comment", None),
    ):
      retriever = KeyRetriever(log_manager=mock_logger)
      with patch("paramiko.Agent") as mock_agent_class:
        # Should NOT call Agent when comment is None
        retriever.prompt_ssh_agent_biometric()
        mock_agent_class.assert_not_called()

  def test_prompt_ssh_agent_biometric_empty_comment(self, mock_logger: Mock) -> None:
    """Test biometric prompt when ssh_agent_key_comment is empty."""
    with (
      patch.object(CommonConfig, "__init__", return_value=None),
      patch.object(CommonConfig, "ssh_agent_key_comment", ""),
      patch("auto_secrets.core.key_retriever.paramiko.Agent") as mock_agent_class,  # Mock the import path
    ):
      mock_agent = Mock()
      mock_agent_class.return_value = mock_agent

      retriever = KeyRetriever(log_manager=mock_logger)
      # Should NOT call Agent when comment is empty string
      retriever.prompt_ssh_agent_biometric()
      mock_agent_class.assert_not_called()

  def test_prompt_ssh_agent_biometric_with_comment(self, mock_logger: Mock) -> None:
    """Test biometric prompt when ssh_agent_key_comment has a value."""
    with (
      patch.object(CommonConfig, "__init__", return_value=None),
      patch.object(CommonConfig, "ssh_agent_key_comment", "test-key"),
      patch("auto_secrets.core.key_retriever.paramiko.Agent") as mock_agent_class,  # Mock the import path
    ):
      mock_agent = Mock()
      mock_agent_class.return_value = mock_agent

      retriever = KeyRetriever(log_manager=mock_logger)
      # Should call Agent when comment is set
      retriever.prompt_ssh_agent_biometric()
      mock_agent_class.assert_called_once()
      mock_agent.get_keys.assert_called_once()

  def test_challenge_string_consistency(self, key_retriever: KeyRetriever) -> None:
    """Test that the challenge string is consistent and secure."""
    expected_challenge = "auto-secrets-session-challenge"

    with (
      patch("paramiko.Agent") as mock_agent_class,
      patch("auto_secrets.core.key_retriever.memfd_create", return_value=5),
      patch("os.fdopen"),
    ):
      mock_agent = Mock()
      mock_key = MockSSHAgentKey(comment="test-key-comment")
      mock_agent.get_keys.return_value = [mock_key]
      mock_agent_class.return_value = mock_agent

      # Capture the challenge passed to sign_ssh_data
      original_sign = mock_key.sign_ssh_data
      challenge_captured = None

      def capture_challenge(key: Any, challenge: str) -> bytes:
        nonlocal challenge_captured
        challenge_captured = challenge
        return original_sign(key, challenge)

      with patch.object(mock_key, "sign_ssh_data", side_effect=capture_challenge):
        key_retriever.derive_smk_from_ssh_agent()

      assert challenge_captured == expected_challenge

  def test_signature_to_bytes_conversion(self, key_retriever: KeyRetriever) -> None:
    """Test that signature is properly converted to bytes."""
    expected_signature = b"test_signature_bytes"

    with (
      patch("paramiko.Agent") as mock_agent_class,
      patch("auto_secrets.core.key_retriever.memfd_create", return_value=5),
      patch("os.fdopen") as mock_fdopen,
    ):
      mock_agent = Mock()
      mock_key = MockSSHAgentKey(comment="test-key-comment")
      mock_key._signature_data = expected_signature
      mock_agent.get_keys.return_value = [mock_key]
      mock_agent_class.return_value = mock_agent

      mock_file = Mock()
      mock_fdopen.return_value.__enter__.return_value = mock_file

      key_retriever.derive_smk_from_ssh_agent()

      # Verify the signature bytes were written to the file
      mock_file.write.assert_called_once_with(expected_signature)

  @pytest.mark.skipif(not HAS_MEMFD, reason="memfd_create not available on this system")
  def test_memfd_constants_on_linux(self) -> None:
    """Test memfd constants on Linux systems."""
    # This test will only run on systems that have memfd_create
    assert MFD_CLOEXEC == 0x0001

  @pytest.mark.skipif(HAS_MEMFD, reason="Only test fallback on non-Linux systems")
  def test_memfd_fallback_on_non_linux(self) -> None:
    """Test memfd fallback implementation on non-Linux systems."""
    from auto_secrets.core.key_retriever import memfd_create

    with pytest.raises(OSError, match="memfd_create is only available on Linux systems"):
      memfd_create(b"test", MFD_CLOEXEC)

  def test_logging_behavior(
    self, key_retriever: KeyRetriever, mock_agent_keys: list[MockSSHAgentKey], mock_logger: Mock
  ) -> None:
    """Test that appropriate log messages are generated."""
    with (
      patch("paramiko.Agent") as mock_agent_class,
      patch("auto_secrets.core.key_retriever.memfd_create", return_value=5),
      patch("os.fdopen"),
    ):
      mock_agent = Mock()
      mock_agent.get_keys.return_value = mock_agent_keys
      mock_agent_class.return_value = mock_agent

      key_retriever.derive_smk_from_ssh_agent()

      # Verify logging calls
      logger_instance = mock_logger.get_logger.return_value
      logger_instance.info.assert_any_call("Found target key: ssh-rsa (test-key-comment)")
      logger_instance.info.assert_any_call("Requesting signature from agent to derive SMK...")
      logger_instance.info.assert_any_call("Signature received successfully.")
      logger_instance.info.assert_any_call("SMK stored in memfd descriptor: 5")

  def test_error_logging_on_signing_failure(self, key_retriever: KeyRetriever, mock_logger: Mock) -> None:
    """Test error logging when signing fails."""
    with patch("paramiko.Agent") as mock_agent_class:
      mock_agent = Mock()
      mock_key = MockSSHAgentKey(comment="test-key-comment")
      mock_agent.get_keys.return_value = [mock_key]
      mock_agent_class.return_value = mock_agent

      with (
        patch.object(mock_key, "sign_ssh_data", side_effect=Exception("User canceled")),
        pytest.raises(KeyRetrieverError),
      ):
        key_retriever.derive_smk_from_ssh_agent()

      # Verify error logging
      logger_instance = mock_logger.get_logger.return_value
      logger_instance.error.assert_called_with(
        "Failed to get signature from agent for key comment 'test-key-comment'. User may have canceled."
      )

  def test_memfd_name_consistency(self, key_retriever: KeyRetriever, mock_agent_keys: list[MockSSHAgentKey]) -> None:
    """Test that memfd is created with consistent name."""
    expected_name = b"session-master-key"

    with (
      patch("paramiko.Agent") as mock_agent_class,
      patch("auto_secrets.core.key_retriever.memfd_create") as mock_memfd,
      patch("os.fdopen"),
    ):
      mock_agent = Mock()
      mock_agent.get_keys.return_value = mock_agent_keys
      mock_agent_class.return_value = mock_agent
      mock_memfd.return_value = 5

      key_retriever.derive_smk_from_ssh_agent()

      mock_memfd.assert_called_once_with(expected_name, MFD_CLOEXEC)

  def test_file_descriptor_handling(self, key_retriever: KeyRetriever, mock_agent_keys: list[MockSSHAgentKey]) -> None:
    """Test proper file descriptor handling and resource management."""
    mock_fd = 7

    with (
      patch("paramiko.Agent") as mock_agent_class,
      patch("auto_secrets.core.key_retriever.memfd_create", return_value=mock_fd),
      patch("os.fdopen") as mock_fdopen,
    ):
      mock_agent = Mock()
      mock_agent.get_keys.return_value = mock_agent_keys
      mock_agent_class.return_value = mock_agent

      # Setup context manager for file operations
      mock_file = Mock()
      mock_fdopen.return_value.__enter__.return_value = mock_file
      mock_fdopen.return_value.__exit__.return_value = None

      result_fd = key_retriever.derive_smk_from_ssh_agent()

      assert result_fd == mock_fd
      mock_fdopen.assert_called_once_with(mock_fd, "wb")
      # Verify context manager was used
      mock_fdopen.return_value.__enter__.assert_called_once()
      mock_fdopen.return_value.__exit__.assert_called_once()


# Integration tests
class TestKeyRetrieverIntegration:
  """Integration tests for KeyRetriever."""

  def test_exception_hierarchy(self) -> None:
    """Test that KeyRetrieverError is properly derived from Exception."""
    error = KeyRetrieverError("Test error")
    assert isinstance(error, Exception)
    assert str(error) == "Test error"

  def test_module_imports(self) -> None:
    """Test that all required modules can be imported."""
    # These should not raise ImportError

    # Test that the constants are defined
    assert isinstance(MFD_CLOEXEC, int)
    assert isinstance(HAS_MEMFD, bool)

  @pytest.mark.skipif(not HAS_MEMFD, reason="Requires Linux with memfd support")
  def test_real_memfd_create(self) -> None:
    """Test real memfd_create functionality on Linux."""
    from auto_secrets.core.key_retriever import memfd_create

    try:
      fd = memfd_create(b"test_memfd", MFD_CLOEXEC)
      assert fd >= 0

      # Test that we can write to the file descriptor
      with os.fdopen(fd, "wb") as f:
        f.write(b"test data")

    except OSError as e:
      # memfd_create might fail due to system limitations
      pytest.skip(f"memfd_create failed: {e}")

  def test_paramiko_agent_import(self) -> None:
    """Test that paramiko Agent can be imported and instantiated."""
    # Mock the Agent to avoid actual SSH agent connection
    with patch("paramiko.Agent") as mock_agent_class:
      mock_agent = Mock()
      mock_agent_class.return_value = mock_agent

      agent = paramiko.Agent()
      # Just test that it can be created - actual functionality
      # depends on SSH agent being available
      assert agent is not None
      mock_agent_class.assert_called_once()


if __name__ == "__main__":
  pytest.main([__file__])
