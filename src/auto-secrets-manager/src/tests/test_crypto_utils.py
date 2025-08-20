"""Comprehensive unit tests for CryptoUtils class."""

import json
import os
import tempfile
from collections.abc import Generator
from pathlib import Path
from typing import Any
from unittest.mock import Mock, patch

import pytest
from cryptography.fernet import Fernet

from auto_secrets.core.crypto_utils import (
  CryptoError,
  CryptoUtils,
  KeyMasterCommunicationError,
  KeyMasterConnectionError,
  KeyMasterEmptyKeyError,
  KeyMasterFileNotFoundError,
)
from auto_secrets.managers.common_config import CommonConfig
from auto_secrets.managers.log_manager import AutoSecretsLogger


class TestCryptoUtils:
  """Test suite for CryptoUtils class."""

  @pytest.fixture
  def mock_logger(self) -> Mock:
    """Create a mock logger."""
    logger_instance = Mock()
    logger_manager = Mock(spec=AutoSecretsLogger)
    logger_manager.get_logger.return_value = logger_instance
    return logger_manager

  @pytest.fixture
  def sample_smk(self) -> bytes:
    """Generate a sample Session Master Key."""
    return Fernet.generate_key()

  @pytest.fixture
  def crypto_utils(self, mock_logger: Mock, sample_smk: bytes) -> CryptoUtils:
    """Create a CryptoUtils instance with mocked dependencies."""
    with (
      patch.object(CommonConfig, "__init__", return_value=None),
      patch.object(CommonConfig, "ssh_agent_key_comment", "test-key"),
    ):
      return CryptoUtils(log_manager=mock_logger, smk=sample_smk)

  @pytest.fixture
  def crypto_utils_no_encryption(self, mock_logger: Mock, sample_smk: bytes) -> CryptoUtils:
    """Create a CryptoUtils instance without encryption."""
    with (
      patch.object(CommonConfig, "__init__", return_value=None),
      patch.object(CommonConfig, "ssh_agent_key_comment", None),
    ):
      return CryptoUtils(log_manager=mock_logger, smk=sample_smk)

  @pytest.fixture
  def temp_dir(self) -> Generator[Path, None, None]:
    """Create a temporary directory for testing."""
    with tempfile.TemporaryDirectory() as tmp_dir:
      yield Path(tmp_dir)

  def test_init_with_provided_smk(self, mock_logger: Mock, sample_smk: bytes) -> None:
    """Test initialization with a provided SMK."""
    with (
      patch.object(CommonConfig, "__init__", return_value=None),
      patch.object(CommonConfig, "ssh_agent_key_comment", "test-key"),
    ):
      crypto_utils = CryptoUtils(log_manager=mock_logger, smk=sample_smk)

      assert crypto_utils.smk == sample_smk
      assert crypto_utils.encryption_key is not None
      assert crypto_utils.ssh_agent_key_comment == "test-key"

  @patch("socket.socket")
  def test_init_with_keymaster(self, mock_socket: Mock, mock_logger: Mock) -> None:
    """Test initialization by retrieving SMK from KeyMaster."""
    # Setup socket mock
    mock_sock_instance = Mock()
    mock_socket.return_value.__enter__.return_value = mock_sock_instance
    mock_sock_instance.recv.return_value = Fernet.generate_key()

    with (
      patch.object(CommonConfig, "__init__", return_value=None),
      patch.object(CommonConfig, "ssh_agent_key_comment", "test-key"),
    ):
      crypto_utils = CryptoUtils(log_manager=mock_logger)

      assert crypto_utils.smk is not None
      mock_sock_instance.connect.assert_called_once()
      mock_sock_instance.sendall.assert_called_once_with(b"GET_SEK")

  def test_derive_session_encryption_key(self, crypto_utils: CryptoUtils, sample_smk: bytes) -> None:
    """Test session encryption key derivation."""
    # Test with valid SMK
    key = crypto_utils.derive_session_encryption_key()
    assert len(key) == 32  # 256-bit key

    # Test reproducibility
    key2 = crypto_utils.derive_session_encryption_key()
    assert key == key2

  def test_derive_session_encryption_key_empty_smk(self, mock_logger: Mock) -> None:
    """Test session encryption key derivation with empty SMK."""
    with (
      patch.object(CommonConfig, "__init__", return_value=None),
      patch.object(CommonConfig, "ssh_agent_key_comment", "test-key"),
    ):
      crypto_utils = CryptoUtils(log_manager=mock_logger, smk=b"")

      with pytest.raises(CryptoError, match="Session Master Key cannot be empty"):
        crypto_utils.derive_session_encryption_key()

  @patch("socket.socket")
  def test_get_key_from_keymaster_success(self, mock_socket: Mock, mock_logger: Mock) -> None:
    """Test successful key retrieval from KeyMaster."""
    expected_key = Fernet.generate_key()
    mock_sock_instance = Mock()
    mock_socket.return_value.__enter__.return_value = mock_sock_instance
    mock_sock_instance.recv.return_value = expected_key

    with (
      patch.object(CommonConfig, "__init__", return_value=None),
      patch.object(CommonConfig, "ssh_agent_key_comment", "test-key"),
    ):
      crypto_utils = CryptoUtils(log_manager=mock_logger)

      assert crypto_utils.smk == expected_key

  @patch("socket.socket")
  def test_get_key_from_keymaster_file_not_found(self, mock_socket: Mock, mock_logger: Mock) -> None:
    """Test KeyMaster file not found error."""
    mock_sock_instance = Mock()
    mock_socket.return_value.__enter__.return_value = mock_sock_instance
    mock_sock_instance.connect.side_effect = FileNotFoundError()

    with (
      patch.object(CommonConfig, "__init__", return_value=None),
      patch.object(CommonConfig, "ssh_agent_key_comment", "test-key"),
      pytest.raises(KeyMasterFileNotFoundError, match="KeyMaster daemon is not available"),
    ):
      CryptoUtils(log_manager=mock_logger)

  @patch("socket.socket")
  def test_get_key_from_keymaster_connection_refused(self, mock_socket: Mock, mock_logger: Mock) -> None:
    """Test KeyMaster connection refused error."""
    mock_sock_instance = Mock()
    mock_socket.return_value.__enter__.return_value = mock_sock_instance
    mock_sock_instance.connect.side_effect = ConnectionRefusedError()

    with (
      patch.object(CommonConfig, "__init__", return_value=None),
      patch.object(CommonConfig, "ssh_agent_key_comment", "test-key"),
      pytest.raises(KeyMasterConnectionError, match="Could not connect to KeyMaster daemon"),
    ):
      CryptoUtils(log_manager=mock_logger)

  @patch("socket.socket")
  def test_get_key_from_keymaster_empty_key(self, mock_socket: Mock, mock_logger: Mock) -> None:
    """Test KeyMaster returning empty key."""
    mock_sock_instance = Mock()
    mock_socket.return_value.__enter__.return_value = mock_sock_instance
    mock_sock_instance.recv.return_value = b""

    with (
      patch.object(CommonConfig, "__init__", return_value=None),
      patch.object(CommonConfig, "ssh_agent_key_comment", "test-key"),
      pytest.raises(KeyMasterEmptyKeyError, match="KeyMaster daemon returned an empty key"),
    ):
      CryptoUtils(log_manager=mock_logger)

  @patch("socket.socket")
  def test_get_key_from_keymaster_communication_error(self, mock_socket: Mock, mock_logger: Mock) -> None:
    """Test KeyMaster communication error."""
    mock_sock_instance = Mock()
    mock_socket.return_value.__enter__.return_value = mock_sock_instance
    mock_sock_instance.connect.side_effect = Exception("Network error")

    with (
      patch.object(CommonConfig, "__init__", return_value=None),
      patch.object(CommonConfig, "ssh_agent_key_comment", "test-key"),
      pytest.raises(KeyMasterCommunicationError, match="A communication error occurred"),
    ):
      CryptoUtils(log_manager=mock_logger)

  def test_encrypt_decrypt_roundtrip(self, crypto_utils: CryptoUtils) -> None:
    """Test encryption and decryption roundtrip."""
    plaintext = "Hello, World! This is a test message."

    # Encrypt
    assert crypto_utils.encryption_key is not None
    ciphertext = crypto_utils._encrypt(crypto_utils.encryption_key, plaintext)
    assert isinstance(ciphertext, bytes)
    assert ciphertext != plaintext.encode("utf-8")

    # Decrypt
    decrypted = crypto_utils._decrypt(crypto_utils.encryption_key, ciphertext)
    assert decrypted == plaintext

  def test_encrypt_unicode(self, crypto_utils: CryptoUtils) -> None:
    """Test encryption with unicode characters."""
    plaintext = "Hello, 世界! 🌍 Émojis and ünïcödé"

    assert crypto_utils.encryption_key is not None
    ciphertext = crypto_utils._encrypt(crypto_utils.encryption_key, plaintext)
    decrypted = crypto_utils._decrypt(crypto_utils.encryption_key, ciphertext)

    assert decrypted == plaintext

  def test_decrypt_invalid_token(self, crypto_utils: CryptoUtils) -> None:
    """Test decryption with invalid token."""
    invalid_ciphertext = b"invalid_ciphertext_data"

    assert crypto_utils.encryption_key is not None
    with pytest.raises(CryptoError, match="Decryption failed. The key is invalid"):
      crypto_utils._decrypt(crypto_utils.encryption_key, invalid_ciphertext)

  def test_decrypt_tampered_data(self, crypto_utils: CryptoUtils) -> None:
    """Test decryption with tampered data."""
    plaintext = "Original message"

    assert crypto_utils.encryption_key is not None
    ciphertext = crypto_utils._encrypt(crypto_utils.encryption_key, plaintext)

    # Tamper with the ciphertext
    tampered = bytearray(ciphertext)
    tampered[-1] ^= 1  # Flip last bit

    with pytest.raises(CryptoError, match="Decryption failed. The key is invalid"):
      crypto_utils._decrypt(crypto_utils.encryption_key, bytes(tampered))

  def test_write_dict_to_file_atomically_encrypted(self, crypto_utils: CryptoUtils, temp_dir: Path) -> None:
    """Test writing dictionary to file with encryption."""
    test_data: dict[str, Any] = {"key1": "value1", "key2": 42, "key3": ["list", "item"], "key4": {"nested": "dict"}}

    result_path = crypto_utils.write_dict_to_file_atomically(
      target_path=temp_dir, file_prefix="test", content=test_data, encrypt=True
    )

    expected_path = temp_dir / "test.enc.json"
    assert result_path == expected_path
    assert result_path.exists()

    # Check file permissions
    stat = result_path.stat()
    assert oct(stat.st_mode)[-3:] == "600"

    # Content should be encrypted (not readable as JSON)
    with open(result_path, "rb") as f:
      content = f.read()
      with pytest.raises(json.JSONDecodeError):
        json.loads(content.decode("utf-8"))

  def test_write_dict_to_file_atomically_unencrypted(
    self, crypto_utils_no_encryption: CryptoUtils, temp_dir: Path
  ) -> None:
    """Test writing dictionary to file without encryption."""
    test_data: dict[str, Any] = {"test": "data"}

    result_path = crypto_utils_no_encryption.write_dict_to_file_atomically(
      target_path=temp_dir, file_prefix="test", content=test_data, encrypt=True
    )

    expected_path = temp_dir / "test.json"
    assert result_path == expected_path
    assert result_path.exists()

    # Content should be readable JSON
    with open(result_path) as f:
      loaded_data = json.load(f)
      assert loaded_data == test_data

  def test_write_dict_to_file_atomically_force_no_encryption(self, crypto_utils: CryptoUtils, temp_dir: Path) -> None:
    """Test writing dictionary to file with encryption disabled."""
    test_data: dict[str, Any] = {"test": "data"}

    result_path = crypto_utils.write_dict_to_file_atomically(
      target_path=temp_dir, file_prefix="test", content=test_data, encrypt=False
    )

    expected_path = temp_dir / "test.json"
    assert result_path == expected_path

  @patch("tempfile.NamedTemporaryFile")
  def test_write_dict_to_file_atomically_error_handling(
    self, mock_temp_file: Mock, crypto_utils: CryptoUtils, temp_dir: Path
  ) -> None:
    """Test error handling in atomic file writing."""
    mock_temp_file.side_effect = OSError("Permission denied")

    with pytest.raises(CryptoError, match="Failed to write encrypted data to file"):
      crypto_utils.write_dict_to_file_atomically(target_path=temp_dir, file_prefix="test", content={"test": "data"})

  def test_read_dict_from_file_encrypted(self, crypto_utils: CryptoUtils, temp_dir: Path) -> None:
    """Test reading encrypted dictionary from file."""
    test_data: dict[str, Any] = {"key1": "value1", "key2": 42, "nested": {"key": "value"}}

    # Write the file first
    crypto_utils.write_dict_to_file_atomically(target_path=temp_dir, file_prefix="test", content=test_data)

    # Read it back
    loaded_data = crypto_utils.read_dict_from_file(target_path=temp_dir, file_prefix="test")

    assert loaded_data == test_data

  def test_read_dict_from_file_unencrypted(self, crypto_utils_no_encryption: CryptoUtils, temp_dir: Path) -> None:
    """Test reading unencrypted dictionary from file."""
    test_data: dict[str, Any] = {"test": "data"}

    # Write the file first
    crypto_utils_no_encryption.write_dict_to_file_atomically(
      target_path=temp_dir, file_prefix="test", content=test_data
    )

    # Read it back
    loaded_data = crypto_utils_no_encryption.read_dict_from_file(target_path=temp_dir, file_prefix="test")

    assert loaded_data == test_data

  def test_read_dict_from_file_not_found(self, crypto_utils: CryptoUtils, temp_dir: Path) -> None:
    """Test reading from non-existent file."""
    with pytest.raises(CryptoError, match="File .* does not exist"):
      crypto_utils.read_dict_from_file(target_path=temp_dir, file_prefix="nonexistent")

  def test_read_dict_from_file_invalid_json(self, crypto_utils_no_encryption: CryptoUtils, temp_dir: Path) -> None:
    """Test reading file with invalid JSON."""
    # Create file with invalid JSON
    invalid_file = temp_dir / "invalid.json"
    invalid_file.write_text("{ invalid json }")

    with pytest.raises(CryptoError, match="Failed to decode JSON"):
      crypto_utils_no_encryption.read_dict_from_file(target_path=temp_dir, file_prefix="invalid")

  def test_read_dict_from_file_wrong_key(self, crypto_utils: CryptoUtils, temp_dir: Path, mock_logger: Mock) -> None:
    """Test reading encrypted file with wrong key."""
    # Create encrypted file with one instance
    test_data = {"test": "data"}
    crypto_utils.write_dict_to_file_atomically(target_path=temp_dir, file_prefix="test", content=test_data)

    # Try to read with different key
    different_smk = Fernet.generate_key()
    with (
      patch.object(CommonConfig, "__init__", return_value=None),
      patch.object(CommonConfig, "ssh_agent_key_comment", "test-key"),
    ):
      different_crypto = CryptoUtils(log_manager=mock_logger, smk=different_smk)
      with pytest.raises(CryptoError, match="Decryption failed"):
        different_crypto.read_dict_from_file(target_path=temp_dir, file_prefix="test")

  def test_environment_variable_socket_path(self, mock_logger: Mock, sample_smk: bytes) -> None:
    """Test that socket path respects environment variable."""
    custom_path = "/custom/socket/path.sock"

    with (
      patch.dict(os.environ, {"AUTO_SECRETS_KEYMASTER_SOCKET": custom_path}),
      patch.object(CommonConfig, "__init__", return_value=None),
      patch.object(CommonConfig, "ssh_agent_key_comment", "test-key"),
    ):
      crypto_utils = CryptoUtils(log_manager=mock_logger, smk=sample_smk)

      assert custom_path == crypto_utils._KEY_MASTER_SOCKET_PATH

  def test_sek_info_string_consistency(self, mock_logger: Mock) -> None:
    """Test that SEK info string is consistent across instances."""
    sample_smk = Fernet.generate_key()

    with (
      patch.object(CommonConfig, "__init__", return_value=None),
      patch.object(CommonConfig, "ssh_agent_key_comment", "test-key"),
    ):
      crypto1 = CryptoUtils(log_manager=mock_logger, smk=sample_smk)
      crypto2 = CryptoUtils(log_manager=mock_logger, smk=sample_smk)

      assert crypto1._SEK_INFO_STRING == crypto2._SEK_INFO_STRING
      assert crypto1.encryption_key == crypto2.encryption_key

  def test_file_permissions_security(self, crypto_utils: CryptoUtils, temp_dir: Path) -> None:
    """Test that created files have secure permissions."""
    test_data = {"sensitive": "data"}

    result_path = crypto_utils.write_dict_to_file_atomically(
      target_path=temp_dir, file_prefix="secure", content=test_data
    )

    # Check that file permissions are restrictive (600)
    stat_info = result_path.stat()
    permissions = oct(stat_info.st_mode)[-3:]
    assert permissions == "600", f"Expected 600, got {permissions}"

  def test_directory_creation(self, crypto_utils: CryptoUtils, temp_dir: Path) -> None:
    """Test that directories are created with proper permissions."""
    nested_dir = temp_dir / "level1" / "level2"
    test_data = {"test": "data"}

    crypto_utils.write_dict_to_file_atomically(target_path=nested_dir, file_prefix="test", content=test_data)

    assert nested_dir.exists()
    assert nested_dir.is_dir()

    # Check directory permissions (700)
    stat_info = nested_dir.stat()
    permissions = oct(stat_info.st_mode)[-3:]
    assert permissions == "700"


# Integration tests
class TestCryptoUtilsIntegration:
  """Integration tests for CryptoUtils."""

  @pytest.fixture
  def real_logger(self) -> AutoSecretsLogger:
    """Create a real logger instance for integration tests."""
    # This would need to be implemented based on your actual AutoSecretsLogger
    return Mock(spec=AutoSecretsLogger)

  def test_full_encryption_workflow(self, temp_dir: Path) -> None:
    """Test complete encryption workflow with real cryptography."""
    # Create a real SMK
    smk = Fernet.generate_key()

    with (
      patch.object(CommonConfig, "__init__", return_value=None),
      patch.object(CommonConfig, "ssh_agent_key_comment", "integration-test"),
    ):
      logger_manager = Mock(spec=AutoSecretsLogger)
      logger_manager.get_logger.return_value = Mock()

      crypto_utils = CryptoUtils(log_manager=logger_manager, smk=smk)

      # Test data
      original_data = {
        "secret": "super_secret_password",
        "config": {"host": "example.com", "port": 443, "ssl": True},
        "tokens": ["token1", "token2", "token3"],
      }

      # Write encrypted file
      file_path = crypto_utils.write_dict_to_file_atomically(
        target_path=temp_dir, file_prefix="integration_test", content=original_data
      )

      # Verify file exists and is encrypted
      assert file_path.exists()
      assert file_path.name == "integration_test.enc.json"

      # Read and verify
      recovered_data = crypto_utils.read_dict_from_file(target_path=temp_dir, file_prefix="integration_test")

      assert recovered_data == original_data

  def test_cross_instance_compatibility(self, temp_dir: Path) -> None:
    """Test that files written by one instance can be read by another."""
    smk = Fernet.generate_key()
    test_data = {"cross_instance": "test"}

    # Create first instance and write file
    with (
      patch.object(CommonConfig, "__init__", return_value=None),
      patch.object(CommonConfig, "ssh_agent_key_comment", "test"),
    ):
      logger_manager = Mock(spec=AutoSecretsLogger)
      logger_manager.get_logger.return_value = Mock()

      crypto1 = CryptoUtils(log_manager=logger_manager, smk=smk)
      crypto1.write_dict_to_file_atomically(target_path=temp_dir, file_prefix="cross_test", content=test_data)

    # Create second instance and read file
    with (
      patch.object(CommonConfig, "__init__", return_value=None),
      patch.object(CommonConfig, "ssh_agent_key_comment", "test"),
    ):
      logger_manager2 = Mock(spec=AutoSecretsLogger)
      logger_manager2.get_logger.return_value = Mock()

      crypto2 = CryptoUtils(log_manager=logger_manager2, smk=smk)
      recovered_data = crypto2.read_dict_from_file(target_path=temp_dir, file_prefix="cross_test")

      assert recovered_data == test_data


if __name__ == "__main__":
  pytest.main([__file__])
