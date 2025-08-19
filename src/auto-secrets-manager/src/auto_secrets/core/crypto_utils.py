"""Shared cryptographic utility functions, encapsulated in a class."""

import json
import os
import socket
import tempfile
from pathlib import Path
from typing import Any, Optional, Union

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from ..managers.common_config import CommonConfig
from ..managers.log_manager import AutoSecretsLogger


# Define a custom exception for this module's errors.
class CryptoError(Exception):
  pass


class KeyMasterFileNotFoundError(Exception):
  pass


class KeyMasterConnectionError(Exception):
  pass


class KeyMasterCommunicationError(Exception):
  pass


class KeyMasterEmptyKeyError(Exception):
  pass


class CryptoUtils:
  """A class for cryptographic utility methods."""

  def __init__(self, log_manager: AutoSecretsLogger, smk: Optional[bytes] = None) -> None:
    """Initialize the CryptoUtils class."""
    # A fixed, constant info string to ensure the same Session Encryption Key (SEK)
    # is derived every time from the same Session Master Key (SMK).
    self._SEK_INFO_STRING: bytes = b"auto-secrets-session-encryption-key-v1"
    # The socket path for communicating with the KeyMaster daemon.
    # This should be read from a shared configuration.
    self._KEY_MASTER_SOCKET_PATH = os.environ.get("AUTO_SECRETS_KEYMASTER_SOCKET", "/tmp/auto-secrets-keymaster.sock")
    self.logger = log_manager.get_logger(name="crypto_utils", component="crypto_utils")
    self.smk = smk if smk else self._get_key_from_keymaster()
    self.encryption_key = self.derive_session_encryption_key()
    common_config = CommonConfig()
    self.ssh_agent_key_comment = common_config.ssh_agent_key_comment

  def derive_session_encryption_key(self) -> bytes:
    """Derives the single, deterministic Session Encryption Key from the SMK."""
    if not self.smk:
      self.logger.error("Session Master Key is empty.")
      raise CryptoError("Session Master Key cannot be empty.")

    hkdf = HKDF(
      algorithm=hashes.SHA256(),
      length=32,  # 256-bit key for Fernet
      salt=None,
      info=self._SEK_INFO_STRING,
    )
    return hkdf.derive(self.smk)

  def _get_key_from_keymaster(self) -> bytes:
    """
    Connects to the KeyMaster daemon via a Unix socket to retrieve the Session Master Key (SMK).
    """
    self.logger.info("No key provided, attempting to retrieve from KeyMaster daemon...")
    try:
      with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.connect(self._KEY_MASTER_SOCKET_PATH)
        sock.sendall(b"GET_SEK")  # Command to request the key
        key = sock.recv(64)  # Fernet keys are base64-encoded, so 64 bytes is safe.
    except FileNotFoundError:
      self.logger.error(f"KeyMaster socket not found at {self._KEY_MASTER_SOCKET_PATH}. Is the daemon running?")
      raise KeyMasterFileNotFoundError("KeyMaster daemon is not available.") from None
    except ConnectionRefusedError:
      self.logger.error(f"Connection refused by KeyMaster daemon at {self._KEY_MASTER_SOCKET_PATH}.")
      raise KeyMasterConnectionError("Could not connect to KeyMaster daemon.") from None
    except Exception as e:
      self.logger.error(f"Failed to retrieve key from KeyMaster at socket {self._KEY_MASTER_SOCKET_PATH}: {e}")
      raise KeyMasterCommunicationError(f"A communication error occurred: {e}") from e

    if not key:
      raise KeyMasterEmptyKeyError("KeyMaster daemon returned an empty key.")

    self.logger.info("Successfully retrieved key from KeyMaster.")
    return key

  def _encrypt(self, plaintext: str) -> bytes:
    """
    Encrypts a plaintext string using the session encryption key.

    Args:
        plaintext: The string to encrypt.

    Returns:
        The encrypted ciphertext as bytes.

    Raises:
      CryptoError: If encryption fails.
    """
    try:
      f = Fernet(self.encryption_key)
      encrypted_data = f.encrypt(plaintext.encode("utf-8"))
      return encrypted_data
    except Exception as e:
      self.logger.error(f"Encryption failed: {e}")
      raise CryptoError(f"Encryption failed: {e}") from e

  def _decrypt(self, ciphertext: bytes) -> str:
    """
    Decrypts a ciphertext byte string using the session encryption key.

    Args:
        ciphertext: The encrypted data to decrypt.

    Returns:
        The decrypted plaintext string.

    Raises:
      CryptoError: If decryption fails due to an invalid key or tampered ciphertext.
    """
    try:
      f = Fernet(self.encryption_key)
      decrypted_data = f.decrypt(ciphertext)
      return decrypted_data.decode("utf-8")
    except InvalidToken:
      self.logger.error("Decryption failed: Invalid token or key.")
      raise CryptoError("Decryption failed. The key is invalid or the data has been tampered with.") from None
    except Exception as e:
      self.logger.error(f"Decryption failed: {e}")
      raise CryptoError(f"Decryption failed: {e}") from e

  def write_dict_to_file_atomically(
    self, target_path: Path, file_prefix: str, content: dict[str, Any], encrypt: bool = True
  ) -> Path:
    """
    Writes a dictionary to a file in JSON format, encrypting the content (if needed).

    Args:
        target_path: The directory where the file will be saved.
        file_prefix: The prefix of the file name to create.
          eg secret to create secret.json or secret.enc.json automatically.
        content: The dictionary to write to the file.
        encrypt: Option to skip encryption even if ssh_agent_key_comment is set, if this option is set to false.
          Defaults to True.

    Returns:
        The path to the written file.

    Raises:
        CryptoError: If encryption or file writing fails.
    """
    temp_path = None
    try:
      to_encrypt = encrypt and self.ssh_agent_key_comment is not None
      # Determine the filename based on the prefix and whether encryption is needed
      filename = f"{file_prefix}.enc.json" if to_encrypt else f"{file_prefix}.json"
      content_json = json.dumps(content, indent=2)
      content_enc: Union[str, bytes] = self._encrypt(content_json) if to_encrypt else content_json
      mode = "wb" if to_encrypt else "w"
      # Ensure directory exists
      target_path.mkdir(parents=True, exist_ok=True, mode=0o700)
      # Create temporary file in same directory
      with tempfile.NamedTemporaryFile(
        mode=mode,
        dir=target_path,
        prefix=f".{filename}.",
        suffix=".tmp",
        delete=False,
      ) as tmp_file:
        tmp_file.write(content_enc)
        tmp_file.flush()
        os.fsync(tmp_file.fileno())
        temp_path = tmp_file.name
      # Set proper permissions
      os.chmod(temp_path, 0o600)
      # Atomic rename
      os.rename(temp_path, target_path / filename)
      self.logger.info(f"Successfully wrote encrypted data to {target_path / filename}")
      return target_path / filename
    except Exception as e:
      # Clean up temp file if it exists
      try:
        if temp_path:
          os.unlink(temp_path)
      except OSError:
        pass
      self.logger.error(f"Failed to write encrypted data to file '{target_path / filename}': {e}")
      raise CryptoError(f"Failed to write encrypted data to file: {e}") from e

  def read_dict_from_file(self, target_path: Path, file_prefix: str, decrypt: bool = True) -> dict[str, Any]:
    """
    Reads a dictionary from a file in JSON format, decrypting the content if needed.

    Args:
      target_path: The directory where the file will be read from.
      file_prefix: The prefix of the file name to read from.
        eg secret to create secret.json or secret.enc.json automatically.
      decrypt: Option to skip decryption even if ssh_agent_key_comment is set, if this option is set to false.
        Defaults to True.

    Returns:
        The dictionary read from the file.

    Raises:
        CryptoError: If decryption or file reading fails.
    """
    try:
      to_decrypt = decrypt and self.ssh_agent_key_comment is not None
      # Determine the filename based on the prefix and whether encryption is needed
      filename = f"{file_prefix}.enc.json" if to_decrypt else f"{file_prefix}.json"
      file_path = target_path / filename
      mode = "rb" if to_decrypt else "r"

      if not file_path.exists():
        raise CryptoError(f"File {file_path} does not exist.")

      with open(file_path, mode) as f:
        content = f.read()
        # Decrypt if necessary
        if to_decrypt:
          content = self._decrypt(content)
        # Parse JSON
        return json.loads(content)
    except FileNotFoundError:
      self.logger.error(f"File not found: {file_path}")
      raise CryptoError(f"File not found: {file_path}") from None
    except json.JSONDecodeError as e:
      self.logger.error(f"Failed to decode JSON from {file_path}: {e}")
      raise CryptoError(f"Failed to decode JSON from {file_path}: {e}") from e
    except Exception as e:
      self.logger.error(f"Failed to read or decrypt data from {file_path}: {e}")
      raise CryptoError(f"Failed to read or decrypt data from {file_path}: {e}") from e
