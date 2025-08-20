import ctypes
import os

import paramiko

from ..managers.common_config import CommonConfig
from ..managers.log_manager import AutoSecretsLogger

try:
  from os import MFD_CLOEXEC, memfd_create  # type: ignore[attr-defined]

  HAS_MEMFD = True
except (ImportError, AttributeError):
  # Fallback constants for non-Linux systems
  MFD_CLOEXEC = 0x0001  # Define the constant value
  HAS_MEMFD = False

  def memfd_create(name: bytes, flags: int) -> int:
    """Fallback memfd_create for non-Linux systems."""
    raise OSError("memfd_create is only available on Linux systems")


class KeyRetrieverError(Exception):
  pass


class KeyRetriever:
  """Handles the secure acquisition of the Session Master Key (SMK)."""

  def __init__(self, log_manager: AutoSecretsLogger):
    """
    Initializes the KeyRetriever.

    Args:
      log_manager: The logger manager instance.
    """
    self.logger = log_manager.get_logger(name="key_retriever", component="key_retriever")

    common_config = CommonConfig()
    self.ssh_agent_key_comment = common_config.ssh_agent_key_comment

  def derive_smk_from_ssh_agent(self) -> int:
    """
    Connects to the SSH agent, derives a key, and returns it in a
    secure memfd file descriptor.
    """
    agent = paramiko.Agent()
    keys = agent.get_keys()
    if not keys:
      raise KeyRetrieverError("No keys found in the SSH agent.")

    target_key = next(
      (key for key in keys if key.comment == self.ssh_agent_key_comment),
      None,
    )

    if not target_key:
      raise KeyRetrieverError(f"Could not find key with comment '{self.ssh_agent_key_comment}' in SSH agent.")

    self.logger.info(f"Found target key: {target_key.get_name()} ({target_key.comment})")
    self.logger.info("Requesting signature from agent to derive SMK...")

    challenge = "auto-secrets-session-challenge"
    try:
      signature = target_key.sign_ssh_data(target_key, challenge)
    except Exception as e:
      self.logger.error(
        f"Failed to get signature from agent for key comment '{self.ssh_agent_key_comment}'. User may have canceled."
      )
      raise KeyRetrieverError("Agent signing operation failed or was canceled.") from e

    self.logger.info("Signature received successfully.")
    session_key = bytes(signature)

    fd_name = b"session-master-key"
    fd: int = memfd_create(fd_name, MFD_CLOEXEC)
    if fd == -1:
      # Get the C-level errno value immediately after the syscall failed.
      error_code = ctypes.get_errno()
      # Get the corresponding error message from the OS.
      error_message = os.strerror(error_code)
      # Raise a proper OSError with both the code and the detailed message.
      raise OSError(error_code, f"memfd_create failed: {error_message}")

    with os.fdopen(fd, "wb") as f:
      f.write(session_key)

    self.logger.info(f"SMK stored in memfd descriptor: {fd}")
    return fd

  def prompt_ssh_agent_biometric(self) -> None:
    """
    Prompts the user for biometric authentication
    """
    try:
      if self.ssh_agent_key_comment is not None and self.ssh_agent_key_comment != "":
        agent = paramiko.Agent()
        agent.get_keys()
    except Exception as e:
      self.logger.error(f"Failed to prompt SSH agent for biometric authentication: {e}")
      raise KeyRetrieverError("SSH agent biometric prompt failed.") from e
