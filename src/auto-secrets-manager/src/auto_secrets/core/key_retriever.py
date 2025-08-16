import ctypes
import logging
import os
from os import MFD_CLOEXEC, memfd_create  # type: ignore[attr-defined]
from typing import Optional

import paramiko


class KeyRetriever:
  """Handles the secure acquisition of the Session Master Key (SMK)."""

  def __init__(self, ssh_agent_key_comment: Optional[str], logger: Optional[logging.Logger] = None):
    """
    Initializes the KeyRetriever.

    Args:
        ssh_agent_key_comment: The specific key comment to search for in the SSH agent.
        logger: An optional logger instance. If not provided, a new one is created.
    """
    self.logger = logger or logging.getLogger(__name__)

    if not ssh_agent_key_comment:
      raise ValueError("ssh_agent_key_comment cannot be empty.")
    self.ssh_agent_key_comment = ssh_agent_key_comment

  def derive_smk_from_ssh_agent(self) -> int:
    """
    Connects to the SSH agent, derives a key, and returns it in a
    secure memfd file descriptor.
    """
    agent = paramiko.Agent()
    keys = agent.get_keys()
    if not keys:
      raise RuntimeError("No keys found in the SSH agent.")

    target_key = next(
      (key for key in keys if key.comment == self.ssh_agent_key_comment),
      None,
    )

    if not target_key:
      raise RuntimeError(f"Could not find key with comment '{self.ssh_agent_key_comment}' in SSH agent.")

    self.logger.info(f"Found target key: {target_key.get_name()} ({target_key.comment})")
    self.logger.info("Requesting signature from agent to derive SMK...")

    challenge = "auto-secrets-session-challenge"
    try:
      signature = target_key.sign_ssh_data(target_key, challenge)
    except Exception as e:
      self.logger.error("Failed to get signature from agent. User may have canceled.")
      raise RuntimeError("Agent signing operation failed or was canceled.") from e

    self.logger.info("Signature received successfully.")
    session_key = bytes(signature)

    fd_name = b"session-master-key"
    fd = memfd_create(fd_name, MFD_CLOEXEC)
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
      if self.ssh_agent_key_comment:
        agent = paramiko.Agent()
        agent.get_keys()
    except Exception as e:
      self.logger.error(f"Failed to prompt SSH agent for biometric authentication: {e}")
      raise RuntimeError("SSH agent biometric prompt failed.") from e
