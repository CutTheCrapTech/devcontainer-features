"""
Auto Secrets Manager - Infisical Secret Manager Implementation

Handles fetching secrets from Infisical using the Python SDK.
"""

import getpass
import os
from dataclasses import dataclass, field
from typing import Optional

from infisical_sdk import InfisicalSDKClient  # type: ignore

from ..core.common_utils import CommonUtils
from ..core.crypto_utils import CryptoUtils
from ..managers.log_manager import AutoSecretsLogger
from .base import (
  AuthenticationError,
  ConnectionTestResult,
  NetworkError,
  SecretManagerBase,
  SecretManagerError,
  SecretNotFoundError,
)


class InifisicalConfigError(Exception):
  """InifisicalConfig-related errors."""

  pass


@dataclass
class InifisicalConfig:
  """Infisical configuration settings."""

  host: str = field(default_factory=str)
  project_id: str = field(default_factory=str)
  client_id: str = field(default_factory=str)

  def __post_init__(self) -> None:
    """Initialize from environment variables after dataclass creation."""
    config = os.getenv("AUTO_SECRETS_SECRET_MANAGER_CONFIG", "{}")
    config_dict = CommonUtils.parse_json("AUTO_SECRETS_SECRET_MANAGER_CONFIG", config)

    if "host" not in config_dict or not config_dict.get("host") or not isinstance(config_dict.get("host"), str):
      raise InifisicalConfigError(f"Missing 'host' or invalid value in AUTO_SECRETS_CACHE_CONFIG - {config_dict}")
    if (
      "project_id" not in config_dict
      or not config_dict.get("project_id")
      or not isinstance(config_dict.get("project_id"), str)
    ):
      raise InifisicalConfigError(f"Missing 'project_id' or invalid value in AUTO_SECRETS_CACHE_CONFIG - {config_dict}")
    if (
      "client_id" not in config_dict
      or not config_dict.get("client_id")
      or not isinstance(config_dict.get("client_id"), str)
    ):
      raise InifisicalConfigError(f"Missing 'client_id' or invalid value in AUTO_SECRETS_CACHE_CONFIG - {config_dict}")

    self.host = config_dict.get("host")
    self.project_id = config_dict.get("project_id")
    self.client_id = config_dict.get("client_id")


class InfisicalSecretManager(SecretManagerBase):
  """
  Infisical secret manager implementation using Python SDK.

  Supports universal authentication method for automated environments.
  """

  def __init__(self, log_manager: AutoSecretsLogger, crypto_utils: CryptoUtils) -> None:
    super().__init__(log_manager, crypto_utils)
    self.logger = log_manager.get_logger(name="secret_managers", component="infisical")
    self.crypto_utils = crypto_utils

    secret_manager_config = InifisicalConfig()

    self._client: Optional[InfisicalSDKClient] = None
    self._authenticated = False

    self.host = secret_manager_config.host
    self.project_id = secret_manager_config.project_id
    self.client_id = secret_manager_config.client_id
    self.client_secret = self.get_secret_value("INFISICAL_CLIENT_SECRET", required=True)

  def _get_secret_json(self) -> dict[str, str]:
    """
    Prompts the user for the Infisical Client Secret and returns it
    as a JSON string.

    This implementation uses getpass to ensure the secret is not echoed
    to the terminal, and it handles empty input or user cancellation.

    Returns:
        str: A dictionary in the format:
             '{"INFISICAL_CLIENT_SECRET": "<secret_value>"}'

    Raises:
        SecretManagerError: If no input is provided or the user cancels.
    """
    try:
      # Use getpass for securely prompting for the secret without screen echo.
      client_secret = getpass.getpass("Enter your Infisical Client Secret: ")

      # Validate that the user actually entered something.
      if not client_secret:
        raise SecretManagerError("Infisical Client Secret cannot be empty.")

      # Construct the dictionary with the required key.
      secret_data = {"INFISICAL_CLIENT_SECRET": client_secret}

      # Serialize the dictionary to a JSON string and return it.
      return secret_data

    except (EOFError, KeyboardInterrupt):
      # Handle cases where the user aborts the input (e.g., Ctrl+D, Ctrl+C).
      # We print a newline to ensure the next shell prompt is on a clean line.
      print()
      raise SecretManagerError("User cancelled secret input.") from None

  def _get_client(self) -> InfisicalSDKClient:
    """Get authenticated Infisical client."""
    if self._client is None:
      try:
        self._client = InfisicalSDKClient(
          host=self.host,
          cache_ttl=300,  # 5 minutes cache
        )
      except Exception as e:
        raise SecretManagerError(f"Failed to initialize Infisical client: {e}") from None

    if not self._authenticated:
      self._authenticate()

    return self._client

  def _authenticate(self) -> None:
    """Authenticate with Infisical using universal auth."""
    if self._client is None:
      raise SecretManagerError("Client not initialized")

    try:
      self._client.auth.universal_auth.login(client_id=self.client_id, client_secret=self.client_secret)
      self._authenticated = True
      self.logger.debug("Infisical authentication successful")
    except Exception as e:
      raise AuthenticationError(f"Infisical authentication failed: {e}") from None

  def fetch_secrets(self, environment: str) -> dict[str, str]:
    """
    Fetch secrets from Infisical for the given environment.

    Args:
        environment: Environment name (e.g., "production", "staging")

    Returns:
        dict: Dictionary of secret key-value pairs

    Raises:
        AuthenticationError: If authentication fails
        NetworkError: If network connection fails
        SecretNotFoundError: If environment not found
        SecretManagerError: For other errors
    """
    if not self.validate_environment(environment):
      raise SecretManagerError(f"Invalid environment name: {environment}")

    client = self._get_client()

    self.logger.debug(f"Fetching secrets for environment: {environment}, project: {self.project_id}")

    try:
      # Get secrets from root path and all subpaths if paths are specified
      all_secrets = {}

      for path in self.all_paths:
        # Normalize path
        secret_path = path if path.startswith("/") else f"/{path}"

        try:
          secrets_response = client.secrets.list_secrets(
            project_id=self.project_id,
            environment_slug=environment,
            secret_path=secret_path,
            expand_secret_references=True,
            include_imports=True,
            recursive=True,
          )

          # Convert response to key-value pairs
          for secret in secrets_response.secrets:
            key = secret.secretKey
            value = secret.secretValue
            secret_path = secret.secretPath

            if key and value is not None:
              # Create full path key
              full_key = f"{secret_path.rstrip('/')}/{key}" if secret_path and secret_path != "/" else f"/{key}"

              all_secrets[full_key] = value

        except Exception as e:
          error_msg = str(e).lower()
          if "unauthorized" in error_msg or "forbidden" in error_msg:
            raise AuthenticationError(
              f"Insufficient permissions for environment '{environment}' or path '{secret_path}'"
            ) from None
          elif "network" in error_msg or "timeout" in error_msg:
            raise NetworkError(f"Network error fetching secrets from path '{secret_path}': {e}") from None
          else:
            raise SecretManagerError(f"Failed to fetch secrets from path '{secret_path}': {e}") from None

      # If no secrets found and we were looking for specific paths, that might be an error
      if not all_secrets and self.all_paths:
        self.logger.debug(f"No secrets found for paths {self.all_paths} in environment {environment}")

      self.logger.debug(f"Successfully fetched {len(all_secrets)} secrets from Infisical")
      return all_secrets

    except AuthenticationError:
      # Re-raise authentication errors
      raise
    except NetworkError:
      # Re-raise network errors
      raise
    except Exception as e:
      error_msg = str(e).lower()
      if "project" in error_msg and "not found" in error_msg:
        raise SecretNotFoundError(f"Project '{self.project_id}' not found") from None
      elif "environment" in error_msg and "not found" in error_msg:
        raise SecretNotFoundError(f"Environment '{environment}' not found in project '{self.project_id}'") from None
      else:
        raise SecretManagerError(
          f"Failed to fetch secrets for project '{self.project_id}' and environment '{environment}': {e}"
        ) from None

  def test_connection(self) -> ConnectionTestResult:
    """
    Test connection to Infisical and check authentication.

    Returns:
        ConnectionTestResult: Result of the connection test
    """
    details = {
      "sdk_available": False,
      "authenticated": False,
      "project_access": False,
      "host": self.host,
      "project_id": self.project_id,
    }

    try:
      # Test SDK availability and client initialization
      try:
        client = self._get_client()
        # Test authentication by attempting to authenticate
        client.auth.universal_auth.login(client_id=self.client_id, client_secret=self.client_secret)
        details["sdk_available"] = True
        details["authenticated"] = True
      except AuthenticationError as e:
        return ConnectionTestResult(
          success=False,
          message=f"Authentication failed: {e}",
          details=details,
          authenticated=False,
        )
      except Exception as e:
        return ConnectionTestResult(
          success=False,
          message=f"Failed to initialize client: {e}",
          details=details,
          authenticated=False,
        )

      # Test project access by trying to get environments
      try:
        details["project_access"] = True

        return ConnectionTestResult(
          success=True,
          message="Connection test successful",
          details=details,
          authenticated=True,
        )

      except Exception as e:
        return ConnectionTestResult(
          success=False,
          message=f"Project access test failed: {e}",
          details=details,
          authenticated=True,
        )

    except Exception as e:
      return ConnectionTestResult(
        success=False,
        message=f"Connection test failed: {e}",
        details=details,
        authenticated=False,
      )

  def clear_authentication_cache(self) -> None:
    """Clear cached authentication."""
    self._authenticated = False
    self._client = None
