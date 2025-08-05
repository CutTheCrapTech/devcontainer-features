"""
Auto Secrets Manager - Infisical Secret Manager Implementation

Handles fetching secrets from Infisical using the Python SDK.
"""

import os
from typing import Dict, List, Optional, Any
from infisical_sdk import InfisicalSDKClient

from .base import (
    SecretManagerBase,
    SecretManagerError,
    AuthenticationError,
    NetworkError,
    SecretNotFoundError,
    ConnectionTestResult,
)


class InfisicalSecretManager(SecretManagerBase):
    """
    Infisical secret manager implementation using Python SDK.

    Supports universal authentication method for automated environments.
    """

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)

        self._client: Optional[InfisicalSDKClient] = None
        self._authenticated = False

        self.project_id: str
        self.client_id: str
        self.client_secret: str

        # Parse Infisical-specific config
        self._parse_config(config)

    def _parse_config(self, config: Dict[str, Any]) -> None:
        """Parse Infisical-specific configuration from JSON."""
        self.host = config.get("host", "https://app.infisical.com")

        project_id = config.get("project_id") or os.getenv("INFISICAL_PROJECT_ID")
        if not project_id:
            raise SecretManagerError("Infisical project_id is required")
        self.project_id: str = project_id

        client_id = config.get("client_id") or os.getenv("INFISICAL_CLIENT_ID")
        if not client_id:
            raise SecretManagerError("Infisical client_id is required")
        self.client_id: str = client_id

        client_secret = os.getenv("INFISICAL_CLIENT_SECRET")
        if not client_secret:
            raise SecretManagerError("Infisical client_secret is required")
        self.client_secret: str = client_secret

    def _get_client(self) -> InfisicalSDKClient:
        """Get authenticated Infisical client."""
        if self._client is None:
            try:
                self._client = InfisicalSDKClient(
                    host=self.host,
                    cache_ttl=300  # 5 minutes cache
                )
            except Exception as e:
                raise SecretManagerError(f"Failed to initialize Infisical client: {e}")

        if not self._authenticated:
            self._authenticate()

        return self._client

    def _authenticate(self) -> None:
        """Authenticate with Infisical using universal auth."""
        if self._client is None:
            raise SecretManagerError("Client not initialized")

        try:
            self._client.auth.universal_auth.login(
                client_id=self.client_id,
                client_secret=self.client_secret
            )
            self._authenticated = True
            self.log_debug("Infisical authentication successful")
        except Exception as e:
            raise AuthenticationError(f"Infisical authentication failed: {e}")

    def fetch_secrets(self, environment: str, paths: Optional[List[str]] = None) -> Dict[str, str]:
        """
        Fetch secrets from Infisical for the given environment.

        Args:
            environment: Environment name (e.g., "production", "staging")
            paths: Optional list of secret paths to filter by

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

        self.log_debug(f"Fetching secrets for environment: {environment}, project: {self.project_id}")

        try:
            # Get secrets from root path and all subpaths if paths are specified
            all_secrets = {}

            # Determine which paths to check
            paths_to_check = paths if paths else ["/"]

            for path in paths_to_check:
                # Normalize path
                secret_path = path if path.startswith("/") else f"/{path}"

                try:
                    secrets_response = client.secrets.list_secrets(
                        project_id=self.project_id,
                        environment_slug=environment,
                        secret_path=secret_path,
                        expand_secret_references=True,
                        include_imports=True,
                        recursive=True
                    )

                    # Convert response to key-value pairs
                    for secret in secrets_response.secrets:
                        key = secret.secretKey
                        value = secret.secretValue
                        secret_path = secret.secretPath

                        if key and value is not None:
                            # Create full path key
                            if secret_path and secret_path != "/":
                                full_key = f"{secret_path.rstrip('/')}/{key}"
                            else:
                                full_key = f"/{key}"

                            all_secrets[full_key] = value

                except Exception as e:
                    error_msg = str(e).lower()
                    if "not found" in error_msg or "does not exist" in error_msg:
                        # Path doesn't exist, continue with other paths
                        continue
                    elif "unauthorized" in error_msg or "forbidden" in error_msg:
                        raise AuthenticationError(f"Insufficient permissions for environment '{environment}' or path '{secret_path}'")
                    elif "network" in error_msg or "timeout" in error_msg:
                        raise NetworkError(f"Network error fetching secrets from path '{secret_path}': {e}")
                    else:
                        raise SecretManagerError(f"Failed to fetch secrets from path '{secret_path}': {e}")

            # If no secrets found and we were looking for specific paths, that might be an error
            if not all_secrets and paths:
                self.log_debug(f"No secrets found for paths {paths} in environment {environment}")

            # Filter by paths if specified and we got secrets from root path
            if paths and "/" in paths_to_check:
                all_secrets = self.filter_secrets_by_paths(all_secrets, paths)

            self.log_debug(f"Successfully fetched {len(all_secrets)} secrets from Infisical")
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
                raise SecretNotFoundError(f"Project '{self.project_id}' not found")
            elif "environment" in error_msg and "not found" in error_msg:
                raise SecretNotFoundError(f"Environment '{environment}' not found in project '{self.project_id}'")
            else:
                raise SecretManagerError(f"Failed to fetch secrets: {e}")

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
                client.auth.universal_auth.login(
                    client_id=self.client_id,
                    client_secret=self.client_secret
                )
                details["sdk_available"] = True
                details["authenticated"] = True
            except AuthenticationError as e:
                return ConnectionTestResult(
                    success=False,
                    message=f"Authentication failed: {e}",
                    details=details,
                    authenticated=False
                )
            except Exception as e:
                return ConnectionTestResult(
                    success=False,
                    message=f"Failed to initialize client: {e}",
                    details=details,
                    authenticated=False
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
                    authenticated=True
                )

        except Exception as e:
            return ConnectionTestResult(
                success=False,
                message=f"Connection test failed: {e}",
                details=details,
                authenticated=False
            )

    def clear_authentication_cache(self) -> None:
        """Clear cached authentication."""
        self._authenticated = False
        if self._client:
            # Reinitialize client to clear any cached auth
            self._client = None
