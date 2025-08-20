# factory.py
import os
from dataclasses import dataclass, field

from ..core.crypto_utils import CryptoUtils
from ..managers.log_manager import AutoSecretsLogger
from .base import SecretManagerBase
from .infisical import InfisicalSecretManager

SECRET_MANAGERS = {
  "infisical": InfisicalSecretManager,
  # Future secret managers can be added here:
  # "vault": VaultSecretManager,
  # "aws": AWSSecretsManagerSecretManager,
  # "azure": AzureKeyVaultSecretManager,
  # "gcp": GCPSecretManagerSecretManager,
}


class FactoryConfigError(Exception):
  """FactoryConfigError-related errors."""

  pass


@dataclass
class FactoryConfig:
  """Configuration for selecting the active secret manager."""

  secret_manager: str = field(default_factory=str)

  def __post_init__(self) -> None:
    """Initialize from environment variables after dataclass creation."""
    secret_manager = os.getenv("AUTO_SECRETS_SECRET_MANAGER")
    if not secret_manager:
      raise FactoryConfigError(f"secret_manager cannot be empty {secret_manager}")
    if secret_manager not in SECRET_MANAGERS:
      raise FactoryConfigError(f"secret_manager {secret_manager} must be one of: {SECRET_MANAGERS.keys()}")
    self.secret_manager = secret_manager


class SecretManagerFactory:
  @classmethod
  def create(cls, log_manager: AutoSecretsLogger, crypto_utils: CryptoUtils) -> "SecretManagerBase":
    """Factory method to create appropriate secret manager."""
    config = FactoryConfig()
    manager_class = SECRET_MANAGERS[config.secret_manager]
    return manager_class(log_manager, crypto_utils)
