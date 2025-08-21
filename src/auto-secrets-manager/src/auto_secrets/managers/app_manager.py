from typing import Optional

from ..core.crypto_utils import CryptoUtils
from ..core.key_retriever import KeyRetriever
from ..core.singleton import SingletonMeta
from ..secret_managers.base import SecretManagerBase
from ..secret_managers.factory import SecretManagerFactory
from .branch_manager import BranchManager
from .cache_manager import CacheManager
from .log_manager import AutoSecretsLogger, ComponentLoggerAdapter


class AppManager(metaclass=SingletonMeta):
  def __init__(
    self,
    log_file: Optional[str] = None,
  ) -> None:
    """
    A singleton service locator for managing and providing access to core components.

    This class ensures that components like the log manager, cache manager,
    and secret manager are initialized only once and can be accessed globally.
    It also handles the dependency injection between components.

    Args:
      log_file: Optional log file name for the session.
    """
    self._log_manager = AutoSecretsLogger(log_file=log_file)
    self._smk: Optional[bytes] = None

    # Lazy Load
    self._branch_manager: Optional[BranchManager] = None
    self._cache_manager: Optional[CacheManager] = None
    self._secret_manager: Optional[SecretManagerBase] = None
    self._key_retriever: Optional[KeyRetriever] = None
    self._crypto_utils: Optional[CryptoUtils] = None

  @property
  def secret_manager(self) -> SecretManagerBase:
    """Get fully configured SecretManager instance."""
    if self._secret_manager is None:
      self._secret_manager = SecretManagerFactory.create(self._log_manager, self.crypto_utils)
    return self._secret_manager

  @property
  def branch_manager(self) -> BranchManager:
    """Get fully configured BranchManager instance."""
    if self._branch_manager is None:
      self._branch_manager = BranchManager(self._log_manager)
    return self._branch_manager

  @property
  def cache_manager(self) -> CacheManager:
    """Get fully configured CacheManager instance."""
    if self._cache_manager is None:
      self._cache_manager = CacheManager(self._log_manager, self.crypto_utils)
    return self._cache_manager

  @property
  def key_retriever(self) -> KeyRetriever:
    """Get fully configured KeyRetriever instance."""
    if self._key_retriever is None:
      self._key_retriever = KeyRetriever(self._log_manager)
    return self._key_retriever

  @property
  def crypto_utils(self) -> CryptoUtils:
    """Get fully configured KeyRetriever instance."""
    if self._crypto_utils is None:
      self._crypto_utils = CryptoUtils(self._log_manager, self._smk)
    return self._crypto_utils

  @property
  def smk(self) -> Optional[bytes]:
    """Get the secret master key."""
    return self._smk

  @smk.setter
  def smk(self, smk: Optional[bytes]) -> None:
    if self._smk != smk:
      self._smk = smk
      self._crypto_utils = None

  def get_logger(
    self,
    name: Optional[str] = None,
    component: Optional[str] = None,
  ) -> ComponentLoggerAdapter:
    """
    Get fully configured logger instance.
    Args:
        name: Optional logger name
        component: Optional component name for logging
    Returns:
        ComponentLoggerAdapter: Configured logger instance
    """
    return self._log_manager.get_logger(
      name=name,
      component=component,
    )
