import threading
from typing import Any


class SingletonMeta(type):
  """
  A thread-safe Singleton metaclass.
  """

  _instances: dict[type, Any] = {}
  _lock = threading.Lock()

  def __call__(cls, *args, **kwargs):
    # The __call__ method is invoked when you "call" the class, e.g., Logger().
    # We use a lock to ensure that only one thread can create the instance.
    with cls._lock:
      if cls not in cls._instances:
        # If no instance exists, create one by calling the parent's __call__.
        instance = super().__call__(*args, **kwargs)
        cls._instances[cls] = instance
    return cls._instances[cls]
