"""
Process lifecycle management utilities.
"""

import ctypes
import signal
import sys

from ..managers.log_manager import ComponentLoggerAdapter

# From <linux/prctl.h>
PR_SET_PDEATHSIG = 1


class ProcessUtils:
  """Provides static utility methods for process management."""

  @staticmethod
  def set_parent_death_signal(logger: ComponentLoggerAdapter) -> None:
    """
    On Linux, ask the kernel to send this process SIGTERM if the parent
    process dies unexpectedly.

    This is the key to ensuring child processes do not become orphaned
    if the supervisor crashes.

    Args:
        logger: The logger instance to use for reporting status.
    """
    if sys.platform == "linux":
      # Step 1: Get a handle to the C library already loaded by Python.
      try:
        libc = ctypes.CDLL(None)
      except OSError as e:
        logger.warning(f"Could not get handle to C library: {e}. Parent death signal not set.")
        return

      # Step 2: Find the 'prctl' function in the library.
      try:
        prctl = libc.prctl
      except AttributeError:
        logger.warning("'prctl' function not found in C library. Parent death signal not set.")
        return

      # Step 3: Set argument and return types for type safety.
      prctl.argtypes = [ctypes.c_int, ctypes.c_int]
      prctl.restype = ctypes.c_int

      # Step 4: Call the function.
      try:
        result = prctl(PR_SET_PDEATHSIG, signal.SIGTERM)
        if result != 0:
          logger.warning("prctl(PR_SET_PDEATHSIG) failed with non-zero result: %d", result)
        else:
          logger.info("Successfully set parent death signal (SIGTERM).")
      except Exception as e:
        logger.error(f"An unexpected error occurred when calling prctl: {e}")
    else:
      logger.debug("Skipping parent death signal setup (not on Linux).")
