import ctypes
import sys
import logging

logger = logging.getLogger(__name__)


class SecureBuffer:
    """A bytes buffer that is pinned in memory and zeroed on unlock.
    
    Note: Memory locking/unlocking is only available on Windows. On other platforms,
    the buffer will still be zeroed when unlocked, but won't be pinned in memory.
    """

    def __init__(self, key_bytes):
        if isinstance(key_bytes, str):
            key_bytes = key_bytes.encode('utf-8')
        self.size = len(key_bytes)
        self.buffer = ctypes.create_string_buffer(key_bytes, self.size)
        
        # Only attempt memory locking on Windows
        if sys.platform == 'win32':
            try:
                ctypes.windll.kernel32.VirtualLock(ctypes.byref(self.buffer), self.size)
            except Exception as e:
                logger.warning(f"Failed to lock memory buffer: {e}")

    def get_bytes(self):
        return self.buffer.raw

    def zero_and_unlock(self):
        # Always zero the buffer regardless of platform
        ctypes.memset(self.buffer, 0, self.size)
        
        # Only attempt memory unlocking on Windows
        if sys.platform == 'win32':
            try:
                ctypes.windll.kernel32.VirtualUnlock(ctypes.byref(self.buffer), self.size)
            except Exception as e:
                logger.warning(f"Failed to unlock memory buffer: {e}")
