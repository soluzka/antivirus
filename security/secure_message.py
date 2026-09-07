"""
Secure messaging module for encrypting log messages and sensitive information.
Uses Fernet symmetric encryption with the FERNET_KEY environment variable.
"""
import os
import sys
import logging
from cryptography.fernet import Fernet
from security.secure_memory import SecureBuffer

logger = logging.getLogger(__name__)

# Get FERNET_KEY from environment, with fallback to config module
# We use a lazy import pattern to avoid circular dependency issues
FERNET_KEY = os.environ.get('FERNET_KEY')
if not FERNET_KEY:
    try:
        # Lazy import to avoid circular dependency
        import config
        FERNET_KEY = getattr(config, 'FERNET_KEY', None)
    except (ImportError, AttributeError, EnvironmentError):
        # If config module fails or doesn't have FERNET_KEY, we'll handle it in _get_fernet()
        pass

_fernet = None


def _get_fernet():
    global _fernet
    if _fernet is not None:
        return _fernet
    if not FERNET_KEY or len(FERNET_KEY) != 44:
        print("[ERROR] FERNET_KEY must be a 44-character base64 string.", file=sys.stderr)
        return None
    raw = FERNET_KEY.encode() if isinstance(FERNET_KEY, str) else FERNET_KEY
    secure_key = SecureBuffer(raw)
    _fernet = Fernet(secure_key.get_bytes())
    secure_key.zero_and_unlock()
    return _fernet


def encrypt_message(message: str) -> str:
    """Encrypt a message string using Fernet."""
    try:
        fernet = _get_fernet()
        if fernet is None:
            return str(message)
        if not isinstance(message, str):
            message = str(message)
        return fernet.encrypt(message.encode()).decode()
    except Exception as e:
        logger.error(f"Encryption failed: {e}")
        return f"{message} [encryption failed]"


def decrypt_message(token: str) -> str:
    """Decrypt a Fernet token."""
    try:
        fernet = _get_fernet()
        if fernet is None:
            return token
        return fernet.decrypt(token.encode()).decode()
    except Exception as e:
        logger.error(f"Decryption failed: {e}")
        return token
