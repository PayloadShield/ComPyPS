"""
Crypto utilities with pluggable encryption handlers.
Supports multiple encryption types: base64, fernet, aes-gcm-256,
chacha20-poly1305, rsa-hybrid, ecdh-aes-gcm, ecies, hpke.
"""

from .EncryptionHandler import EncryptionHandler
from .Base64EncryptionHandler import Base64EncryptionHandler
from .FernetEncryptionHandler import FernetEncryptionHandler
from .AESGCM256EncryptionHandler import AESGCM256EncryptionHandler
from .HybridRSAEncryptionHandler import HybridRSAEncryptionHandler
from .ChaChaEncryptionHandler import ChaChaEncryptionHandler
from .ECDHAESGCMEncryptionHandler import ECDHAESGCMEncryptionHandler
from .ECIESEncryptionHandler import ECIESEncryptionHandler
from .HPKEEncryptionHandler import HPKEEncryptionHandler

# ============================================================================
# Handler Registry & Factory
# ============================================================================

_HANDLERS = {
    "base64": Base64EncryptionHandler(),
    "fernet": FernetEncryptionHandler(),
    "aes-gcm-256": AESGCM256EncryptionHandler(),
    "rsa-hybrid": HybridRSAEncryptionHandler(),
    "chacha20-poly1305": ChaChaEncryptionHandler(),
    "ecdh-aes-gcm": ECDHAESGCMEncryptionHandler(),
    "ecies": ECIESEncryptionHandler(),
    "hpke": HPKEEncryptionHandler(),
}


def register_handler(name: str, handler: EncryptionHandler) -> None:
    """
    Register a new encryption handler.

    Args:
        name: Name of the handler (e.g., "base64", "fernet", "aes-gcm-256")
        handler: EncryptionHandler instance to register
    """
    _HANDLERS[name.lower()] = handler


def get_handler(name: str) -> EncryptionHandler:
    """
    Get a registered encryption handler by name.

    Args:
        name: Name of the handler (e.g., "base64", "fernet", "aes-gcm-256")

    Returns:
        EncryptionHandler instance

    Raises:
        ValueError: If handler not found
    """
    handler_name = name.lower()
    if handler_name not in _HANDLERS:
        available = ", ".join(_HANDLERS.keys())
        raise ValueError(
            f"Encryption handler '{name}' not found. "
            f"Available handlers: {available}"
        )
    return _HANDLERS[handler_name]
