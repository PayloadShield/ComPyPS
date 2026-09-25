"""Framework-neutral encryption primitives for PayloadShield."""

from .config import PayloadShieldEnc
from .crypto import (
    AESGCM256EncryptionHandler,
    Base64EncryptionHandler,
    ChaChaEncryptionHandler,
    ECDHAESGCMEncryptionHandler,
    ECIESEncryptionHandler,
    EncryptionHandler,
    FernetEncryptionHandler,
    HPKEEncryptionHandler,
    HybridRSAEncryptionHandler,
    get_handler,
    register_handler,
)

__version__ = "1.0.0"

__all__ = [
    "PayloadShieldEnc",
    "EncryptionHandler",
    "Base64EncryptionHandler",
    "FernetEncryptionHandler",
    "AESGCM256EncryptionHandler",
    "HybridRSAEncryptionHandler",
    "ChaChaEncryptionHandler",
    "ECDHAESGCMEncryptionHandler",
    "ECIESEncryptionHandler",
    "HPKEEncryptionHandler",
    "register_handler",
    "get_handler",
]
