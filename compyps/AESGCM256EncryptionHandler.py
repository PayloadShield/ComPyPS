import base64
import json
from typing import Any, Dict, Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .EncryptionHandler import EncryptionHandler

# ============================================================================
# AES-GCM-256 Encryption Handler
# ============================================================================

class AESGCM256EncryptionHandler(EncryptionHandler):
    """
    AES-GCM-256 symmetric encryption handler.
    Requires "Key" to be set via PayloadShieldEnc.init({"Key": ...}).
    The key must resolve to exactly 32 bytes (raw UTF-8 or base64 encoded).
    """

    def encode(self, data: Any, config: Optional[Dict[str, Any]] = None) -> str:
        key = self._get_key(config)
        nonce = self._random_bytes(12)
        aesgcm = AESGCM(key)
        payload = json.dumps(data).encode("utf-8")
        ciphertext = aesgcm.encrypt(nonce, payload, None)
        return base64.b64encode(nonce + ciphertext).decode("utf-8")

    def decode(self, encoded_data: str, config: Optional[Dict[str, Any]] = None) -> Any:
        key = self._get_key(config)
        try:
            raw = base64.b64decode(encoded_data.encode("utf-8"))
            nonce, ciphertext = raw[:12], raw[12:]
            aesgcm = AESGCM(key)
            payload = aesgcm.decrypt(nonce, ciphertext, None)
            return json.loads(payload.decode("utf-8"))
        except Exception as e:
            raise ValueError(f"Failed to decode aes-gcm-256 data: {str(e)}")

    @staticmethod
    def _random_bytes(length: int) -> bytes:
        import os
        return os.urandom(length)

    @staticmethod
    def _get_key(config: Optional[Dict[str, Any]]) -> bytes:
        key = (config or {}).get("Key")
        if not key:
            raise ValueError(
                "AES-GCM-256 encryption requires 'Key' to be set via "
                "PayloadShieldEnc.init({'Key': ...})"
            )

        key_bytes = key.encode("utf-8") if isinstance(key, str) else key
        if len(key_bytes) == 32:
            return key_bytes

        try:
            decoded = base64.b64decode(key_bytes)
        except Exception:
            decoded = b""

        if len(decoded) == 32:
            return decoded

        raise ValueError("AES-256 key must resolve to exactly 32 bytes")