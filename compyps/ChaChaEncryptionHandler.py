import base64
import json
import os
from typing import Any, Dict, Optional

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from .EncryptionHandler import EncryptionHandler

# ============================================================================
# ChaCha20-Poly1305 Encryption Handler
# ============================================================================

class ChaChaEncryptionHandler(EncryptionHandler):
    """
    ChaCha20-Poly1305 symmetric encryption handler.
    Requires "Key" to be set via PayloadShieldEnc.init({"Key": ...}).
    The key must resolve to exactly 32 bytes (raw UTF-8 or base64 encoded).
    """

    NONCE_SIZE = 12
    KEY_SIZE = 32

    def encode(self, data: Any, config: Optional[Dict[str, Any]] = None) -> str:
        key = self._get_key(config)
        nonce = os.urandom(self.NONCE_SIZE)
        cipher = ChaCha20Poly1305(key)
        payload = json.dumps(data).encode("utf-8")
        ciphertext = cipher.encrypt(nonce, payload, None)
        return base64.b64encode(nonce + ciphertext).decode("utf-8")

    def decode(self, encoded_data: str, config: Optional[Dict[str, Any]] = None) -> Any:
        key = self._get_key(config)
        try:
            raw = base64.b64decode(encoded_data.encode("utf-8"))
            nonce, ciphertext = raw[:self.NONCE_SIZE], raw[self.NONCE_SIZE:]
            cipher = ChaCha20Poly1305(key)
            payload = cipher.decrypt(nonce, ciphertext, None)
            return json.loads(payload.decode("utf-8"))
        except Exception as e:
            raise ValueError(f"Failed to decode chacha20-poly1305 data: {str(e)}")

    @staticmethod
    def _get_key(config: Optional[Dict[str, Any]]) -> bytes:
        key = (config or {}).get("Key")
        if not key:
            raise ValueError(
                "ChaCha20-Poly1305 encryption requires 'Key' to be set via "
                "PayloadShieldEnc.init({'Key': ...})"
            )

        key_bytes = key.encode("utf-8") if isinstance(key, str) else key
        if len(key_bytes) == ChaChaEncryptionHandler.KEY_SIZE:
            return key_bytes

        try:
            decoded = base64.b64decode(key_bytes)
        except Exception:
            decoded = b""

        if len(decoded) == ChaChaEncryptionHandler.KEY_SIZE:
            return decoded

        raise ValueError("ChaCha20-Poly1305 key must resolve to exactly 32 bytes")