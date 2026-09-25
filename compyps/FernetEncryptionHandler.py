import base64
import json
from typing import Any, Dict, Optional
import binascii

from .EncryptionHandler import EncryptionHandler
from cryptography.fernet import Fernet

# ============================================================================
# Fernet Encryption Handler
# ============================================================================

class FernetEncryptionHandler(EncryptionHandler):
    """
    Fernet symmetric encryption handler.
    Requires "Key" to be set via PayloadShieldEnc.init({"Key": ...}).
    """

    def encode(self, data: Any, config: Optional[Dict[str, Any]] = None) -> str:
        cipher = Fernet(self._get_key(config))
        payload = json.dumps(data).encode("utf-8")
        return cipher.encrypt(payload).decode("utf-8")

    def decode(self, encoded_data: str, config: Optional[Dict[str, Any]] = None) -> Any:
        cipher = Fernet(self._get_key(config))
        try:
            payload = cipher.decrypt(encoded_data.encode("utf-8"))
            return json.loads(payload.decode("utf-8"))
        except Exception as e:
            raise ValueError(f"Failed to decode fernet data: {str(e)}")

    @staticmethod
    def _get_key(config: Optional[Dict[str, Any]]) -> bytes:
        key = (config or {}).get("Key")

        if not key:
            raise ValueError(
                "Fernet encryption requires 'Key' to be set via "
                "PayloadShieldEnc.init({'Key': ...})"
            )

        # Convert string to bytes
        if isinstance(key, str):
            key_bytes = key.encode("utf-8")
        elif isinstance(key, bytes):
            key_bytes = key
        else:
            raise ValueError("'Key' must be a string or bytes")

        # ---------------------------------------------------------
        # Case 1: Already a valid Fernet key
        # ---------------------------------------------------------
        try:
            decoded = base64.urlsafe_b64decode(key_bytes)

            if len(decoded) == 32:
                return key_bytes
        except (ValueError, binascii.Error):
            pass

        # ---------------------------------------------------------
        # Case 2: Raw 32-byte key -> convert to Fernet key
        # ---------------------------------------------------------
        if len(key_bytes) == 32:
            return base64.urlsafe_b64encode(key_bytes)

        # ---------------------------------------------------------
        # Invalid key
        # ---------------------------------------------------------
        raise ValueError(
            "Invalid Fernet key. 'Key' must be either a valid "
            "URL-safe Base64-encoded 32-byte Fernet key or exactly "
            "32 raw bytes."
        )