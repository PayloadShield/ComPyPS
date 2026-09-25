import base64
import json
from typing import Any, Dict, Optional
from .EncryptionHandler import EncryptionHandler

# ============================================================================
# Base64 Encryption Handler
# ============================================================================

class Base64EncryptionHandler(EncryptionHandler):
    """
    Base64 encoding/decoding handler.
    Note: Base64 is encoding, not encryption. Use for obfuscation only.
    No key configuration is required.
    """

    def encode(self, data: Any, config: Optional[Dict[str, Any]] = None) -> str:
        """Encode data to base64 string."""
        if isinstance(data, dict):
            json_str = json.dumps(data)
        else:
            json_str = str(data)

        return base64.b64encode(json_str.encode('utf-8')).decode('utf-8')

    def decode(self, encoded_data: str, config: Optional[Dict[str, Any]] = None) -> Any:
        """Decode base64 string to data."""
        try:
            decoded_bytes = base64.b64decode(encoded_data.encode('utf-8'))
            decoded_str = decoded_bytes.decode('utf-8')
            return json.loads(decoded_str)
        except Exception as e:
            raise ValueError(f"Failed to decode base64 data: {str(e)}")