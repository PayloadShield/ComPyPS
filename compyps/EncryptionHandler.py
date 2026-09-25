from abc import ABC, abstractmethod
from typing import Any, Dict, Optional

# ============================================================================
# Abstract Encryption Handler Interface
# ============================================================================

class EncryptionHandler(ABC):
    """
    Abstract base class for encryption handlers.
    Implement this to add support for new encryption types.

    Every handler receives the global key configuration produced by
    ``PayloadShieldEnc.init({...})`` (a dict with "Key", "PrivateKey" and
    "PublicKey") and is responsible for pulling out whatever it needs.
    """

    @abstractmethod
    def encode(self, data: Any, config: Optional[Dict[str, Any]] = None) -> str:
        """
        Encode/encrypt data to a string.

        Args:
            data: Dictionary or JSON serializable object
            config: Global key configuration from PayloadShieldEnc.init()

        Returns:
            Encoded/encrypted string
        """
        pass

    @abstractmethod
    def decode(self, encoded_data: str, config: Optional[Dict[str, Any]] = None) -> Any:
        """
        Decode/decrypt a string back to data.

        Args:
            encoded_data: Encoded/encrypted string
            config: Global key configuration from PayloadShieldEnc.init()

        Returns:
            Decoded dictionary or object

        Raises:
            ValueError: If data cannot be decoded
        """
        pass