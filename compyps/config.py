"""
Global encryption configuration for PayloadShield.
"""

import os
from pathlib import Path
from typing import Any, Dict, Optional


class PayloadShieldEnc:
    """
    Holds the global key configuration used by PayloadShield's encryption
    handlers. Call ``PayloadShieldEnc.init(...)`` once at application
    startup before using any ``@PayloadShield`` decorator.
    """

    _config: Dict[str, Optional[str]] = {
        "Key": None,
        "PrivateKey": None,
        "PublicKey": None,
        "ECPrivateKey": None,
        "ECPublicKey": None,
        "HPKEPrivateKey": None,
        "HPKEPublicKey": None,
    }

    @classmethod
    def init(cls, config: Dict[str, Any]) -> None:
        """
        Initialize the global encryption configuration.

        Args:
            config: Dictionary with any of the following keys:
                - "Key": symmetric key used by handlers such as
                  "fernet", "aes-gcm-256" and "chacha20-poly1305".
                - "PrivateKey": RSA/hybrid private key. Accepts either a
                  file path or the raw PEM key content.
                - "PublicKey": RSA/hybrid public key. Accepts either a
                  file path or the raw PEM key content.
                - "ECPrivateKey"/"ECPublicKey": EC (P-256) PEM keys used by
                  "ecdh-aes-gcm" and "ecies". Accepts a file path or raw
                  PEM key content.
                - "HPKEPrivateKey"/"HPKEPublicKey": X25519 PEM keys used by
                  "hpke". Accepts a file path or raw PEM key content.
        """
        cls._config["Key"] = config.get("Key")
        cls._config["PrivateKey"] = cls._resolve_key_material(config.get("PrivateKey"))
        cls._config["PublicKey"] = cls._resolve_key_material(config.get("PublicKey"))
        cls._config["ECPrivateKey"] = cls._resolve_key_material(config.get("ECPrivateKey"))
        cls._config["ECPublicKey"] = cls._resolve_key_material(config.get("ECPublicKey"))
        cls._config["HPKEPrivateKey"] = cls._resolve_key_material(config.get("HPKEPrivateKey"))
        cls._config["HPKEPublicKey"] = cls._resolve_key_material(config.get("HPKEPublicKey"))

    @classmethod
    def get_config(cls) -> Dict[str, Optional[str]]:
        """Return a copy of the current global key configuration."""
        return dict(cls._config)

    @staticmethod
    def _resolve_key_material(value: Optional[str]) -> Optional[str]:
        """Resolve a key value that may be a file path or raw key content."""
        if not value:
            return None
        if os.path.isfile(value):
            return Path(value).read_text(encoding="utf-8")
        return value
