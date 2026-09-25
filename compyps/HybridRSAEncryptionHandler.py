import base64
import json
from typing import Any, Dict, Optional

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .EncryptionHandler import EncryptionHandler

# ============================================================================
# Hybrid AES-256-GCM + RSA-OAEP Encryption Handler
# ============================================================================

class HybridRSAEncryptionHandler(EncryptionHandler):
    """
    Hybrid RSA+AES encryption handler.

    A random AES-256 key encrypts the payload (AES-GCM); the AES key itself
    is encrypted with the RSA public key (RSA-OAEP/SHA-256). Decryption
    reverses the process using the RSA private key.

    Requires "PublicKey" (encode) and "PrivateKey" (decode) to be set via
    PayloadShieldEnc.init({"PublicKey": ..., "PrivateKey": ...}).
    """

    def encode(self, data: Any, config: Optional[Dict[str, Any]] = None) -> str:
        public_key = self._load_public_key(config)

        import os
        aes_key = os.urandom(32)
        nonce = os.urandom(12)
        payload = json.dumps(data).encode("utf-8")
        ciphertext = AESGCM(aes_key).encrypt(nonce, payload, None)

        encrypted_key = public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

        bundle = {
            "key": base64.b64encode(encrypted_key).decode("utf-8"),
            "nonce": base64.b64encode(nonce).decode("utf-8"),
            "data": base64.b64encode(ciphertext).decode("utf-8"),
        }
        return base64.b64encode(json.dumps(bundle).encode("utf-8")).decode("utf-8")

    def decode(self, encoded_data: str, config: Optional[Dict[str, Any]] = None) -> Any:
        private_key = self._load_private_key(config)
        try:
            bundle = json.loads(base64.b64decode(encoded_data.encode("utf-8")))
            encrypted_key = base64.b64decode(bundle["key"])
            nonce = base64.b64decode(bundle["nonce"])
            ciphertext = base64.b64decode(bundle["data"])

            aes_key = private_key.decrypt(
                encrypted_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
            payload = AESGCM(aes_key).decrypt(nonce, ciphertext, None)
            return json.loads(payload.decode("utf-8"))
        except Exception as e:
            raise ValueError(f"Failed to decode rsa-hybrid data: {str(e)}")

    @staticmethod
    def _load_public_key(config: Optional[Dict[str, Any]]):
        pem = (config or {}).get("PublicKey")
        if not pem:
            raise ValueError(
                "Hybrid RSA encryption requires 'PublicKey' to be set via "
                "PayloadShieldEnc.init({'PublicKey': ...})"
            )
        pem_bytes = pem.encode("utf-8") if isinstance(pem, str) else pem
        return serialization.load_pem_public_key(pem_bytes)

    @staticmethod
    def _load_private_key(config: Optional[Dict[str, Any]]):
        pem = (config or {}).get("PrivateKey")
        if not pem:
            raise ValueError(
                "Hybrid RSA decryption requires 'PrivateKey' to be set via "
                "PayloadShieldEnc.init({'PrivateKey': ...})"
            )
        pem_bytes = pem.encode("utf-8") if isinstance(pem, str) else pem
        return serialization.load_pem_private_key(pem_bytes, password=None)
