import base64
import json
import os
from typing import Any, Dict, Optional

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .EncryptionHandler import EncryptionHandler

# ============================================================================
# ECDH (P-256) + AES-256-GCM Encryption Handler
# ============================================================================

class ECDHAESGCMEncryptionHandler(EncryptionHandler):
    """
    Ephemeral-static ECDH (NIST P-256) key agreement + AES-256-GCM handler.

    A fresh EC key pair is generated per message; its private key is
    combined with the recipient's static public key (ECDH) and the shared
    secret is stretched via HKDF-SHA256 into an AES-256 key. Decryption
    reverses the process using the static private key and the ephemeral
    public key shipped alongside the ciphertext.

    Requires "ECPublicKey" (encrypt) and "ECPrivateKey" (decrypt) to be set
    via PayloadShieldEnc.init({"ECPublicKey": ..., "ECPrivateKey": ...}).
    """

    _HKDF_INFO = b"ecdh-aes-gcm"

    def encode(self, data: Any, config: Optional[Dict[str, Any]] = None) -> str:
        public_key = self._load_public_key(config)

        ephemeral_private = ec.generate_private_key(ec.SECP256R1())
        shared_key = ephemeral_private.exchange(ec.ECDH(), public_key)
        aes_key = self._derive_key(shared_key)

        nonce = os.urandom(12)
        payload = json.dumps(data).encode("utf-8")
        ciphertext = AESGCM(aes_key).encrypt(nonce, payload, None)

        ephemeral_public_pem = ephemeral_private.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")

        bundle = {
            "ephemeral_public_key": ephemeral_public_pem,
            "nonce": base64.b64encode(nonce).decode("utf-8"),
            "data": base64.b64encode(ciphertext).decode("utf-8"),
        }
        return base64.b64encode(json.dumps(bundle).encode("utf-8")).decode("utf-8")

    def decode(self, encoded_data: str, config: Optional[Dict[str, Any]] = None) -> Any:
        private_key = self._load_private_key(config)
        try:
            bundle = json.loads(base64.b64decode(encoded_data.encode("utf-8")))
            ephemeral_public_key = serialization.load_pem_public_key(
                bundle["ephemeral_public_key"].encode("utf-8")
            )
            nonce = base64.b64decode(bundle["nonce"])
            ciphertext = base64.b64decode(bundle["data"])

            shared_key = private_key.exchange(ec.ECDH(), ephemeral_public_key)
            aes_key = self._derive_key(shared_key)

            payload = AESGCM(aes_key).decrypt(nonce, ciphertext, None)
            return json.loads(payload.decode("utf-8"))
        except Exception as e:
            raise ValueError(f"Failed to decode ecdh-aes-gcm data: {str(e)}")

    @classmethod
    def _derive_key(cls, shared_key: bytes) -> bytes:
        return HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=cls._HKDF_INFO,
        ).derive(shared_key)

    @staticmethod
    def _load_public_key(config: Optional[Dict[str, Any]]):
        pem = (config or {}).get("ECPublicKey")
        if not pem:
            raise ValueError(
                "ECDH-AES-GCM encryption requires 'ECPublicKey' to be set via "
                "PayloadShieldEnc.init({'ECPublicKey': ...})"
            )
        pem_bytes = pem.encode("utf-8") if isinstance(pem, str) else pem
        return serialization.load_pem_public_key(pem_bytes)

    @staticmethod
    def _load_private_key(config: Optional[Dict[str, Any]]):
        pem = (config or {}).get("ECPrivateKey")
        if not pem:
            raise ValueError(
                "ECDH-AES-GCM decryption requires 'ECPrivateKey' to be set via "
                "PayloadShieldEnc.init({'ECPrivateKey': ...})"
            )
        pem_bytes = pem.encode("utf-8") if isinstance(pem, str) else pem
        return serialization.load_pem_private_key(pem_bytes, password=None)
