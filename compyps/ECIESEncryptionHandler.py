import base64
import hashlib
import hmac
import json
import os
from typing import Any, Dict, Optional, Tuple

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .EncryptionHandler import EncryptionHandler

# ============================================================================
# ECIES (P-256, HKDF, AES-256-CTR, HMAC-SHA256) Encryption Handler
# ============================================================================

class ECIESEncryptionHandler(EncryptionHandler):
    """
    Classic ECIES (SEC1-style) encryption handler.

    A fresh EC (P-256) key pair is generated per message and combined with
    the recipient's static public key via ECDH. HKDF-SHA256 stretches the
    shared secret into a 32-byte AES-256 encryption key and a 32-byte
    HMAC-SHA256 MAC key; the payload is encrypted with AES-256-CTR and
    authenticated with an encrypt-then-MAC tag over the IV and ciphertext.

    Requires "ECPublicKey" (encrypt) and "ECPrivateKey" (decrypt) to be set
    via PayloadShieldEnc.init({"ECPublicKey": ..., "ECPrivateKey": ...}).
    """

    _HKDF_INFO = b"ecies-encryption"

    def encode(self, data: Any, config: Optional[Dict[str, Any]] = None) -> str:
        public_key = self._load_public_key(config)

        ephemeral_private = ec.generate_private_key(ec.SECP256R1())
        shared_key = ephemeral_private.exchange(ec.ECDH(), public_key)
        enc_key, mac_key = self._derive_keys(shared_key)

        iv = os.urandom(16)
        payload = json.dumps(data).encode("utf-8")
        encryptor = Cipher(algorithms.AES(enc_key), modes.CTR(iv)).encryptor()
        ciphertext = encryptor.update(payload) + encryptor.finalize()
        tag = hmac.new(mac_key, iv + ciphertext, hashlib.sha256).digest()

        ephemeral_public_pem = ephemeral_private.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")

        bundle = {
            "ephemeral_public_key": ephemeral_public_pem,
            "iv": base64.b64encode(iv).decode("utf-8"),
            "data": base64.b64encode(ciphertext).decode("utf-8"),
            "tag": base64.b64encode(tag).decode("utf-8"),
        }
        return base64.b64encode(json.dumps(bundle).encode("utf-8")).decode("utf-8")

    def decode(self, encoded_data: str, config: Optional[Dict[str, Any]] = None) -> Any:
        private_key = self._load_private_key(config)
        try:
            bundle = json.loads(base64.b64decode(encoded_data.encode("utf-8")))
            ephemeral_public_key = serialization.load_pem_public_key(
                bundle["ephemeral_public_key"].encode("utf-8")
            )
            iv = base64.b64decode(bundle["iv"])
            ciphertext = base64.b64decode(bundle["data"])
            tag = base64.b64decode(bundle["tag"])

            shared_key = private_key.exchange(ec.ECDH(), ephemeral_public_key)
            enc_key, mac_key = self._derive_keys(shared_key)

            expected_tag = hmac.new(mac_key, iv + ciphertext, hashlib.sha256).digest()
            if not hmac.compare_digest(tag, expected_tag):
                raise ValueError("MAC verification failed")

            decryptor = Cipher(algorithms.AES(enc_key), modes.CTR(iv)).decryptor()
            payload = decryptor.update(ciphertext) + decryptor.finalize()
            return json.loads(payload.decode("utf-8"))
        except Exception as e:
            raise ValueError(f"Failed to decode ecies data: {str(e)}")

    @classmethod
    def _derive_keys(cls, shared_key: bytes) -> Tuple[bytes, bytes]:
        derived = HKDF(
            algorithm=hashes.SHA256(),
            length=64,
            salt=None,
            info=cls._HKDF_INFO,
        ).derive(shared_key)
        return derived[:32], derived[32:]

    @staticmethod
    def _load_public_key(config: Optional[Dict[str, Any]]):
        pem = (config or {}).get("ECPublicKey")
        if not pem:
            raise ValueError(
                "ECIES encryption requires 'ECPublicKey' to be set via "
                "PayloadShieldEnc.init({'ECPublicKey': ...})"
            )
        pem_bytes = pem.encode("utf-8") if isinstance(pem, str) else pem
        return serialization.load_pem_public_key(pem_bytes)

    @staticmethod
    def _load_private_key(config: Optional[Dict[str, Any]]):
        pem = (config or {}).get("ECPrivateKey")
        if not pem:
            raise ValueError(
                "ECIES decryption requires 'ECPrivateKey' to be set via "
                "PayloadShieldEnc.init({'ECPrivateKey': ...})"
            )
        pem_bytes = pem.encode("utf-8") if isinstance(pem, str) else pem
        return serialization.load_pem_private_key(pem_bytes, password=None)
