import base64
import hashlib
import hmac
import json
from typing import Any, Dict, Optional, Tuple

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from .EncryptionHandler import EncryptionHandler

# ============================================================================
# HPKE (RFC 9180) Base Mode Encryption Handler
# ============================================================================
# Ciphersuite: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20Poly1305
# (KEM id 0x0020, KDF id 0x0001, AEAD id 0x0003) - single-shot seal/open.

_KEM_ID = 0x0020
_KDF_ID = 0x0001
_AEAD_ID = 0x0003
_NSECRET = 32
_NK = 32
_NN = 12


def _i2osp(value: int, length: int) -> bytes:
    return value.to_bytes(length, "big")


_KEM_SUITE_ID = b"KEM" + _i2osp(_KEM_ID, 2)
_HPKE_SUITE_ID = b"HPKE" + _i2osp(_KEM_ID, 2) + _i2osp(_KDF_ID, 2) + _i2osp(_AEAD_ID, 2)


def _hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def _hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    okm, t, counter = b"", b"", 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        okm += t
        counter += 1
    return okm[:length]


def _labeled_extract(salt: bytes, label: bytes, ikm: bytes, suite_id: bytes) -> bytes:
    return _hkdf_extract(salt, b"HPKE-v1" + suite_id + label + ikm)


def _labeled_expand(prk: bytes, label: bytes, info: bytes, length: int, suite_id: bytes) -> bytes:
    labeled_info = _i2osp(length, 2) + b"HPKE-v1" + suite_id + label + info
    return _hkdf_expand(prk, labeled_info, length)


class HPKEEncryptionHandler(EncryptionHandler):
    """
    RFC 9180 Hybrid Public Key Encryption, base mode, single-shot semantics:
    DHKEM(X25519, HKDF-SHA256) + HKDF-SHA256 + ChaCha20-Poly1305.

    A fresh X25519 encapsulation key pair is generated per message and
    combined with the recipient's static public key (DHKEM) to derive a
    shared secret, which is run through the HPKE key schedule to produce a
    ChaCha20-Poly1305 key/nonce used for a single AEAD seal/open.

    Requires "HPKEPublicKey" (encrypt) and "HPKEPrivateKey" (decrypt) to be
    set via PayloadShieldEnc.init({"HPKEPublicKey": ..., "HPKEPrivateKey": ...}).
    """

    def encode(self, data: Any, config: Optional[Dict[str, Any]] = None) -> str:
        recipient_public_key = self._load_public_key(config)

        ephemeral_private = x25519.X25519PrivateKey.generate()
        enc = ephemeral_private.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        dh = ephemeral_private.exchange(recipient_public_key)
        pkrm = recipient_public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        shared_secret = self._extract_and_expand(dh, enc + pkrm)
        key, base_nonce = self._key_schedule(shared_secret)

        payload = json.dumps(data).encode("utf-8")
        ciphertext = ChaCha20Poly1305(key).encrypt(base_nonce, payload, None)

        bundle = {
            "enc": base64.b64encode(enc).decode("utf-8"),
            "data": base64.b64encode(ciphertext).decode("utf-8"),
        }
        return base64.b64encode(json.dumps(bundle).encode("utf-8")).decode("utf-8")

    def decode(self, encoded_data: str, config: Optional[Dict[str, Any]] = None) -> Any:
        recipient_private_key = self._load_private_key(config)
        try:
            bundle = json.loads(base64.b64decode(encoded_data.encode("utf-8")))
            enc = base64.b64decode(bundle["enc"])
            ciphertext = base64.b64decode(bundle["data"])

            ephemeral_public_key = x25519.X25519PublicKey.from_public_bytes(enc)
            dh = recipient_private_key.exchange(ephemeral_public_key)
            pkrm = recipient_private_key.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
            shared_secret = self._extract_and_expand(dh, enc + pkrm)
            key, base_nonce = self._key_schedule(shared_secret)

            payload = ChaCha20Poly1305(key).decrypt(base_nonce, ciphertext, None)
            return json.loads(payload.decode("utf-8"))
        except Exception as e:
            raise ValueError(f"Failed to decode hpke data: {str(e)}")

    @staticmethod
    def _extract_and_expand(dh: bytes, kem_context: bytes) -> bytes:
        eae_prk = _labeled_extract(b"", b"eae_prk", dh, _KEM_SUITE_ID)
        return _labeled_expand(eae_prk, b"shared_secret", kem_context, _NSECRET, _KEM_SUITE_ID)

    @staticmethod
    def _key_schedule(shared_secret: bytes) -> Tuple[bytes, bytes]:
        psk_id_hash = _labeled_extract(b"", b"psk_id_hash", b"", _HPKE_SUITE_ID)
        info_hash = _labeled_extract(b"", b"info_hash", b"", _HPKE_SUITE_ID)
        key_schedule_context = b"\x00" + psk_id_hash + info_hash  # mode_base = 0x00
        secret = _labeled_extract(shared_secret, b"secret", b"", _HPKE_SUITE_ID)
        key = _labeled_expand(secret, b"key", key_schedule_context, _NK, _HPKE_SUITE_ID)
        base_nonce = _labeled_expand(secret, b"base_nonce", key_schedule_context, _NN, _HPKE_SUITE_ID)
        return key, base_nonce

    @staticmethod
    def _load_public_key(config: Optional[Dict[str, Any]]):
        pem = (config or {}).get("HPKEPublicKey")
        if not pem:
            raise ValueError(
                "HPKE encryption requires 'HPKEPublicKey' to be set via "
                "PayloadShieldEnc.init({'HPKEPublicKey': ...})"
            )
        pem_bytes = pem.encode("utf-8") if isinstance(pem, str) else pem
        return serialization.load_pem_public_key(pem_bytes)

    @staticmethod
    def _load_private_key(config: Optional[Dict[str, Any]]):
        pem = (config or {}).get("HPKEPrivateKey")
        if not pem:
            raise ValueError(
                "HPKE decryption requires 'HPKEPrivateKey' to be set via "
                "PayloadShieldEnc.init({'HPKEPrivateKey': ...})"
            )
        pem_bytes = pem.encode("utf-8") if isinstance(pem, str) else pem
        return serialization.load_pem_private_key(pem_bytes, password=None)
