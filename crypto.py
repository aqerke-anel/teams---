"""Шифрлау функциялары: кілт алу (scrypt) және AES-256-GCM."""
import base64
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


def new_salt() -> bytes:
    return os.urandom(16)


def derive_key(master_password: str, salt: bytes) -> bytes:
    """Master парольден 32 байттық шифрлау кілтін алады."""
    kdf = Scrypt(salt=salt, length=32, n=2**15, r=8, p=1)
    return kdf.derive(master_password.encode("utf-8"))


def encrypt(key: bytes, plaintext: str) -> str:
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, plaintext.encode("utf-8"), None)
    return base64.b64encode(nonce + ct).decode("ascii")


def decrypt(key: bytes, token: str) -> str:
    raw = base64.b64decode(token)
    nonce, ct = raw[:12], raw[12:]
    return AESGCM(key).decrypt(nonce, ct, None).decode("utf-8")
