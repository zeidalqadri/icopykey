"""AES-256-GCM vault for encrypting/decrypting JSON data."""

from __future__ import annotations

import logging

try:
    from Crypto.Cipher import AES
    from Crypto.Random import get_random_bytes
    from Crypto.Protocol.KDF import PBKDF2

    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

from .errors import VaultAccessError

logger = logging.getLogger("copykey_cli.vault")


class AESVault:
    """Encrypt/decrypt JSON data with PBKDF2 + AES-256-GCM."""

    ITERATIONS = 100_000
    SALT_LEN = 16
    IV_LEN = 12
    TAG_LEN = 16
    KEY_LEN = 32

    def __init__(self, password: str) -> None:
        if not password:
            raise ValueError("Password cannot be empty")
        if not CRYPTO_AVAILABLE:
            raise ImportError("pycryptodome required for AES vault")
        self.password = password

    def _derive_key(self, salt: bytes) -> bytes:
        return PBKDF2(
            self.password.encode("utf-8"), salt, dkLen=self.KEY_LEN, count=self.ITERATIONS
        )

    def encrypt(self, plaintext: str) -> bytes:
        salt = get_random_bytes(self.SALT_LEN)
        key = self._derive_key(salt)
        iv = get_random_bytes(self.IV_LEN)
        cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
        data = plaintext.encode("utf-8")
        ciphertext, tag = cipher.encrypt_and_digest(data)
        return salt + iv + tag + ciphertext

    def decrypt(self, blob: bytes) -> str:
        if len(blob) < (self.SALT_LEN + self.IV_LEN + self.TAG_LEN):
            raise ValueError("Invalid encrypted data format")
        salt = blob[: self.SALT_LEN]
        iv = blob[self.SALT_LEN : self.SALT_LEN + self.IV_LEN]
        tag = blob[self.SALT_LEN + self.IV_LEN : self.SALT_LEN + self.IV_LEN + self.TAG_LEN]
        ciphertext = blob[self.SALT_LEN + self.IV_LEN + self.TAG_LEN :]
        key = self._derive_key(salt)
        cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
        try:
            return cipher.decrypt_and_verify(ciphertext, tag).decode("utf-8")
        except ValueError:
            raise VaultAccessError()
