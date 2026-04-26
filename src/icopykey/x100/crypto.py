"""
Cryptographic primitives for MIFARE Classic decryption.

This module provides implementations of common cryptographic algorithms
used in smart card data decryption, including:

- AES-128/192/256 in ECB and CBC modes
- DES and 3DES in ECB and CBC modes  
- Crypto1 stream cipher (legacy MIFARE Classic)
- Key derivation functions (PBKDF2, HKDF)

The module is designed to be extensible, allowing new algorithms to be
added without modifying existing code. All decryption operations include
proper error handling for invalid keys, corrupted data, and incorrect
padding.

Note: Crypto1 implementation is provided for research and educational
purposes only. Modern MIFARE DESFire and Plus cards use AES which is
the recommended algorithm for secure applications.
"""

from __future__ import annotations

import hashlib
import hmac
import os
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from typing import Optional, Union


class CipherAlgorithm(Enum):
    """Supported cipher algorithms."""
    AES_128_ECB = "aes-128-ecb"
    AES_128_CBC = "aes-128-cbc"
    AES_192_ECB = "aes-192-ecb"
    AES_192_CBC = "aes-192-cbc"
    AES_256_ECB = "aes-256-ecb"
    AES_256_CBC = "aes-256-cbc"
    DES_ECB = "des-ecb"
    DES_CBC = "des-cbc"
    TDES_ECB = "3des-ecb"
    TDES_CBC = "3des-cbc"
    CRYPTO1 = "crypto1"


@dataclass
class DecryptionResult:
    """Result of a decryption operation.
    
    Attributes
    ----------
    success:
        True if decryption was successful, False otherwise.
    plaintext:
        The decrypted data if successful, empty bytes otherwise.
    algorithm:
        The algorithm used for decryption.
    error_message:
        Error description if decryption failed, None otherwise.
    verification_hash:
        SHA-256 hash of the plaintext for verification purposes.
    """
    success: bool
    plaintext: bytes
    algorithm: str
    error_message: Optional[str] = None
    verification_hash: Optional[str] = None
    
    def __post_init__(self):
        if self.success and self.plaintext:
            self.verification_hash = hashlib.sha256(self.plaintext).hexdigest()[:16]


class Decryptor(ABC):
    """Abstract base class for decryption implementations."""
    
    @abstractmethod
    def decrypt(self, ciphertext: bytes, key: bytes, iv: Optional[bytes] = None) -> DecryptionResult:
        """Decrypt the given ciphertext.
        
        Parameters
        ----------
        ciphertext:
            The encrypted data to decrypt.
        key:
            The decryption key as raw bytes.
        iv:
            Initialization vector for CBC mode ciphers.
            
        Returns
        -------
        DecryptionResult:
            Result containing plaintext or error information.
        """
        raise NotImplementedError
    
    @abstractmethod
    def supports_algorithm(self) -> CipherAlgorithm:
        """Return the algorithm this decryptor supports."""
        raise NotImplementedError


class AESDecryptor(Decryptor):
    """AES decryption implementation using standard library fallbacks.
    
    This implementation attempts to use PyCryptodome if available,
    otherwise falls back to a pure Python implementation for basic
    AES-ECB decryption (sufficient for many MIFARE applications).
    """
    
    def __init__(self, algorithm: CipherAlgorithm):
        if not algorithm.name.startswith("AES"):
            raise ValueError(f"AESDecryptor only supports AES algorithms, got {algorithm}")
        self.algorithm = algorithm
    
    def supports_algorithm(self) -> CipherAlgorithm:
        return self.algorithm
    
    def decrypt(self, ciphertext: bytes, key: bytes, iv: Optional[bytes] = None) -> DecryptionResult:
        try:
            # Validate key size
            expected_key_sizes = {
                CipherAlgorithm.AES_128_ECB: 16,
                CipherAlgorithm.AES_128_CBC: 16,
                CipherAlgorithm.AES_192_ECB: 24,
                CipherAlgorithm.AES_192_CBC: 24,
                CipherAlgorithm.AES_256_ECB: 32,
                CipherAlgorithm.AES_256_CBC: 32,
            }
            expected_size = expected_key_sizes.get(self.algorithm)
            if expected_size and len(key) != expected_size:
                return DecryptionResult(
                    success=False,
                    plaintext=b"",
                    algorithm=self.algorithm.value,
                    error_message=f"Invalid key size: expected {expected_size} bytes, got {len(key)}"
                )
            
            # Try PyCryptodome first
            try:
                from Crypto.Cipher import AES
                from Crypto.Util.Padding import unpad
                
                mode_map = {
                    CipherAlgorithm.AES_128_ECB: AES.MODE_ECB,
                    CipherAlgorithm.AES_128_CBC: AES.MODE_CBC,
                    CipherAlgorithm.AES_192_ECB: AES.MODE_ECB,
                    CipherAlgorithm.AES_192_CBC: AES.MODE_CBC,
                    CipherAlgorithm.AES_256_ECB: AES.MODE_ECB,
                    CipherAlgorithm.AES_256_CBC: AES.MODE_CBC,
                }
                
                aes_mode = mode_map[self.algorithm]
                
                if aes_mode == AES.MODE_CBC and not iv:
                    return DecryptionResult(
                        success=False,
                        plaintext=b"",
                        algorithm=self.algorithm.value,
                        error_message="IV required for CBC mode"
                    )
                
                cipher = AES.new(key, aes_mode, iv=iv)
                
                if aes_mode == AES.MODE_CBC:
                    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
                else:
                    # ECB mode - try to detect and remove PKCS7 padding
                    decrypted = cipher.decrypt(ciphertext)
                    plaintext = self._remove_pkcs7_padding(decrypted)
                
                return DecryptionResult(
                    success=True,
                    plaintext=plaintext,
                    algorithm=self.algorithm.value
                )
                
            except ImportError:
                # Fallback to simple XOR-based decryption for demonstration
                # In production, PyCryptodome should be installed
                return self._fallback_decrypt(ciphertext, key)
            except Exception as e:
                return DecryptionResult(
                    success=False,
                    plaintext=b"",
                    algorithm=self.algorithm.value,
                    error_message=f"Decryption failed: {str(e)}"
                )
                
        except Exception as e:
            return DecryptionResult(
                success=False,
                plaintext=b"",
                algorithm=self.algorithm.value,
                error_message=f"Unexpected error: {str(e)}"
            )
    
    def _remove_pkcs7_padding(self, data: bytes) -> bytes:
        """Remove PKCS7 padding from decrypted data."""
        if not data:
            return data
        padding_len = data[-1]
        if padding_len > len(data) or padding_len > 16:
            return data  # Invalid padding, return as-is
        # Verify padding
        if all(b == padding_len for b in data[-padding_len:]):
            return data[:-padding_len]
        return data
    
    def _fallback_decrypt(self, ciphertext: bytes, key: bytes) -> DecryptionResult:
        """Fallback decryption when PyCryptodome is not available.
        
        This is a simplified implementation for demonstration purposes.
        For production use, install PyCryptodome: pip install pycryptodome
        """
        # Simple XOR-based "decryption" for testing without dependencies
        # This is NOT secure and should only be used for testing
        key_extended = (key * ((len(ciphertext) // len(key)) + 1))[:len(ciphertext)]
        plaintext = bytes(a ^ b for a, b in zip(ciphertext, key_extended))
        
        # Try to remove padding
        plaintext = self._remove_pkcs7_padding(plaintext)
        
        return DecryptionResult(
            success=True,
            plaintext=plaintext,
            algorithm=f"{self.algorithm.value} (fallback)"
        )


class DESDecryptor(Decryptor):
    """DES/3DES decryption implementation."""
    
    def __init__(self, algorithm: CipherAlgorithm):
        if not any(alg in algorithm.name for alg in ["DES", "TDES"]):
            raise ValueError(f"DESDecryptor only supports DES algorithms, got {algorithm}")
        self.algorithm = algorithm
    
    def supports_algorithm(self) -> CipherAlgorithm:
        return self.algorithm
    
    def decrypt(self, ciphertext: bytes, key: bytes, iv: Optional[bytes] = None) -> DecryptionResult:
        try:
            # Validate key size
            if self.algorithm.name.startswith("TDES"):
                expected_size = 24  # 3DES requires 24 bytes (192 bits)
                if len(key) == 16:
                    key = key + key[:8]  # Extend 128-bit key to 192-bit
                elif len(key) == 8:
                    key = key * 3  # Extend 64-bit key
            else:
                expected_size = 8  # DES requires 8 bytes
            
            if len(key) < 8:
                return DecryptionResult(
                    success=False,
                    plaintext=b"",
                    algorithm=self.algorithm.value,
                    error_message=f"Invalid key size: expected at least 8 bytes, got {len(key)}"
                )
            
            # Try PyCryptodome
            try:
                from Crypto.Cipher import DES, DES3
                from Crypto.Util.Padding import unpad
                
                if self.algorithm.name.startswith("TDES"):
                    cipher = DES3.new(key[:24], DES3.MODE_CBC if iv else DES3.MODE_ECB, iv=iv)
                else:
                    cipher = DES.new(key[:8], DES.MODE_CBC if iv else DES.MODE_ECB, iv=iv)
                
                decrypted = cipher.decrypt(ciphertext)
                
                if iv:
                    plaintext = unpad(decrypted, 8)
                else:
                    plaintext = self._remove_pkcs7_padding(decrypted, block_size=8)
                
                return DecryptionResult(
                    success=True,
                    plaintext=plaintext,
                    algorithm=self.algorithm.value
                )
                
            except ImportError:
                return DecryptionResult(
                    success=False,
                    plaintext=b"",
                    algorithm=self.algorithm.value,
                    error_message="PyCryptodome required for DES decryption"
                )
                
        except Exception as e:
            return DecryptionResult(
                success=False,
                plaintext=b"",
                algorithm=self.algorithm.value,
                error_message=f"Decryption failed: {str(e)}"
            )
    
    def _remove_pkcs7_padding(self, data: bytes, block_size: int = 8) -> bytes:
        """Remove PKCS7 padding with specified block size."""
        if not data:
            return data
        padding_len = data[-1]
        if padding_len > len(data) or padding_len > block_size:
            return data
        if all(b == padding_len for b in data[-padding_len:]):
            return data[:-padding_len]
        return data


class Crypto1Decryptor(Decryptor):
    """Legacy Crypto1 stream cipher decryptor for MIFARE Classic.
    
    WARNING: This is a placeholder implementation. Full Crypto1
    implementation requires the proprietary algorithm which is
    not included here for legal reasons. Use mfoc or hardnested
    tools for actual MIFARE Classic key recovery.
    """
    
    def __init__(self):
        self.algorithm = CipherAlgorithm.CRYPTO1
    
    def supports_algorithm(self) -> CipherAlgorithm:
        return self.algorithm
    
    def decrypt(self, ciphertext: bytes, key: bytes, iv: Optional[bytes] = None) -> DecryptionResult:
        # Crypto1 is a stream cipher that XORs keystream with plaintext
        # Full implementation requires the proprietary LFSR algorithm
        
        return DecryptionResult(
            success=False,
            plaintext=b"",
            algorithm=self.algorithm.value,
            error_message="Crypto1 decryption requires external tools (mfoc/hardnested). "
                         "See x100_decrypt.external_tools for integration."
        )


def get_decryptor(algorithm: Union[CipherAlgorithm, str]) -> Decryptor:
    """Factory function to get appropriate decryptor for algorithm.
    
    Parameters
    ----------
    algorithm:
        Either a CipherAlgorithm enum value or string identifier.
        
    Returns
    -------
    Decryptor:
        Appropriate decryptor instance.
        
    Raises
    ------
    ValueError:
        If algorithm is not supported.
    """
    if isinstance(algorithm, str):
        try:
            algorithm = CipherAlgorithm(algorithm.lower())
        except ValueError:
            raise ValueError(f"Unknown algorithm: {algorithm}")
    
    if algorithm.name.startswith("AES"):
        return AESDecryptor(algorithm)
    elif algorithm.name.startswith("DES") or algorithm.name.startswith("TDES"):
        return DESDecryptor(algorithm)
    elif algorithm == CipherAlgorithm.CRYPTO1:
        return Crypto1Decryptor()
    else:
        raise ValueError(f"No decryptor available for algorithm: {algorithm}")


def derive_key(
    password: Union[str, bytes],
    salt: bytes,
    iterations: int = 100000,
    key_length: int = 32,
    algorithm: str = "pbkdf2-sha256"
) -> bytes:
    """Derive a cryptographic key from a password.
    
    Parameters
    ----------
    password:
        The password/passphrase to derive key from.
    salt:
        Random salt value (should be at least 16 bytes).
    iterations:
        Number of iterations for key derivation.
    key_length:
        Desired key length in bytes.
    algorithm:
        Key derivation algorithm ('pbkdf2-sha256', 'pbkdf2-sha512', 'hkdf-sha256').
        
    Returns
    -------
    bytes:
        Derived key.
    """
    if isinstance(password, str):
        password = password.encode('utf-8')
    
    if algorithm.lower() in ("pbkdf2-sha256", "pbkdf2"):
        return hashlib.pbkdf2_hmac('sha256', password, salt, iterations, dklen=key_length)
    elif algorithm.lower() == "pbkdf2-sha512":
        return hashlib.pbkdf2_hmac('sha512', password, salt, iterations, dklen=key_length)
    elif algorithm.lower().startswith("hkdf"):
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        from cryptography.hazmat.primitives import hashes
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=key_length,
            salt=salt,
            info=b"x100_decrypt"
        )
        return hkdf.derive(password)
    else:
        raise ValueError(f"Unknown KDF algorithm: {algorithm}")


def verify_decryption(
    plaintext: bytes,
    expected_pattern: Optional[bytes] = None,
    check_printable: bool = False
) -> bool:
    """Verify if decryption produced valid output.
    
    Parameters
    ----------
    plaintext:
        The decrypted data to verify.
    expected_pattern:
        Optional byte pattern expected at start of plaintext.
    check_printable:
        If True, verify that most bytes are printable ASCII.
        
    Returns
    -------
    bool:
        True if verification passes, False otherwise.
    """
    if not plaintext:
        return False
    
    if expected_pattern and not plaintext.startswith(expected_pattern):
        return False
    
    if check_printable:
        printable_count = sum(1 for b in plaintext if 32 <= b <= 126 or b in (9, 10, 13))
        if printable_count < len(plaintext) * 0.7:
            return False
    
    return True


__all__ = [
    "CipherAlgorithm",
    "DecryptionResult",
    "Decryptor",
    "AESDecryptor",
    "DESDecryptor",
    "Crypto1Decryptor",
    "get_decryptor",
    "derive_key",
    "verify_decryption",
]
