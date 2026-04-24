"""
Key management module for x100_decrypt.

This module provides secure handling of cryptographic keys from multiple
input sources including hex strings, binary files, and environment variables.
It includes key validation, derivation functions, and secure storage patterns.

Features:
- Multiple key input methods (hex, file, environment)
- Key format validation
- Key derivation from passwords using PBKDF2
- Secure key masking for logging
- Support for multiple key formats (raw, hex-encoded, base64)
"""

from __future__ import annotations

import base64
import os
import re
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Optional, Union


class KeySource(Enum):
    """Enumeration of possible key sources."""
    HEX_STRING = "hex_string"
    FILE = "file"
    ENVIRONMENT = "environment"
    DERIVED = "derived"
    RAW_BYTES = "raw_bytes"


@dataclass
class KeyInfo:
    """Metadata about a loaded key.
    
    Attributes
    ----------
    source:
        Where the key was loaded from.
    key_length:
        Length of the key in bytes.
    key_type:
        Type identifier (e.g., 'AES-128', 'DES').
    fingerprint:
        Short hash of key for identification without exposing full key.
    is_derived:
        True if key was derived from a password.
    """
    source: KeySource
    key_length: int
    key_type: str
    fingerprint: str
    is_derived: bool = False
    
    def __str__(self) -> str:
        return f"Key({self.key_type}, {self.key_length} bytes, src={self.source.value})"


class KeyManager:
    """Manages cryptographic keys with secure loading and validation.
    
    This class provides a unified interface for loading keys from various
    sources while maintaining security best practices. Keys are never
    logged in full and are masked when displayed.
    
    Example usage:
        km = KeyManager()
        key = km.load_from_hex("00112233445566778899AABBCCDDEEFF")
        # or
        key = km.load_from_file("/path/to/key.bin")
        # or
        key = km.load_from_env("MY_SECRET_KEY")
    """
    
    # Common key sizes in bytes
    VALID_KEY_SIZES = {
        8: "DES",
        16: "AES-128/DES3",
        24: "AES-192/DES3",
        32: "AES-256",
    }
    
    def __init__(self, auto_detect_type: bool = True):
        """Initialize KeyManager.
        
        Parameters
        ----------
        auto_detect_type:
            If True, automatically detect key type based on length.
        """
        self.auto_detect_type = auto_detect_type
        self._loaded_keys: dict[str, tuple[bytes, KeyInfo]] = {}
    
    def load_from_hex(
        self, 
        hex_string: str, 
        key_id: str = "default",
        strip_prefix: bool = True
    ) -> tuple[bytes, KeyInfo]:
        """Load a key from a hexadecimal string.
        
        Parameters
        ----------
        hex_string:
            The key as a hex-encoded string. May optionally start with
            '0x' or '0X' prefix.
        key_id:
            Identifier to store this key under.
        strip_prefix:
            If True, remove '0x' prefix if present.
            
        Returns
        -------
        tuple[bytes, KeyInfo]:
            The raw key bytes and metadata.
            
        Raises
        ------
        ValueError:
            If hex string is invalid or has wrong length.
        """
        original = hex_string
        
        # Strip optional 0x prefix
        if strip_prefix and hex_string.lower().startswith("0x"):
            hex_string = hex_string[2:]
        
        # Remove any whitespace or separators
        hex_string = re.sub(r'[\s:-]', '', hex_string)
        
        # Validate hex characters
        if not re.match(r'^[0-9a-fA-F]+$', hex_string):
            raise ValueError(f"Invalid hex string: contains non-hexadecimal characters")
        
        # Check even length
        if len(hex_string) % 2 != 0:
            raise ValueError(f"Invalid hex string: must have even length")
        
        try:
            key_bytes = bytes.fromhex(hex_string)
        except ValueError as e:
            raise ValueError(f"Failed to decode hex string: {e}")
        
        # Validate key length
        if len(key_bytes) not in self.VALID_KEY_SIZES:
            valid_sizes = sorted(self.VALID_KEY_SIZES.keys())
            raise ValueError(
                f"Invalid key length: {len(key_bytes)} bytes. "
                f"Valid sizes: {valid_sizes}"
            )
        
        key_info = self._create_key_info(
            key_bytes, 
            KeySource.HEX_STRING, 
            original[:8] + "..." if len(original) > 8 else original
        )
        
        self._loaded_keys[key_id] = (key_bytes, key_info)
        return key_bytes, key_info
    
    def load_from_file(
        self,
        file_path: Union[str, Path],
        key_id: str = "default",
        encoding: str = "binary"
    ) -> tuple[bytes, KeyInfo]:
        """Load a key from a file.
        
        Parameters
        ----------
        file_path:
            Path to the key file.
        key_id:
            Identifier to store this key under.
        encoding:
            How to interpret the file: 'binary', 'hex', or 'base64'.
            
        Returns
        -------
        tuple[bytes, KeyInfo]:
            The raw key bytes and metadata.
            
        Raises
        ------
        FileNotFoundError:
            If key file doesn't exist.
        ValueError:
            If file content is invalid.
        """
        path = Path(file_path)
        
        if not path.exists():
            raise FileNotFoundError(f"Key file not found: {path}")
        
        if not path.is_file():
            raise ValueError(f"Not a file: {path}")
        
        with open(path, 'rb') as f:
            content = f.read()
        
        # Decode based on encoding type
        if encoding == "binary":
            key_bytes = content
        elif encoding == "hex":
            key_bytes = bytes.fromhex(content.decode('ascii').strip())
        elif encoding == "base64":
            key_bytes = base64.b64decode(content.strip())
        else:
            raise ValueError(f"Unknown encoding: {encoding}")
        
        # Validate key length
        if len(key_bytes) not in self.VALID_KEY_SIZES:
            valid_sizes = sorted(self.VALID_KEY_SIZES.keys())
            raise ValueError(
                f"Invalid key length from file: {len(key_bytes)} bytes. "
                f"Valid sizes: {valid_sizes}"
            )
        
        key_info = self._create_key_info(
            key_bytes,
            KeySource.FILE,
            str(path)
        )
        
        self._loaded_keys[key_id] = (key_bytes, key_info)
        return key_bytes, key_info
    
    def load_from_env(
        self,
        env_var: str,
        key_id: str = "default",
        encoding: str = "hex"
    ) -> tuple[bytes, KeyInfo]:
        """Load a key from an environment variable.
        
        Parameters
        ----------
        env_var:
            Name of the environment variable.
        key_id:
            Identifier to store this key under.
        encoding:
            How to interpret the value: 'hex', 'base64', or 'raw'.
            
        Returns
        -------
        tuple[bytes, KeyInfo]:
            The raw key bytes and metadata.
            
        Raises
        ------
        KeyError:
            If environment variable is not set.
        ValueError:
            If value cannot be decoded.
        """
        value = os.environ.get(env_var)
        
        if value is None:
            raise KeyError(f"Environment variable '{env_var}' not set")
        
        # Decode based on encoding type
        if encoding == "hex":
            key_bytes = bytes.fromhex(value.replace("0x", "").replace(" ", ""))
        elif encoding == "base64":
            key_bytes = base64.b64decode(value)
        elif encoding == "raw":
            key_bytes = value.encode('utf-8')
        else:
            raise ValueError(f"Unknown encoding: {encoding}")
        
        # Validate key length
        if len(key_bytes) not in self.VALID_KEY_SIZES:
            valid_sizes = sorted(self.VALID_KEY_SIZES.keys())
            raise ValueError(
                f"Invalid key length from env: {len(key_bytes)} bytes. "
                f"Valid sizes: {valid_sizes}"
            )
        
        key_info = self._create_key_info(
            key_bytes,
            KeySource.ENVIRONMENT,
            env_var
        )
        
        self._loaded_keys[key_id] = (key_bytes, key_info)
        return key_bytes, key_info
    
    def derive_from_password(
        self,
        password: Union[str, bytes],
        salt: Optional[bytes] = None,
        key_length: int = 32,
        iterations: int = 100000,
        key_id: str = "default"
    ) -> tuple[bytes, KeyInfo]:
        """Derive a key from a password using PBKDF2.
        
        Parameters
        ----------
        password:
            The password/passphrase to derive from.
        salt:
            Salt for key derivation. If None, generates random salt.
        key_length:
            Desired key length in bytes.
        iterations:
            Number of PBKDF2 iterations.
        key_id:
            Identifier to store this key under.
            
        Returns
        -------
        tuple[bytes, KeyInfo]:
            The derived key bytes and metadata.
        """
        from .crypto import derive_key
        
        if salt is None:
            salt = os.urandom(16)
        
        if isinstance(password, str):
            password = password.encode('utf-8')
        
        derived = derive_key(password, salt, iterations, key_length)
        
        key_info = KeyInfo(
            source=KeySource.DERIVED,
            key_length=len(derived),
            key_type=f"AES-{key_length * 8}",
            fingerprint=self._fingerprint(derived),
            is_derived=True
        )
        
        self._loaded_keys[key_id] = (derived, key_info)
        return derived, key_info
    
    def get_key(self, key_id: str = "default") -> Optional[bytes]:
        """Retrieve a previously loaded key by ID.
        
        Parameters
        ----------
        key_id:
            The identifier used when loading the key.
            
        Returns
        -------
        Optional[bytes]:
            The key bytes if found, None otherwise.
        """
        entry = self._loaded_keys.get(key_id)
        return entry[0] if entry else None
    
    def get_key_info(self, key_id: str = "default") -> Optional[KeyInfo]:
        """Get metadata about a loaded key.
        
        Parameters
        ----------
        key_id:
            The identifier used when loading the key.
            
        Returns
        -------
        Optional[KeyInfo]:
            Key metadata if found, None otherwise.
        """
        entry = self._loaded_keys.get(key_id)
        return entry[1] if entry else None
    
    def clear_key(self, key_id: str = "default") -> bool:
        """Securely remove a key from memory.
        
        Parameters
        ----------
        key_id:
            The identifier of the key to clear.
            
        Returns
        -------
        bool:
            True if key was cleared, False if not found.
        """
        if key_id in self._loaded_keys:
            del self._loaded_keys[key_id]
            return True
        return False
    
    def clear_all_keys(self) -> None:
        """Clear all loaded keys from memory."""
        self._loaded_keys.clear()
    
    def _create_key_info(
        self,
        key_bytes: bytes,
        source: KeySource,
        source_detail: str
    ) -> KeyInfo:
        """Create KeyInfo metadata for a loaded key."""
        key_type = self.VALID_KEY_SIZES.get(
            len(key_bytes), 
            f"CUSTOM-{len(key_bytes) * 8}"
        )
        
        return KeyInfo(
            source=source,
            key_length=len(key_bytes),
            key_type=key_type,
            fingerprint=self._fingerprint(key_bytes),
            is_derived=False
        )
    
    def _fingerprint(self, key_bytes: bytes) -> str:
        """Generate a short fingerprint of a key without exposing it."""
        import hashlib
        # Use first 8 chars of SHA256 hash as fingerprint
        return hashlib.sha256(key_bytes).hexdigest()[:8]
    
    @staticmethod
    def mask_key(key: bytes, visible_chars: int = 4) -> str:
        """Create a masked representation of a key for safe display.
        
        Parameters
        ----------
        key:
            The key bytes to mask.
        visible_chars:
            Number of hex characters to show at start and end.
            
        Returns
        -------
        str:
            Masked key string like 'abcd...wxyz'
        """
        hex_repr = key.hex()
        if len(hex_repr) <= visible_chars * 2:
            return '*' * len(hex_repr)
        return f"{hex_repr[:visible_chars]}...{hex_repr[-visible_chars:]}"


def validate_key_format(
    key: Union[str, bytes],
    expected_size: Optional[int] = None,
    allow_hex: bool = True
) -> tuple[bool, str]:
    """Validate a key's format and size.
    
    Parameters
    ----------
    key:
        The key to validate (hex string or bytes).
    expected_size:
        Expected key size in bytes (optional).
    allow_hex:
        If True, accept hex-encoded strings.
        
    Returns
    -------
    tuple[bool, str]:
        (is_valid, error_message) - error_message is empty if valid.
    """
    # Convert to bytes if needed
    if isinstance(key, str):
        if not allow_hex:
            return False, "String keys not allowed"
        try:
            key = bytes.fromhex(key.replace("0x", "").replace(" ", ""))
        except ValueError as e:
            return False, f"Invalid hex format: {e}"
    
    # Check size
    if expected_size and len(key) != expected_size:
        return False, f"Key size mismatch: expected {expected_size}, got {len(key)}"
    
    # Check against known sizes
    valid_sizes = {8, 16, 24, 32}
    if len(key) not in valid_sizes:
        return False, f"Unusual key size: {len(key)} bytes"
    
    return True, ""


__all__ = [
    "KeySource",
    "KeyInfo",
    "KeyManager",
    "validate_key_format",
]
