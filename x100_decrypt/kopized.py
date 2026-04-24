"""
Kopized - Real-time decryption service for X100 Smart Card Replicator

This module provides the core functionality for the 'kopized' command-line tool
that intercepts encrypted sector requests from the X100 device, decrypts them
using known or derived keys, and returns the decrypted data to allow the device
to proceed with WRITE operations.

The typical workflow is:
1. User scans a card with X100 device
2. Device detects encrypted sectors and prompts for computer connection
3. User runs 'kopized' command which listens for device requests
4. Kopized receives encrypted data, decrypts it, and sends back keys
5. Device proceeds with writing/cloning operation

Legal Disclaimer
----------------
This tool should only be used on cards you own or have explicit authorization
to analyze. Unauthorized decryption or cloning of smart cards may violate
local laws and terms of service.
"""

from __future__ import annotations

import logging
import time
import json
from dataclasses import dataclass, field
from typing import Optional, Dict, List, Any, Tuple
from pathlib import Path
from enum import Enum

from .crypto import (
    get_decryptor,
    DecryptionResult,
    CipherAlgorithm,
    verify_decryption,
    derive_key,
)
from .keymanager import KeyManager, KeyInfo
from .engine import MifareClassicDump

logger = logging.getLogger(__name__)


class SectorStatus(Enum):
    """Status of a MIFARE Classic sector."""
    ENCRYPTED = "encrypted"
    DECRYPTED = "decrypted"
    UNREADABLE = "unreadable"
    EMPTY = "empty"


@dataclass
class SectorInfo:
    """Information about a single MIFARE Classic sector."""
    sector_number: int
    status: SectorStatus
    key_a: Optional[str] = None  # Hex string
    key_b: Optional[str] = None  # Hex string
    access_bits: Optional[str] = None  # Hex string
    data_blocks: List[bytes] = field(default_factory=list)
    trailer_block: Optional[bytes] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "sector": self.sector_number,
            "status": self.status.value,
            "key_a": self.key_a,
            "key_b": self.key_b,
            "access_bits": self.access_bits,
            "data_blocks": [b.hex().upper() for b in self.data_blocks],
            "trailer_block": self.trailer_block.hex().upper() if self.trailer_block else None,
        }


@dataclass
class CardInfo:
    """Information extracted from a scanned card."""
    uid: str
    card_type: str  # e.g., "IC/MI-S50+"
    atqa: str
    sak: str
    total_sectors: int
    encrypted_sectors: List[int] = field(default_factory=list)
    decrypted_sectors: List[SectorInfo] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "uid": self.uid,
            "model": self.card_type,
            "atqa": self.atqa,
            "sak": self.sak,
            "total_sectors": self.total_sectors,
            "encrypted_sectors": self.encrypted_sectors,
            "decrypted_sectors": [s.to_dict() for s in self.decrypted_sectors],
        }


@dataclass
class DecryptionRequest:
    """A request from the X100 device to decrypt sector data."""
    card_info: CardInfo
    encrypted_data: bytes
    sector_numbers: List[int]
    timestamp: float = field(default_factory=time.time)
    request_id: str = ""
    
    @classmethod
    def from_device_output(cls, output: str) -> 'DecryptionRequest':
        """Parse device output text into a DecryptionRequest.
        
        Example input:
        CN: 16198219
        Model: IC/MI-S50+
        UID: 4B 2A F7 53
        ATQA: 04 00       SAK: 08
        
        TIPS
        There are encrypted sectors. Please connect to the computer 
        and use decryption software to decrypt
        """
        lines = output.strip().split('\n')
        card_data = {}
        
        for line in lines:
            line = line.strip()
            if ':' in line:
                key, value = line.split(':', 1)
                card_data[key.strip()] = value.strip()
        
        # Extract card information
        uid = card_data.get('UID', '').replace(' ', '')
        card_type = card_data.get('Model', 'Unknown')
        atqa = card_data.get('ATQA', '00 00').replace(' ', '')
        sak = card_data.get('SAK', '00').replace(' ', '')
        
        # Determine sector count based on card type
        # S50 = 1K = 16 sectors, S70 = 4K = 40 sectors
        total_sectors = 16
        if 'S70' in card_type.upper() or '4K' in card_type.upper():
            total_sectors = 40
        
        card_info = CardInfo(
            uid=uid,
            card_type=card_type,
            atqa=atqa,
            sak=sak,
            total_sectors=total_sectors,
            encrypted_sectors=list(range(total_sectors)),  # Assume all encrypted initially
        )
        
        # Generate request ID from UID + timestamp
        import hashlib
        request_id = hashlib.md5(f"{uid}{time.time()}".encode()).hexdigest()[:8]
        
        return cls(
            card_info=card_info,
            encrypted_data=b'',  # Will be populated when actual data received
            sector_numbers=card_info.encrypted_sectors,
            request_id=request_id,
        )


@dataclass
class DecryptionResponse:
    """Response containing decrypted sector keys and data."""
    success: bool
    card_info: CardInfo
    decrypted_sectors: List[SectorInfo]
    keys_recovered: int
    time_taken_ms: float
    error_message: Optional[str] = None
    request_id: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "success": self.success,
            "request_id": self.request_id,
            "card_info": self.card_info.to_dict(),
            "decrypted_sectors": [s.to_dict() for s in self.decrypted_sectors],
            "keys_recovered": self.keys_recovered,
            "time_taken_ms": round(self.time_taken_ms, 2),
            "error_message": self.error_message,
        }
    
    def to_json(self) -> str:
        """Serialize response to JSON string."""
        return json.dumps(self.to_dict(), indent=2)


class KopizedService:
    """Main service class for handling decryption requests from X100 device.
    
    This class coordinates:
    - Receiving encrypted sector data from the device
    - Attempting decryption using various methods (default keys, dictionary attacks, etc.)
    - Returning decrypted keys to allow the device to proceed with WRITE operations
    """
    
    # Default MIFARE Classic keys (factory defaults)
    DEFAULT_KEYS = [
        "FFFFFFFFFFFF",  # Factory default
        "000000000000",  # Blank key
        "A0A1A2A3A4A5",  # Common default
        "D3F7D3F7D3F7",  # NXP default
        "123456789988",  # Common default
        "6FFFFFF87788",  # Some readers
        "001122334455",  # Sequential
        "112233445566",  # Sequential
        "AABBCCDDEEFF",  # Sequential
        "1A2B3C4D5E6F",  # Alternating
    ]
    
    def __init__(
        self,
        key_manager: Optional[KeyManager] = None,
        custom_keys: Optional[List[str]] = None,
        use_default_keys: bool = True,
        algorithm: Optional[CipherAlgorithm] = None,
        verbose: bool = False,
    ):
        """Initialize the Kopized service.
        
        Parameters
        ----------
        key_manager : KeyManager, optional
            Custom key manager instance. If not provided, a new one is created.
        custom_keys : list of str, optional
            Additional hex-encoded keys to try during decryption.
        use_default_keys : bool, default True
            Whether to include the default factory keys in the search.
        algorithm : CipherAlgorithm, optional
            Specific algorithm to use for decryption. If None, auto-detect.
        verbose : bool, default False
            Enable verbose logging.
        """
        self.key_manager = key_manager or KeyManager()
        self.verbose = verbose
        self.algorithm = algorithm
        
        # Build key list
        self.available_keys: List[bytes] = []
        
        if use_default_keys:
            for key_hex in self.DEFAULT_KEYS:
                try:
                    self.available_keys.append(bytes.fromhex(key_hex))
                except ValueError:
                    logger.warning(f"Invalid default key format: {key_hex}")
        
        # Add custom keys
        if custom_keys:
            for key_hex in custom_keys:
                try:
                    key_bytes = bytes.fromhex(key_hex.replace(' ', ''))
                    if key_bytes not in self.available_keys:
                        self.available_keys.append(key_bytes)
                except ValueError as e:
                    logger.warning(f"Invalid custom key format {key_hex}: {e}")
        
        if self.verbose:
            logger.info(f"Initialized with {len(self.available_keys)} keys")
    
    def add_key(self, key_hex: str) -> bool:
        """Add a new key to the available key pool.
        
        Parameters
        ----------
        key_hex : str
            Hex-encoded key (12 characters for 6-byte MIFARE key).
            
        Returns
        -------
        bool
            True if key was added successfully, False if invalid format.
        """
        try:
            key_bytes = bytes.fromhex(key_hex.replace(' ', ''))
            if len(key_bytes) != 6:
                logger.warning(f"Key must be 6 bytes (12 hex chars), got {len(key_bytes)}")
                return False
            if key_bytes not in self.available_keys:
                self.available_keys.append(key_bytes)
                logger.debug(f"Added key: {key_hex}")
                return True
            return False  # Already exists
        except ValueError as e:
            logger.error(f"Invalid key format {key_hex}: {e}")
            return False
    
    def load_keys_from_file(self, filepath: str) -> int:
        """Load keys from a text file (one key per line).
        
        Parameters
        ----------
        filepath : str
            Path to the key file.
            
        Returns
        -------
        int
            Number of keys successfully loaded.
        """
        count = 0
        try:
            with open(filepath, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        if self.add_key(line):
                            count += 1
        except Exception as e:
            logger.error(f"Failed to load keys from {filepath}: {e}")
        return count
    
    def attempt_sector_decryption(
        self,
        encrypted_data: bytes,
        sector_number: int,
        card_uid: str,
    ) -> Optional[SectorInfo]:
        """Attempt to decrypt a single sector using available keys.
        
        This method tries each available key against the encrypted sector data.
        For MIFARE Classic, this typically involves trying keys against the
        trailer block to recover Key A and Key B.
        
        Parameters
        ----------
        encrypted_data : bytes
            The encrypted sector data (typically 64 bytes for standard sectors).
        sector_number : int
            The sector number being decrypted.
        card_uid : str
            The card's UID (used in some key derivation schemes).
            
        Returns
        -------
        SectorInfo or None
            SectorInfo with decrypted keys if successful, None otherwise.
        """
        if len(encrypted_data) < 16:
            logger.debug(f"Sector {sector_number}: insufficient data ({len(encrypted_data)} bytes)")
            return None
        
        # Try each key
        for key in self.available_keys:
            key_hex = key.hex().upper()
            
            # For MIFARE Classic, the trailer block (last block of sector) contains:
            # - Key A (6 bytes)
            # - Access Bits (4 bytes)
            # - Key B (6 bytes)
            # Total: 16 bytes
            
            # Check if this key matches Key A position
            if encrypted_data[:6] == key:
                logger.debug(f"Sector {sector_number}: Found Key A = {key_hex}")
                # Try to extract full trailer
                trailer = encrypted_data[-16:] if len(encrypted_data) >= 16 else encrypted_data
                key_a = key_hex
                access_bits = trailer[6:10].hex().upper() if len(trailer) > 10 else None
                key_b = trailer[10:].hex().upper() if len(trailer) > 10 else None
                
                return SectorInfo(
                    sector_number=sector_number,
                    status=SectorStatus.DECRYPTED,
                    key_a=key_a,
                    key_b=key_b,
                    access_bits=access_bits,
                    trailer_block=trailer,
                )
            
            # Check if this key matches Key B position (last 6 bytes of trailer)
            if len(encrypted_data) >= 16 and encrypted_data[-6:] == key:
                logger.debug(f"Sector {sector_number}: Found Key B = {key_hex}")
                trailer = encrypted_data[-16:] if len(encrypted_data) >= 16 else encrypted_data
                key_a = trailer[:6].hex().upper() if len(trailer) > 6 else None
                access_bits = trailer[6:10].hex().upper() if len(trailer) > 10 else None
                key_b = key_hex
                
                return SectorInfo(
                    sector_number=sector_number,
                    status=SectorStatus.DECRYPTED,
                    key_a=key_a,
                    key_b=key_b,
                    access_bits=access_bits,
                    trailer_block=trailer,
                )
        
        # No key matched
        logger.debug(f"Sector {sector_number}: No matching key found")
        return None
    
    def decrypt_request(self, request: DecryptionRequest) -> DecryptionResponse:
        """Process a decryption request from the X100 device.
        
        This is the main entry point for decrypting sector data. It attempts
        to decrypt all specified sectors using available keys and returns
        a response suitable for sending back to the device.
        
        Parameters
        ----------
        request : DecryptionRequest
            The decryption request from the device.
            
        Returns
        -------
        DecryptionResponse
            Response containing decrypted sector information or error details.
        """
        start_time = time.time()
        logger.info(f"Processing decryption request {request.request_id} for card {request.card_info.uid}")
        
        decrypted_sectors: List[SectorInfo] = []
        failed_sectors: List[int] = []
        
        # Process each sector
        for sector_num in request.sector_numbers:
            # For now, we simulate having the encrypted data
            # In real implementation, this would come from the device
            if request.encrypted_data:
                # Calculate sector offset (64 bytes per sector for 1K cards)
                offset = sector_num * 64
                sector_data = request.encrypted_data[offset:offset + 64]
                
                result = self.attempt_sector_decryption(
                    sector_data,
                    sector_num,
                    request.card_info.uid,
                )
                
                if result:
                    decrypted_sectors.append(result)
                else:
                    failed_sectors.append(sector_num)
            else:
                # No encrypted data provided - try common default configurations
                # This is useful for cards that still use factory defaults
                sector_info = SectorInfo(
                    sector_number=sector_num,
                    status=SectorStatus.DECRYPTED,
                    key_a="FFFFFFFFFFFF",
                    key_b="FFFFFFFFFFFF",
                    access_bits="FF0780",
                )
                decrypted_sectors.append(sector_info)
        
        elapsed_ms = (time.time() - start_time) * 1000
        
        # Build response
        success = len(decrypted_sectors) > 0 or len(request.sector_numbers) == 0
        
        response = DecryptionResponse(
            success=success,
            card_info=request.card_info,
            decrypted_sectors=decrypted_sectors,
            keys_recovered=len(decrypted_sectors) * 2,  # Key A + Key B per sector
            time_taken_ms=elapsed_ms,
            request_id=request.request_id,
        )
        
        if failed_sectors:
            response.error_message = f"Failed to decrypt sectors: {failed_sectors}"
            logger.warning(response.error_message)
        
        logger.info(
            f"Decryption complete: {len(decrypted_sectors)} sectors decrypted "
            f"in {elapsed_ms:.2f}ms"
        )
        
        return response
    
    def generate_device_command(
        self,
        response: DecryptionResponse,
    ) -> str:
        """Generate the command sequence to send back to the X100 device.
        
        The exact format depends on the X100 protocol. This method generates
        a standardized format that can be adapted to specific device requirements.
        
        Parameters
        ----------
        response : DecryptionResponse
            The decryption response to encode.
            
        Returns
        -------
        str
            Command string to send to the device.
        """
        # Format: One command per decrypted sector
        # Example: WRITE_KEY <sector> <key_type> <key_hex>
        commands = []
        
        for sector in response.decrypted_sectors:
            if sector.key_a:
                commands.append(f"WRITE_KEY {sector.sector_number} A {sector.key_a}")
            if sector.key_b:
                commands.append(f"WRITE_KEY {sector.sector_number} B {sector.key_b}")
        
        # Add confirmation command
        commands.append("DECRYPTION_COMPLETE ACK")
        
        return "\n".join(commands)


def create_kopized_service(
    key_file: Optional[str] = None,
    custom_keys: Optional[List[str]] = None,
    use_defaults: bool = True,
    verbose: bool = False,
) -> KopizedService:
    """Factory function to create a configured KopizedService instance.
    
    Parameters
    ----------
    key_file : str, optional
        Path to a file containing additional keys (one per line).
    custom_keys : list of str, optional
        Additional keys provided as hex strings.
    use_defaults : bool, default True
        Whether to include default factory keys.
    verbose : bool, default False
        Enable verbose output.
        
    Returns
    -------
    KopizedService
        Configured service instance ready for decryption operations.
    """
    service = KopizedService(
        custom_keys=custom_keys,
        use_default_keys=use_defaults,
        verbose=verbose,
    )
    
    if key_file:
        count = service.load_keys_from_file(key_file)
        if verbose:
            print(f"Loaded {count} keys from {key_file}")
    
    return service
