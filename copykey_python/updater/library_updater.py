"""
CopyKEY Python Tool - Updater Module

Card Format & Key Database Update Handler
CONTROLLED NETWORK ACCESS - Only for library updates
"""
import requests
import json
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional

from config.network_policy import (
    is_network_request_allowed,
    NetworkPermission,
    validate_url_for_purpose
)

logger = logging.getLogger(__name__)


class LibraryUpdater:
    """
    Updates card format definitions and default key databases.
    
    ONLY network communication allowed: library downloads from whitelisted endpoints.
    All other operations are offline.
    """
    
    # Whitelisted endpoints - ONLY for libraries
    CARD_FORMATS_URL = "https://copykey.hyctec.cn/libraries/card_formats.json"
    DEFAULT_KEYS_URL = "https://copykey.hyctec.cn/libraries/default_keys.json"
    
    def __init__(self, library_dir: Path = None):
        """
        Initialize library updater.
        
        Args:
            library_dir: Directory to store downloaded libraries
        """
        if library_dir is None:
            library_dir = Path.home() / '.copykey' / 'libraries'
        self.library_dir = Path(library_dir)
        self.library_dir.mkdir(parents=True, exist_ok=True)
    
    def update_card_formats(self) -> bool:
        """
        Download latest card format definitions.
        
        Returns:
            True if successful
        """
        # Validate URL
        allowed, reason = validate_url_for_purpose(
            self.CARD_FORMATS_URL,
            NetworkPermission.LIBRARY_UPDATE
        )
        
        if not allowed:
            logger.error(f"Card formats update blocked: {reason}")
            return False
        
        try:
            response = requests.get(self.CARD_FORMATS_URL, timeout=10)
            response.raise_for_status()
            
            formats = response.json()
            
            # Save to local library
            output_path = self.library_dir / 'card_formats.json'
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(formats, f, indent=2, ensure_ascii=False)
            
            format_count = len(formats.get('formats', []))
            logger.info(f"Updated card formats: {format_count} types saved to {output_path}")
            return True
            
        except requests.RequestException as e:
            logger.warning(f"Card format update failed: {e}")
            return False
        except Exception as e:
            logger.error(f"Card format update error: {e}")
            return False
    
    def update_default_keys(self) -> bool:
        """
        Download updated default key database.
        
        Returns:
            True if successful
        """
        # Validate URL
        allowed, reason = validate_url_for_purpose(
            self.DEFAULT_KEYS_URL,
            NetworkPermission.LIBRARY_UPDATE
        )
        
        if not allowed:
            logger.error(f"Default keys update blocked: {reason}")
            return False
        
        try:
            response = requests.get(self.DEFAULT_KEYS_URL, timeout=10)
            response.raise_for_status()
            
            keys_data = response.json()
            
            # Save to local library
            output_path = self.library_dir / 'default_keys.json'
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(keys_data, f, indent=2, ensure_ascii=False)
            
            key_count = len(keys_data.get('keys', []))
            logger.info(f"Updated default keys: {key_count} keys saved to {output_path}")
            return True
            
        except requests.RequestException as e:
            logger.warning(f"Default keys update failed: {e}")
            return False
        except Exception as e:
            logger.error(f"Default keys update error: {e}")
            return False
    
    def load_card_formats(self) -> Dict[str, Any]:
        """
        Load card formats from local library.
        
        Returns:
            Card formats dictionary or empty dict if not found
        """
        path = self.library_dir / 'card_formats.json'
        if path.exists():
            try:
                with open(path, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception as e:
                logger.error(f"Failed to load card formats: {e}")
                return {'formats': []}
        
        logger.debug("No card formats file found")
        return {'formats': []}
    
    def load_default_keys(self) -> List[bytes]:
        """
        Load default keys from local library.
        
        Returns:
            List of 6-byte keys or empty list if not found
        """
        path = self.library_dir / 'default_keys.json'
        if path.exists():
            try:
                with open(path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    keys = []
                    for key_hex in data.get('keys', []):
                        try:
                            key_bytes = bytes.fromhex(key_hex.replace(' ', '').replace(':', ''))
                            if len(key_bytes) == 6:
                                keys.append(key_bytes)
                        except ValueError:
                            logger.warning(f"Invalid key format: {key_hex}")
                    return keys
            except Exception as e:
                logger.error(f"Failed to load default keys: {e}")
                return []
        
        logger.debug("No default keys file found")
        return []
    
    def get_card_format(self, format_name: str) -> Optional[Dict[str, Any]]:
        """
        Get specific card format by name.
        
        Args:
            format_name: Name of the card format
            
        Returns:
            Format definition or None if not found
        """
        formats = self.load_card_formats()
        for fmt in formats.get('formats', []):
            if fmt.get('name', '').lower() == format_name.lower():
                return fmt
        return None
    
    def get_supported_card_types(self) -> List[str]:
        """
        Get list of supported card type names.
        
        Returns:
            List of card type names
        """
        formats = self.load_card_formats()
        return [fmt.get('name', 'Unknown') for fmt in formats.get('formats', [])]
    
    def save_custom_key(self, key: bytes, label: str = '') -> bool:
        """
        Save a custom key to local custom keys file.
        
        Args:
            key: 6-byte key
            label: Optional label for the key
            
        Returns:
            True if successful
        """
        if len(key) != 6:
            logger.error("Key must be 6 bytes")
            return False
        
        custom_keys_path = self.library_dir / 'custom_keys.json'
        
        # Load existing keys
        custom_keys = []
        if custom_keys_path.exists():
            try:
                with open(custom_keys_path, 'r') as f:
                    custom_keys = json.load(f)
            except:
                custom_keys = []
        
        # Add new key
        key_entry = {
            'key': key.hex(),
            'label': label,
            'added': str(Path.home())
        }
        
        # Avoid duplicates
        key_hex = key.hex()
        if not any(k.get('key', '').lower() == key_hex.lower() for k in custom_keys):
            custom_keys.append(key_entry)
            
            with open(custom_keys_path, 'w') as f:
                json.dump(custom_keys, f, indent=2)
            
            logger.info(f"Saved custom key: {label or 'unnamed'}")
            return True
        
        logger.debug("Key already exists in custom keys")
        return True
    
    def load_custom_keys(self) -> List[bytes]:
        """
        Load custom keys from local file.
        
        Returns:
            List of 6-byte keys
        """
        custom_keys_path = self.library_dir / 'custom_keys.json'
        if custom_keys_path.exists():
            try:
                with open(custom_keys_path, 'r') as f:
                    data = json.load(f)
                    keys = []
                    for entry in data:
                        try:
                            key_bytes = bytes.fromhex(entry['key'])
                            if len(key_bytes) == 6:
                                keys.append(key_bytes)
                        except (ValueError, KeyError):
                            pass
                    return keys
            except Exception as e:
                logger.error(f"Failed to load custom keys: {e}")
                return []
        return []
    
    def get_all_keys(self) -> List[Dict[str, Any]]:
        """
        Get all available keys (default + custom) with metadata.
        
        Returns:
            List of key dictionaries with source information
        """
        keys = []
        
        # Load default keys
        default_keys = self.load_default_keys()
        for key in default_keys:
            keys.append({
                'key': key,
                'source': 'default',
                'label': 'Default key'
            })
        
        # Load custom keys
        custom_keys_path = self.library_dir / 'custom_keys.json'
        if custom_keys_path.exists():
            try:
                with open(custom_keys_path, 'r') as f:
                    data = json.load(f)
                    for entry in data:
                        try:
                            key_bytes = bytes.fromhex(entry['key'])
                            if len(key_bytes) == 6:
                                keys.append({
                                    'key': key_bytes,
                                    'source': 'custom',
                                    'label': entry.get('label', 'Custom key')
                                })
                        except (ValueError, KeyError):
                            pass
            except:
                pass
        
        return keys
