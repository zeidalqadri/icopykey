"""
CopyKEY Python Tool - Updater Module

Firmware Update Handler
CONTROLLED NETWORK ACCESS - Only for firmware downloads
"""
import requests
import hashlib
import logging
from pathlib import Path
from typing import Optional, Dict, Any

from config.network_policy import (
    is_network_request_allowed,
    NetworkPermission,
    validate_url_for_purpose
)

logger = logging.getLogger(__name__)


class FirmwareUpdater:
    """
    Handles firmware updates for CopyKEY device.
    
    ONLY network communication allowed: firmware download from whitelisted endpoint.
    All other operations are offline.
    """
    
    # Whitelisted endpoint - ONLY for firmware
    FIRMWARE_URL = "https://copykey.hyctec.cn/firmware/latest.json"
    
    def __init__(self):
        self.current_version: Optional[str] = None
        self.latest_version: Optional[str] = None
    
    def check_for_updates(self, current_version: str) -> Dict[str, Any]:
        """
        Check for available firmware updates.
        
        Args:
            current_version: Current firmware version string (e.g., "1.2.3")
            
        Returns:
            Dictionary with update info or {'available': False}
        """
        # Validate URL before making request
        allowed, reason = validate_url_for_purpose(
            self.FIRMWARE_URL, 
            NetworkPermission.FIRMWARE_UPDATE
        )
        
        if not allowed:
            logger.error(f"Firmware update URL blocked: {reason}")
            return {'available': False, 'error': 'Network policy violation'}
        
        try:
            response = requests.get(self.FIRMWARE_URL, timeout=10)
            response.raise_for_status()
            data = response.json()
            
            latest_ver = data.get('version', '0.0.0')
            
            if self._compare_versions(latest_ver, current_version) > 0:
                update_info = {
                    'available': True,
                    'version': latest_ver,
                    'url': data.get('download_url'),
                    'hash': data.get('sha256'),
                    'notes': data.get('release_notes', ''),
                    'size': data.get('size', 0)
                }
                
                # Validate download URL
                if update_info['url']:
                    url_allowed, url_reason = validate_url_for_purpose(
                        update_info['url'],
                        NetworkPermission.FIRMWARE_UPDATE
                    )
                    if not url_allowed:
                        logger.error(f"Firmware download URL blocked: {url_reason}")
                        return {'available': False, 'error': 'Download URL not allowed'}
                
                logger.info(f"Firmware update available: {current_version} -> {latest_ver}")
                return update_info
            
            logger.info(f"Firmware is up to date: {current_version}")
            return {'available': False}
            
        except requests.RequestException as e:
            logger.warning(f"Firmware update check failed (offline?): {e}")
            return {'available': False, 'error': str(e)}
        except Exception as e:
            logger.error(f"Firmware update check error: {e}")
            return {'available': False, 'error': str(e)}
    
    def download_firmware(self, url: str, dest_path: Path, 
                         progress_callback=None) -> bool:
        """
        Download firmware file with progress tracking.
        
        Args:
            url: Firmware download URL
            dest_path: Destination file path
            progress_callback: Optional callback(progress_percent, downloaded, total)
            
        Returns:
            True if successful
        """
        # Validate URL
        allowed, reason = validate_url_for_purpose(
            url,
            NetworkPermission.FIRMWARE_UPDATE
        )
        
        if not allowed:
            logger.error(f"Firmware download blocked: {reason}")
            return False
        
        try:
            response = requests.get(url, stream=True, timeout=30)
            response.raise_for_status()
            
            total_size = int(response.headers.get('content-length', 0))
            downloaded = 0
            
            dest_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(dest_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)
                        downloaded += len(chunk)
                        
                        if progress_callback and total_size:
                            progress = (downloaded / total_size) * 100
                            progress_callback(progress, downloaded, total_size)
            
            logger.info(f"Firmware downloaded: {dest_path} ({downloaded} bytes)")
            return True
            
        except requests.RequestException as e:
            logger.error(f"Firmware download failed: {e}")
            return False
        except Exception as e:
            logger.error(f"Firmware download error: {e}")
            return False
    
    def verify_firmware(self, file_path: Path, expected_hash: str) -> bool:
        """
        Verify firmware integrity with SHA-256.
        
        Args:
            file_path: Path to downloaded firmware file
            expected_hash: Expected SHA-256 hash
            
        Returns:
            True if hash matches
        """
        if not file_path.exists():
            logger.error(f"Firmware file not found: {file_path}")
            return False
        
        try:
            sha256 = hashlib.sha256()
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(8192), b''):
                    sha256.update(chunk)
            
            actual_hash = sha256.hexdigest()
            
            if actual_hash.lower() == expected_hash.lower():
                logger.info("Firmware verification successful")
                return True
            else:
                logger.error(f"Firmware verification failed!")
                logger.error(f"  Expected: {expected_hash}")
                logger.error(f"  Actual:   {actual_hash}")
                return False
                
        except Exception as e:
            logger.error(f"Firmware verification error: {e}")
            return False
    
    def _compare_versions(self, v1: str, v2: str) -> int:
        """
        Compare version strings.
        
        Returns:
            Positive if v1 > v2, negative if v1 < v2, 0 if equal
        """
        def normalize(v):
            try:
                return [int(x) for x in v.split('.')]
            except ValueError:
                # Handle non-numeric versions
                return v.split('.')
        
        parts1 = normalize(v1)
        parts2 = normalize(v2)
        
        for p1, p2 in zip(parts1, parts2):
            if isinstance(p1, int) and isinstance(p2, int):
                if p1 > p2:
                    return 1
                elif p1 < p2:
                    return -1
            else:
                # String comparison for non-numeric parts
                if str(p1) > str(p2):
                    return 1
                elif str(p1) < str(p2):
                    return -1
        
        return len(parts1) - len(parts2)
    
    def install_firmware(self, firmware_path: Path, device) -> bool:
        """
        Install firmware on device.
        
        Note: Implementation depends on device-specific protocol.
        This is a placeholder for the actual installation logic.
        
        Args:
            firmware_path: Path to firmware file
            device: CopyKeyDevice instance
            
        Returns:
            True if installation successful
        """
        logger.warning("Firmware installation not yet implemented")
        logger.warning("This requires device-specific protocol implementation")
        return False
