"""
CopyKEY Python Tool - Core Module

USB HID Communication with NFC Reader/Writer Device
NO NETWORK COMMUNICATION - 100% offline operation
"""
import logging
from typing import Optional, List, Dict, Any

try:
    import hid
    HID_AVAILABLE = True
except ImportError:
    HID_AVAILABLE = False
    logging.warning("hidapi not installed. Install with: pip install hidapi")

logger = logging.getLogger(__name__)


class CopyKeyDevice:
    """
    USB HID communication layer for CopyKEY-compatible devices.
    
    This class handles all hardware communication and is completely offline.
    No network calls are made from this module.
    """
    
    # Default VID/PID - should be overridden based on actual device
    DEFAULT_VID = 0x0483  # Example: STM32
    DEFAULT_PID = 0x5740
    
    def __init__(self, vid: int = None, pid: int = None):
        """
        Initialize device interface.
        
        Args:
            vid: Vendor ID (default: 0x0483)
            pid: Product ID (default: 0x5740)
        """
        self.vid = vid or self.DEFAULT_VID
        self.pid = pid or self.DEFAULT_PID
        self.device = None
        self.device_path = None
        self.manufacturer = None
        self.product = None
        self.serial = None
        
        if not HID_AVAILABLE:
            logger.error("hidapi library not available")
            raise ImportError("hidapi library required. Install with: pip install hidapi")
    
    def enumerate_devices(self) -> List[Dict[str, Any]]:
        """
        List all connected compatible devices.
        
        Returns:
            List of device information dictionaries
        """
        try:
            devices = hid.enumerate(self.vid, self.pid)
            logger.info(f"Found {len(devices)} compatible device(s)")
            return devices
        except Exception as e:
            logger.error(f"Error enumerating devices: {e}")
            return []
    
    def connect(self, path: str = None) -> bool:
        """
        Open connection to device.
        
        Args:
            path: Device path (if None, connects to first available)
            
        Returns:
            True if connection successful
        """
        try:
            if path:
                self.device_path = path
                self.device = hid.Device(path)
            else:
                devices = self.enumerate_devices()
                if not devices:
                    logger.warning("No compatible devices found")
                    return False
                
                self.device_path = devices[0]['path']
                self.device = hid.Device(self.device_path)
            
            # Get device information
            try:
                self.manufacturer = self.device.get_manufacturer_string()
                self.product = self.device.get_product_string()
                self.serial = self.device.get_serial_number_string()
            except Exception as e:
                logger.warning(f"Could not get device info: {e}")
            
            logger.info(f"Connected to device: {self.product} ({self.serial})")
            return True
            
        except Exception as e:
            logger.error(f"Failed to connect to device: {e}")
            self.device = None
            return False
    
    def disconnect(self):
        """Close device connection"""
        if self.device:
            try:
                self.device.close()
            except Exception as e:
                logger.warning(f"Error closing device: {e}")
            finally:
                self.device = None
                self.device_path = None
            logger.info("Device disconnected")
    
    def is_connected(self) -> bool:
        """Check if device is connected"""
        return self.device is not None
    
    def send_feature_report(self, data: bytes) -> bool:
        """
        Send HID feature report to device.
        
        Args:
            data: Report data (must include report_id as first byte)
            
        Returns:
            True if successful
        """
        if not self.device:
            logger.error("Device not connected")
            return False
        
        try:
            self.device.send_feature_report(data)
            logger.debug(f"Sent feature report: {data.hex()}")
            return True
        except Exception as e:
            logger.error(f"Failed to send feature report: {e}")
            return False
    
    def get_feature_report(self, report_id: int, length: int = 64) -> Optional[bytes]:
        """
        Get HID feature report from device.
        
        Args:
            report_id: Report ID to request
            length: Expected response length
            
        Returns:
            Response data or None if failed
        """
        if not self.device:
            logger.error("Device not connected")
            return None
        
        try:
            data = self.device.get_feature_report(report_id, length)
            logger.debug(f"Received feature report: {data.hex()}")
            return data
        except Exception as e:
            logger.error(f"Failed to get feature report: {e}")
            return None
    
    def write(self, data: bytes) -> int:
        """
        Write data to device via output report.
        
        Args:
            data: Data to write
            
        Returns:
            Number of bytes written
        """
        if not self.device:
            logger.error("Device not connected")
            return 0
        
        try:
            # Prepend report ID (0x00 for most devices)
            report_data = b'\x00' + data
            bytes_written = self.device.write(report_data)
            logger.debug(f"Wrote {bytes_written} bytes")
            return bytes_written
        except Exception as e:
            logger.error(f"Failed to write to device: {e}")
            return 0
    
    def read(self, length: int = 64, timeout_ms: int = 1000) -> Optional[bytes]:
        """
        Read data from device via input report.
        
        Args:
            length: Maximum bytes to read
            timeout_ms: Read timeout in milliseconds
            
        Returns:
            Response data or None if timeout/failed
        """
        if not self.device:
            logger.error("Device not connected")
            return None
        
        try:
            data = self.device.read(length, timeout_ms)
            if data:
                logger.debug(f"Read {len(data)} bytes: {data.hex()}")
            return bytes(data) if data else None
        except Exception as e:
            logger.error(f"Failed to read from device: {e}")
            return None
    
    # High-level device commands
    
    def read_card(self) -> Optional[Dict[str, Any]]:
        """
        Read card data from device.
        
        Returns:
            Card data dictionary or None if failed
        """
        if not self.is_connected():
            logger.error("Device not connected")
            return None
        
        # Send read command (protocol-specific)
        # This is a placeholder - actual protocol needs reverse engineering
        cmd = bytes([0x01, 0x00, 0x00, 0x00])  # Example: READ_CARD command
        
        try:
            self.write(cmd)
            response = self.read(timeout_ms=5000)
            
            if response:
                # Parse response (protocol-specific)
                return self._parse_read_response(response)
            return None
        except Exception as e:
            logger.error(f"Read card failed: {e}")
            return None
    
    def write_card(self, card_data: Dict[str, Any]) -> bool:
        """
        Write card data to blank card.
        
        Args:
            card_data: Card data to write
            
        Returns:
            True if successful
        """
        if not self.is_connected():
            logger.error("Device not connected")
            return False
        
        # Send write command (protocol-specific)
        # This is a placeholder - actual protocol needs reverse engineering
        cmd = bytes([0x02]) + self._serialize_card_data(card_data)
        
        try:
            self.write(cmd)
            response = self.read(timeout_ms=10000)
            
            if response and response[0] == 0x00:  # Success response
                logger.info("Card write successful")
                return True
            else:
                logger.error("Card write failed")
                return False
        except Exception as e:
            logger.error(f"Write card failed: {e}")
            return False
    
    def decode_card(self, key_list: List[bytes] = None) -> Optional[Dict[str, Any]]:
        """
        Decode locked sectors using provided keys.
        
        Args:
            key_list: List of 6-byte keys to try
            
        Returns:
            Decoded card data or None if failed
        """
        if not self.is_connected():
            logger.error("Device not connected")
            return None
        
        # Build decode command with keys
        keys_data = b''
        if key_list:
            for key in key_list:
                if len(key) == 6:
                    keys_data += key
        
        cmd = bytes([0x03, len(key_list) if key_list else 0]) + keys_data
        
        try:
            self.write(cmd)
            # Decoding may take time
            response = self.read(timeout_ms=30000)
            
            if response:
                return self._parse_decode_response(response)
            return None
        except Exception as e:
            logger.error(f"Decode card failed: {e}")
            return None
    
    def get_device_info(self) -> Optional[Dict[str, str]]:
        """
        Get device information.
        
        Returns:
            Dictionary with manufacturer, product, serial
        """
        return {
            'manufacturer': self.manufacturer,
            'product': self.product,
            'serial': self.serial,
            'path': self.device_path.decode() if self.device_path else None
        }
    
    # Protocol-specific parsing (to be implemented based on reverse engineering)
    
    def _parse_read_response(self, response: bytes) -> Optional[Dict[str, Any]]:
        """Parse read card response - protocol specific"""
        # Placeholder implementation
        # Actual implementation requires protocol reverse engineering
        return {
            'uid': response[1:5].hex() if len(response) > 4 else None,
            'raw_data': response.hex(),
            'status': 'success' if response[0] == 0x00 else 'error'
        }
    
    def _parse_decode_response(self, response: bytes) -> Optional[Dict[str, Any]]:
        """Parse decode response - protocol specific"""
        # Placeholder implementation
        return {
            'decoded': True,
            'raw_data': response.hex()
        }
    
    def _serialize_card_data(self, card_data: Dict[str, Any]) -> bytes:
        """Serialize card data for writing - protocol specific"""
        # Placeholder implementation
        return card_data.get('raw_data', '').encode() if isinstance(card_data.get('raw_data'), str) else b''
    
    def __enter__(self):
        """Context manager entry"""
        self.connect()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.disconnect()
        return False
