"""
CopyKEY Python Tool - Core Package
Offline-first NFC card copying utilities
"""

__version__ = "0.1.0"
__author__ = "CopyKEY Python Team"
__license__ = "MIT"

# Network policy is enforced at the package level
from config.network_policy import (
    NetworkPermission,
    is_network_request_allowed,
    get_allowed_endpoints,
    audit_network_calls
)

__all__ = [
    'NetworkPermission',
    'is_network_request_allowed',
    'get_allowed_endpoints',
    'audit_network_calls',
]
