"""
CopyKEY Python Tool - Network Policy Enforcement

This module enforces strict network access control.
ONLY firmware updates and library updates are permitted.
All other network communications are blocked.
"""
from enum import Enum
from typing import Set, Optional
from urllib.parse import urlparse
import logging

logger = logging.getLogger(__name__)


class NetworkPermission(Enum):
    """Allowed network permissions"""
    FIRMWARE_UPDATE = "firmware"
    LIBRARY_UPDATE = "library"
    VERSION_CHECK = "version"


# Explicitly whitelisted hosts
ALLOWED_HOSTS: Set[str] = {
    "copykey.hyctec.cn",  # ONLY for firmware and libraries
}

# Whitelisted path prefixes
ALLOWED_PATHS: Set[str] = {
    "/firmware/",
    "/libraries/",
    "/version.json",
}

# Explicitly blacklisted paths (defense in depth)
DENIED_PATHS: Set[str] = {
    "/api/auth/",
    "/api/user/",
    "/api/cloud/",
    "/api/analytics/",
    "/api/chat/",
    "/api/sync/",
    "/api/telemetry/",
    "/login",
    "/register",
    "/user/",
    "/cloud/",
}

# Denied host patterns
DENIED_HOSTS: Set[str] = {
    "client.copykey.hyctec.cn",  # Explicitly blocked
}


def is_network_request_allowed(url: str, purpose: Optional[NetworkPermission] = None) -> bool:
    """
    Validate if a network request is permitted.
    
    Args:
        url: The URL to validate
        purpose: The intended purpose of the request
        
    Returns:
        True only for whitelisted firmware/library updates
        
    Raises:
        ValueError: If URL is invalid
    """
    try:
        parsed = urlparse(url)
    except Exception as e:
        logger.error(f"Invalid URL: {url} - {e}")
        return False
    
    # Check if URL has valid scheme
    if parsed.scheme not in ('https', 'http'):
        logger.warning(f"Invalid scheme: {parsed.scheme}")
        return False
    
    hostname = parsed.hostname
    if not hostname:
        logger.warning(f"No hostname in URL: {url}")
        return False
    
    # Check explicit deny list first (defense in depth)
    if hostname in DENIED_HOSTS:
        logger.warning(f"Request blocked - denied host: {hostname}")
        return False
    
    # Check path deny list
    for denied_path in DENIED_PATHS:
        if parsed.path.startswith(denied_path):
            logger.warning(f"Request blocked - denied path: {denied_path}")
            return False
    
    # Check host whitelist
    if hostname not in ALLOWED_HOSTS:
        logger.warning(f"Request blocked - host not whitelisted: {hostname}")
        return False
    
    # Check path whitelist
    path_allowed = any(parsed.path.startswith(p) for p in ALLOWED_PATHS)
    if not path_allowed:
        logger.warning(f"Request blocked - path not whitelisted: {parsed.path}")
        return False
    
    # Verify purpose matches path (additional validation)
    if purpose:
        if purpose == NetworkPermission.FIRMWARE_UPDATE:
            if not parsed.path.startswith("/firmware/"):
                logger.warning(f"Purpose mismatch: FIRMWARE_UPDATE but path is {parsed.path}")
                return False
        elif purpose == NetworkPermission.LIBRARY_UPDATE:
            if not parsed.path.startswith("/libraries/"):
                logger.warning(f"Purpose mismatch: LIBRARY_UPDATE but path is {parsed.path}")
                return False
    
    logger.info(f"Network request allowed: {purpose.value if purpose else 'unspecified'} -> {url}")
    return True


def get_allowed_endpoints() -> dict:
    """
    Return dictionary of allowed endpoints for documentation.
    
    Returns:
        Dict with allowed hosts and paths
    """
    return {
        "allowed_hosts": list(ALLOWED_HOSTS),
        "allowed_paths": list(ALLOWED_PATHS),
        "denied_hosts": list(DENIED_HOSTS),
        "denied_paths": list(DENIED_PATHS),
        "policy": "offline_first",
        "description": "Only firmware and library updates are permitted. All other operations are offline."
    }


def validate_url_for_purpose(url: str, purpose: NetworkPermission) -> tuple[bool, str]:
    """
    Validate URL for a specific purpose and return detailed result.
    
    Args:
        url: URL to validate
        purpose: Intended purpose
        
    Returns:
        Tuple of (is_allowed, reason_message)
    """
    if not is_network_request_allowed(url, purpose):
        return False, f"URL not allowed for {purpose.value}"
    
    parsed = urlparse(url)
    
    if purpose == NetworkPermission.FIRMWARE_UPDATE:
        if not parsed.path.startswith("/firmware/"):
            return False, "Firmware updates must use /firmware/ path"
    
    elif purpose == NetworkPermission.LIBRARY_UPDATE:
        if not parsed.path.startswith("/libraries/"):
            return False, "Library updates must use /libraries/ path"
    
    return True, "URL validated successfully"


# Security audit helper
def audit_network_calls(code_path: str) -> list:
    """
    Scan Python code file for potential network calls.
    This is a static analysis helper for security audits.
    
    Args:
        code_path: Path to Python file to audit
        
    Returns:
        List of potential issues found
    """
    import re
    
    issues = []
    network_patterns = [
        (r'requests\.(get|post|put|delete|patch)\s*\(', 'requests call'),
        (r'urllib\.request\.(urlopen|Request)\s*\(', 'urllib call'),
        (r'httpx\.(get|post|put|delete|patch)\s*\(', 'httpx call'),
        (r'aiohttp\.ClientSession\(\)', 'aiohttp session'),
    ]
    
    try:
        with open(code_path, 'r') as f:
            content = f.read()
            lines = content.split('\n')
            
        for line_num, line in enumerate(lines, 1):
            # Skip comments
            if line.strip().startswith('#'):
                continue
            
            for pattern, description in network_patterns:
                if re.search(pattern, line):
                    # Check if it's in updater module (allowed)
                    if '/updater/' not in code_path:
                        issues.append({
                            'line': line_num,
                            'code': line.strip(),
                            'issue': f'Potential unauthorized {description}',
                            'file': code_path
                        })
        
        # Check for prohibited endpoint references
        prohibited_strings = [
            'client.copykey.hyctec.cn',
            '/api/auth/',
            '/api/user/',
            '/api/cloud/',
        ]
        
        for prov_str in prohibited_strings:
            if prov_str in content:
                issues.append({
                    'line': None,
                    'code': f'Reference to: {prov_str}',
                    'issue': 'Prohibited endpoint reference found',
                    'file': code_path
                })
                
    except FileNotFoundError:
        issues.append({'issue': f'File not found: {code_path}'})
    except Exception as e:
        issues.append({'issue': f'Error reading file: {e}'})
    
    return issues


if __name__ == "__main__":
    # Test the policy
    import sys
    
    print("=== CopyKEY Network Policy Audit ===\n")
    print(get_allowed_endpoints())
    print("\n=== Testing URLs ===\n")
    
    test_urls = [
        ("https://copykey.hyctec.cn/firmware/latest.json", NetworkPermission.FIRMWARE_UPDATE, True),
        ("https://copykey.hyctec.cn/libraries/card_formats.json", NetworkPermission.LIBRARY_UPDATE, True),
        ("https://client.copykey.hyctec.cn/api/user/login", None, False),
        ("https://copykey.hyctec.cn/api/auth/login", None, False),
        ("https://evil.com/malware.exe", None, False),
        ("https://copykey.hyctec.cn/api/analytics/track", None, False),
    ]
    
    for url, purpose, expected in test_urls:
        result = is_network_request_allowed(url, purpose)
        status = "✓ PASS" if result == expected else "✗ FAIL"
        print(f"{status}: {url[:60]}... -> {result} (expected {expected})")
    
    print("\n=== Policy Summary ===")
    print("✓ Offline-first design enforced")
    print("✓ Only firmware and library updates allowed")
    print("✓ All authentication/cloud/analytics endpoints blocked")
    print("✓ client.copykey.hyctec.cn explicitly blocked")
