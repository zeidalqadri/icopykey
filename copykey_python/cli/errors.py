"""
Custom exception hierarchy for CopyKEY CLI.

Provides typed exceptions with user-friendly messages and optional
recovery hints for all failure modes in the CLI application.
"""

from __future__ import annotations


class CopyKeyError(Exception):
    """Base exception for all CopyKEY CLI errors."""

    def __init__(self, message: str, hint: str | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.hint = hint

    def __str__(self) -> str:
        if self.hint:
            return f"{self.message}\n  Hint: {self.hint}"
        return self.message


class DeviceError(CopyKeyError):
    """Errors related to hardware device communication."""


class DeviceNotFoundError(DeviceError):
    """Device not found on USB bus."""

    def __init__(self, vid: int | None = None, pid: int | None = None) -> None:
        hw = f" VID=0x{vid:04X} PID=0x{pid:04X}" if vid and pid else ""
        super().__init__(
            f"No CopyKEY device found{hw}",
            hint="Ensure the device is connected and powered on. Try a different USB cable or port.",
        )


class DeviceDisconnectedError(DeviceError):
    """Device was disconnected during an operation."""

    def __init__(self) -> None:
        super().__init__(
            "Device disconnected during operation",
            hint="Reconnect the device and try again. Use 'Reconnect device' from the menu.",
        )


class DeviceTimeoutError(DeviceError):
    """Device did not respond within the expected time."""

    def __init__(self, operation: str, timeout_ms: int) -> None:
        super().__init__(
            f"Device timeout during '{operation}' after {timeout_ms}ms",
            hint="The device may be busy or the card may not be properly positioned.",
        )


class DeviceCommandError(DeviceError):
    """Device rejected a command or returned an error."""

    def __init__(self, command: str, response_code: int) -> None:
        super().__init__(
            f"Device rejected '{command}' command (response: 0x{response_code:02X})",
            hint="Check that a compatible card is on the reader and try again.",
        )


class ValidationError(CopyKeyError):
    """User input validation failures."""


class InvalidHexError(ValidationError):
    """Input is not valid hexadecimal."""

    def __init__(self, value: str, field_name: str = "value") -> None:
        super().__init__(
            f"Invalid hex {field_name}: '{value}'",
            hint="Enter only hexadecimal characters (0-9, A-F).",
        )


class InvalidKeyError(ValidationError):
    """Key is not the correct format."""

    def __init__(self, value: str, expected_bytes: int = 6) -> None:
        super().__init__(
            f"Invalid key: '{value}' (expected {expected_bytes * 2} hex digits = {expected_bytes} bytes)",
            hint=f"Enter exactly {expected_bytes * 2} hex characters.",
        )


class InvalidUIDError(ValidationError):
    """UID is invalid format."""

    def __init__(self, value: str) -> None:
        super().__init__(
            f"Invalid UID: '{value}'",
            hint="UID must be 4, 7, or 10 bytes (8, 14, or 20 hex digits).",
        )


class InvalidAccessBitsError(ValidationError):
    """Access bits are invalid."""

    def __init__(self, value: str) -> None:
        super().__init__(
            f"Invalid access bits: '{value}'",
            hint="Access bits must be 4 bytes (8 hex digits). Valid examples: FF078069 (default), 78778800 (read-only).",
        )


class InvalidCardTypeError(ValidationError):
    """Card type is not recognized."""

    def __init__(self, value: str) -> None:
        super().__init__(
            f"Unknown card type: '{value}'",
            hint="Supported types: mifare_classic_1k, mifare_classic_4k, id_card, ntag_ultralight.",
        )


class ConfigError(CopyKeyError):
    """Configuration file errors."""


class ConfigNotFoundError(ConfigError):
    """Configuration file does not exist."""

    def __init__(self, path: str) -> None:
        super().__init__(
            f"Configuration file not found: {path}",
            hint="Run the application once to generate a default configuration, or create one manually.",
        )


class ConfigParseError(ConfigError):
    """Configuration file has invalid format."""

    def __init__(self, path: str, detail: str) -> None:
        super().__init__(
            f"Failed to parse config '{path}': {detail}",
            hint="Check the JSON syntax in the config file. Restore from backup or delete to regenerate defaults.",
        )


class LibraryError(CopyKeyError):
    """Card or key library errors."""


class VaultAccessError(LibraryError):
    """Could not decrypt the vault (wrong password or corruption)."""

    def __init__(self) -> None:
        super().__init__(
            "Failed to decrypt vault - wrong password or corrupted data",
            hint="If you forgot your password, delete the vault files and start fresh. Back up .enc files first.",
        )


class CardNotFoundError(LibraryError):
    """Card not found in library."""

    def __init__(self, identifier: str) -> None:
        super().__init__(
            f"Card not found: '{identifier}'",
            hint="Use 'Card Library' to browse available cards, or 'Import Card' to add from a file.",
        )


class KeyNotFoundError(LibraryError):
    """Key not found in library."""

    def __init__(self, name: str) -> None:
        super().__init__(
            f"Key not found: '{name}'",
            hint="Use 'Key Library' to add keys, or supply keys via the -k/--key argument.",
        )


class FileOperationError(CopyKeyError):
    """File read/write errors."""

    def __init__(self, path: str, operation: str, detail: str) -> None:
        super().__init__(
            f"Failed to {operation} file '{path}': {detail}",
            hint="Check file permissions and disk space.",
        )


class ImportError_CLI(CopyKeyError):
    """Failed to import card data from file."""

    def __init__(self, path: str, detail: str) -> None:
        super().__init__(
            f"Failed to import card from '{path}': {detail}",
            hint="Ensure the file is a valid .json, .mfd, or .bin card dump.",
        )
