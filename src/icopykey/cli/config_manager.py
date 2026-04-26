"""
Configuration manager for CopyKEY CLI.

Handles JSON-based configuration file with defaults, validation,
and persistent storage of user preferences.

The config file lives at ~/.copykey_cli/config.json by default.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any

from .errors import ConfigNotFoundError, ConfigParseError

DEFAULT_CONFIG_DIR = Path.home() / ".copykey_cli"
DEFAULT_CONFIG_FILE = DEFAULT_CONFIG_DIR / "config.json"


@dataclass
class DeviceConfig:
    """Device connection preferences."""

    vid: str = "0x6300"
    pid: str = "0x1991"
    usage_page: str = "0xFF00"


@dataclass
class PathsConfig:
    """File paths for data storage."""

    vault_dir: str = str(DEFAULT_CONFIG_DIR)
    library_dir: str = str(DEFAULT_CONFIG_DIR / "cards")
    export_dir: str = str(Path.home() / "Documents")
    key_file: str = ""
    log_dir: str = str(DEFAULT_CONFIG_DIR / "logs")


@dataclass
class DisplayConfig:
    """Display and formatting preferences."""

    colors: bool = True
    progress_bars: bool = True
    compact_output: bool = False
    theme: str = "default"


@dataclass
class SecurityConfig:
    """Security-related preferences."""

    confirm_writes: bool = True
    backup_before_write: bool = True
    max_password_attempts: int = 3
    auto_lock_timeout_minutes: int = 0  # 0 = never


@dataclass
class DefaultsConfig:
    """Default values for card operations."""

    sector_count: int = 16
    access_bits: str = "FF078069"
    transport_key: str = "FFFFFFFFFFFF"
    default_key_file: str = ""
    auto_save_on_decode: bool = False


@dataclass
class AppConfig:
    """Top-level application configuration."""

    device: DeviceConfig = field(default_factory=DeviceConfig)
    paths: PathsConfig = field(default_factory=PathsConfig)
    display: DisplayConfig = field(default_factory=DisplayConfig)
    security: SecurityConfig = field(default_factory=SecurityConfig)
    defaults: DefaultsConfig = field(default_factory=DefaultsConfig)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "device": asdict(self.device),
            "paths": asdict(self.paths),
            "display": asdict(self.display),
            "security": asdict(self.security),
            "defaults": asdict(self.defaults),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AppConfig":
        """Deserialize from dictionary, merging with defaults."""
        device_data = data.get("device", {})
        paths_data = data.get("paths", {})
        display_data = data.get("display", {})
        security_data = data.get("security", {})
        defaults_data = data.get("defaults", {})

        return cls(
            device=DeviceConfig(**{k: v for k, v in device_data.items() if k in DeviceConfig.__dataclass_fields__}),
            paths=PathsConfig(**{k: v for k, v in paths_data.items() if k in PathsConfig.__dataclass_fields__}),
            display=DisplayConfig(**{k: v for k, v in display_data.items() if k in DisplayConfig.__dataclass_fields__}),
            security=SecurityConfig(**{k: v for k, v in security_data.items() if k in SecurityConfig.__dataclass_fields__}),
            defaults=DefaultsConfig(**{k: v for k, v in defaults_data.items() if k in DefaultsConfig.__dataclass_fields__}),
        )


class ConfigManager:
    """Manages loading, saving, and accessing configuration."""

    def __init__(self, config_path: str | Path | None = None) -> None:
        self.config_path = Path(config_path) if config_path else DEFAULT_CONFIG_FILE
        self._config: AppConfig = AppConfig()
        self._loaded = False

    @property
    def config(self) -> AppConfig:
        """Get the current configuration (loads if not yet loaded)."""
        if not self._loaded:
            self.load()
        return self._config

    def load(self, path: str | Path | None = None) -> AppConfig:
        """Load configuration from disk, creating defaults if missing."""
        if path:
            self.config_path = Path(path)

        if not self.config_path.exists():
            self._config = AppConfig()
            self.save()
            self._loaded = True
            return self._config

        try:
            raw = self.config_path.read_text(encoding="utf-8")
            data = json.loads(raw)
            self._config = AppConfig.from_dict(data)
            self._loaded = True
            return self._config
        except json.JSONDecodeError as e:
            raise ConfigParseError(str(self.config_path), str(e)) from e
        except OSError as e:
            raise ConfigNotFoundError(str(self.config_path)) from e

    def save(self, path: str | Path | None = None) -> None:
        """Save current configuration to disk."""
        if path:
            self.config_path = Path(path)

        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        data = self._config.to_dict()
        self.config_path.write_text(
            json.dumps(data, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )

    def get(self, section: str, key: str, default: Any = None) -> Any:
        """Get a configuration value by section and key."""
        cfg = self.config
        section_data = getattr(cfg, section, None)
        if section_data is None:
            return default
        return getattr(section_data, key, default)

    def set(self, section: str, key: str, value: Any) -> None:
        """Set a configuration value and persist."""
        cfg = self.config
        section_data = getattr(cfg, section)
        if section_data is None:
            raise KeyError(f"Unknown config section: {section}")
        if not hasattr(section_data, key):
            raise KeyError(f"Unknown config key: {section}.{key}")
        setattr(section_data, key, value)
        self.save()

    def get_vid(self) -> int:
        """Get VID as integer."""
        return int(self.config.device.vid, 16)

    def get_pid(self) -> int:
        """Get PID as integer."""
        return int(self.config.device.pid, 16)

    def is_color_enabled(self) -> bool:
        """Check if color output is enabled."""
        return self.config.display.colors

    def reset(self) -> None:
        """Reset configuration to factory defaults."""
        self._config = AppConfig()
        self.save()
