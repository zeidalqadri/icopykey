"""
Tests for configuration manager.

Covers config creation, serialization, persistence, and edge cases.
"""

from __future__ import annotations

import json
import pytest
from pathlib import Path

from ..config_manager import (
    AppConfig,
    ConfigManager,
    DeviceConfig,
    DisplayConfig,
    SecurityConfig,
    PathsConfig,
    DefaultsConfig,
    ConfigParseError,
)


class TestAppConfig:
    def test_default_config(self) -> None:
        cfg = AppConfig()
        assert cfg.device.vid == "0x6300"
        assert cfg.device.pid == "0x1991"
        assert cfg.display.colors is True
        assert cfg.security.confirm_writes is True

    def test_to_dict_roundtrip(self) -> None:
        cfg = AppConfig()
        d = cfg.to_dict()
        cfg2 = AppConfig.from_dict(d)
        assert cfg2.device.vid == cfg.device.vid
        assert cfg2.display.theme == cfg.display.theme

    def test_from_dict_partial(self) -> None:
        data = {"device": {"vid": "1234"}, "display": {}}
        cfg = AppConfig.from_dict(data)
        assert cfg.device.vid == "1234"
        assert cfg.device.pid == "0x1991"  # default preserved
        assert cfg.display.colors is True  # default preserved


class TestConfigManager:
    def test_creates_default_on_missing(self, tmp_path: Path) -> None:
        config_path = tmp_path / "config.json"
        mgr = ConfigManager(config_path)
        cfg = mgr.load()
        assert config_path.exists()
        assert cfg.device.vid == "0x6300"

    def test_load_existing(self, tmp_path: Path) -> None:
        config_path = tmp_path / "config.json"
        data = {"device": {"vid": "ABCD"}, "display": {"colors": False}}
        config_path.write_text(json.dumps(data))

        mgr = ConfigManager(config_path)
        cfg = mgr.load()
        assert cfg.device.vid == "ABCD"
        assert cfg.display.colors is False

    def test_save_persists(self, tmp_path: Path) -> None:
        config_path = tmp_path / "config.json"
        mgr = ConfigManager(config_path)
        mgr.load()
        mgr.set("device", "vid", "BEEF")
        mgr.save()

        raw = json.loads(config_path.read_text())
        assert raw["device"]["vid"] == "BEEF"

    def test_get_unknown_section_returns_default(self) -> None:
        mgr = ConfigManager()
        assert mgr.get("nonexistent", "key", "fallback") == "fallback"

    def test_set_unknown_key_raises(self, tmp_path: Path) -> None:
        mgr = ConfigManager(tmp_path / "cfg.json")
        mgr.load()
        with pytest.raises(KeyError):
            mgr.set("device", "nonexistent_key", "value")

    def test_reset(self, tmp_path: Path) -> None:
        config_path = tmp_path / "config.json"
        mgr = ConfigManager(config_path)
        mgr.load()
        mgr.set("device", "vid", "FFFF")
        mgr.reset()

        cfg = mgr.config
        assert cfg.device.vid == "0x6300"

    def test_get_vid_pid_as_int(self, tmp_path: Path) -> None:
        mgr = ConfigManager(tmp_path / "config.json")
        assert mgr.get_vid() == 0x6300
        assert mgr.get_pid() == 0x1991

    def test_parse_error(self, tmp_path: Path) -> None:
        config_path = tmp_path / "bad.json"
        config_path.write_text("not json{")

        mgr = ConfigManager(config_path)
        with pytest.raises(ConfigParseError):
            mgr.load()

    def test_is_color_enabled(self) -> None:
        mgr = ConfigManager()
        assert mgr.is_color_enabled() is True

        mgr._config.display.colors = False
        assert mgr.is_color_enabled() is False
