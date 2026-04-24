"""
Configuration loader for x100_decrypt.

The project is designed to be extensible via YAML configuration files.  A
configuration file can specify custom offsets for format strategies or
enable/disable external tool integration.  All configuration keys are
optional; sensible defaults are used when a key is absent.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Optional

import yaml  # type: ignore


@dataclass
class StrategyConfig:
    """Configuration overrides for a particular strategy.

    The :class:`~x100_decrypt.strategies.x100_format.X100FormatStrategy`
    exposes several tunables such as the size of the header and the
    offsets of various fields.  A YAML configuration may specify an
    override for any of these.  Unknown keys are ignored.
    """

    header_magic: Optional[str] = None  # override the expected magic
    header_size: Optional[int] = None   # total header length in bytes
    payload_offset: Optional[int] = None  # offset to start reading card data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "StrategyConfig":
        return cls(
            header_magic=data.get("header_magic"),
            header_size=data.get("header_size"),
            payload_offset=data.get("payload_offset"),
        )


@dataclass
class Config:
    """Container for all configuration loaded from YAML.

    Attributes
    ----------
    strategies:
        A mapping from strategy name to :class:`StrategyConfig`
        instances.  Unknown strategies are ignored when applying
        overrides.
    use_external_recovery:
        Global flag controlling whether external key recovery tools are
        used by default.  Can be overridden on the command line.
    """

    strategies: Dict[str, StrategyConfig] = field(default_factory=dict)
    use_external_recovery: bool = False

    @classmethod
    def from_yaml(cls, path: str) -> "Config":
        """Load configuration from a YAML file.

        Parameters
        ----------
        path:
            Path to the YAML configuration file.

        Returns
        -------
        Config
            Parsed configuration with nested ``StrategyConfig`` objects.
        """
        with open(path, "r", encoding="utf-8") as fh:
            raw = yaml.safe_load(fh) or {}
        cfg = cls()
        # global flag
        cfg.use_external_recovery = bool(raw.get("use_external_recovery", False))
        strat_cfgs = raw.get("strategies", {}) or {}
        for name, data in strat_cfgs.items():
            cfg.strategies[name] = StrategyConfig.from_dict(data)
        return cfg