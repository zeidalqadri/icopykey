"""
Strategy registry and convenient imports for x100_decrypt.

This subpackage defines multiple ``FormatStrategy`` implementations
which are automatically registered upon import.  Consumers can call
:func:`get_strategy` to obtain the first strategy that recognises a
given dump.  Additional strategies may be added by importing and
registering them within this module.
"""

from .base import FormatStrategy, StrategyRegistry, get_strategy  # noqa: F401

# Import strategies so that they register themselves
from .raw_format import RawFormatStrategy  # noqa: F401
from .x100_format import X100FormatStrategy  # noqa: F401

# Expose names
__all__ = [
    "FormatStrategy",
    "StrategyRegistry",
    "get_strategy",
    "RawFormatStrategy",
    "X100FormatStrategy",
]