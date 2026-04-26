"""
Abstract base classes and utilities for format strategies.

The notion of a ``FormatStrategy`` encapsulates the logic needed to
recognise and normalise different proprietary dump formats.  Each
strategy must implement two methods:

``can_handle(data: bytes) -> bool``
    Returns ``True`` if the strategy believes it can parse the given
    byte sequence.  Strategies should perform cheap checks here (e.g.
    examining magic bytes) and avoid raising exceptions.

``normalize(data: bytes, strict: bool = True) -> MifareClassicDump``
    Performs the actual parsing and returns a
    :class:`~x100_decrypt.engine.MifareClassicDump`.  When ``strict``
    is ``True`` the method must raise a descriptive exception if the
    input does not conform to the expected format.  When ``strict`` is
    ``False`` strategies are encouraged to salvage incomplete dumps by
    truncating or padding the payload; the specifics are left to
    individual implementations.

Strategies may be registered via the module level ``STRATEGIES`` list
in :mod:`x100_decrypt.strategies`.  New strategies must be added to
that list to be discovered by :func:`get_strategy`.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Type

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    # Only import for type checking; avoids circular import at runtime
    from ..engine import MifareClassicDump


class FormatStrategy(ABC):
    """Abstract base class for all format strategies."""

    name: str = "unnamed"

    @abstractmethod
    def can_handle(self, data: bytes) -> bool:
        """Return ``True`` if this strategy recognises the input bytes."""
        raise NotImplementedError

    @abstractmethod
    def normalize(self, data: bytes, strict: bool = True) -> 'MifareClassicDump':
        """Parse and normalise the input into a ``MifareClassicDump``.

        When ``strict`` is ``True`` implementations should raise
        ``ValueError`` or a subclass when the input does not conform to
        the expected structure.  When ``False`` strategies may attempt
        to recover by truncating or padding the payload.  This behaviour
        should be clearly documented for each strategy.
        """
        raise NotImplementedError


class StrategyRegistry:
    """Registry for available format strategies.

    ``FormatStrategy`` subclasses register themselves by calling
    :meth:`register`.  The registry maintains the order in which
    strategies are registered; :func:`get_strategy` will select the
    first strategy whose ``can_handle`` returns ``True``.
    """

    _registry: list[FormatStrategy] = []

    @classmethod
    def register(cls, strategy: FormatStrategy) -> None:
        cls._registry.append(strategy)

    @classmethod
    def strategies(cls) -> list[FormatStrategy]:
        return list(cls._registry)


def get_strategy(data: bytes) -> FormatStrategy:
    """Return the first registered strategy that claims the input.

    If no strategy recognises the data a ``ValueError`` is raised.
    """
    for strategy in StrategyRegistry.strategies():
        try:
            if strategy.can_handle(data):
                return strategy
        except Exception:
            # ignore strategies that throw in can_handle
            continue
    raise ValueError("No strategy can handle input data")