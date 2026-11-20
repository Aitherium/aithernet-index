"""awindex: the AitherNet Index as a library and CLI."""

__version__ = "0.3.0"

from .netindex import TIERS, Index, Record, load, trust, validate  # noqa: E402

__all__ = ["TIERS", "Index", "Record", "load", "trust", "validate", "__version__"]
