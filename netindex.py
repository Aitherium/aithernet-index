"""Shim: the library lives in awindex/netindex.py (pip install awindex)."""

import sys

from awindex import netindex as _netindex

sys.modules[__name__] = _netindex
