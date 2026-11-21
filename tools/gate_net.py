#!/usr/bin/env python3
"""Network primitives shared by the listing gate. Stdlib only.

Everything here has a PURE counterpart so the rules can be tested without a
network: ``fetch``/``tls_check``/``dns_query_a`` only move bytes, and every
verdict is decided in ``reputation.py`` or ``listing_gate.py`` from their
outputs (or from fixtures shaped exactly like them).

    from gate_net import fetch, tls_check, dns_query_a

The gate never disables TLS verification: ``tls_check`` uses the default
context, so an expired, self-signed, incomplete or hostname-mismatched chain is
a failed handshake, not a warning.
"""

from __future__ import annotations

import socket
import ssl
import struct
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import List, Tuple

UA = "aithernet-index-listing-gate/1 (+https://index.aitherium.com)"
MAX_BODY = 262144


@dataclass
class Fetch:
    """One HTTP GET as a browser would see it: status, final URL, bounded body."""

    status: int
    body: str
    final_url: str
    error: str = ""

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 300


def fetch(url: str, timeout: float = 15, limit: int = MAX_BODY,
          headers: "dict | None" = None, data: "bytes | None" = None) -> Fetch:
    """GET (or POST when ``data`` is set) with redirects followed, bounded read."""
    hdrs = {"User-Agent": UA}
    if headers:
        hdrs.update(headers)
    req = urllib.request.Request(url, headers=hdrs, data=data)
    if data is not None:
        req.get_method = lambda: "POST"  # noqa: E731 - urllib's own hook
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
            raw = resp.read(limit)
            return Fetch(resp.status, raw.decode("utf-8", "replace"),
                         resp.geturl() or url)
    except urllib.error.HTTPError as exc:
        body = b""
        try:
            body = exc.read(min(limit, 8192))
        except Exception:  # noqa: BLE001 - an error page is still data
            pass
        return Fetch(exc.code, body.decode("utf-8", "replace"), url,
                     f"http {exc.code}")
    except urllib.error.URLError as exc:
        return Fetch(0, "", url, str(exc.reason)[:200])
    except (OSError, ValueError) as exc:
        return Fetch(0, "", url, str(exc)[:200])


def fetch_json(url: str, timeout: float = 15,
               headers: "dict | None" = None) -> "Tuple[object, Fetch]":
    """GET and parse JSON. Returns (parsed or None, raw Fetch for the reason)."""
    import json

    got = fetch(url, timeout=timeout, headers=headers)
    if not got.ok:
        return None, got
    try:
        return json.loads(got.body), got
    except ValueError:
        return None, Fetch(got.status, got.body, got.final_url, "non-JSON body")


@dataclass
class TLSResult:
    ok: bool
    reason: str
    not_after: str = ""


def tls_check(host: str, port: int = 443, timeout: float = 10) -> TLSResult:
    """A verified TLS handshake with the record's hostname.

    ``create_default_context`` enforces the public trust store, the validity
    window and (because we pass ``server_hostname``) the hostname. No ``-k``.
    """
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert() or {}
                return TLSResult(True, f"verified {tls.version()}", cert.get("notAfter", ""))
    except ssl.SSLCertVerificationError as exc:
        return TLSResult(False, f"certificate not valid: {exc.verify_message}")
    except ssl.SSLError as exc:
        return TLSResult(False, f"TLS handshake failed: {exc.reason or exc}")
    except (socket.timeout, TimeoutError):
        return TLSResult(False, f"TLS handshake timed out after {timeout}s")
    except OSError as exc:
        return TLSResult(False, f"could not connect: {type(exc).__name__}: {exc}")


@dataclass
class DNSResult:
    rcode: int          # 0 NOERROR, 2 SERVFAIL, 3 NXDOMAIN
    ips: List[str]
    error: str = ""

    @property
    def answered(self) -> bool:
        return not self.error and self.rcode == 0 and bool(self.ips)


def dns_packet(name: str, txid: int) -> bytes:
    """A minimal RFC1035 A query. Pure, so a test can pin the wire bytes."""
    header = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0)
    qname = b"".join(bytes([len(p)]) + p.encode("ascii")
                     for p in name.strip(".").split(".") if p) + b"\x00"
    return header + qname + struct.pack("!HH", 1, 1)


def _skip_name(data: bytes, off: int) -> int:
    while True:
        length = data[off]
        if length == 0:
            return off + 1
        if length & 0xC0 == 0xC0:
            return off + 2
        off += 1 + length


def parse_dns_a(data: bytes) -> DNSResult:
    """rcode + A records from a DNS response. Pure; malformed input is an error."""
    try:
        _rid, flags, qd, an, _ns, _ar = struct.unpack("!HHHHHH", data[:12])
        rcode = flags & 0x0F
        off = 12
        for _ in range(qd):
            off = _skip_name(data, off) + 4
        ips: List[str] = []
        for _ in range(an):
            off = _skip_name(data, off)
            rtype, _rclass, _ttl, rdlength = struct.unpack("!HHIH", data[off:off + 10])
            off += 10
            if rtype == 1 and rdlength == 4:
                ips.append(".".join(str(b) for b in data[off:off + 4]))
            off += rdlength
        return DNSResult(rcode, ips)
    except (struct.error, IndexError) as exc:
        return DNSResult(-1, [], f"malformed DNS response: {exc}")


def dns_query_a(name: str, server: str, timeout: float = 4) -> DNSResult:
    """Plain DNS A lookup over UDP. Used only for the Quad9 filtered/unfiltered diff."""
    import random

    txid = random.randint(0, 65535)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(dns_packet(name, txid), (server, 53))
            data, _ = sock.recvfrom(4096)
    except (socket.timeout, TimeoutError):
        return DNSResult(-1, [], f"no answer from {server} in {timeout}s")
    except OSError as exc:
        return DNSResult(-1, [], f"{server}: {type(exc).__name__}: {exc}")
    return parse_dns_a(data)


def host_of(url: str) -> str:
    """The lowercase hostname of a URL, or '' when it cannot be parsed."""
    try:
        return (urllib.parse.urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


def urlencode(value: str) -> str:
    return urllib.parse.quote(value, safe="")
