#!/usr/bin/env python3
"""Decrypto — passive subdomain discovery for authorized live audits.

Discovers candidate subdomains for an explicitly authorized apex domain using
only public, passive data sources:

- Certificate Transparency logs (crt.sh) — no connection to the target or any
  discovered subdomain is made; this is a read of public third-party log data.
- DNS resolution via the local resolver — confirms a candidate currently has a
  record without sending any traffic to the candidate host itself.

This module never contacts a discovered subdomain directly. Pair its output
with decrypto_assumption_scan.py, which enforces its own per-run request caps,
rate limiting, and `--authorized` requirement before sending anything to those
hosts.
"""

from __future__ import annotations

import json
import re
import socket
import ssl
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

CRTSH_URL_TEMPLATE = "https://crt.sh/?q=%25.{domain}&output=json"
_HOSTNAME_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))*$", re.I)


def _valid_hostname(name: str) -> bool:
    return bool(name) and len(name) <= 253 and bool(_HOSTNAME_RE.match(name))


def discover_subdomains_crtsh(domain: str, *, timeout: float = 8.0) -> set[str]:
    """Query crt.sh certificate-transparency logs for subdomains of `domain`.

    Passive OSINT only — this contacts crt.sh's public log API, never the
    target domain or any subdomain. Returns a deduplicated, lowercased,
    validated hostname set scoped to `domain`.
    """
    domain = domain.strip().lower().rstrip(".")
    if not _valid_hostname(domain):
        raise ValueError("Invalid domain name")

    url = CRTSH_URL_TEMPLATE.format(domain=domain)
    request = Request(url, headers={"User-Agent": "Decrypto-Subdomain-Audit/1.0 (passive; authorized)"})
    try:
        with urlopen(request, timeout=timeout, context=ssl.create_default_context()) as response:
            raw = response.read(5_000_000)
    except (HTTPError, URLError, TimeoutError, ssl.SSLError, OSError) as exc:
        raise RuntimeError(f"crt.sh lookup failed: {type(exc).__name__}") from exc

    try:
        entries = json.loads(raw.decode("utf-8", errors="replace"))
    except json.JSONDecodeError as exc:
        raise RuntimeError("crt.sh returned a non-JSON response") from exc

    names: set[str] = set()
    for entry in entries if isinstance(entries, list) else []:
        name_value = entry.get("name_value", "") if isinstance(entry, dict) else ""
        for candidate in str(name_value).splitlines():
            candidate = candidate.strip().lower().lstrip("*.")
            if candidate and (candidate == domain or candidate.endswith("." + domain)) and _valid_hostname(candidate):
                names.add(candidate)
    return names


def resolve_live_hosts(hostnames: set[str], *, timeout: float = 3.0, max_hosts: int = 50) -> dict[str, list[str]]:
    """Resolve which candidate subdomains currently have a DNS record.

    Only a DNS lookup via the local resolver is performed; no packets are ever
    sent to the candidate host's own infrastructure. Caps lookups at
    `max_hosts` to bound passive recon runs.
    """
    live: dict[str, list[str]] = {}
    previous_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        for hostname in sorted(hostnames)[:max_hosts]:
            try:
                infos = socket.getaddrinfo(hostname, None)
            except (socket.gaierror, OSError):
                continue
            addresses = sorted({info[4][0] for info in infos})
            if addresses:
                live[hostname] = addresses
    finally:
        socket.setdefaulttimeout(previous_timeout)
    return live


def discover_authorized_subdomains(domain: str, *, scheme: str = "https", max_subdomains: int = 10,
                                    lookup_timeout: float = 8.0, resolve_timeout: float = 3.0) -> list[str]:
    """Return up to `max_subdomains` authorized-domain URLs discovered passively.

    Combines crt.sh discovery with DNS liveness filtering. The apex domain is
    always included first if live. Intended to feed decrypto_assumption_scan.py,
    which enforces its own `--authorized`, request-count, and rate limits before
    any discovered host is actually contacted.
    """
    if max_subdomains < 1 or max_subdomains > 20:
        raise ValueError("max_subdomains must be between 1 and 20")
    if scheme not in ("http", "https"):
        raise ValueError("scheme must be http or https")

    domain = domain.strip().lower().rstrip(".")
    candidates = discover_subdomains_crtsh(domain, timeout=lookup_timeout)
    candidates.add(domain)
    live = resolve_live_hosts(candidates, timeout=resolve_timeout, max_hosts=max(max_subdomains * 4, 20))

    ordered = [domain] if domain in live else []
    ordered += sorted(h for h in live if h != domain)
    return [f"{scheme}://{h}/" for h in ordered[:max_subdomains]]


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(
        description="Decrypto passive subdomain discovery (crt.sh + DNS) — authorized domains only"
    )
    parser.add_argument("domain", help="Apex domain you are authorized to test")
    parser.add_argument("--max-subdomains", type=int, default=10, help="Cap on discovered subdomains (1-20)")
    parser.add_argument("--scheme", choices=("http", "https"), default="https")
    args = parser.parse_args(argv)

    try:
        urls = discover_authorized_subdomains(args.domain, scheme=args.scheme, max_subdomains=args.max_subdomains)
    except (ValueError, RuntimeError) as exc:
        parser.error(str(exc))
        return 2

    for url in urls:
        print(url)
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
