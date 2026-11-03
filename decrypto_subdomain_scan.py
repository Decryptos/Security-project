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

import concurrent.futures
import fnmatch
import json
import math
import re
import socket
import ssl
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

CRTSH_URL_TEMPLATE = "https://crt.sh/?q=%25.{domain}&output=json"
_HOSTNAME_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))*$", re.I)

# Hard safety ceiling for subdomains returned from one discovery call. Passed
# as the default `max_subdomains` so a plain `--domain` run automatically
# covers every discovered, live subdomain up to this bound — in practice
# "all of them" for the vast majority of domains, while still preventing an
# unbounded sweep against domains with very large certificate-transparency
# histories.
MAX_SUBDOMAINS_CEILING = 100

# Bound on concurrent DNS lookups in resolve_live_hosts(). These lookups never
# reach the candidate host's own infrastructure (see module docstring), so
# running them in parallel changes nothing about the tool's safety posture
# toward the authorized target — it only changes how many queries the
# operator's own configured resolver handles at once, which is routinely far
# higher than this for ordinary browsing.
MAX_RESOLVER_WORKERS = 20


def _valid_hostname(name: str) -> bool:
    return bool(name) and len(name) <= 253 and bool(_HOSTNAME_RE.match(name))


def normalize_exclusions(patterns) -> frozenset[str]:
    """Lowercase and strip a collection of exact hostnames or glob patterns."""
    return frozenset(p.strip().lower().rstrip(".") for p in (patterns or ()) if p and p.strip())


def is_excluded(hostname: str, exclude_patterns: frozenset[str]) -> bool:
    """Return True if `hostname` exactly matches, or glob-matches, any exclusion pattern.

    Patterns use shell-style wildcards (`fnmatch`), e.g. "internal.example.com"
    (exact) or "dev-*.example.com" / "*.staging.example.com" (glob).
    """
    hostname = hostname.lower()
    return any(fnmatch.fnmatch(hostname, pattern) for pattern in exclude_patterns)


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


def resolve_live_hosts(hostnames: set[str], *, timeout: float = 3.0, max_hosts: int = 50,
                        max_workers: int = MAX_RESOLVER_WORKERS) -> dict[str, list[str]]:
    """Resolve which candidate subdomains currently have a DNS record.

    Only a DNS lookup via the local resolver is performed; no packets are ever
    sent to the candidate host's own infrastructure. Caps lookups at
    `max_hosts` to bound passive recon runs.

    Lookups run concurrently (bounded by `max_workers`), so resolving many
    candidates costs close to one lookup's latency rather than their sum.
    This also fixes a latent correctness gap: `socket.getaddrinfo()` takes no
    timeout argument and does not honor `socket.setdefaulttimeout()`, so a
    purely sequential loop (the previous implementation) had no real per-host
    bound — one slow-to-resolve hostname could stall the entire discovery
    run. Here each lookup is instead raced against `timeout` from a worker
    thread; a lookup still running when its deadline passes is abandoned
    (never cancelled — Python cannot interrupt a blocking call) and simply
    excluded from the result, which is no worse than the previous unbounded
    behavior and far better in every other case.
    """
    targets = sorted(hostnames)[:max_hosts]
    if not targets:
        return {}

    workers = max(1, min(max_workers, len(targets)))
    # Generous overall deadline: worst case is one full `timeout` per
    # sequential batch the pool must run, plus one spare batch of slack.
    overall_timeout = timeout * (math.ceil(len(targets) / workers) + 1)

    live: dict[str, list[str]] = {}
    # Not a `with` block: on exit that would call shutdown(wait=True), which
    # blocks until every submitted lookup finishes — defeating the deadline
    # below for any hostname whose lookup is still hanging. shutdown(wait=False)
    # instead lets this function return on time and abandons stragglers; the
    # process (a short-lived CLI run) exits soon after regardless.
    pool = concurrent.futures.ThreadPoolExecutor(max_workers=workers)
    try:
        future_to_host = {pool.submit(socket.getaddrinfo, hostname, None): hostname for hostname in targets}
        try:
            for future in concurrent.futures.as_completed(future_to_host, timeout=overall_timeout):
                hostname = future_to_host[future]
                try:
                    infos = future.result()
                except (socket.gaierror, OSError):
                    continue
                addresses = sorted({info[4][0] for info in infos})
                if addresses:
                    live[hostname] = addresses
        except concurrent.futures.TimeoutError:
            pass  # Remaining candidates did not resolve within the bounded window; simply omitted.
    finally:
        pool.shutdown(wait=False, cancel_futures=True)
    return live


def discover_authorized_subdomains(domain: str, *, scheme: str = "https", max_subdomains: int = MAX_SUBDOMAINS_CEILING,
                                    exclude=None, lookup_timeout: float = 8.0, resolve_timeout: float = 3.0) -> list[str]:
    """Return up to `max_subdomains` authorized-domain URLs discovered passively.

    Combines crt.sh discovery with DNS liveness filtering. The apex domain is
    always included first if live. `max_subdomains` defaults to
    `MAX_SUBDOMAINS_CEILING`, so a plain call automatically covers every
    discovered, live subdomain up to that safety ceiling (in practice "all of
    them" for most domains). `exclude` is an optional iterable of exact
    hostnames or `fnmatch`-style glob patterns (e.g. "dev-*.example.com")
    skipped before DNS resolution. Intended to feed
    decrypto_assumption_scan.py, which enforces its own `--authorized`,
    request-count, and rate limits before any discovered host is actually
    contacted.
    """
    report = discover_authorized_subdomains_report(
        domain, scheme=scheme, max_subdomains=max_subdomains, exclude=exclude,
        lookup_timeout=lookup_timeout, resolve_timeout=resolve_timeout,
    )
    return report["selected"]


def discover_authorized_subdomains_report(domain: str, *, scheme: str = "https",
                                           max_subdomains: int = MAX_SUBDOMAINS_CEILING,
                                           exclude=None, lookup_timeout: float = 8.0,
                                           resolve_timeout: float = 3.0) -> dict:
    """Like `discover_authorized_subdomains`, but also reports discovery/exclusion metadata.

    Useful for disclosure reports that should show *why* a candidate is
    absent (excluded by pattern, not live, or truncated by the safety
    ceiling) rather than silently omitting it.
    """
    if max_subdomains < 1 or max_subdomains > MAX_SUBDOMAINS_CEILING:
        raise ValueError(f"max_subdomains must be between 1 and {MAX_SUBDOMAINS_CEILING}")
    if scheme not in ("http", "https"):
        raise ValueError("scheme must be http or https")

    domain = domain.strip().lower().rstrip(".")
    exclude_patterns = normalize_exclusions(exclude)
    candidates = discover_subdomains_crtsh(domain, timeout=lookup_timeout)
    candidates.add(domain)
    excluded = {h for h in candidates if is_excluded(h, exclude_patterns)} if exclude_patterns else set()
    in_scope = candidates - excluded

    resolve_cap = min(max(max_subdomains * 4, 20), 300)
    live = resolve_live_hosts(in_scope, timeout=resolve_timeout, max_hosts=resolve_cap)

    ordered = [domain] if domain in live else []
    ordered += sorted(h for h in live if h != domain)
    selected = ordered[:max_subdomains]
    return {
        "domain": domain,
        "candidates_found": len(candidates),
        "excluded_by_pattern": sorted(excluded),
        "live_and_in_scope": len(live),
        "selected": [f"{scheme}://{h}/" for h in selected],
        "truncated_by_ceiling": len(ordered) > len(selected),
    }


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(
        description="Decrypto passive subdomain discovery (crt.sh + DNS) — authorized domains only"
    )
    parser.add_argument("domain", help="Apex domain you are authorized to test")
    parser.add_argument("--max-subdomains", type=int, default=MAX_SUBDOMAINS_CEILING,
                         help=f"Cap on discovered subdomains (1-{MAX_SUBDOMAINS_CEILING}, "
                              f"default {MAX_SUBDOMAINS_CEILING} = effectively all discovered+live subdomains)")
    parser.add_argument("--exclude", action="append", default=[],
                         help="Exact hostname or glob pattern (e.g. 'dev-*.example.com') to exclude; repeatable")
    parser.add_argument("--scheme", choices=("http", "https"), default="https")
    args = parser.parse_args(argv)

    try:
        urls = discover_authorized_subdomains(args.domain, scheme=args.scheme, max_subdomains=args.max_subdomains,
                                               exclude=args.exclude)
    except (ValueError, RuntimeError) as exc:
        parser.error(str(exc))
        return 2

    for url in urls:
        print(url)
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
