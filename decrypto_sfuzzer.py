#!/usr/bin/env python3
"""Bounded, authorized DNS wordlist discovery for explicitly scoped subdomains."""

from __future__ import annotations

import argparse
import ipaddress
import json
import math
import re
import socket
import sys
import time
from pathlib import Path
from typing import Callable

from decrypto_bounty import ProgramScope, load_scope

DEFAULT_LABELS = (
    "www", "api", "app", "admin", "dev", "staging",
    "test", "mail", "cdn", "static", "docs", "portal",
)
MAX_WORDLIST_BYTES = 1_000_000
MAX_CANDIDATES = 500
DEFAULT_MAX_CANDIDATES = 100
MIN_DELAY_SECONDS = 0.5
MAX_DELAY_SECONDS = 60.0
_DNS_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$", re.ASCII)


def normalize_domain(value: str) -> str:
    """Return a canonical ASCII DNS domain, rejecting URLs and IP literals."""
    if not isinstance(value, str):
        raise ValueError("Domain must be text")
    domain = value.strip().rstrip(".")
    if (not domain or any(char in domain for char in "/:?@[]\\#%")
            or "://" in domain):
        raise ValueError("Provide an apex domain only, without a scheme or path")
    try:
        ascii_domain = domain.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ValueError("Domain is not valid IDNA text") from exc

    labels = ascii_domain.split(".")
    if len(ascii_domain) > 253 or len(labels) < 2:
        raise ValueError("Domain must contain at least two valid labels")
    if any(not _DNS_LABEL.fullmatch(label) for label in labels):
        raise ValueError("Domain contains an invalid DNS label")
    try:
        ipaddress.ip_address(ascii_domain)
    except ValueError:
        pass
    else:
        raise ValueError("IP addresses are not valid apex domains")
    return ascii_domain


def normalize_label(value: str) -> str:
    """Validate one wordlist item as exactly one DNS label."""
    if not isinstance(value, str):
        raise ValueError("Wordlist entries must be text")
    label = value.strip()
    if not label or any(char in label for char in "/\\:?@[]#%"):
        raise ValueError("Wordlist entry must be one DNS label")
    try:
        ascii_label = label.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ValueError("Wordlist entry is not valid IDNA text") from exc
    if "." in ascii_label or not _DNS_LABEL.fullmatch(ascii_label):
        raise ValueError("Wordlist entry must be one valid DNS label")
    return ascii_label


def load_wordlist(path: Path | None, max_candidates: int) -> tuple[list[str], int]:
    """Load and de-duplicate a local wordlist or use the small built-in list."""
    if not 1 <= max_candidates <= MAX_CANDIDATES:
        raise ValueError(f"max_candidates must be between 1 and {MAX_CANDIDATES}")

    if path is None:
        raw_lines = list(DEFAULT_LABELS)
    else:
        if path.stat().st_size > MAX_WORDLIST_BYTES:
            raise ValueError("Wordlist exceeds 1 MB")
        try:
            raw_lines = path.read_text(encoding="utf-8").splitlines()
        except UnicodeError as exc:
            raise ValueError("Wordlist must be UTF-8 text") from exc

    words: list[str] = []
    seen: set[str] = set()
    invalid = 0
    for raw in raw_lines:
        item = raw.strip()
        if not item or item.startswith("#"):
            continue
        try:
            label = normalize_label(item)
        except ValueError:
            invalid += 1
            continue
        if label in seen:
            continue
        seen.add(label)
        words.append(label)
        if len(words) > max_candidates:
            raise ValueError(
                f"Wordlist exceeds the {max_candidates}-candidate limit; "
                "raise --max-candidates up to 500 or use a smaller list"
            )
    if not words:
        raise ValueError("Wordlist contains no valid DNS labels")
    return words, invalid


def resolve_dns(hostname: str) -> list[str]:
    """Resolve a hostname through the configured system resolver.

    Only address-family labels are returned. IP addresses are never retained.
    """
    records = socket.getaddrinfo(
        hostname, None, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM
    )
    families = set()
    for family, _socktype, _proto, _canonname, _sockaddr in records:
        if family == socket.AF_INET:
            families.add("IPv4")
        elif family == socket.AF_INET6:
            families.add("IPv6")
    return sorted(families)


def _is_name_not_found(error: socket.gaierror) -> bool:
    codes = {getattr(socket, "EAI_NONAME", None), getattr(socket, "EAI_NODATA", None)}
    codes.discard(None)
    return error.errno in codes


def _host_is_in_scope(scope: ProgramScope, hostname: str) -> bool:
    """Require the candidate host root to be in scope for at least one scheme."""
    return any(
        scope.allows(f"{scheme}://{hostname}/")
        for scheme in ("https", "http")
    )


def enumerate_subdomains(
    domain: str,
    words: list[str],
    scope: ProgramScope,
    *,
    delay: float = MIN_DELAY_SECONDS,
    max_candidates: int = DEFAULT_MAX_CANDIDATES,
    resolver: Callable[[str], list[str]] | None = None,
    sleeper: Callable[[float], None] | None = None,
) -> dict:
    """Resolve in-scope one-label candidates sequentially; never make HTTP requests."""
    apex = normalize_domain(domain)
    if scope is None:
        raise ValueError("A program scope is required")
    if not math.isfinite(delay) or not MIN_DELAY_SECONDS <= delay <= MAX_DELAY_SECONDS:
        raise ValueError(
            f"delay must be between {MIN_DELAY_SECONDS} and {MAX_DELAY_SECONDS} seconds"
        )
    if not 1 <= max_candidates <= MAX_CANDIDATES:
        raise ValueError(f"max_candidates must be between 1 and {MAX_CANDIDATES}")

    normalized_words: list[str] = []
    seen: set[str] = set()
    invalid_words = 0
    for raw in words:
        try:
            label = normalize_label(raw)
        except ValueError:
            invalid_words += 1
            continue
        if label not in seen:
            seen.add(label)
            normalized_words.append(label)
        if len(normalized_words) > max_candidates:
            raise ValueError(f"Candidate count exceeds the limit of {max_candidates}")
    if not normalized_words:
        raise ValueError("No valid DNS labels to query")

    resolver = resolver or resolve_dns
    sleeper = sleeper or time.sleep
    resolved: list[dict[str, object]] = []
    errors: list[dict[str, object]] = []
    attempts = 0
    not_found = 0
    out_of_scope = 0

    for label in normalized_words:
        hostname = f"{label}.{apex}"
        if not _host_is_in_scope(scope, hostname):
            out_of_scope += 1
            continue
        if attempts:
            sleeper(delay)
        attempts += 1
        try:
            families = sorted(set(resolver(hostname)))
        except socket.gaierror as exc:
            if _is_name_not_found(exc):
                not_found += 1
            else:
                errors.append({
                    "host": hostname,
                    "error_type": "gaierror",
                    "error_code": exc.errno,
                })
            continue
        except OSError as exc:
            errors.append({
                "host": hostname,
                "error_type": type(exc).__name__,
            })
            continue
        if families:
            resolved.append({"host": hostname, "address_families": families})
        else:
            not_found += 1

    return {
        "tool": "Decrypto scoped DNS wordlist discovery",
        "status": "DNS observations only; not a security finding",
        "domain": apex,
        "candidate_count": len(normalized_words),
        "invalid_word_count": invalid_words,
        "lookups_attempted": attempts,
        "out_of_scope_skipped_count": out_of_scope,
        "not_resolved_count": not_found,
        "resolved": resolved,
        "errors": errors,
        "scope": {
            "program": scope.program,
            "scope_file": scope.source_name,
            "scope_sha256": scope.source_sha256,
        },
        "privacy": (
            "DNS lookups only. No HTTP requests, port probes, IP addresses, "
            "response bodies, credentials, or DNS error messages are stored."
        ),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Decrypto bounded DNS wordlist discovery for authorized subdomains"
    )
    parser.add_argument("--domain", required=True, help="Apex domain you are authorized to assess")
    parser.add_argument("--wordlist", type=Path, help="Local UTF-8 file with one DNS label per line")
    parser.add_argument("--scope", type=Path, required=True, help="Local program scope JSON; each candidate host must be in scope")
    parser.add_argument("--authorized", action="store_true", help="Affirm explicit permission for DNS queries under this domain")
    parser.add_argument("--delay", type=float, default=MIN_DELAY_SECONDS, help="Delay between lookups (0.5–60 seconds)")
    parser.add_argument("--max-candidates", type=int, default=DEFAULT_MAX_CANDIDATES, help="Candidate cap (1–500, default 100)")
    parser.add_argument("--out", type=Path, default=Path("decrypto_sfuzzer.json"), help="JSON report path")
    args = parser.parse_args(argv)

    if not args.authorized:
        parser.error("DNS discovery requires --authorized AND permission from the domain owner")
    if not 1 <= args.max_candidates <= MAX_CANDIDATES:
        parser.error(f"--max-candidates must be between 1 and {MAX_CANDIDATES}")
    if not math.isfinite(args.delay) or not MIN_DELAY_SECONDS <= args.delay <= MAX_DELAY_SECONDS:
        parser.error(f"--delay must be between {MIN_DELAY_SECONDS} and {MAX_DELAY_SECONDS} seconds")

    try:
        scope = load_scope(args.scope)
        words, invalid_count = load_wordlist(args.wordlist, args.max_candidates)
        result = enumerate_subdomains(
            args.domain,
            words,
            scope,
            delay=args.delay,
            max_candidates=args.max_candidates,
        )
        result["invalid_word_count"] += invalid_count
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    except (OSError, ValueError, UnicodeError, json.JSONDecodeError) as exc:
        parser.error(str(exc))

    print(
        f"Completed {result['lookups_attempted']} in-scope DNS lookups; "
        f"{len(result['resolved'])} names resolved; "
        f"{len(result['errors'])} resolver errors"
    )
    print(f"JSON report: {args.out}")
    return 0 if not result["errors"] else 2


if __name__ == "__main__":
    sys.exit(main())
