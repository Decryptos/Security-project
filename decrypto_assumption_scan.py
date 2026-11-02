#!/usr/bin/env python3
"""Decrypto — assumption-driven security checks + responsible disclosure report.

Python 3.9+ stdlib, read-only, explicitly scoped website/API auditor.
Reports falsifiable *leads*, not confirmed exploits.
"""

from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import math
import re
import ssl
import sys
import time
from datetime import datetime, timezone
from email.message import Message
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit, urlunsplit
from urllib.request import HTTPHandler, HTTPSHandler, HTTPRedirectHandler, ProxyHandler, Request, build_opener
from decrypto_validation import ORIGINS, evaluate_cors_pair, metadata

VERSION = "1.3"
MARKER_ORIGIN = "https://audit-origin.invalid"
SESSION_NAME = re.compile(r"(?:session|sessid|(^|[_-])sid($|[_-])|auth|token|jwt|login)", re.I)
METHODS = {"get", "post", "put", "patch", "delete", "head", "options"}


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


def normalize_url(url: str) -> str:
    """Canonicalize URL values for stable comparisons and consistent scope checks."""
    p = urlsplit(url)
    if p.scheme not in ("http", "https") or not p.hostname:
        raise ValueError("Invalid HTTP(S) URL")
    if p.username or p.password:
        raise ValueError("URLs must not contain credentials")
    if p.query or p.fragment:
        raise ValueError("URLs must not include query or fragment")
    if p.path.startswith("//"):
        raise ValueError("Path must not start with double slash")
    if p.hostname.endswith("."):
        raise ValueError("Hostname cannot end with a period")
    if p.scheme == "http" and p.hostname not in ("localhost", "127.0.0.1", "::1"):
        raise ValueError("Non-HTTPS targets are allowed only on localhost")
    if p.port is not None and not 1 <= p.port <= 65535:
        raise ValueError("Invalid URL port")

    scheme = p.scheme.lower()
    hostname = p.hostname.lower()
    port = p.port
    if (scheme == "https" and port == 443) or (scheme == "http" and port == 80):
        port = None
    host = f"[{hostname}]" if ":" in hostname else hostname
    netloc = host if port is None else f"{host}:{port}"
    path = p.path or "/"
    return urlunsplit((scheme, netloc, path, "", ""))


def validate_url(url: str) -> str:
    """Validation helper that keeps only explicit, restricted URLs in scope."""
    normalized = normalize_url(url)
    return normalized


def new_finding(rule: str, url: str, title: str, assumption: str,
                evidence: dict[str, Any], reasoning: str, fix: str, verification: str,
                priority: str = "review") -> dict[str, Any]:
    return {
        "id": hashlib.sha256((rule + "|" + url).encode()).hexdigest()[:10].upper(),
        "rule": rule,
        "target": url,
        "title": title,
        "priority": priority,
        "status": "UNCONFIRMED — needs owner validation",
        "evidence_class": "observable_configuration_or_contract",
        "assumption_tested": assumption,
        "evidence": evidence,
        "how_model_found_it": reasoning,
        "remediation": fix,
        "validation_needed": verification,
    }


def directives(headers: Message, name: str) -> dict[str, str]:
    """Parse exact directive tokens across repeated fields; retain no raw values."""
    return {part.partition("=")[0].strip().lower(): part.partition("=")[2].strip().strip('"')
            for value in headers.get_all(name, []) for part in value.split(",")}


def shared_cache(headers: Message) -> bool:
    cache = directives(headers, "Cache-Control")
    if any(key in cache for key in ("no-store", "private", "no-cache")):
        return False
    age = cache.get("s-maxage")
    return (age.isascii() and age.isdigit() and bool(age.strip("0"))) if age is not None else "public" in cache


def hsts_state(headers: Message) -> str:
    values = headers.get_all("Strict-Transport-Security", [])
    if not values:
        return "absent"
    # Browsers process the first field only. Duplicate max-age is invalid.
    ages = [part.partition("=")[2].strip().strip('"') for part in values[0].split(";")
            if part.partition("=")[0].strip().lower() == "max-age"]
    if len(ages) != 1 or not ages[0].isascii() or not ages[0].isdigit():
        return "invalid"
    return "disabled" if not ages[0].strip("0") else "enabled"


def cookie_metadata(headers: Message) -> list[dict[str, Any]]:
    """Never save cookie names or values; only inspect session-like names in memory."""
    data: list[dict[str, Any]] = []
    for raw in headers.get_all("Set-Cookie", []) or []:
        sections = [x.strip() for x in raw.split(";")]
        if not sections or "=" not in sections[0]:
            continue
        name = sections[0].split("=", 1)[0]
        attrs = {x.partition("=")[0].lower().strip(): x.partition("=")[2].strip() for x in sections[1:]}
        same = attrs.get("samesite", "").lower()
        data.append({
            "session_like": bool(SESSION_NAME.search(name)),
            "secure": "secure" in attrs,
            "httponly": "httponly" in attrs,
            "samesite": same in {"lax", "strict", "none"},
            "none_without_secure": same == "none" and "secure" not in attrs,
            "prefix_invalid": (name.startswith("__Secure-") and "secure" not in attrs) or (name.startswith("__Host-") and ("secure" not in attrs or "domain" in attrs or attrs.get("path") != "/")),
        })
    return data


def has_auth_indicators(headers: Message) -> bool:
    """Return True when response suggests auth-relevant behavior."""
    www_auth = (headers.get("WWW-Authenticate") or "").lower()
    set_cookie_values = headers.get_all("Set-Cookie", []) or []
    cookie_names = []
    for raw in set_cookie_values:
        sections = [x.strip() for x in raw.split(";")]
        if sections and "=" in sections[0]:
            cookie_names.append(sections[0].split("=", 1)[0].lower())
    auth_cookie_names = any(
        SESSION_NAME.search(name) for name in cookie_names
    )
    return bool(www_auth or auth_cookie_names)


def send(opener, url: str, method: str, origin: str | None, timeout: float):
    headers = {"User-Agent": "Decrypto-Assumption-Audit/1.3 (read-only; authorized)", "Accept": "*/*"}
    if origin:
        headers["Origin"] = origin
    request = Request(url, method=method, headers=headers)
    try:
        with opener.open(request, timeout=timeout) as response:
            return response.status, response.headers
    except HTTPError as err:
        try:
            return err.code, err.headers
        finally:
            err.close()


def observe(url: str, status: int, headers: Message, private: bool) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    scheme = urlsplit(url).scheme
    cookies = cookie_metadata(headers)

    if scheme == "https" and status < 400 and hsts_state(headers) != "enabled":
        findings.append(new_finding(
            "TLS-HSTS",
            url,
            "HSTS absent, disabled or invalid",
            "HTTPS deployment should consistently enforce upgrade to HTTPS.",
            {"status": status, "strict_transport_security": hsts_state(headers)},
            "Compared the expected HTTPS transport invariant to the actual response header.",
            "Publish an appropriate Strict-Transport-Security policy on the relevant HTTPS host; test subdomain impact first.",
            "Confirm any inherited or gateway-applied HSTS policy; absence alone is a hardening lead.",
            "low",
        ))

    for idx, cookie in enumerate(cookies, 1):
        if not cookie["session_like"] and not cookie["prefix_invalid"]:
            continue
        missing = [k for k in ("secure", "httponly", "samesite") if not cookie[k]] if cookie["session_like"] else []
        if cookie["none_without_secure"]:
            missing.append("samesite_none_requires_secure")
        if cookie["prefix_invalid"]:
            missing.append("cookie_prefix_requirements")
        if missing:
            findings.append(new_finding(
                f"SESSION-COOKIE-{idx}",
                url,
                "Cookie protection or prefix configuration needs review",
                "Session authentication state should have purpose-appropriate browser boundaries.",
                {"status": status, "cookie_index": idx, "missing_flags": missing},
                "Recognized a session-like cookie by name, then tested browser-boundary attributes without recording its name or value.",
                "For authentication cookies, use Secure, HttpOnly and an appropriate SameSite policy; verify legitimate cross-site workflows.",
                "Owner must verify this cookie actually authenticates a session and the missing flag is security-relevant.",
                "review",
            ))

    if private and 200 <= status < 300 and has_auth_indicators(headers):
        findings.append(new_finding(
            "AUTH-BOUNDARY",
            url,
            "Protected endpoint accepted anonymous request",
            "The owner-declared private endpoint should deny unauthenticated access.",
            {"expected_status": "401/403 (or documented denial)", "observed_status": status},
            "Compared the explicit owner-declared access expectation with a credential-free HTTP response that also showed auth-related behavior.",
            "Enforce authentication and object-level authorization on the server before returning protected content.",
            "Verify the route genuinely contains protected content with a test-owned resource. HTTP 200 alone is NOT an authorization bypass.",
            "review",
        ))

    if private and 200 <= status < 300 and shared_cache(headers):
        findings.append(new_finding(
            "PRIVATE-CACHE",
            url,
            "Potential shared-cache policy conflict on protected endpoint",
            "Protected, identity-dependent responses should not be stored in shared caches.",
            {"observed_status": status, "shared_cache_enabled": True},
            "Compared the declared private endpoint assumption to an observed shared-cache directive on the owner-declared private response.",
            "For private responses, use Cache-Control: private, no-store as appropriate and configure the CDN cache key correctly.",
            "Inspect gateway/cache configuration with the owner; this does not demonstrate exposure to another user.",
            "review",
        ))

    return findings


def cors_checks(url: str, status: int, headers: Message) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    allow = (headers.get("Access-Control-Allow-Origin") or "").strip()
    creds = (headers.get("Access-Control-Allow-Credentials") or "").strip()
    if len(headers.get_all("Access-Control-Allow-Origin", [])) != 1 or len(headers.get_all("Access-Control-Allow-Credentials", [])) > 1:
        return findings

    if allow == MARKER_ORIGIN and creds == "true":
        findings.append(new_finding(
            "CORS-TRUST",
            url,
            "Arbitrary test Origin reflected with credential permission",
            "Cross-origin trust should be restricted to independently approved origins.",
            {"status": status, "reflected_test_origin": True, "access_control_allow_credentials": True},
            "Compared the response to an innocuous, untrusted Origin header and observed credentialed reflection.",
            "Use an exact allowlist of trusted origins; avoid credentialed reflection of arbitrary origins; set Vary: Origin if dynamically varying.",
            "Validate in an authorized browser with a test account. SameSite cookies, browser rules and response sensitivity determine exploitability.",
            "review",
        ))

    if allow == MARKER_ORIGIN and not {"origin", "*"}.intersection(directives(headers, "Vary")) and shared_cache(headers):
        findings.append(new_finding(
            "CORS-CACHE",
            url,
            "Origin-dependent policy may not be represented in cache key",
            "Caching should not reuse an Origin-specific access policy across unrelated origins.",
            {"status": status, "origin_reflected": True, "vary_origin": False, "shared_cache_enabled": True},
            "Compared the observed Origin-specific CORS policy to shared caching and Vary behavior.",
            "Set Vary: Origin where appropriate and configure CDN cache keys to reflect origin-sensitive responses.",
            "Confirm the route is actually shared-cached; no poisoning or cross-user test was performed.",
            "review",
        ))

    return findings


def inspect_openapi(path: Path) -> tuple[list[dict[str, Any]], dict[str, Any] | None]:
    """Inspect only a local JSON contract, never download/follow external refs."""
    if path.stat().st_size > 2_000_000:
        raise ValueError("OpenAPI JSON exceeds 2 MB")
    spec = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(spec, dict) or not (spec.get("openapi") or spec.get("swagger")):
        raise ValueError("Expected OpenAPI/Swagger JSON")

    components = spec.get("components") or {}
    if not isinstance(components, dict):
        raise ValueError("OpenAPI components must be an object")
    schemes = components.get("securitySchemes") or spec.get("securityDefinitions") or {}
    if not isinstance(schemes, dict) or not isinstance(spec.get("paths", {}), dict):
        raise ValueError("OpenAPI schemes and paths must be objects")
    for security in [spec.get("security", [])] + [op.get("security", [])
            for item in spec.get("paths", {}).values() if isinstance(item, dict)
            for verb, op in item.items() if verb.lower() in METHODS and isinstance(op, dict)]:
        if not isinstance(security, list) or any(not isinstance(req, dict) for req in security):
            raise ValueError("OpenAPI security must be an array of requirement objects")
    findings: list[dict[str, Any]] = []
    for name, scheme in schemes.items():
        if not isinstance(scheme, dict):
            continue
        if scheme.get("type") == "apiKey" and scheme.get("in") == "query":
            label = f"{path.name}:components.securitySchemes.{name}"
            findings.append(new_finding(
                "OAS-KEY-IN-URL",
                label,
                "API contract places an API key in a URL query parameter",
                "Authentication secrets should avoid URLs that may enter browser history, logs or intermediaries.",
                {"scheme": name, "location": "query"},
                "Reviewed the documented authentication representation without generating or using a credential.",
                "Use an Authorization header or suitable secure credential transport, and redact any existing logs.",
                "Confirm this scheme is used by the deployed API; the contract alone proves no actual credential leakage.",
                "review",
            ))

    operations = 0
    for path_str, methods in (spec.get("paths") or {}).items():
        if not isinstance(methods, dict):
            continue
        for verb, operation in methods.items():
            if verb.lower() not in METHODS or not isinstance(operation, dict):
                continue
            operations += 1
            if "$ref" in operation or "$ref" in methods:
                continue  # Unresolved references are not evidence of absent security.
            if verb.lower() not in {"post", "put", "patch", "delete"}:
                continue
            effective = operation.get("security", spec.get("security"))
            if schemes and (effective is None or effective == [] or (isinstance(effective, list) and {} in effective)):
                label = f"{path.name}:{verb.upper()} {path_str}"
                findings.append(new_finding(
                    "OAS-WRITE-NO-AUTH",
                    label,
                    "Mutating operation has no documented authentication requirement",
                    "State-changing operations typically require a defined authorization policy.",
                    {"method": verb.upper(), "security_declared": effective is not None},
                    "Compared the operation's effective security requirement to the API's advertised authentication schemes.",
                    "Declare and enforce the appropriate operation security, unless this is intentionally public.",
                    "Owner must confirm intended access policy and actual implementation; public registration endpoints are legitimate.",
                    "review",
                ))

    api_meta = {
        "operations_reviewed": operations,
        "schemes": len(schemes),
        "source_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
    }
    return findings, api_meta


def correlate_assumptions(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Identify consistent multi-control contradictions, never assert exploitability."""
    by_target: dict[str, dict[str, dict[str, Any]]] = {}
    for finding in findings:
        by_target.setdefault(finding["target"], {})[finding["rule"]] = finding

    hypotheses: list[dict[str, Any]] = []
    patterns = [
        (
            "TRUST-CACHE-ORIGIN",
            ("CORS-TRUST", "CORS-CACHE"),
            "Cross-origin trust and cache partition assumptions conflict",
            "An untrusted Origin is credential-authorized and the response appears publicly cacheable without Vary: Origin.",
            "Confirm a shared cache exists and reproduce any actual policy crossover with owner-controlled test responses; do not infer data disclosure from these headers alone.",
            "Restrict allowed origins and ensure origin-varying responses have a correct cache key / Vary policy.",
        ),
        (
            "TRUST-CACHE-PRIVATE",
            ("AUTH-BOUNDARY", "PRIVATE-CACHE"),
            "Declared access boundary and public-cache policy disagree",
            "An endpoint marked private by the tester returned a 2xx anonymous response with a shared-cache directive.",
            "Confirm the documented route contract and test only owner-created non-sensitive records; a 2xx could be an intentional public shell.",
            "Enforce server-side authorization and use private/no-store for responses containing identity-dependent data.",
        ),
    ]

    for target, present in by_target.items():
        for rule, required, title, explanation, missing, remediation in patterns:
            if not all(key in present for key in required):
                continue
            hypotheses.append({
                "id": hashlib.sha256((rule + "|" + target).encode()).hexdigest()[:10].upper(),
                "title": title,
                "target": target,
                "finding_ids": [present[key]["id"] for key in required],
                "status": "UNCONFIRMED — correlated observations, not verified impact",
                "assumption_conflict": explanation,
                "missing_evidence": missing,
                "remediation": remediation,
                "request_count_added": 0,
            })
    return hypotheses


def scan(urls: list[str], private_urls: set[str], *, cors: bool = False,
         delay: float = 1.0, timeout: float = 6.0, openapi: Path | None = None,
         verify_cors: bool = False) -> dict[str, Any]:
    if len(urls) > 12 or len(urls) != len(set(urls)):
        raise ValueError("Use at most 12 different, explicitly listed URLs per run")

    normalized_urls: list[str] = []
    seen: set[str] = set()
    for url in urls:
        canonical = validate_url(url)
        if canonical not in seen:
            seen.add(canonical)
            normalized_urls.append(canonical)

    if verify_cors and len(normalized_urls) > 8:
        raise ValueError("Paired CORS verification is limited to 8 URLs and 24 total requests")
    normalized_private_urls = {validate_url(u) for u in private_urls}
    if not normalized_private_urls.issubset(set(normalized_urls)):
        raise ValueError("Every --private-url must be included in --url")

    if not math.isfinite(delay) or not math.isfinite(timeout) or delay < 0.5 or timeout < 1 or timeout > 20:
        raise ValueError("Minimum 0.5s delay; timeout must be between 1 and 20 seconds")

    api_findings, api_meta = inspect_openapi(openapi) if openapi else ([], None)
    opener = build_opener(NoRedirect(), HTTPHandler(), HTTPSHandler(context=ssl.create_default_context()), ProxyHandler({}))
    findings: list[dict[str, Any]] = []
    observations: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    sent = 0
    paired_verification: list[dict[str, Any]] = []

    for url in normalized_urls:
        pair_samples: list[dict[str, Any]] = []
        for method, origin in [("GET" if url in normalized_private_urls else "HEAD", None)] + ([("GET", MARKER_ORIGIN)] if cors or verify_cors else []) + ([("GET", ORIGINS[1])] if verify_cors else []):
            if sent:
                time.sleep(delay)
            sent += 1
            try:
                status, headers = send(opener, url, method, origin, timeout)
            except (HTTPError, URLError, TimeoutError, ssl.SSLError, OSError, ValueError, http.client.HTTPException) as exc:
                errors.append({"url": url, "method": method, "error_type": type(exc).__name__})
                continue
            observations.append({
                "url": url,
                "method": method,
                "status": status,
                "cors_probe": bool(origin),
                "redirect_not_followed": 300 <= status < 400,
            })
            if origin:
                if verify_cors:
                    pair_samples.append(metadata(origin, status, headers))
                if origin == MARKER_ORIGIN:
                    findings.extend(cors_checks(url, status, headers))
            else:
                findings.extend(observe(url, status, headers, url in normalized_private_urls))
        if verify_cors:
            paired_verification.append(evaluate_cors_pair(url, pair_samples))

    findings.extend(api_findings)

    findings.sort(key=lambda f: (f["rule"], f["target"]))
    correlated = correlate_assumptions(findings)
    return {
        "tool": "Decrypto Assumption-Driven Auditor",
        "version": VERSION,
        "date_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "status": "Security leads only — not verified vulnerabilities",
        "method": [
            "state a falsifiable security assumption",
            "observe the relevant trust boundary or implementation contract",
            "record a contradiction without exploit payloads",
            "correlate compatible contradictions without claiming exploitability",
            "require owner validation before assigning impact",
        ],
        "scope": normalized_urls,
        "total_requests": sent,
        "finding_count": len(findings),
        "findings": findings,
        "correlated_assumption_hypotheses": correlated,
        "correlated_hypothesis_count": len(correlated),
        "observations": observations,
        "paired_cors_verification": paired_verification,
        "errors": errors,
        "openapi_review": api_meta,
        "not_tested": [
            "exploitation",
            "credential attacks",
            "parameter injection",
            "object ID substitution",
            "data extraction",
            "cryptographic nonce attacks",
            "cross-account access",
            "bypassing access controls",
        ],
        "privacy": "No response bodies, credentials, cookie names/values, redirect destinations or session tokens were stored.",
    }


def markdown_report(result: dict[str, Any]) -> str:
    lines = [
        "# Security observation and responsible disclosure draft",
        "",
        "**Research attribution:** Decrypto — assumption-driven methodology",
        "",
        f"**UTC:** {result['date_utc']}",
        f"**Scope:** {', '.join(result['scope']) or 'Offline OpenAPI review only'}",
        "",
        f"**Requests:** {result['total_requests']}; **review leads:** {result['finding_count']}; **correlated hypotheses:** {result.get('correlated_hypothesis_count', 0)}; **errors:** {len(result.get('errors', []))}",
        "",
        "**Disclosure status:** UNCONFIRMED. Do not submit a claim of exploitability without separately reproducing the impact within the program rules.",
        "",
        "## Methodology",
        "",
        "This audit stated security assumptions, observed safe HTTP/contract behavior, and compared the two. A contradiction is a hypothesis—not proof of a security breach.",
        "",
    ]
    if not result["findings"]:
        lines += [
            "## Findings",
            "",
            "No leads detected by these limited checks. This does **not** establish that the target is secure.",
            "",
        ]
    for number, finding in enumerate(result["findings"], 1):
        lines += [
            f"## Finding {number}: {finding['title']}",
            "",
            f"**ID:** `{finding['id']}` | **Rule:** `{finding['rule']}` | **Priority:** {finding['priority']} | **Status:** {finding['status']}",
            "",
            f"**Affected endpoint/contract:** `{finding['target']}`",
            "",
            "**Assumption tested:** " + finding["assumption_tested"],
            "",
            "**Evidence observed:**",
            "",
            "```json",
            json.dumps(finding["evidence"], indent=2, ensure_ascii=False),
            "```",
            "",
            "**How the assumption-driven model found it:** " + finding["how_model_found_it"],
            "",
            "**Suggested remediation:** " + finding["remediation"],
            "",
            "**Evidence required before a vulnerability report:** " + finding["validation_needed"],
            "",
            "**Reproduction scope:** Credential-free HEAD/GET observations (up to two harmless Origin probes), or offline local contract inspection, limited to the explicitly authorized URL. No payloads or sensitive elements were stored.",
            "",
        ]

    for number, corr in enumerate(result.get("correlated_assumption_hypotheses", []), 1):
        lines += [
            f"## Correlated assumption hypothesis {number}: {corr['title']}",
            "",
            f"**Target:** `{corr['target']}`",
            "",
            f"**Underlying observation IDs:** {', '.join(corr['finding_ids'])}",
            "",
            f"**Potential mismatch:** {corr['assumption_conflict']}",
            "",
            f"**Evidence still missing:** {corr['missing_evidence']}",
            "",
            f"**Suggested remediation:** {corr['remediation']}",
            "",
            "**Not a confirmed exploit or separate vulnerability.**",
            "",
        ]

    if result.get("errors"):
        lines += [
            "## Errors / unavailable checks",
            "",
            "```json",
            json.dumps(result["errors"], indent=2),
            "```",
            "",
        ]

    lines += [
        "## Reporting guidance",
        "",
        "Share only findings you independently confirm, using a program-approved disclosure channel. Attach redacted evidence, the affected URL, explicit authorization scope, and the remediation plan.",
        "",
        "**Limitations:** This tool intentionally does not send attack payloads, test authorization with other users' objects, read response bodies, or confirm browser-based exploitability.",
        "",
    ]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Decrypto assumption-driven site/API review — authorized targets only")
    parser.add_argument("--url", action="append", default=[], help="Exact authorized HTTP(S) URL; repeat for more URLs (max 12)")
    parser.add_argument("--private-url", action="append", default=[], help="One of --url values that should deny anonymous GET")
    parser.add_argument("--cors", action="store_true", help="Add one credential-free GET per URL with innocuous Origin")
    parser.add_argument("--verify-cors", action="store_true", help="Compare two credential-free Origin probes; never proves exploitability")
    parser.add_argument("--openapi", type=Path, help="Optional LOCAL OpenAPI JSON specification to review offline")
    parser.add_argument("--authorized", action="store_true", help="Affirm explicit permission for every HTTP target")
    parser.add_argument("--delay", type=float, default=1, help="Seconds between requests (minimum 0.5)")
    parser.add_argument("--timeout", type=float, default=6, help="Request timeout in seconds (1–20)")
    parser.add_argument("--out", type=Path, default=Path("decrypto_findings"), help="Report prefix; generates .json and .md")
    args = parser.parse_args(argv)

    if not args.url and not args.openapi:
        parser.error("Provide --url or --openapi")
    if args.url and not args.authorized:
        parser.error("Web/API tests require --authorized AND permission from the asset owner")
    if len(args.url) * (3 if args.verify_cors else 2 if args.cors else 1) > 24:
        parser.error("Maximum of 24 requests per run")

    try:
        result = scan(args.url, set(args.private_url), cors=args.cors, delay=args.delay, timeout=args.timeout, openapi=args.openapi, verify_cors=args.verify_cors)
        json_path = args.out.with_suffix(".json")
        md_path = args.out.with_suffix(".md")
        json_path.parent.mkdir(parents=True, exist_ok=True)
        json_path.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        md_path.write_text(markdown_report(result), encoding="utf-8")
        print(f"Completed {result['total_requests']} requests; {result['finding_count']} unconfirmed leads, {len(result['errors'])} errors")
        print(f"JSON evidence: {json_path}\nDisclosure draft: {md_path}")
        return 0 if not result["errors"] else 2
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    sys.exit(main())
