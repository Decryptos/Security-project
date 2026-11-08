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
import socket
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
from decrypto_bounty import ProgramScope, load_scope, package_bounty, render_bounty_markdown
from decrypto_taxonomy import classify, summarize
from decrypto_validation import ORIGINS, evaluate_cors_pair, metadata

VERSION = "1.3"
MARKER_ORIGIN = "https://audit-origin.invalid"
REDIRECT_MARKER = "https://audit-redirect.invalid/"
REDIRECT_PARAMS = ("redirect", "return", "next")
SENSITIVE_PATH_KINDS = {
    "/.git/HEAD": "version-control",
    "/.svn/entries": "version-control",
    "/.env": "environment-file",
    "/.aws/credentials": "cloud-credentials",
    "/.htpasswd": "credential-file",
    "/id_rsa": "private-key",
    "/wp-config.php.bak": "backup-file",
    "/backup.zip": "backup-file",
    "/.DS_Store": "metadata-file",
    "/phpinfo.php": "debug-endpoint",
    "/server-status": "debug-endpoint",
    "/actuator/env": "debug-endpoint",
}
SENSITIVE_PATHS = tuple(SENSITIVE_PATH_KINDS)
WEAK_TLS_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}
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
    if p.query:
        raise ValueError("URLs must not include a query string")
    # Fragments are not sent to the server. A browser URL such as
    # http://localhost:3000/#/ is scanned as http://localhost:3000/ only.
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


_ID_EVIDENCE_KEYS = ("path", "tested_parameter", "cookie_index", "scheme", "method")


def _finding_material(rule: str, url: str, evidence: dict[str, Any]) -> str:
    """Keep distinct leads distinct when one rule matches several paths on one URL."""
    parts = [rule, url]
    for key in _ID_EVIDENCE_KEYS:
        value = evidence.get(key)
        if isinstance(value, bool) or value is None or value == "":
            continue
        if isinstance(value, (str, int)):
            parts.append(f"{key}={value}")
    return "|".join(parts)


def new_finding(rule: str, url: str, title: str, assumption: str,
                evidence: dict[str, Any], reasoning: str, fix: str, verification: str,
                priority: str = "review", exploitability: dict[str, Any] | None = None) -> dict[str, Any]:
    """Build a finding.

    `exploitability`, when provided, states — in a conservative, falsifiable way —
    whether the *observed response data alone* (never an attack payload) already
    confirms the mechanism, or whether further owner-authorized testing is still
    required before any impact claim. It never upgrades `status`, which always
    stays UNCONFIRMED until the owner validates real-world impact.
    """
    finding = {
        "id": hashlib.sha256(_finding_material(rule, url, evidence).encode()).hexdigest()[:10].upper(),
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
        "taxonomy": classify(rule),
    }
    if exploitability is not None:
        finding["exploitability"] = exploitability
    return finding





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


def _throttled_send(opener, state: dict[str, int], delay: float, url: str, method: str,
                     origin: str | None, timeout: float):
    """Send one request, sleeping `delay` seconds before every request after the first.

    `state["sent"]` is shared across every check in a single `scan()` run so the
    rate limit applies to the whole run, not just one check's own requests.
    """
    if state["sent"]:
        time.sleep(delay)
    state["sent"] += 1
    return send(opener, url, method, origin, timeout)


def security_header_checks(url: str, status: int, headers: Message) -> list[dict[str, Any]]:
    """Check framing, MIME-sniffing and version-disclosure headers on a normal response.

    Uses only headers already received for the baseline request — no extra
    requests are sent. Header *absence* is directly verifiable from the
    response alone, so each finding states that plainly; whether it is
    actually exploitable still depends on page content the tool never reads.
    """
    findings: list[dict[str, Any]] = []
    if status >= 400:
        return findings

    frame_options = (headers.get("X-Frame-Options") or "").strip()
    csp = headers.get("Content-Security-Policy") or ""
    if not frame_options and "frame-ancestors" not in csp.lower():
        findings.append(new_finding(
            "CLICKJACK-HEADERS",
            url,
            "No framing-protection header observed",
            "Pages should declare an explicit framing policy (X-Frame-Options or CSP frame-ancestors).",
            {"status": status, "x_frame_options": "absent", "csp_frame_ancestors": "absent"},
            "Compared the response headers to the expected framing-control invariant.",
            "Add X-Frame-Options: DENY/SAMEORIGIN or a Content-Security-Policy with frame-ancestors.",
            "Confirm the page renders sensitive, state-changing UI in a browser before treating this as clickjackable; static or non-interactive pages are lower risk.",
            "low",
            exploitability={
                "directly_verifiable": True,
                "method": "header_absence",
                "requires_additional_testing": "Confirm the page has sensitive interactive UI that is worth framing",
            },
        ))

    content_type_options = (headers.get("X-Content-Type-Options") or "").strip().lower()
    if content_type_options != "nosniff":
        findings.append(new_finding(
            "MIME-SNIFF",
            url,
            "X-Content-Type-Options: nosniff not observed",
            "Responses should opt browsers out of MIME type sniffing.",
            {"status": status, "x_content_type_options": content_type_options or "absent"},
            "Compared the response header to the expected anti-sniffing invariant.",
            "Add X-Content-Type-Options: nosniff.",
            "Confirm the endpoint serves user-influenced content before treating this as exploitable; a reflection/upload vector is required.",
            "low",
            exploitability={
                "directly_verifiable": True,
                "method": "header_absence",
                "requires_additional_testing": "Yes — needs a content reflection/upload vector to be exploitable",
            },
        ))

    banner = " ".join(filter(None, [headers.get("Server"), headers.get("X-Powered-By")])).strip()
    if re.search(r"\d+\.\d+(\.\d+)?", banner):
        findings.append(new_finding(
            "SERVER-BANNER",
            url,
            "Server/X-Powered-By header discloses version information",
            "Version banners should not be exposed, to reduce targeted exploitation of known CVEs.",
            {"status": status, "banner_excerpt": banner[:80]},
            "Parsed the Server/X-Powered-By headers for an embedded version number.",
            "Suppress or genericize version banners at the web server/framework layer.",
            "Match the disclosed version against a CVE database to assess real risk; a version string alone is not a vulnerability.",
            "low",
            exploitability={
                "directly_verifiable": True,
                "method": "header_disclosure",
                "requires_additional_testing": "Match the disclosed version against known CVEs",
            },
        ))

    findings.extend(header_variant_checks(url, status, headers))
    return findings


FRAMEWORK_HEADERS = ("X-AspNet-Version", "X-AspNetMvc-Version", "X-Generator", "X-Drupal-Cache", "X-Runtime")


def _header_finding(rule: str, url: str, title: str, assumption: str, evidence: dict[str, Any],
                    fix: str, verification: str, priority: str = "low") -> dict[str, Any]:
    return new_finding(
        rule, url, title, assumption, evidence,
        "Parsed the response headers already received for the baseline request; no extra request was sent.",
        fix, verification, priority,
        exploitability={"directly_verifiable": True, "method": "header_analysis",
                        "requires_additional_testing": "Confirm real impact on the specific page and browsers in scope"},
    )


def header_variant_checks(url: str, status: int, headers: Message) -> list[dict[str, Any]]:
    """Variant-level header findings: CSP weaknesses, referrer/permissions policy, framework banners, CORS wildcard."""
    findings: list[dict[str, Any]] = []
    csp_values = headers.get_all("Content-Security-Policy", [])
    csp = {part.strip().split(None, 1)[0].lower(): (part.strip().split(None, 1)[1] if " " in part.strip() else "")
           for value in csp_values for part in value.split(";") if part.strip()}

    if not csp_values:
        findings.append(_header_finding(
            "CSP-MISSING", url, "No Content-Security-Policy header observed",
            "Pages should restrict script and resource origins with a CSP to limit XSS impact.",
            {"status": status, "content_security_policy": "absent"},
            "Add a restrictive Content-Security-Policy (default-src 'self' plus nonces/hashes for scripts).",
            "CSP is defence in depth; confirm whether the page handles untrusted content before treating it as risk."))
    else:
        script_src = (csp.get("script-src") or csp.get("default-src") or "").lower()
        if "'unsafe-inline'" in script_src and "'nonce-" not in script_src and "'strict-dynamic'" not in script_src:
            findings.append(_header_finding(
                "CSP-UNSAFE-INLINE", url, "CSP allows unsafe-inline scripts",
                "A CSP should block inline script execution.",
                {"status": status, "directive": "script-src/default-src", "token": "'unsafe-inline'"},
                "Remove 'unsafe-inline'; use nonces or hashes.",
                "Weakens XSS mitigation only; it is not itself an XSS vulnerability.", "review"))
        if "'unsafe-eval'" in script_src:
            findings.append(_header_finding(
                "CSP-UNSAFE-EVAL", url, "CSP allows unsafe-eval",
                "A CSP should block string-to-code evaluation.",
                {"status": status, "directive": "script-src/default-src", "token": "'unsafe-eval'"},
                "Remove 'unsafe-eval' and refactor code that needs eval().",
                "Weakens XSS mitigation only; it is not itself an XSS vulnerability."))
        wide = [tok for tok in script_src.split() if tok in ("*", "https:", "http:", "data:")]
        if wide:
            findings.append(_header_finding(
                "CSP-WILDCARD-SOURCE", url, "CSP script source allows a wildcard or whole scheme",
                "Script sources should be an explicit allowlist.",
                {"status": status, "directive": "script-src/default-src", "tokens": sorted(set(wide))},
                "Replace wildcard/scheme sources with specific origins, nonces or hashes.",
                "Check whether any allowed origin lets attackers host script (JSONP, open buckets).", "review"))
        missing = [d for d in ("object-src", "base-uri") if d not in csp]
        if missing:
            findings.append(_header_finding(
                "CSP-MISSING-DIRECTIVES", url, "CSP lacks object-src and/or base-uri",
                "These directives do not fall back to default-src and are common CSP bypass paths.",
                {"status": status, "missing_directives": missing},
                "Add object-src 'none' and base-uri 'self'.",
                "Defence-in-depth gap; confirm with the owner."))

    referrer = (headers.get("Referrer-Policy") or "").strip().lower()
    if not referrer or referrer in ("unsafe-url", "no-referrer-when-downgrade"):
        findings.append(_header_finding(
            "REFERRER-POLICY", url, "Referrer-Policy missing or leaks full URLs",
            "Responses should limit referrer data sent to other origins.",
            {"status": status, "referrer_policy": referrer or "absent"},
            "Set Referrer-Policy: strict-origin-when-cross-origin (or stricter).",
            "Matters only if URLs on this site carry sensitive data."))

    if not headers.get("Permissions-Policy") and not headers.get("Feature-Policy"):
        findings.append(_header_finding(
            "PERMISSIONS-POLICY", url, "No Permissions-Policy header observed",
            "Pages should disable browser features they do not use.",
            {"status": status, "permissions_policy": "absent"},
            "Add a Permissions-Policy denying camera, microphone, geolocation, etc. unless needed.",
            "Hardening only; low impact."))

    exposed = [name for name in FRAMEWORK_HEADERS if headers.get(name)]
    if exposed:
        findings.append(_header_finding(
            "FRAMEWORK-BANNER", url, "Framework/CMS version header exposed",
            "Framework fingerprinting headers should be removed.",
            {"status": status, "headers": exposed},
            "Remove or genericize these headers.",
            "Match any disclosed version against known CVEs."))

    allow = (headers.get("Access-Control-Allow-Origin") or "").strip()
    creds = (headers.get("Access-Control-Allow-Credentials") or "").strip()
    if allow == "*":
        findings.append(_header_finding(
            "CORS-WILDCARD", url, "Access-Control-Allow-Origin wildcard",
            "Cross-origin access should be limited to approved origins.",
            {"status": status, "allow_origin": "*", "allow_credentials_header": creds or "absent"},
            "Use an explicit origin allowlist unless the resource is intentionally public.",
            "Browsers refuse credentialed requests with '*'; confirm the content is public before reporting."))
    return findings


def open_redirect_checks(opener, state: dict[str, int], delay: float, url: str, timeout: float,
                         allow=None, skipped: list[dict[str, str]] | None = None) -> list[dict[str, Any]]:
    """Probe common redirect-style query parameters for unvalidated reflection.

    Appends a harmless, clearly-marked external URL to a redirect-style query
    parameter; redirects are never followed (see NoRedirect), only the
    Location header is inspected. Stops at the first confirmed parameter to
    minimize requests.
    """
    parsed = urlsplit(url)
    findings: list[dict[str, Any]] = []
    for param in REDIRECT_PARAMS:
        test_url = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, f"{param}={REDIRECT_MARKER}", ""))
        if allow is not None and not allow(test_url):
            if skipped is not None:
                skipped.append({
                    "url": urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", "", "")),
                    "reason": f"Redirect probe for parameter {param} is outside the declared program scope and was not sent",
                })
            continue
        try:
            status, headers = _throttled_send(opener, state, delay, test_url, "GET", None, timeout)
        except (HTTPError, URLError, TimeoutError, ssl.SSLError, OSError, http.client.HTTPException):
            continue
        location = (headers.get("Location") or "") if headers else ""
        if 300 <= status < 400 and location.startswith(REDIRECT_MARKER):
            findings.append(new_finding(
                "OPEN-REDIRECT",
                url,
                "Unvalidated redirect target reflected in Location header",
                "Redirect-handling parameters should only redirect to an allowlisted set of destinations.",
                {"status": status, "tested_parameter": param, "location_matches_marker": True},
                "Supplied a harmless, clearly-marked external URL in a common redirect parameter and observed it reflected in the Location header. The redirect was never followed.",
                "Validate redirect targets against an allowlist of paths/domains before issuing a redirect.",
                "Confirm end-user impact (e.g., phishing or token-leak chaining) with the asset owner; no browser redirect was actually followed by this tool.",
                "review",
                exploitability={
                    "directly_verifiable": True,
                    "method": "location_header_reflection",
                    "requires_additional_testing": "Owner confirmation of real-world phishing/credential-leak impact",
                },
            ))
            break
    return findings


def sensitive_path_checks(opener, state: dict[str, int], delay: float, url: str, timeout: float,
                          allow=None, skipped: list[dict[str, str]] | None = None) -> list[dict[str, Any]]:
    """HEAD-probe a short list of well-known sensitive paths.

    Uses HEAD only, so no response body is ever read or stored, preserving the
    tool's privacy guarantee. A 2xx status is a lead, not confirmation — many
    servers return 200 for any path via SPA catch-all routing.
    """
    parsed = urlsplit(url)
    findings: list[dict[str, Any]] = []
    for sub in SENSITIVE_PATHS:
        test_url = urlunsplit((parsed.scheme, parsed.netloc, sub, "", ""))
        if allow is not None and not allow(test_url):
            if skipped is not None:
                skipped.append({
                    "url": test_url,
                    "reason": "Sensitive-path probe is outside the declared program scope and was not sent",
                })
            continue
        try:
            status, _headers = _throttled_send(opener, state, delay, test_url, "HEAD", None, timeout)
        except (HTTPError, URLError, TimeoutError, ssl.SSLError, OSError, http.client.HTTPException):
            continue
        if 200 <= status < 300:
            findings.append(new_finding(
                "SENSITIVE-PATH-EXPOSED",
                url,
                f"Potentially sensitive path responded 2xx: {sub}",
                "Version-control and credential files should not be reachable over HTTP.",
                {"status": status, "path": sub, "kind": SENSITIVE_PATH_KINDS[sub]},
                "Requested a well-known sensitive path with HEAD only; no response body was read or stored.",
                "Block access to VCS directories and credential/config files at the web server layer; verify they are not present in the deployed webroot.",
                "Many servers return 200 for any path (SPA catch-all routing); manually confirm within your authorized session that the body actually contains the sensitive file before reporting.",
                "review",
                exploitability={
                    "directly_verifiable": False,
                    "method": "head_status_only",
                    "requires_additional_testing": "Confirm with an authorized GET that the response body is the real sensitive file, not a generic catch-all page",
                },
            ))
    return findings


def tls_checks(hostname: str, port: int, timeout: float) -> list[dict[str, Any]]:
    """Open one TLS connection to read the certificate expiry and negotiated protocol.

    No HTTP request is sent on this connection; only the TLS handshake metadata
    is inspected. Errors are swallowed because this check is best-effort and
    optional (`--check-tls`).
    """
    findings: list[dict[str, Any]] = []
    target = f"https://{hostname}/"
    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as tls_sock:
                cert = tls_sock.getpeercert()
                protocol = tls_sock.version()
    except (OSError, ssl.SSLError, socket.timeout):
        return findings

    not_after = cert.get("notAfter") if cert else None
    if not_after:
        try:
            expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        except ValueError:
            expiry = None
        if expiry is not None:
            days_left = (expiry - datetime.now(timezone.utc)).days
            if days_left < 14:
                findings.append(new_finding(
                    "TLS-CERT-EXPIRY",
                    target,
                    "TLS certificate is expired or expiring soon",
                    "Certificates should be renewed well before expiry to avoid trust failures.",
                    {"not_after": not_after, "days_left": days_left},
                    "Read the peer certificate's notAfter field from the TLS handshake; no HTTP request was sent.",
                    "Renew the certificate and confirm automated renewal (e.g., ACME) is configured.",
                    "Directly verifiable from the certificate itself; no further testing needed.",
                    "high" if days_left < 0 else "review",
                    exploitability={"directly_verifiable": True, "method": "tls_certificate_metadata", "requires_additional_testing": "No"},
                ))

    if protocol in WEAK_TLS_PROTOCOLS:
        findings.append(new_finding(
            "TLS-WEAK-PROTOCOL",
            target,
            f"Weak TLS protocol version negotiated: {protocol}",
            "Servers should negotiate TLS 1.2 or newer only.",
            {"negotiated_protocol": protocol},
            "Read the negotiated protocol version from the TLS handshake; no HTTP request was sent.",
            "Disable SSLv2/SSLv3/TLS1.0/TLS1.1 on the server and require TLS 1.2+.",
            "Directly verifiable from the handshake itself; no further testing needed.",
            "high",
            exploitability={"directly_verifiable": True, "method": "tls_handshake_metadata", "requires_additional_testing": "No"},
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
         verify_cors: bool = False, check_redirects: bool = False,
         check_sensitive_paths: bool = False, check_tls: bool = False,
         max_urls: int = 12, scope: ProgramScope | None = None,
         skipped_targets: list[dict[str, str]] | None = None) -> dict[str, Any]:
    if len(urls) > max_urls or len(urls) != len(set(urls)):
        raise ValueError(f"Use at most {max_urls} different, explicitly listed URLs per run")

    normalized_urls: list[str] = []
    seen: set[str] = set()
    for url in urls:
        canonical = validate_url(url)
        if canonical not in seen:
            seen.add(canonical)
            normalized_urls.append(canonical)

    if scope is not None:
        rejected = [url for url in normalized_urls if not scope.allows(url)]
        if rejected:
            raise ValueError("Out-of-scope targets refused before any request: " + ", ".join(rejected))

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
    skipped: list[dict[str, str]] | None = None
    allow = None
    if scope is not None:
        skipped = list(skipped_targets or [])
        allow = scope.allows

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
                findings.extend(security_header_checks(url, status, headers))
        if verify_cors:
            paired_verification.append(evaluate_cors_pair(url, pair_samples))

        state = {"sent": sent}
        if check_redirects:
            findings.extend(open_redirect_checks(opener, state, delay, url, timeout, allow=allow, skipped=skipped))
        if check_sensitive_paths:
            findings.extend(sensitive_path_checks(opener, state, delay, url, timeout, allow=allow, skipped=skipped))
        if check_tls and urlsplit(url).scheme == "https":
            if state["sent"]:
                time.sleep(delay)
            state["sent"] += 1
            findings.extend(tls_checks(urlsplit(url).hostname, urlsplit(url).port or 443, timeout))
        sent = state["sent"]

    findings.extend(api_findings)

    findings.sort(key=lambda f: (f["rule"], f["target"]))
    correlated = correlate_assumptions(findings)
    result = {
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
        "findings_by_category": summarize(findings),
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
            "SQL/command/template injection payloads",
            "object ID substitution",
            "data extraction",
            "cryptographic nonce attacks",
            "cross-account access",
            "bypassing access controls",
            "denial-of-service or load testing",
        ],
        "privacy": "No response bodies, credentials, cookie names/values, redirect destinations or session tokens were stored.",
    }
    if scope is not None:
        result["bounty"] = package_bounty(
            findings,
            scope,
            assets=normalized_urls,
            skipped=skipped or [],
            generated_utc=result["date_utc"],
        )
    return result


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
            f"**ID:** `{finding['id']}` | **Rule:** `{finding['rule']}` | **Class:** {finding['taxonomy']['category']} / {finding['taxonomy']['subtype']} ({finding['taxonomy']['cwe'] or 'no CWE'}) | **Priority:** {finding['priority']} | **Status:** {finding['status']}",
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
        ]
        exploitability = finding.get("exploitability")
        if exploitability is not None:
            verified = "YES — response data alone confirms this mechanism" if exploitability.get("directly_verifiable") else "No — further owner-authorized testing required"
            lines += [
                f"**Exploitability verification:** {verified} (method: `{exploitability.get('method')}`)",
                "",
                f"**Further testing required:** {exploitability.get('requires_additional_testing')}",
                "",
            ]
        lines += [
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
    parser.add_argument("--check-redirects", action="store_true", help="Probe common redirect parameters for unvalidated open-redirect reflection")
    parser.add_argument("--check-sensitive-paths", action="store_true", help="HEAD-probe a short list of well-known sensitive paths (.git/HEAD, .env, etc.)")
    parser.add_argument("--check-tls", action="store_true", help="Read TLS certificate expiry and negotiated protocol via one handshake per HTTPS URL")
    parser.add_argument("--all-checks", action="store_true", help="Run every existing read-only check: CORS, redirect reflection, sensitive-path HEAD probes, and TLS. Does not add attack payloads.")
    parser.add_argument("--domain", help="Apex domain you are AUTHORIZED to test; discovers subdomains passively (crt.sh + DNS) and adds them to --url")
    parser.add_argument("--max-subdomains", type=int, default=5, help="Cap on subdomains added from --domain (1-15, default 5)")
    parser.add_argument("--openapi", type=Path, help="Optional LOCAL OpenAPI JSON specification to review offline")
    parser.add_argument("--authorized", action="store_true", help="Affirm explicit permission for every HTTP target")
    parser.add_argument("--delay", type=float, default=1, help="Seconds between requests (minimum 0.5)")
    parser.add_argument("--timeout", type=float, default=6, help="Request timeout in seconds (1–20)")
    parser.add_argument("--out", type=Path, default=Path("decrypto_findings"), help="Report prefix; generates .json and .md")
    parser.add_argument("--scope", type=Path, help="Local JSON program scope. Live targets must match before any request; out-of-scope targets are refused.")
    args = parser.parse_args(argv)
    if args.all_checks:
        args.cors = True
        args.verify_cors = True
        args.check_redirects = True
        args.check_sensitive_paths = True
        args.check_tls = True

    scope = None
    discovery_skipped: list[dict[str, str]] = []
    if args.scope:
        try:
            scope = load_scope(args.scope)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            parser.error(f"Could not load scope file: {exc}")
        for raw_url in args.url:
            try:
                canonical = validate_url(raw_url)
            except ValueError as exc:
                parser.error(str(exc))
            if not scope.allows(canonical):
                parser.error("Refusing out-of-scope targets before any request: " + canonical)

    urls = list(args.url)
    if args.domain:
        if not args.authorized:
            parser.error("--domain requires --authorized AND permission from the domain owner")
        if not 1 <= args.max_subdomains <= 15:
            parser.error("--max-subdomains must be between 1 and 15")
        try:
            from decrypto_subdomain_scan import discover_authorized_subdomains
            discovered = discover_authorized_subdomains(args.domain, max_subdomains=args.max_subdomains)
        except (ValueError, RuntimeError) as exc:
            parser.error(f"Subdomain discovery failed: {exc}")
        allowed_discovered = []
        for found in discovered:
            if found in urls:
                continue
            if scope is not None and not scope.allows(found):
                discovery_skipped.append({
                    "url": found,
                    "reason": "Discovered host is outside the declared program scope and was not contacted",
                })
                continue
            allowed_discovered.append(found)
        urls.extend(allowed_discovered)

    if scope is not None and not urls and discovery_skipped and not args.openapi:
        parser.error("No discovered host matched the program scope; nothing was contacted")
    if not urls and not args.openapi:
        parser.error("Provide --url, --domain, or --openapi")
    if urls and not args.authorized:
        parser.error("Web/API tests require --authorized AND permission from the asset owner")

    max_urls = 15 if args.domain else 12
    per_url_requests = (
        (3 if args.verify_cors else 2 if args.cors else 1)
        + (len(REDIRECT_PARAMS) if args.check_redirects else 0)
        + (len(SENSITIVE_PATHS) if args.check_sensitive_paths else 0)
        + (1 if args.check_tls else 0)
    )
    if len(urls) > max_urls:
        parser.error(f"Maximum of {max_urls} URLs per run")
    if len(urls) * per_url_requests > 250:
        parser.error("Maximum of 250 requests per run with the selected checks; reduce URLs or disable some --check-* flags")

    try:
        result = scan(urls, set(args.private_url), cors=args.cors, delay=args.delay, timeout=args.timeout, openapi=args.openapi,
                      verify_cors=args.verify_cors, check_redirects=args.check_redirects,
                      check_sensitive_paths=args.check_sensitive_paths, check_tls=args.check_tls, max_urls=max_urls,
                      scope=scope, skipped_targets=discovery_skipped)
        json_path = args.out.with_suffix(".json")
        md_path = args.out.with_suffix(".md")
        json_path.parent.mkdir(parents=True, exist_ok=True)
        json_path.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        md_path.write_text(markdown_report(result), encoding="utf-8")
        print(f"Completed {result['total_requests']} requests; {result['finding_count']} unconfirmed leads, {len(result['errors'])} errors")
        print(f"JSON evidence: {json_path}\nDisclosure draft: {md_path}")
        if scope is not None:
            bounty_path = args.out.with_suffix(".bounty.md")
            bounty_path.write_text(render_bounty_markdown(result), encoding="utf-8")
            print(f"Bounty draft: {bounty_path}")
        return 0 if not result["errors"] else 2
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    sys.exit(main())
