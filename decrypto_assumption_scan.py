#!/usr/bin/env python3
"""Decrypto — assumption-driven security checks + responsible disclosure report.

One-file, Python 3.9+ stdlib, read-only, explicitly scoped website/API auditor.
Reports falsifiable *leads*, not confirmed exploits.
"""

from __future__ import annotations

import argparse
import hashlib
import http.client
import json
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

VERSION = "1.2"
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
        raise ValueError(f"Invalid URL: {url!r}")
    if p.username or p.password:
        raise ValueError(f"URLs must not contain credentials: {url!r}")
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
    netloc = hostname if port is None else f"{hostname}:{port}"
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


def cookie_metadata(headers: Message) -> list[dict[str, Any]]:
    """Never save cookie names or values; only inspect session-like names in memory."""
    data: list[dict[str, Any]] = []
    for raw in headers.get_all("Set-Cookie", []) or []:
        sections = [x.strip() for x in raw.split(";")]
        if not sections or "=" not in sections[0]:
            continue
        name = sections[0].split("=", 1)[0]
        attrs = {x.split("=", 1)[0].lower().strip() for x in sections[1:]}
        data.append({
            "session_like": bool(SESSION_NAME.search(name)),
            "secure": "secure" in attrs,
            "httponly": "httponly" in attrs,
            "samesite": "samesite" in attrs,
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
    headers = {"User-Agent": "Decrypto-Assumption-Audit/1.2 (read-only; authorized)", "Accept": "*/*"}
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
    cache = (headers.get("Cache-Control") or "").lower()
    cookies = cookie_metadata(headers)

    if scheme == "https" and status < 400 and not headers.get("Strict-Transport-Security"):
        findings.append(new_finding(
            "TLS-HSTS",
            url,
            "HSTS not observed",
            "HTTPS deployment should consistently enforce upgrade to HTTPS.",
            {"status": status, "strict_transport_security": "absent"},
            "Compared the expected HTTPS transport invariant to the actual response header.",
            "Publish an appropriate Strict-Transport-Security policy on the relevant HTTPS host; test subdomain impact first.",
            "Confirm any inherited or gateway-applied HSTS policy; absence alone is a hardening lead.",
            "low",
        ))

    for idx, cookie in enumerate(cookies, 1):
        if not cookie["session_like"]:
            continue
        missing = [k for k in ("secure", "httponly", "samesite") if not cookie[k]]
        if missing:
            findings.append(new_finding(
                f"SESSION-COOKIE-{idx}",
                url,
                "Session-like cookie missing protective attributes",
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

    if private and 200 <= status < 300 and has_auth_indicators(headers) and ("public" in cache or "s-maxage" in cache):
        findings.append(new_finding(
            "PRIVATE-CACHE",
            url,
            "Potential shared-cache policy conflict on protected endpoint",
            "Protected, identity-dependent responses should not be stored in shared caches.",
            {"observed_status": status, "cache_control": cache[:140]},
            "Compared the declared private endpoint assumption to an observed shared-cache directive on a response that also showed auth-sensitive behavior.",
            "For private responses, use Cache-Control: private, no-store as appropriate and configure the CDN cache key correctly.",
            "Inspect gateway/cache configuration with the owner; this does not demonstrate exposure to another user.",
            "review",
        ))

    return findings


def cors_checks(url: str, status: int, headers: Message) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    allow = (headers.get("Access-Control-Allow-Origin") or "").strip()
    creds = (headers.get("Access-Control-Allow-Credentials") or "").strip().lower()
    vary = (headers.get("Vary") or "").strip().lower()
    cache = (headers.get("Cache-Control") or "").strip().lower()

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

    if allow == MARKER_ORIGIN and "origin" not in [x.strip() for x in vary.split(",")] and ("public" in cache or "s-maxage" in cache):
        findings.append(new_finding(
            "CORS-CACHE",
            url,
            "Origin-dependent policy may not be represented in cache key",
            "Caching should not reuse an Origin-specific access policy across unrelated origins.",
            {"status": status, "origin_reflected": True, "vary_origin": False, "cache_control": cache[:140]},
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

    schemes = (spec.get("components") or {}).get("securitySchemes") or spec.get("securityDefinitions") or {}
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
            if verb.lower() not in {"post", "put", "patch", "delete"}:
                continue
            effective = operation.get("security", spec.get("security"))
            if schemes and (effective is None or effective == []):
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
         delay: float = 1.0, timeout: float = 6.0, openapi: Path | None = None) -> dict[str, Any]:
    if len(urls) > 12 or len(urls) != len(set(urls)):
        raise ValueError("Use at most 12 different, explicitly listed URLs per run")

    normalized_urls: list[str] = []
    seen: set[str] = set()
    for url in urls:
        canonical = validate_url(url)
        if canonical not in seen:
            seen.add(canonical)
            normalized_urls.append(canonical)

    normalized_private_urls = {validate_url(u) for u in private_urls}
    if not normalized_private_urls.issubset(set(normalized_urls)):
        raise ValueError("Every --private-url must be included in --url")

    if delay < 0.5 or timeout < 1 or timeout > 20:
        raise ValueError("Minimum 0.5s delay; timeout must be between 1 and 20 seconds")

    opener = build_opener(NoRedirect(), HTTPHandler(), HTTPSHandler(context=ssl.create_default_context()), ProxyHandler({}))
    findings: list[dict[str, Any]] = []
    observations: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    sent = 0

    for url in normalized_urls:
        for method, origin in [("GET" if url in normalized_private_urls else "HEAD", None)] + ([("GET", MARKER_ORIGIN)] if cors else []):
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
                findings.extend(cors_checks(url, status, headers))
            else:
                findings.extend(observe(url, status, headers, url in normalized_private_urls))

    api_meta = None
    if openapi:
        extra, api_meta = inspect_openapi(openapi)
        findings.extend(extra)

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
            "**Reproduction scope:** A single non-authenticated HEAD/GET request (and optionally one harmless Origin probe), limited to the explicitly authorized URL. No payloads or sensitive elements were stored.",
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
    if len(args.url) * (2 if args.cors else 1) > 24:
        parser.error("Maximum of 24 requests per run")

    try:
        result = scan(args.url, set(args.private_url), cors=args.cors, delay=args.delay, timeout=args.timeout, openapi=args.openapi)
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

"""

Local functionality tests for the Decrypto auditor; NOT a real-world validation study.
"""

from __future__ import annotations

import importlib.util
import json
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

spec = importlib.util.spec_from_file_location("auditor", Path(__file__).with_name("decrypto_assumption_scan.py"))
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def respond(self):
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "https://unapproved.invalid/secret")
            self.end_headers()
            return
        self.send_response(403 if self.path == "/protected-safe" else 200)
        self.send_header("Content-Type", "application/json")
        if self.path == "/protected-test":
            self.send_header("Cache-Control", "public,max-age=30")
            self.send_header("Set-Cookie", "sessionid=DONT_SAVE_THIS; Path=/")
        if self.path == "/cors" and self.headers.get("Origin"):
            self.send_header("Access-Control-Allow-Origin", self.headers["Origin"])
            self.send_header("Access-Control-Allow-Credentials", "true")
            self.send_header("Cache-Control", "public,max-age=30")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(b'{"private":"DONT_SAVE_THIS"}')

    do_GET = respond
    do_HEAD = respond


class Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.httpd.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.thread.join(2)

    def test_private_boundary_and_cache_and_secret_redaction(self):
        url = self.base + "/protected-test"
        res = mod.scan([url], {url}, delay=0.5)
        rules = {f["rule"] for f in res["findings"]}
        self.assertIn("AUTH-BOUNDARY", rules)
        self.assertIn("PRIVATE-CACHE", rules)
        self.assertIn("SESSION-COOKIE-1", rules)
        self.assertNotIn("DONT_SAVE_THIS", json.dumps(res))
        md = mod.markdown_report(res)
        self.assertIn("How the assumption-driven model found it", md)
        self.assertIn("Suggested remediation", md)
        self.assertNotIn("DONT_SAVE_THIS", md)

    def test_cors_credentialed_reflection(self):
        url = self.base + "/cors"
        res = mod.scan([url], set(), cors=True, delay=0.5)
        rules = {f["rule"] for f in res["findings"]}
        self.assertIn("CORS-TRUST", rules)
        self.assertIn("CORS-CACHE", rules)
        self.assertEqual(res["total_requests"], 2)

    def test_protected_denied_is_not_vulnerability(self):
        url = self.base + "/protected-safe"
        res = mod.scan([url], {url}, delay=0.5)
        self.assertNotIn("AUTH-BOUNDARY", {f["rule"] for f in res["findings"]})

    def test_redirect_does_not_leave_scope(self):
        url = self.base + "/redirect"
        res = mod.scan([url], set())
        self.assertEqual(res["observations"][0]["status"], 302)
        self.assertTrue(res["observations"][0]["redirect_not_followed"])
        self.assertNotIn("unapproved.invalid", json.dumps(res))

    def test_reject_unencrypted_external(self):
        with self.assertRaises(ValueError):
            mod.scan(["http://example.com/"], set())

    def test_reject_unlisted_private_url(self):
        with self.assertRaises(ValueError):
            mod.scan([self.base + "/"], {self.base + "/not-listed"})

    def test_offline_openapi_contract(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "api.json"
            path.write_text(json.dumps({
                "openapi": "3.0.3",
                "components": {
                    "securitySchemes": {"ApiKey": {"type": "apiKey", "in": "query", "name": "token"}},
                },
                "paths": {"/profiles": {"post": {"summary": "Create"}}},
            }))
            res = mod.scan([], set(), openapi=path)
            rules = {f["rule"] for f in res["findings"]}
            self.assertEqual(res["total_requests"], 0)
            self.assertEqual(rules, {"OAS-KEY-IN-URL", "OAS-WRITE-NO-AUTH"})

    def test_assumption_correlation_for_cors_and_cache(self):
        url = self.base + "/cors"
        res = mod.scan([url], set(), cors=True, delay=0.5)
        self.assertEqual(res["correlated_hypothesis_count"], 1)
        hypothesis = res["correlated_assumption_hypotheses"][0]
        self.assertIn("Cross-origin trust", hypothesis["title"])
        self.assertEqual(hypothesis["request_count_added"], 0)
        self.assertIn("Correlated assumption hypothesis", mod.markdown_report(res))
        self.assertIn("UNCONFIRMED", hypothesis["status"])

    def test_assumption_correlation_for_declared_private_and_cache(self):
        url = self.base + "/protected-test"
        res = mod.scan([url], {url}, delay=0.5)
        self.assertEqual(res["correlated_hypothesis_count"], 1)
        hypothesis = res["correlated_assumption_hypotheses"][0]
        self.assertIn("access boundary", hypothesis["title"])
        self.assertIn("AUTH-BOUNDARY", {x["rule"] for x in res["findings"]})
        self.assertNotIn("DONT_SAVE_THIS", json.dumps(hypothesis))

    def test_safe_response_does_not_generate_correlation(self):
        url = self.base + "/protected-safe"
        res = mod.scan([url], {url}, cors=True, delay=0.5)
        self.assertEqual(res["correlated_hypothesis_count"], 0)

    def test_normalize_url_handles_default_ports(self):
        self.assertEqual(mod.normalize_url("https://example.com:443/"), "https://example.com/")
        self.assertEqual(mod.normalize_url("http://localhost:80/"), "http://localhost/")


if __name__ == "__main__":
    unittest.main(verbosity=2)

"""