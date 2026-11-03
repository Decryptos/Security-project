"""Active, payload-based bug-class verification for owner-authorized targets.

Opt-in only: the CLI gates this behind `--enable-active-payloads` *and*
`--authorized`. Unlike the rest of Decrypto (which only observes responses
to harmless requests), these checks send small, deliberately non-destructive
payloads to parameters the *target page itself* exposes in its own forms and
links — never guessed parameter names, never another user's data.

Payload safety invariants:
  * SQL/command injection checks use only `sleep`-style timing side effects
    (never DROP/UPDATE/DELETE, never data extraction via UNION, etc.). The
    command-injection check covers common POSIX shell chaining/substitution
    syntax (`;`, `|`, `&&`, `||`, backticks, `$()`, newline) plus Windows
    cmd.exe (`ping -n` against loopback only — never an external host, since
    Windows has no built-in `sleep`) and PowerShell (`Start-Sleep`)
    equivalents — it never reads, copies, or discloses any file (e.g. it
    never runs `cat`/`type` against `/etc/shadow` or any other sensitive
    file: that would be unreliable, since such files are rarely readable by
    the process a web app runs as, and unsafe, since any content it returned
    would otherwise end up stored in the JSON/Markdown report).
  * The XSS check uses one inert, tool-generated HTML marker — no <script>
    that calls out anywhere, no cookie theft, no DOM manipulation.
  * The path-traversal check only looks for a signature of a well-known,
    non-secret OS file (e.g. /etc/passwd's header line) to prove *read*
    access is possible; the file content itself is never stored or reported.

Every finding this module produces still goes through `new_finding`, so
`status` always stays "UNCONFIRMED — needs owner validation" — this module
only ever strengthens the `exploitability` field with directly observed,
reproducible evidence (a timing delta, a database error signature, a byte-
for-byte reflected marker, or a known-file signature).
"""

from __future__ import annotations

import http.client
import re
import ssl
import time
import uuid
from html.parser import HTMLParser
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urljoin, urlsplit, urlunsplit
from urllib.request import Request

MAX_INJECTION_POINTS = 3
MAX_BODY_BYTES = 200_000
TIME_DELAY_SECONDS = 3
TIME_THRESHOLD_SECONDS = 2.5
SAFE_DEFAULT_VALUE = "1"

_NETWORK_ERRORS = (HTTPError, URLError, TimeoutError, ssl.SSLError, OSError, http.client.HTTPException)

SQLI_ERROR_PAYLOAD = "'\""
SQLI_ERROR_PATTERNS = tuple(re.compile(p, re.IGNORECASE) for p in (
    r"sql syntax.*mysql",
    r"warning:\s*mysqli?_",
    r"unclosed quotation mark after the character string",
    r"quoted string not properly terminated",
    r"pg_query\(\)|postgresql.*error|syntax error at or near",
    r"sqlite3\.OperationalError|SQLITE_ERROR|near \".*\": syntax error",
    r"ORA-\d{5}",
    r"Microsoft OLE DB Provider for ODBC Drivers",
))
SQLI_TIME_PAYLOADS = (
    f"' OR SLEEP({TIME_DELAY_SECONDS})-- -",
    f"'||pg_sleep({TIME_DELAY_SECONDS})||'",
    f"1' AND SLEEP({TIME_DELAY_SECONDS}) AND '1'='1",
)
COMMAND_TIME_PAYLOADS = (
    # POSIX shell: command separators/chaining/substitution (all non-destructive
    # — every variant only ever runs `sleep`, which has no side effects).
    f"; sleep {TIME_DELAY_SECONDS} #",
    f"| sleep {TIME_DELAY_SECONDS}",
    f"`sleep {TIME_DELAY_SECONDS}`",
    f"$(sleep {TIME_DELAY_SECONDS})",
    f"&& sleep {TIME_DELAY_SECONDS}",
    f"|| sleep {TIME_DELAY_SECONDS}",
    f"; sleep {TIME_DELAY_SECONDS} ;",
    f"\nsleep {TIME_DELAY_SECONDS}\n",
    # Windows cmd.exe has no built-in `sleep`; `ping -n` against loopback only
    # (never an external host) is the standard non-destructive timing proxy.
    f"& ping -n {TIME_DELAY_SECONDS + 1} 127.0.0.1 & ",
    f"| ping -n {TIME_DELAY_SECONDS + 1} 127.0.0.1",
    f"&& ping -n {TIME_DELAY_SECONDS + 1} 127.0.0.1",
    # PowerShell
    f"; Start-Sleep -Seconds {TIME_DELAY_SECONDS}",
    f"| Start-Sleep -Seconds {TIME_DELAY_SECONDS}",
)
PATH_TRAVERSAL_PAYLOADS = (
    "../../../../../../etc/passwd",
    "..\\..\\..\\..\\..\\..\\windows\\win.ini",
)
PATH_TRAVERSAL_SIGNATURES = (
    re.compile(r"root:.*:0:0:"),
    re.compile(r"\[extensions\]", re.IGNORECASE),
)

# Worst case requests for one injection point: 1 sqli baseline + 1 sqli error
# + len(SQLI_TIME_PAYLOADS) + 1 xss + len(COMMAND_TIME_PAYLOADS) + len(PATH_TRAVERSAL_PAYLOADS)
MAX_PAYLOAD_REQUESTS_PER_POINT = 2 + len(SQLI_TIME_PAYLOADS) + 1 + len(COMMAND_TIME_PAYLOADS) + len(PATH_TRAVERSAL_PAYLOADS)

_TITLES = {
    "SQLI-ERROR-BASED": "SQL injection confirmed via database error signature",
    "SQLI-TIME-BLIND": "Blind SQL injection confirmed via response-time delay",
    "XSS-REFLECTED": "Reflected cross-site scripting confirmed via marker reflection",
    "COMMAND-INJECTION-TIME-BLIND": "OS command injection confirmed via response-time delay",
    "PATH-TRAVERSAL": "Path traversal confirmed via known-file signature",
}
_ASSUMPTIONS = {
    "SQLI-ERROR-BASED": "User-supplied input should never be interpreted as part of a SQL statement.",
    "SQLI-TIME-BLIND": "User-supplied input should never be interpreted as part of a SQL statement.",
    "XSS-REFLECTED": "User-supplied input reflected in a response should never be rendered as live HTML/script.",
    "COMMAND-INJECTION-TIME-BLIND": "User-supplied input should never be interpreted as part of a shell/OS command.",
    "PATH-TRAVERSAL": "User-supplied input should never let a caller read files outside the intended directory.",
}


class _FormAndLinkParser(HTMLParser):
    """Collect <form> fields and <a href> query parameters from one HTML page."""

    def __init__(self, base_url: str):
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.forms: list[dict[str, Any]] = []
        self.links: list[str] = []
        self._current_form: dict[str, Any] | None = None

    def handle_starttag(self, tag, attrs):
        attr = dict(attrs)
        if tag == "form":
            action = urljoin(self.base_url, attr.get("action") or self.base_url)
            method = (attr.get("method") or "get").strip().lower()
            self._current_form = {"action": action, "method": method if method in ("get", "post") else "get", "fields": {}}
            self.forms.append(self._current_form)
        elif tag in ("input", "textarea", "select") and self._current_form is not None:
            name = attr.get("name")
            if not name:
                return
            field_type = (attr.get("type") or "text").strip().lower()
            if field_type in ("submit", "button", "image", "reset", "file"):
                return
            editable = field_type not in ("hidden", "checkbox", "radio")
            value = attr.get("value") if not editable else SAFE_DEFAULT_VALUE
            self._current_form["fields"][name] = {"value": value or SAFE_DEFAULT_VALUE, "editable": editable}
        elif tag == "a":
            href = attr.get("href")
            if href:
                self.links.append(urljoin(self.base_url, href))

    def handle_endtag(self, tag):
        if tag == "form":
            self._current_form = None


def discover_injection_points(base_url: str, body: str, max_points: int = MAX_INJECTION_POINTS) -> list[dict[str, Any]]:
    """Return at most `max_points` injectable (form/query, parameter) pairs found in one page's own markup.

    Only parameters the page itself defines are tested — nothing is guessed.
    """
    parser = _FormAndLinkParser(base_url)
    try:
        parser.feed(body)
    except (AssertionError, ValueError):
        return []
    points: list[dict[str, Any]] = []
    base_host = urlsplit(base_url).hostname

    for form in parser.forms:
        if urlsplit(form["action"]).hostname != base_host:
            continue
        editable = [name for name, field in form["fields"].items() if field["editable"]]
        for name in editable:
            if len(points) >= max_points:
                return points
            points.append({
                "kind": "form",
                "target_url": form["action"],
                "method": form["method"],
                "param": name,
                "baseline_fields": {n: f["value"] for n, f in form["fields"].items()},
            })

    for link in parser.links:
        parsed = urlsplit(link)
        if parsed.hostname != base_host or not parsed.query:
            continue
        params = dict(pair.split("=", 1) if "=" in pair else (pair, "") for pair in parsed.query.split("&") if pair)
        for name in params:
            if len(points) >= max_points:
                return points
            points.append({
                "kind": "query",
                "target_url": urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", "")),
                "method": "get",
                "param": name,
                "baseline_fields": dict(params),
            })
    return points


def _build_request(point: dict[str, Any], value: str) -> tuple[str, str, bytes | None]:
    fields = dict(point["baseline_fields"])
    fields[point["param"]] = value
    if point["method"] == "get":
        parsed = urlsplit(point["target_url"])
        url = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode(fields), ""))
        return url, "GET", None
    return point["target_url"], "POST", urlencode(fields).encode()


def _send_payload(opener, url: str, method: str, data: bytes | None, timeout: float):
    headers = {"User-Agent": "Decrypto-Assumption-Audit/1.3 (read-only; authorized)", "Accept": "*/*"}
    if data is not None:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    request = Request(url, data=data, method=method.upper(), headers=headers)
    start = time.monotonic()
    try:
        with opener.open(request, timeout=timeout) as response:
            body = response.read(MAX_BODY_BYTES)
            return response.status, response.headers, body.decode("utf-8", "replace"), time.monotonic() - start
    except HTTPError as err:
        try:
            body = err.read(MAX_BODY_BYTES)
            return err.code, err.headers, body.decode("utf-8", "replace"), time.monotonic() - start
        finally:
            err.close()


def _throttled_payload_send(opener, state: dict[str, int], delay: float, url: str, method: str,
                             data: bytes | None, timeout: float):
    if state["sent"]:
        time.sleep(delay)
    state["sent"] += 1
    return _send_payload(opener, url, method, data, timeout)


def _finding(rule: str, point: dict[str, Any], evidence: dict[str, Any], reasoning: str, fix: str,
             directly_verifiable: bool, method: str, priority: str = "high") -> dict[str, Any]:
    from decrypto_assumption_scan import (
        new_finding,  # deferred: avoids a module import cycle
    )

    full_evidence = {**evidence, "parameter": point["param"], "http_method": point["method"]}
    return new_finding(
        rule,
        point["target_url"],
        _TITLES[rule],
        _ASSUMPTIONS[rule],
        full_evidence,
        reasoning,
        fix,
        "This tool only compared a payload response/timing to an identical harmless request on a parameter the page "
        "itself exposes; it did not read, modify or exfiltrate persistent data. Confirm business impact and scope "
        "with the asset owner before any disclosure claim.",
        priority,
        exploitability={
            "directly_verifiable": directly_verifiable,
            "method": method,
            "requires_additional_testing": "No" if directly_verifiable else "Confirm manually in an authorized session",
        },
    )


def sqli_checks(opener, state: dict[str, int], delay: float, point: dict[str, Any], timeout: float) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    base_url, base_method, base_data = _build_request(point, SAFE_DEFAULT_VALUE)
    try:
        _, _, baseline_body, baseline_elapsed = _throttled_payload_send(opener, state, delay, base_url, base_method, base_data, timeout)
    except _NETWORK_ERRORS:
        return findings

    err_url, err_method, err_data = _build_request(point, SQLI_ERROR_PAYLOAD)
    try:
        _, _, error_body, _ = _throttled_payload_send(opener, state, delay, err_url, err_method, err_data, timeout)
        if (any(p.search(error_body) for p in SQLI_ERROR_PATTERNS)
                and not any(p.search(baseline_body) for p in SQLI_ERROR_PATTERNS)):
            findings.append(_finding(
                "SQLI-ERROR-BASED", point,
                {"payload_class": "quote_characters", "matched_database_error_signature": True},
                "Injected quote characters and the response changed to include a database error signature that was absent from the identical request with a harmless value.",
                "Use parameterized queries/prepared statements; never concatenate user input into SQL; return generic error pages.",
                True, "sql_error_signature_diff",
            ))
            return findings
    except _NETWORK_ERRORS:
        pass

    for payload in SQLI_TIME_PAYLOADS:
        t_url, t_method, t_data = _build_request(point, payload)
        try:
            _, _, _, payload_elapsed = _throttled_payload_send(opener, state, delay, t_url, t_method, t_data, timeout)
        except _NETWORK_ERRORS:
            continue
        if payload_elapsed - baseline_elapsed >= TIME_THRESHOLD_SECONDS:
            findings.append(_finding(
                "SQLI-TIME-BLIND", point,
                {"payload_class": "time_delay", "delay_seconds": TIME_DELAY_SECONDS,
                 "baseline_elapsed_s": round(baseline_elapsed, 2), "payload_elapsed_s": round(payload_elapsed, 2)},
                f"Injected a {TIME_DELAY_SECONDS}s SQL time-delay payload and the response took measurably longer than the identical request with a harmless value.",
                "Use parameterized queries/prepared statements; never concatenate user input into SQL.",
                True, "response_time_delta",
            ))
            break
    return findings


def xss_checks(opener, state: dict[str, int], delay: float, point: dict[str, Any], timeout: float) -> list[dict[str, Any]]:
    marker = f"dcx{uuid.uuid4().hex[:8]}"
    payload = f"<{marker}>alert(1)</{marker}>"
    url, method, data = _build_request(point, payload)
    try:
        _, _, body, _ = _throttled_payload_send(opener, state, delay, url, method, data, timeout)
    except _NETWORK_ERRORS:
        return []
    if payload in body:
        return [_finding(
            "XSS-REFLECTED", point,
            {"payload_class": "inert_html_marker", "reflected_unescaped": True},
            "Injected a unique, inert HTML marker and it was reflected byte-for-byte (unescaped) in the response body — the same path a live <script> payload would reach.",
            "HTML-encode all untrusted output for its rendering context (body/attribute/JS string/URL) or use an auto-escaping template engine; add a strict Content-Security-Policy as defense in depth.",
            True, "unescaped_reflection",
        )]
    return []


def command_injection_checks(opener, state: dict[str, int], delay: float, point: dict[str, Any], timeout: float) -> list[dict[str, Any]]:
    base_url, base_method, base_data = _build_request(point, SAFE_DEFAULT_VALUE)
    try:
        _, _, _, baseline_elapsed = _throttled_payload_send(opener, state, delay, base_url, base_method, base_data, timeout)
    except _NETWORK_ERRORS:
        return []
    for payload in COMMAND_TIME_PAYLOADS:
        url, method, data = _build_request(point, payload)
        try:
            _, _, _, payload_elapsed = _throttled_payload_send(opener, state, delay, url, method, data, timeout)
        except _NETWORK_ERRORS:
            continue
        if payload_elapsed - baseline_elapsed >= TIME_THRESHOLD_SECONDS:
            return [_finding(
                "COMMAND-INJECTION-TIME-BLIND", point,
                {"payload_class": "time_delay", "delay_seconds": TIME_DELAY_SECONDS,
                 "baseline_elapsed_s": round(baseline_elapsed, 2), "payload_elapsed_s": round(payload_elapsed, 2)},
                f"Injected a shell metacharacter payload containing `sleep {TIME_DELAY_SECONDS}` and the response took measurably longer than the identical request with a harmless value.",
                "Never pass user input to a shell; use safe APIs (e.g. subprocess with an argument list, no shell=True) and strict input allowlisting.",
                True, "response_time_delta",
            )]
    return []


def path_traversal_checks(opener, state: dict[str, int], delay: float, point: dict[str, Any], timeout: float) -> list[dict[str, Any]]:
    for payload in PATH_TRAVERSAL_PAYLOADS:
        url, method, data = _build_request(point, payload)
        try:
            _, _, body, _ = _throttled_payload_send(opener, state, delay, url, method, data, timeout)
        except _NETWORK_ERRORS:
            continue
        if any(sig.search(body) for sig in PATH_TRAVERSAL_SIGNATURES):
            return [_finding(
                "PATH-TRAVERSAL", point,
                {"payload_class": "relative_path_traversal", "matched_known_file_signature": True},
                "Injected a relative path-traversal payload and the response body matched a signature unique to a well-known OS file, which this parameter should never be able to reach. The file content itself was not stored.",
                "Validate/allowlist file-path input server-side; never pass user input directly to filesystem APIs; serve files from a jailed directory with resolved-path checks.",
                True, "known_file_signature_match",
            )]
    return []


def active_payload_checks(opener, state: dict[str, int], delay: float, url: str, timeout: float,
                           max_points: int = MAX_INJECTION_POINTS) -> list[dict[str, Any]]:
    """Discover injection points on one authorized URL's own page and verify common bug classes.

    Only forms/links the page itself serves are tested, bounded to
    `max_points` parameters. Every payload is non-destructive (see module
    docstring). Returns a (possibly empty) list of findings.
    """
    findings: list[dict[str, Any]] = []
    try:
        status, _, body, _ = _throttled_payload_send(opener, state, delay, url, "GET", None, timeout)
    except _NETWORK_ERRORS:
        return findings
    if status >= 400 or not body:
        return findings

    for point in discover_injection_points(url, body, max_points):
        findings.extend(sqli_checks(opener, state, delay, point, timeout))
        findings.extend(xss_checks(opener, state, delay, point, timeout))
        findings.extend(command_injection_checks(opener, state, delay, point, timeout))
        findings.extend(path_traversal_checks(opener, state, delay, point, timeout))
    return findings
