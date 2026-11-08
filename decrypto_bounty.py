"""Authorized bug-bounty scope checks and submission drafts.

Load a local scope file, decide whether a URL is in scope, and render review
leads for a researcher who is already allowed to test that program. This module
does not contact networks, generate attack inputs, or mark a lead as a
confirmed vulnerability.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

_MAX_SCOPE_BYTES = 65_536
_MAX_ENTRIES = 64
_HOST = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))*$")
_SECRET_KEYS = {
    "authorization",
    "cookie",
    "credential",
    "credentials",
    "match_excerpt",
    "password",
    "secret",
    "session",
    "set-cookie",
    "token",
}
_REPRO_BY_RULE = {
    "SENSITIVE-PATH-EXPOSED": (
        "An unauthenticated HEAD was sent to the path recorded in the evidence. "
        "The response status was 2xx. The body was not read. A 2xx status can be a "
        "generic page, so this observation does not show that a sensitive file was returned."
    ),
    "OPEN-REDIRECT": (
        "A credential-free GET added one benign marker to a redirect-style query parameter. "
        "The Location header started with that marker. The redirect was not followed."
    ),
    "CRYPTO-HARDKEY": (
        "A quoted literal in local source matched the hardcoded-secret heuristic. "
        "The report stores the file location and a SHA-256 of the source bytes, not the literal."
    ),
    "CRYPTO-AEAD-STATIC-NONCE": (
        "The Python syntax shows an AEAD encrypt call whose nonce expression is fixed. "
        "This does not show that the same key and nonce are reused at runtime."
    ),
}


@dataclass(frozen=True)
class ScopeEntry:
    """One include or exclude rule from a program scope file."""

    kind: str
    host: str
    scheme: str | None
    port: int | None
    path: str
    path_mode: str
    raw: str

    # Host-only entries intentionally cover both schemes and all ports.\n    # Use URL entries for a precise scheme/port boundary.\n    def matches(self, scheme: str, host: str, port: int | None, path: str) -> bool:
        if not _host_matches(self.host, host):
            return False
        if self.kind == "host":
            return True
        if self.scheme != scheme or self.port != port:
            return False
        if self.path_mode == "any":
            return True
        if self.path_mode == "prefix":
            base = self.path.rstrip("/") or "/"
            if base == "/":
                return True
            return path.casefold() == base.casefold() or path.casefold().startswith(base.casefold() + "/")
        return path.casefold() == self.path.casefold()


@dataclass(frozen=True)
class ProgramScope:
    """In-scope and out-of-scope assets for one authorized program."""

    program: str
    includes: tuple[ScopeEntry, ...]
    excludes: tuple[ScopeEntry, ...]
    code_assets: tuple[str, ...]
    notes: str
    source_sha256: str
    source_name: str

    def allows(self, url: str) -> bool:
        """Return whether a concrete URL survives excludes and matches an include."""
        try:
            candidate = _candidate(url)
        except ValueError:
            return False
        if any(entry.matches(*candidate) for entry in self.excludes):
            return False
        return any(entry.matches(*candidate) for entry in self.includes)

    def allows_asset(self, asset: str) -> bool:
        """Return whether a report asset is a listed URL, host, or code label."""
        text = asset.strip()
        if not text:
            return False
        if "://" in text:
            return self.allows(text)
        if text in self.code_assets:
            return True
        if "/" in text or "\\" in text or any(char.isspace() for char in text):
            return False
        for scheme in ("https", "http"):
            if text.startswith("[") and "]" in text:
                bracket, _, rest = text.partition("]")
                host = bracket[1:]
                suffix = rest if rest.startswith(":") else ""
                if self.allows(f"{scheme}://[{host}]{suffix}/"):
                    return True
                continue
            if self.allows(f"{scheme}://{text}/"):
                return True
        return False

    def to_report(self) -> dict[str, Any]:
        return {
            "program": self.program,
            "scope_file": self.source_name,
            "scope_sha256": self.source_sha256,
            "in_scope": [entry.raw for entry in self.includes],
            "out_of_scope": [entry.raw for entry in self.excludes],
            "code_assets": list(self.code_assets),
            "notes": self.notes,
        }


def load_scope(path: Path) -> ProgramScope:
    """Load a local scope file. Reject broad, credentialed, or malformed rules."""
    if path.stat().st_size > _MAX_SCOPE_BYTES:
        raise ValueError("Scope file exceeds 64 KiB")
    raw = path.read_bytes()
    try:
        spec = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("Scope file must be UTF-8 JSON") from exc
    if not isinstance(spec, dict):
        raise ValueError("Scope file must be a JSON object")
    unknown = set(spec) - {"program", "in_scope", "out_of_scope", "code_assets", "notes"}
    if unknown:
        raise ValueError("Unknown scope fields: " + ", ".join(sorted(unknown)))
    program = spec.get("program")
    if not isinstance(program, str) or not program.strip() or len(program) > 200:
        raise ValueError("Scope program must be a non-empty string up to 200 characters")
    notes = spec.get("notes", "")
    if not isinstance(notes, str) or len(notes) > 2000:
        raise ValueError("Scope notes must be a string up to 2000 characters")
    includes = tuple(_parse_entries(spec.get("in_scope"), "in_scope"))
    if not includes:
        raise ValueError("in_scope must list at least one host or URL")
    excludes = tuple(_parse_entries(spec.get("out_of_scope", []), "out_of_scope"))
    code_assets = tuple(_parse_code_assets(spec.get("code_assets", [])))
    return ProgramScope(
        program=program.strip(),
        includes=includes,
        excludes=excludes,
        code_assets=code_assets,
        notes=notes.strip(),
        source_sha256=hashlib.sha256(raw).hexdigest(),
        source_name=path.name,
    )


def asset_label(finding: dict[str, Any]) -> str:
    """Location a reviewer can cite without copying a matched secret."""
    evidence = finding.get("evidence") or {}
    path = evidence.get("path")
    target = str(finding.get("target") or "")
    if isinstance(path, str) and path.startswith("/") and "://" in target:
        parts = urlsplit(target)
        if parts.scheme and parts.netloc:
            return urlunsplit((parts.scheme, parts.netloc, path, "", ""))
    if evidence.get("file") and evidence.get("line"):
        return f"{evidence.get('file')}:{evidence.get('line')}:{evidence.get('column')}"
    return target


def review_model(assumption: str, observation: str, falsifier: str, mechanism_observed: bool) -> dict[str, Any]:
    """Record what the assumption model actually compared.

    ``mechanism_observed`` means the configuration is visible in data the tool
    already collected. ``impact_shown`` stays false: this comparison is not an
    exploitability proof.
    """
    return {
        "kind": "assumption",
        "assumption": assumption,
        "observation": observation,
        "mechanism_observed": bool(mechanism_observed),
        "impact_shown": False,
        "falsifier": falsifier,
    }


def model_from_finding(finding: dict[str, Any]) -> dict[str, Any]:
    """Normalize a finding's model and refuse an impact claim."""
    model = finding.get("model")
    if isinstance(model, dict):
        return review_model(
            str(model.get("assumption") or finding.get("assumption_tested") or finding.get("title") or ""),
            str(model.get("observation") or finding.get("how_model_found_it") or ""),
            str(model.get("falsifier") or finding.get("validation_needed") or "Owner review is still required."),
            bool(model.get("mechanism_observed")),
        )
    exploitability = finding.get("exploitability") or {}
    return review_model(
        str(finding.get("assumption_tested") or finding.get("title") or ""),
        str(finding.get("how_model_found_it") or ""),
        str(finding.get("validation_needed") or "Owner review is still required."),
        bool(exploitability.get("directly_verifiable")) if isinstance(exploitability, dict) else False,
    )


def impact_assumption(finding: dict[str, Any]) -> str:
    text = finding.get("assumption_tested") or finding.get("title") or "The matched pattern needs review."
    return "Assumption, not confirmed impact: " + str(text)


def reproduction_notes(finding: dict[str, Any]) -> str:
    """Describe the observation the tool already made."""
    rule = str(finding.get("rule") or "")
    if rule in _REPRO_BY_RULE:
        return _REPRO_BY_RULE[rule]
    base, _, suffix = rule.rpartition("-")
    if suffix.isdigit() and base in _REPRO_BY_RULE:
        return _REPRO_BY_RULE[base]
    if finding.get("evidence_class") == "static_code_finding":
        evidence = finding.get("evidence") or {}
        return (
            f"Review the local file {evidence.get('file')} at line {evidence.get('line')}, "
            f"column {evidence.get('column')}. Compare it with the recorded source SHA-256. "
            "The matched text is not included. No attack input was generated."
        )
    observed = finding.get("how_model_found_it")
    if observed:
        return str(observed) + " No attack input was sent, and no response body was stored."
    return "The lead records an observation only. No attack input was sent, and no response body was stored."


def bounty_lead(finding: dict[str, Any], program_asset: str | None = None) -> dict[str, Any]:
    taxonomy = finding.get("taxonomy") or {}
    return {
        "id": finding.get("id"),
        "title": finding.get("title"),
        "rule": finding.get("rule"),
        "program_asset": program_asset or finding.get("target"),
        "location": asset_label(finding),
        "status": finding.get("status"),
        "confirmed_vulnerability": False,
        "priority": finding.get("priority"),
        "evidence_class": finding.get("evidence_class"),
        "taxonomy": taxonomy,
        "evidence": redact(finding.get("evidence") or {}),
        "assumption": impact_assumption(finding),
        "reproduction_notes": reproduction_notes(finding),
        "remediation": finding.get("remediation"),
        "validation_needed": finding.get("validation_needed"),
        "model": model_from_finding(finding),
        "exploitability": redact(finding.get("exploitability")) if finding.get("exploitability") else None,
    }


def package_bounty(findings: list[dict[str, Any]], scope: ProgramScope, *, assets: list[str],
                   skipped: list[dict[str, str]], generated_utc: str) -> dict[str, Any]:
    """Build the machine-readable bounty section. Every lead stays unconfirmed."""
    program_asset = assets[0] if len(assets) == 1 else None
    report = scope.to_report()
    report.update({
        "generated_utc": generated_utc,
        "targets_requested": list(assets),
        "targets_skipped": list(skipped),
        "leads": [bounty_lead(finding, program_asset=program_asset or finding.get("target")) for finding in findings],
        "confirmed_vulnerability_count": 0,
    })
    return report


def render_bounty_markdown(result: dict[str, Any]) -> str:
    """Render a submission draft from an assumption-scan or static-scan result."""
    bounty = result["bounty"]
    lines = [
        "# Bug-bounty review draft",
        "",
        f"**Program:** {bounty['program']}",
        "",
        f"**Generated (UTC):** {bounty.get('generated_utc') or result.get('date_utc')}",
        "",
        "**Status:** Unconfirmed review leads. This draft is not a vulnerability confirmation and it is not a submission by itself.",
        "",
        f"**Confirmed vulnerabilities in this export:** {bounty.get('confirmed_vulnerability_count', 0)}",
        "",
        "Decrypto compared observable configuration, contract text, or source patterns with stated assumptions. "
        "It did not generate attack inputs. Submit a report only when you are allowed to test this program and "
        "you have validated the impact under that program's rules.",
        "",
        f"**Scope file:** `{bounty.get('scope_file')}`",
        "",
        f"**Scope SHA-256:** `{bounty.get('scope_sha256')}`",
        "",
        "**In-scope rules:** " + (", ".join(f"`{item}`" for item in bounty.get("in_scope", [])) or "(none)"),
        "",
        "**Out-of-scope rules:** " + (", ".join(f"`{item}`" for item in bounty.get("out_of_scope", [])) or "(none)"),
        "",
        "**Assets requested:** " + (", ".join(f"`{item}`" for item in bounty.get("targets_requested", [])) or "(none)"),
        "",
    ]
    if bounty.get("notes"):
        lines += ["**Scope notes:** " + bounty["notes"], ""]
    skipped = bounty.get("targets_skipped") or []
    if skipped:
        lines += ["## Targets not contacted", ""]
        for item in skipped:
            lines.append(f"- `{item.get('url')}` — {item.get('reason')}")
        lines.append("")
    categories = result.get("findings_by_category") or {}
    if categories:
        lines += ["## Leads by category", ""]
        for category, subtypes in categories.items():
            total = sum(subtypes.values())
            lines.append(f"- {category}: {total}")
        lines.append("")
    leads = bounty.get("leads") or []
    if not leads:
        lines += [
            "## Leads",
            "",
            "No leads were produced by these checks. That does not establish that the asset is secure.",
            "",
        ]
    for number, lead in enumerate(leads, 1):
        taxonomy = lead.get("taxonomy") or {}
        cwe = taxonomy.get("cwe") or "no CWE"
        owasp = taxonomy.get("owasp_top10_2021") or "unspecified"
        lines += [
            f"## Lead {number}: {lead.get('title')}",
            "",
            f"- **Finding ID:** `{lead.get('id')}`",
            f"- **Rule:** `{lead.get('rule')}`",
            f"- **Status:** {lead.get('status')}",
            "- **Confirmed vulnerability:** no",
            f"- **Priority:** {lead.get('priority')}",
            f"- **Program asset:** `{lead.get('program_asset')}`",
            f"- **Location:** `{lead.get('location')}`",
            f"- **Taxonomy:** {taxonomy.get('category')} / {taxonomy.get('subtype')}; {cwe}; OWASP Top 10 2021 {owasp}",
            "",
            "### Assumption",
            "",
            str(lead.get("assumption") or ""),
            "",
            "### Evidence",
            "",
            "```json",
            json.dumps(lead.get("evidence") or {}, indent=2, ensure_ascii=False),
            "```",
            "",
            "### Reproduction notes",
            "",
            str(lead.get("reproduction_notes") or ""),
            "",
            "### Remediation",
            "",
            str(lead.get("remediation") or ""),
            "",
            "### Validation still required",
            "",
            str(lead.get("validation_needed") or "Owner review is still required."),
            "",
            "### Model",
            "",
            f"Mechanism observed: {'yes' if (lead.get('model') or {}).get('mechanism_observed') else 'no'}. "
            "Impact shown: no. A visible configuration is not an exploitability proof.",
            "",
            "What would falsify this lead: " + str((lead.get("model") or {}).get("falsifier") or lead.get("validation_needed") or ""),
            "",
        ]
    for number, item in enumerate(result.get("correlated_assumption_hypotheses") or [], 1):
        lines += [
            f"## Correlated hypothesis {number}: {item.get('title')}",
            "",
            f"**Target:** `{item.get('target')}`",
            "",
            f"**Status:** {item.get('status')}",
            "",
            str(item.get("assumption_conflict") or ""),
            "",
            "This correlation is not a separate confirmed vulnerability.",
            "",
        ]
    lines += [
        "## Filing notes",
        "",
        "Keep this draft inside the program's disclosure channel. Finding IDs are stable hashes of the rule and the asset location, so repeated runs and multiple paths on one host can be de-duplicated. "
        "Evidence lists locations, statuses, header metadata, and hashes. It omits matched secret literals, response bodies, cookie values, and credentials.",
        "",
        "Do not test an asset that this scope marks out of scope, and do not point the live scanner at a program you are not allowed to test.",
        "",
    ]
    return "\n".join(lines)


def redact(value: Any) -> Any:
    """Drop secret-like fields before they can reach a bounty draft."""
    if isinstance(value, dict):
        cleaned = {}
        for key, item in value.items():
            lowered = str(key).lower()
            if lowered in _SECRET_KEYS or lowered.endswith(("secret", "token", "password", "credential")):
                cleaned[str(key)] = "redacted"
            else:
                cleaned[str(key)] = redact(item)
        return cleaned
    if isinstance(value, list):
        return [redact(item) for item in value]
    if isinstance(value, str) and _looks_secret_material(value):
        return "redacted"
    if isinstance(value, str) and len(value) > 300:
        return {"sha256": hashlib.sha256(value.encode("utf-8")).hexdigest(), "length": len(value)}
    return value


def _looks_secret_material(value: str) -> bool:
    upper = value.upper()
    return "PRIVATE KEY" in upper or "BEGIN OPENSSH" in upper or "BEGIN CERTIFICATE" in upper


def _parse_entries(value: Any, field: str) -> list[ScopeEntry]:
    if not isinstance(value, list) or len(value) > _MAX_ENTRIES:
        raise ValueError(f"{field} must be a list of at most {_MAX_ENTRIES} strings")
    entries = []
    for item in value:
        if not isinstance(item, str):
            raise ValueError(f"{field} entries must be strings")
        entries.append(_parse_entry(item))
    return entries


def _parse_code_assets(value: Any) -> list[str]:
    if not isinstance(value, list) or len(value) > _MAX_ENTRIES:
        raise ValueError("code_assets must be a list of at most 64 strings")
    assets = []
    for item in value:
        if not isinstance(item, str) or not item.strip() or len(item) > 200 or any(char.isspace() for char in item):
            raise ValueError("code_assets entries must be non-empty strings without whitespace")
        assets.append(item.strip())
    return assets


def _parse_entry(raw: str) -> ScopeEntry:
    text = raw.strip()
    if not text or len(text) > 300 or any(char.isspace() for char in text):
        raise ValueError("Scope entries must be non-empty and cannot contain whitespace")
    if text == "*" or text.endswith("*") and not text.endswith("/*"):
        raise ValueError("Overly broad scope entry")
    if "@" in text:
        raise ValueError("Scope entries must not contain credentials")
    prefix = text.endswith("/*")
    body = text[:-2] if prefix else text
    if "://" not in body:
        if "/" in body or "*" in body[1:]:
            raise ValueError("Path rules need an http(s) URL; put source labels in code_assets")
        if body.startswith("*") and not body.startswith("*."):
            raise ValueError("Overly broad scope entry")
        host = _validate_host(body.lower().rstrip("."), allow_wildcard=True)
        return ScopeEntry("host", host, None, None, "/", "any", text)
    if "://" in text:
        remainder = text.split("://", 1)[1]
        if remainder.startswith("*") and not remainder.startswith("*."):
            raise ValueError("Overly broad scope entry")
    parts = urlsplit(body)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ValueError("Scope URLs must be http(s) and include a host")
    if parts.username or parts.password or parts.query or parts.fragment:
        raise ValueError("Scope URLs cannot contain credentials, queries, or fragments")
    host = _validate_host(parts.hostname.lower().rstrip("."), allow_wildcard=True)
    port = parts.port
    if (parts.scheme == "https" and port == 443) or (parts.scheme == "http" and port == 80):
        port = None
    path = parts.path or "/"
    if "*" in path:
        raise ValueError("Only a trailing /* path wildcard is supported")
    if prefix:
        path_mode = "any" if path in ("", "/") else "prefix"
        path = "/" if path in ("", "/") else path.rstrip("/")
    elif path in ("", "/"):
        path_mode = "any"
        path = "/"
    else:
        path_mode = "exact"
        path = path.rstrip("/") or "/"
    return ScopeEntry("url", host, parts.scheme, port, path, path_mode, text)


def _validate_host(host: str, *, allow_wildcard: bool) -> str:
    if allow_wildcard and host.startswith("*."):
        base = host[2:]
        if "." not in base or not _plain_host(base):
            raise ValueError("Wildcard hosts must look like *.name.tld")
        return "*." + base
    if not _plain_host(host):
        raise ValueError("Invalid host in scope entry")
    return host


def _plain_host(host: str) -> bool:
    if not host or "*" in host:
        return False
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return bool(_HOST.match(host))


def _host_matches(pattern: str, host: str) -> bool:
    if pattern.startswith("*."):
        suffix = pattern[1:]
        base = pattern[2:]
        return host != base and host.endswith(suffix)
    return pattern == host


def _candidate(url: str) -> tuple[str, str, int | None, str]:
    parts = urlsplit(url.strip())
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ValueError("Invalid URL")
    if parts.username or parts.password:
        raise ValueError("Invalid URL")
    host = parts.hostname.lower().rstrip(".")
    if not _plain_host(host):
        raise ValueError("Invalid URL")
    port = parts.port
    if (parts.scheme == "https" and port == 443) or (parts.scheme == "http" and port == 80):
        port = None
    path = parts.path or "/"
    if path != "/":
        path = path.rstrip("/") or "/"
    return parts.scheme, host, port, path
