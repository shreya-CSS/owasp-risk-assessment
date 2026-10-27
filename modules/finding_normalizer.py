"""Normalisation, sanitisation and de-duplication of findings from all tools."""
from __future__ import annotations

import hashlib
import re
from urllib.parse import urlsplit

from modules.models import Finding

MAX_TEXT = 4000
MAX_EVIDENCE = 2000
MAX_EVIDENCE_SAMPLES = 3
MAX_LOCATIONS = 50

_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

_SEVERITY_ALIASES = {
    "critical": "critical", "crit": "critical", "4": "critical",
    "high": "high", "3": "high",
    "medium": "medium", "moderate": "medium", "2": "medium",
    "low": "low", "1": "low",
    "info": "info", "informational": "info", "information": "info", "0": "info", "none": "info",
}
_SEVERITY_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1, "unrated": 0}

_CONFIDENCE_ALIASES = {
    "confirmed": "confirmed", "certain": "confirmed", "4": "confirmed",
    "high": "high", "firm": "high", "3": "high",
    "medium": "medium", "2": "medium",
    "low": "low", "tentative": "low", "1": "low",
    "false positive": "false_positive", "falsepositive": "false_positive", "0": "false_positive",
}
_CONFIDENCE_RANK = {"confirmed": 4, "high": 3, "medium": 2, "low": 1, "unknown": 0}


def clean_text(value: object, max_len: int = MAX_TEXT) -> str:
    """Strip control characters and cap length. Scanner output is untrusted data."""
    if value is None:
        return ""
    text = _CONTROL_CHARS.sub("", str(value)).replace("\r\n", "\n").strip()
    if len(text) > max_len:
        text = text[: max_len - 15].rstrip() + " …[truncated]"
    return text


def normalize_severity(raw: object) -> str:
    return _SEVERITY_ALIASES.get(str(raw or "").strip().lower(), "unrated")


def normalize_confidence(raw: object) -> str:
    return _CONFIDENCE_ALIASES.get(str(raw or "").strip().lower(), "unknown")


def severity_rank(severity: str) -> int:
    return _SEVERITY_RANK.get(severity, 0)


def url_key(url: str) -> str:
    """Scheme, host, port and path only — queries and fragments vary between requests."""
    if not url:
        return ""
    parts = urlsplit(url.strip())
    host = (parts.hostname or "").lower()
    try:
        port = parts.port
    except ValueError:
        port = None
    netloc = f"{host}:{port}" if port else host
    path = parts.path or "/"
    return f"{parts.scheme.lower()}://{netloc}{path}"


def origin_key(url: str) -> str:
    """scheme://host:port of a URL."""
    key = url_key(url)
    parts = urlsplit(key)
    return f"{parts.scheme}://{parts.netloc}" if key else ""


def compute_fingerprint(finding: Finding) -> str:
    """Stable identity for a finding, independent of scan: issue + origin + parameter.
    Like ZAP's alert view, one issue on many pages of the same site is ONE finding whose
    affected URLs are kept in `locations`. Tool-independent when the finding has an
    issue_key, so the same issue from two tools also collapses into one."""
    identity = finding.issue_key or f"{finding.source_tool}:{finding.rule_id or finding.title.lower()}"
    location = origin_key(finding.affected_url) or finding.asset.lower()
    # An issue_key already names the header/cookie; tools disagree on what they put in 'parameter'.
    parameter = "" if finding.issue_key else finding.parameter.lower()
    raw = "|".join((identity, location, parameter))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:24]


def sanitize_finding(finding: Finding) -> Finding:
    finding.title = clean_text(finding.title, 300) or "Untitled finding"
    finding.description = clean_text(finding.description)
    finding.evidence = clean_text(finding.evidence, MAX_EVIDENCE)
    finding.remediation = clean_text(finding.remediation)
    finding.affected_url = clean_text(finding.affected_url, 2048)
    finding.asset = clean_text(finding.asset, 300)
    finding.parameter = clean_text(finding.parameter, 300)
    finding.rule_id = clean_text(finding.rule_id, 100)
    finding.references = [clean_text(r, 500) for r in finding.references if r][:10]
    finding.scanner_tags = [clean_text(t, 100) for t in finding.scanner_tags if t][:30]
    if finding.scanner_severity not in _SEVERITY_RANK:
        finding.scanner_severity = normalize_severity(finding.scanner_severity)
    if finding.confidence not in _CONFIDENCE_RANK:
        finding.confidence = normalize_confidence(finding.confidence)
        if finding.confidence == "false_positive":
            finding.confidence = "unknown"
    if finding.cvss_score is not None and not 0.0 <= float(finding.cvss_score) <= 10.0:
        finding.cvss_score = None
    if not finding.sources:
        finding.sources = [finding.source_tool]
    if not finding.locations:
        loc = url_key(finding.affected_url) or finding.asset
        finding.locations = [loc] if loc else []
    finding.fingerprint = compute_fingerprint(finding)
    return finding


def _merge(into: Finding, other: Finding) -> None:
    into.occurrences += other.occurrences
    for src in other.sources:
        if src not in into.sources:
            into.sources.append(src)
    if severity_rank(other.scanner_severity) > severity_rank(into.scanner_severity):
        into.scanner_severity = other.scanner_severity
    if _CONFIDENCE_RANK.get(other.confidence, 0) > _CONFIDENCE_RANK.get(into.confidence, 0):
        into.confidence = other.confidence
    for loc in other.locations:
        if loc not in into.locations and len(into.locations) < MAX_LOCATIONS:
            into.locations.append(loc)
    samples = [s for s in into.evidence.split("\n---\n") if s]
    if other.evidence and other.evidence not in samples and len(samples) < MAX_EVIDENCE_SAMPLES:
        samples.append(other.evidence)
        into.evidence = clean_text("\n---\n".join(samples), MAX_EVIDENCE)
    for ref in other.references:
        if ref not in into.references:
            into.references.append(ref)
    for tag in other.scanner_tags:
        if tag not in into.scanner_tags:
            into.scanner_tags.append(tag)
    into.cwe_id = into.cwe_id or other.cwe_id
    if into.cvss_score is None:
        into.cvss_score = other.cvss_score
    into.remediation = into.remediation or other.remediation
    into.description = into.description or other.description
    into.exploit_evidence = into.exploit_evidence or other.exploit_evidence


def deduplicate(findings: list[Finding]) -> list[Finding]:
    """Merge findings with the same fingerprint. Evidence samples, source tools and
    occurrence counts are kept, so no meaningful information is discarded."""
    merged: dict[str, Finding] = {}
    for finding in findings:
        sanitize_finding(finding)
        existing = merged.get(finding.fingerprint)
        if existing is None:
            merged[finding.fingerprint] = finding
        else:
            _merge(existing, finding)
    return list(merged.values())
