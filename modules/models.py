"""Shared data structures: the normalised finding and per-tool execution results."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

# Scanner-reported severity after normalisation. "unrated" = the tool gives no severity.
SCANNER_SEVERITIES = ("critical", "high", "medium", "low", "info", "unrated")
# Application-calculated priority levels, most urgent first.
PRIORITY_LEVELS = ("Critical", "High", "Medium", "Low", "Informational")
CONFIDENCE_LEVELS = ("confirmed", "high", "medium", "low", "unknown")

# Scan / tool lifecycle states
SCAN_STATUSES = ("queued", "running", "completed", "partial", "failed", "cancelled")
TOOL_STATUSES = ("completed", "failed", "unavailable", "timeout", "cancelled", "skipped")


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class Finding:
    """One normalised finding. Scanner-provided fields are kept separate from the
    fields this application derives (OWASP mapping and risk priority)."""

    title: str
    source_tool: str
    scanner_severity: str = "unrated"
    description: str = ""
    affected_url: str = ""
    asset: str = ""
    parameter: str = ""
    evidence: str = ""
    confidence: str = "unknown"
    rule_id: str = ""
    issue_key: str = ""          # tool-independent key used to correlate the same issue across tools
    cwe_id: int | None = None
    scanner_tags: list[str] = field(default_factory=list)
    cvss_score: float | None = None   # only when the scanner itself supplies one
    remediation: str = ""
    references: list[str] = field(default_factory=list)
    exploit_evidence: bool = False    # scanner reports a successful attack/payload (e.g. ZAP active scan)
    detected_at: str = field(default_factory=utc_now)
    # Derived by the pipeline
    sources: list[str] = field(default_factory=list)
    locations: list[str] = field(default_factory=list)   # every affected URL/asset (instances)
    occurrences: int = 1
    fingerprint: str = ""
    owasp_id: str = ""
    owasp_name: str = ""
    owasp_status: str = "unmapped"   # mapped | potential | unmapped
    owasp_basis: str = ""
    risk_score: float = 0.0
    priority: str = "Informational"
    rationale: list[dict] = field(default_factory=list)


@dataclass
class ToolResult:
    tool: str
    status: str
    findings: list[Finding] = field(default_factory=list)
    message: str = ""
    started_at: str = field(default_factory=utc_now)
    finished_at: str = ""
    exit_code: int | None = None
    command: str = ""


@dataclass
class ScanConfig:
    tools: list[str]
    tool_timeout: int = 300
    nmap_ports: str = "80,443,8000,8080,8443"
    nmap_service_detection: bool = True
    zap_active_scan: bool = False
    zap_max_children: int = 20
    asset_criticality: str = "medium"   # low | medium | high (declared by the user)
    exposure: str = "internal"          # lab | internal | internet (declared by the user)

    def to_dict(self) -> dict:
        return dict(self.__dict__)

    @classmethod
    def from_dict(cls, data: dict) -> "ScanConfig":
        known = {k: v for k, v in data.items() if k in cls.__dataclass_fields__}
        return cls(**known)
