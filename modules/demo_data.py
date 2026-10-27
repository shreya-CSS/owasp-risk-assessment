"""Deterministic DEMO fixture data.

These findings are hand-written examples shaped like real tool output. They are stored
only in scans with mode='demo', every source is suffixed '(demo fixture)', and the UI
and reports label them as demo data. They are never presented as scanner discoveries.
"""
from __future__ import annotations

from modules.models import Finding, ScanConfig, ToolResult

DEMO_TARGET = "http://demo-lab.invalid/"
DEMO_CONFIG = ScanConfig(tools=["builtin", "zap", "nikto", "nmap"], tool_timeout=300,
                         asset_criticality="high", exposure="internet")
_TS = "2026-01-15T10:00:00Z"


def _f(tool: str, **kwargs) -> Finding:
    return Finding(source_tool=f"{tool} (demo fixture)", detected_at=_TS, **kwargs)


def demo_findings() -> list[Finding]:
    base = DEMO_TARGET
    return [
        _f("zap", title="SQL Injection", scanner_severity="high", confidence="medium", cwe_id=89,
           affected_url=base + "rest/products/search", parameter="q", rule_id="zap-40018",
           scanner_tags=["OWASP_2021_A03", "WSTG-v42-INPV-05"], exploit_evidence=True,
           evidence="Attack: ')) OR 1=1--\nEvidence: SQLITE_ERROR",
           description="SQL injection may be possible: the response changed when a boolean condition was injected.",
           remediation="Use parameterised queries / prepared statements for all database access."),
        _f("zap", title="Cross Site Scripting (Reflected)", scanner_severity="high", confidence="medium", cwe_id=79,
           affected_url=base + "search", parameter="term", rule_id="zap-40012",
           scanner_tags=["OWASP_2021_A03"], exploit_evidence=True,
           evidence="Attack: <scRipt>alert(1);</scRipt>",
           description="User input is reflected into the HTML response without encoding.",
           remediation="Contextually encode output and validate input; add a restrictive Content-Security-Policy."),
        _f("zap", title="Content Security Policy (CSP) Header Not Set", scanner_severity="medium", confidence="high",
           cwe_id=693, affected_url=base, rule_id="zap-10038", issue_key="header-missing:content-security-policy",
           scanner_tags=["OWASP_2021_A05"], description="No Content-Security-Policy header was returned."),
        _f("builtin", title="Content-Security-Policy header not set", scanner_severity="medium", confidence="high",
           cwe_id=693, affected_url=base, issue_key="header-missing:content-security-policy",
           rule_id="IVA-HDR-content-security-policy", evidence="Response has no 'content-security-policy' header."),
        _f("builtin", title="Missing anti-clickjacking protection", scanner_severity="medium", confidence="high",
           cwe_id=1021, affected_url=base, issue_key="header-missing:x-frame-options",
           rule_id="IVA-HDR-x-frame-options", evidence="Response has no 'x-frame-options' header."),
        _f("nikto", title="The anti-clickjacking X-Frame-Options header is not present.", scanner_severity="unrated",
           affected_url=base, issue_key="header-missing:x-frame-options", rule_id="nikto-999957",
           evidence="GET /: The anti-clickjacking X-Frame-Options header is not present."),
        _f("builtin", title="Cookie 'session' without HttpOnly flag", scanner_severity="low", confidence="high",
           cwe_id=1004, affected_url=base, issue_key="cookie:no-httponly:session", rule_id="IVA-COOKIE-httponly",
           evidence="Set-Cookie: session=…; attributes: path"),
        _f("builtin", title="CORS policy reflects arbitrary origins with credentials", scanner_severity="high",
           confidence="high", cwe_id=942, affected_url=base + "api/", issue_key="cors:reflected-origin",
           rule_id="IVA-CORS-reflect",
           evidence="Access-Control-Allow-Origin: https://iva-cors-probe.invalid\nAccess-Control-Allow-Credentials: true"),
        _f("nikto", title="/backup/: Directory indexing found.", scanner_severity="unrated", affected_url=base + "backup/",
           issue_key="directory-listing", rule_id="nikto-000390", evidence="GET /backup/: Directory indexing found."),
        _f("zap", title="Server Leaks Version Information via \"Server\" HTTP Response Header Field",
           scanner_severity="low", confidence="high", cwe_id=497, affected_url=base, rule_id="zap-10036",
           issue_key="disclosure:server-version", scanner_tags=["OWASP_2021_A05"],
           evidence="Server: Apache/2.4.49 (Unix)"),
        _f("nikto", title="Apache/2.4.49 appears to be outdated (current is at least 2.4.62).",
           scanner_severity="unrated", affected_url=base, rule_id="nikto-600050",
           evidence="GET /: Apache/2.4.49 appears to be outdated"),
        _f("zap", title="Application Error Disclosure", scanner_severity="medium", confidence="medium", cwe_id=550,
           affected_url=base + "rest/user/login", rule_id="zap-90022", evidence="Error: Unexpected path"),
        _f("nmap", title="Open port 22/tcp (ssh)", scanner_severity="info", confidence="confirmed",
           asset="203.0.113.10:22/tcp", issue_key="open-port:tcp/22", rule_id="nmap-open-tcp",
           evidence="22/tcp open ssh — OpenSSH 8.2p1"),
        _f("nmap", title="Open port 80/tcp (http)", scanner_severity="info", confidence="confirmed",
           asset="203.0.113.10:80/tcp", issue_key="open-port:tcp/80", rule_id="nmap-open-tcp",
           evidence="80/tcp open http — Apache httpd 2.4.49"),
        _f("zap", title="Information Disclosure - Suspicious Comments", scanner_severity="info", confidence="low",
           cwe_id=615, affected_url=base + "main.js", rule_id="zap-10027", evidence="// TODO: remove debug user"),
    ]


def demo_tool_runs(findings: list[Finding]) -> list[ToolResult]:
    msg = "DEMO FIXTURE — no tool was executed; findings are sample data."
    return [ToolResult(tool=t, status="completed", message=msg, started_at=_TS, finished_at=_TS,
                       command="(demo fixture)",
                       findings=[f for f in findings if f.source_tool.startswith(f"{t} ")])
            for t in DEMO_CONFIG.tools]
