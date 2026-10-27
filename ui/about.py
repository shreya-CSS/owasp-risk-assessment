"""System status, coverage and methodology (what is and is not checked)."""
from __future__ import annotations

import pandas as pd
import streamlit as st

from modules import risk_engine
from ui import style
from ui.common import TOOL_LABELS, get_manager, tool_availability

COVERAGE = [
    ("A01 Broken Access Control", "Built-in: directory listing. ZAP/Nikto: path traversal, exposed files (tool dependent).",
     "Authorization logic (IDOR, privilege escalation) needs authenticated manual testing — not covered."),
    ("A02 Cryptographic Failures", "Built-in: cleartext HTTP, missing HSTS, cookies without Secure.",
     "TLS protocol/cipher configuration is not analysed."),
    ("A03 Injection", "ZAP active scan only (SQLi, XSS, …) — requires IVA_ALLOW_ACTIVE_SCAN=true.",
     "Not checked by passive methods."),
    ("A04 Insecure Design", "Clickjacking protection (CWE-1021) via built-in/ZAP.", "Design flaws need human review."),
    ("A05 Security Misconfiguration", "Built-in: security headers, banners, CORS, error disclosure. ZAP passive, Nikto, "
     "Nmap (exposed services, potential mapping).", "Server hardening beyond HTTP responses is not inspected."),
    ("A06 Vulnerable & Outdated Components", "Nikto outdated-software messages; version banners.",
     "No CVE database lookup; versions are not correlated with vulnerabilities."),
    ("A07 Identification & Authentication Failures", "Cookie flags; ZAP alerts where applicable.",
     "Login, MFA, brute-force and session-fixation testing are not performed."),
    ("A08 Software & Data Integrity Failures", "ZAP alerts where applicable (e.g. missing SRI).", "Mostly out of scope."),
    ("A09 Security Logging & Monitoring Failures", "—", "Cannot be observed from outside; out of scope."),
    ("A10 SSRF", "ZAP active scan may flag it.", "No dedicated check."),
]


def render() -> None:
    manager = get_manager()
    settings = manager.settings
    style.hero("System & method", "Tool health, the authorization policy, OWASP coverage and the risk model — "
               "everything the system does is documented here.", ["Transparent", "Configurable", "Deterministic"])

    st.subheader("Assessment tools")
    if st.button("Re-check tools"):
        tool_availability.clear()
    avail = tool_availability()
    st.dataframe(pd.DataFrame([{"Method": TOOL_LABELS[k], "Available": "✅" if ok else "🚫", "Details": msg}
                               for k, (ok, msg) in avail.items()]), hide_index=True, width="stretch")

    st.subheader("Target authorization policy")
    st.markdown(
        f"- Localhost / loopback: **always allowed** (local labs)\n"
        f"- Private networks (10/8, 172.16/12, 192.168/16): **{'allowed' if settings.allow_private_networks else 'blocked'}** "
        f"(`IVA_ALLOW_PRIVATE_NETWORKS`)\n"
        f"- Explicitly authorized targets (`IVA_ALLOWED_TARGETS`): "
        f"**{', '.join(settings.allowed_targets) or 'none'}**\n"
        f"- Link-local / cloud metadata, multicast, reserved: **always blocked**\n"
        f"- ZAP active scanning: **{'enabled' if settings.allow_active_scan else 'disabled'}** (`IVA_ALLOW_ACTIVE_SCAN`)\n"
        f"- ZAP API key configured: **{'yes' if settings.zap_api_key else 'no'}**")

    st.subheader(f"OWASP coverage ({manager.mapper.title})")
    st.dataframe(pd.DataFrame(COVERAGE, columns=["Category", "Implemented checks", "Not covered / limits"]),
                 hide_index=True, width="stretch")
    st.caption("Category mapping order: scanner OWASP tag → project rule for known checks → official CWE list → "
               "title keyword (marked *potential*) → unmapped. Rules live in config/owasp_2021.json.")

    st.subheader("Risk prioritization model")
    st.markdown(
        "**score = base × confidence + category impact + exploit evidence + asset criticality + exposure + spread**, "
        "clamped to 0–100. Priority thresholds: ≥80 Critical, ≥60 High, ≥35 Medium, ≥15 Low, else Informational. "
        "A guardrail caps priority at one level above the scanner's own rating.")
    c1, c2 = st.columns(2)
    c1.dataframe(pd.DataFrame(list(risk_engine.SEVERITY_BASE.items()), columns=["Scanner severity", "Base"]),
                 hide_index=True, width="stretch")
    c2.dataframe(pd.DataFrame(list(risk_engine.CONFIDENCE_MULTIPLIER.items()), columns=["Confidence", "Multiplier"]),
                 hide_index=True, width="stretch")
    st.markdown(
        f"- Category impact: per-category weight from the mapping file (full if *mapped*, half if *potential*)\n"
        f"- Exploit evidence: +{risk_engine.EXPLOIT_BONUS} when the scanner reports a successful attack payload\n"
        f"- Asset criticality: {risk_engine.CRITICALITY_ADJUST}; exposure: {risk_engine.EXPOSURE_ADJUST}\n"
        f"- Spread: +{risk_engine.SPREAD_BONUS} if the same issue occurs ≥{risk_engine.SPREAD_THRESHOLD} times\n"
        "- CVSS is used only when a scanner supplies it; the application never invents CVSS scores.")
