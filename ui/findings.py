"""Findings explorer: filterable table and a detail view with evidence, rationale and remediation.

All scanner-originated text is displayed with st.code / st.text / dataframes (never as
raw HTML), so hostile content in scanner output cannot execute in the browser.
"""
from __future__ import annotations

import pandas as pd
import streamlit as st

from modules.models import PRIORITY_LEVELS
from ui import style
from ui.common import (PRIORITY_COLORS, TOOL_LABELS, demo_banner, get_manager, priority_label, select_scan, status_label,
                       tool_status_line)


def _filter(findings: list[dict], query: str, priorities: list[str], categories: list[str],
            sources: list[str], statuses: list[str]) -> list[dict]:
    q = query.strip().lower()
    out = []
    for f in findings:
        if priorities and f["priority"] not in priorities:
            continue
        if categories and (f["owasp_id"] or "Unmapped") not in categories:
            continue
        if sources and not set(sources) & {s.split(" ")[0] for s in f["sources"]}:
            continue
        if statuses and f["owasp_status"] not in statuses:
            continue
        if q and q not in " ".join((f["title"], f["description"], f["affected_url"], f["asset"],
                                    f["evidence"], f["owasp_name"])).lower():
            continue
        out.append(f)
    return out


def _detail(f: dict) -> None:
    with st.container(border=True):
        style.finding_header(f["title"], f["priority"], PRIORITY_COLORS.get(f["priority"], "#898781"),
                             f"{f['owasp_id'] or 'Unmapped'} · {', '.join(f['sources'])} · "
                             f"{len(f.get('locations') or [])} location(s)")
        c = st.columns(4)
        c[0].metric("Calculated priority", priority_label(f["priority"]))
        c[1].metric("Risk score", f"{f['risk_score']:.1f} / 100")
        c[2].metric("Scanner severity", f["scanner_severity"])
        c[3].metric("Confidence", f["confidence"])

        left, right = st.columns(2)
        with left:
            locations = f.get("locations") or [f["affected_url"] or f["asset"] or "-"]
            st.markdown(f"**Affected** ({len(locations)} location{'s' if len(locations) != 1 else ''})")
            st.code("\n".join(locations), language=None)
            if f["parameter"]:
                st.markdown("**Parameter**")
                st.code(f["parameter"], language=None)
            st.markdown("**Detected by**")
            st.text(", ".join(f["sources"]) + (f"  ·  {f['occurrences']} raw alerts merged" if f["occurrences"] > 1 else ""))
            st.markdown("**Scanner reference**")
            st.text(" · ".join(filter(None, [f["rule_id"], f"CWE-{f['cwe_id']}" if f["cwe_id"] else "",
                                            f"CVSS {f['cvss_score']} (scanner)" if f["cvss_score"] is not None else ""]))
                    or "-")
        with right:
            st.markdown("**OWASP Top 10 category**")
            if f["owasp_id"]:
                badge = {"mapped": "✔ mapped", "potential": "≈ potential — needs confirmation"}[f["owasp_status"]]
                st.text(f"{f['owasp_id']} {f['owasp_name']}  ({badge})")
            else:
                st.text("Unmapped")
            st.caption(f["owasp_basis"])
            st.markdown("**Why this priority?**")
            st.dataframe(pd.DataFrame(f["rationale"])[["factor", "effect", "detail"]], hide_index=True,
                         width="stretch")

        if f["description"]:
            st.markdown("**Description**")
            st.text(f["description"])
        st.markdown("**Evidence** (verbatim from the tool, untrusted)")
        st.code(f["evidence"] or "No evidence supplied by the tool.", language=None)
        st.markdown("**Recommended remediation**")
        st.info(f["remediation"], icon="🛠️")
        if f["references"]:
            st.markdown("**References**")
            for ref in f["references"]:
                st.text(ref)


def render() -> None:
    manager = get_manager()
    style.hero("Findings explorer", "Every finding with its evidence, OWASP mapping, explainable priority and "
               "remediation.", ["Search & filter", "Cross-tool merged", "Untrusted output rendered safely"])
    scans = manager.db.list_scans()
    if not scans:
        st.info("No scans yet. Run one from *New scan* or load demo data there.")
        return
    scan = select_scan(scans, key="findings_scan")
    demo_banner(scan)
    runs = manager.db.get_tool_runs(scan["id"])
    st.caption(f"Status: {status_label(scan['status'])}  ·  Target: {scan['target_url']}  ·  "
               f"Authorization basis: {scan['policy_reason']}")
    if runs:
        st.caption(tool_status_line(runs))
    if scan["status"] in ("partial", "failed") and scan["error"]:
        st.warning(f"Some checks did not complete: {scan['error']}")

    findings = manager.db.get_findings(scan["id"])
    if not findings:
        if scan["status"] in ("queued", "running"):
            st.info("The scan is still running — findings appear when it finishes.")
        elif scan["status"] == "failed":
            st.error("No assessment method ran successfully, so there are no results to show.")
        else:
            st.success("The methods that ran reported no findings. This is not proof that the target is secure.")
        return

    with st.container(border=True):
        c1, c2, c3, c4, c5 = st.columns([2, 1.3, 1.3, 1.2, 1.2])
        query = c1.text_input("Search", placeholder="title, URL, evidence…")
        priorities = c2.multiselect("Priority", PRIORITY_LEVELS)
        categories = c3.multiselect("OWASP", sorted({f["owasp_id"] or "Unmapped" for f in findings}))
        tools = sorted({s.split(" ")[0] for f in findings for s in f["sources"]})
        sources = c4.multiselect("Tool", tools, format_func=lambda t: TOOL_LABELS.get(t, t))
        statuses = c5.multiselect("Mapping", ["mapped", "potential", "unmapped"])
    shown = _filter(findings, query, priorities, categories, sources, statuses)
    st.caption(f"Showing {len(shown)} of {len(findings)} findings. Select a row to see details.")

    table = pd.DataFrame([{
        "Priority": priority_label(f["priority"]), "Score": f["risk_score"],
        "Scanner severity": f["scanner_severity"], "Title": f["title"],
        "OWASP": (f["owasp_id"] + (" (potential)" if f["owasp_status"] == "potential" else "")) or "Unmapped",
        "Location": (f["affected_url"] or f["asset"])
        + (f" (+{len(f['locations']) - 1} more)" if len(f["locations"]) > 1 else ""),
        "Sources": ", ".join(f["sources"]),
        "Confidence": f["confidence"],
    } for f in shown])
    event = st.dataframe(table, hide_index=True, width="stretch", on_select="rerun",
                         selection_mode="single-row", key=f"tbl_{scan['id']}",
                         column_config={"Score": st.column_config.ProgressColumn(
                             "Score", min_value=0, max_value=100, format="%.1f")})
    rows = event.selection.rows if event and event.selection else []
    if shown:
        _detail(shown[rows[0]] if rows else shown[0])
        if not rows:
            st.caption("Showing the highest-priority finding; select another row above to change.")
