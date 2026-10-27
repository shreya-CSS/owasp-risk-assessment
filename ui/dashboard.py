"""Dashboard: security posture overview — KPIs, risk gauge, priority vs. severity, OWASP
heat-grid, cross-tool agreement, trend and recent scan activity."""
from __future__ import annotations

from collections import Counter

import pandas as pd
import streamlit as st

from ui import charts, nav, style
from ui.common import (PRIORITY_COLORS, demo_banner, duration, get_manager, priority_label, short_time,
                       status_label)

_PLOT_CFG = {"displayModeBar": False}


def _empty_state(mode: str) -> None:
    manager = get_manager()
    style.hero("Security posture", "No scans stored yet for this data source.",
               ["OWASP Top 10:2021", "SQLite", "4 assessment methods"])
    if mode == "live":
        st.info("No live scans yet. Start a scan against an authorized target (for example the bundled lab "
                "server on http://127.0.0.1:8008/), or explore the dashboard with demo data.")
    else:
        st.info("No demo scans stored yet.")
    c1, c2 = st.columns(2)
    if c1.button("🎯 Start a scan", width="stretch", type="primary"):
        nav.go("new-scan")
    if c2.button("🧪 Load demo data", width="stretch"):
        st.session_state["selected_scan"] = manager.create_demo_scan()
        st.rerun()


def render() -> None:
    manager = get_manager()
    mode_label = st.segmented_control("Data source", ["Live scans", "Demo scans"], default="Live scans",
                                      key="dash_mode", help="Demo data is kept separate from real scan results.")
    mode = "demo" if mode_label == "Demo scans" else "live"
    scans = manager.db.list_scans(mode=mode)
    if not scans:
        _empty_state(mode)
        return

    scope_ids = ["__all__"] + [s["id"] for s in scans]
    by_id = {s["id"]: s for s in scans}
    latest = scans[0]
    tools_seen = sorted({t for s in scans for t in s["config"].get("tools", [])})
    style.hero("Security posture",
               f"Latest assessment: {latest['target_url']} · {short_time(latest['created_at'])} · "
               f"status {latest['status']}",
               [manager.mapper.title, f"{len(scans)} scan(s)", "Methods: " + ", ".join(tools_seen)],
               live=mode == "live")
    if mode == "demo":
        demo_banner({"mode": "demo"})

    scope = st.selectbox(
        "Scope", scope_ids, key="dash_scope",
        format_func=lambda i: f"All {mode} scans ({len(scans)})" if i == "__all__"
        else f"{short_time(by_id[i]['created_at'])} · {by_id[i]['target_url']} · {by_id[i]['status']}")
    findings = (manager.db.get_all_findings(mode=mode) if scope == "__all__" else manager.db.get_findings(scope))

    prio = Counter(f["priority"] for f in findings)
    multi = sum(1 for f in findings if len(f["sources"]) > 1)
    raw_alerts = sum(f["occurrences"] for f in findings)
    style.kpis([
        ("Scans performed", len(scans), f"{sum(s['status'] == 'completed' for s in scans)} completed", "#22d3ee"),
        ("Distinct findings", len(findings), f"from {raw_alerts} raw tool results", "#a78bfa"),
        ("Critical", prio.get("Critical", 0), "calculated priority", PRIORITY_COLORS["Critical"]),
        ("High", prio.get("High", 0), "calculated priority", PRIORITY_COLORS["High"]),
        ("Cross-tool confirmed", multi, "found by 2+ tools", "#34d399"),
    ])

    if not findings:
        st.success("No findings in the selected scope. That only covers the checks that ran — see the scan's "
                   "tool status for coverage.")
    else:
        top_score = max(f["risk_score"] for f in findings)
        g, p, s = st.columns([1.05, 1.2, 1.2])
        with g:
            with st.container(border=True):
                st.plotly_chart(charts.risk_gauge(top_score, "Highest risk score in scope"), width="stretch",
                                config=_PLOT_CFG)
        with p:
            with st.container(border=True):
                st.markdown("**Calculated priority**")
                st.plotly_chart(charts.priority_chart(findings), width="stretch", config=_PLOT_CFG)
        with s:
            with st.container(border=True):
                st.markdown("**Scanner-reported severity**")
                st.plotly_chart(charts.severity_chart(findings), width="stretch", config=_PLOT_CFG)
        st.caption("Priority is calculated by this application (see *System & method*); severity is what each tool "
                   "reported. 'unrated' = the tool gives no severity (e.g. Nikto).")

        style.section("OWASP Top 10 coverage", "findings per category in the selected scope")
        counts = Counter(f["owasp_id"].split(":")[0] for f in findings if f["owasp_id"])
        names = {cid: cat.name for cid, cat in manager.mapper.categories.items()}
        style.owasp_grid(counts, names)
        unmapped = sum(1 for f in findings if not f["owasp_id"])
        if unmapped:
            st.caption(f"{unmapped} finding(s) could not be mapped to a category with sufficient evidence.")

        a, b = st.columns(2)
        with a:
            style.section("Cross-tool agreement", "independent tools reporting the same issue")
            st.plotly_chart(charts.tool_agreement_chart(findings), width="stretch", config=_PLOT_CFG)
        with b:
            style.section("Findings by tool", "before merging")
            st.plotly_chart(charts.tool_chart(findings), width="stretch", config=_PLOT_CFG)

        style.section("Top priority findings")
        top = sorted(findings, key=lambda f: -f["risk_score"])[:6]
        st.dataframe(pd.DataFrame([{
            "Priority": priority_label(f["priority"]), "Score": f["risk_score"], "Title": f["title"],
            "OWASP": f["owasp_id"] or "Unmapped", "Tools": ", ".join(x.split(" ")[0] for x in f["sources"]),
            "Location": f["affected_url"] or f["asset"],
        } for f in top]), hide_index=True, width="stretch",
            column_config={"Score": st.column_config.ProgressColumn("Score", min_value=0, max_value=100,
                                                                    format="%.1f")})

    finished = [s for s in scans if s["status"] not in ("queued", "running")]
    if len(finished) >= 2:
        style.section("Findings trend", "distinct findings per scan")
        st.plotly_chart(charts.trend_chart(finished), width="stretch", config=_PLOT_CFG)

    style.section("Recent scan activity")
    st.dataframe(pd.DataFrame([{
        "Started": short_time(s["created_at"]), "Target": s["target_url"], "Status": status_label(s["status"]),
        "Duration": duration(s), "Tools": ", ".join(s["config"].get("tools", [])), "Findings": s["findings_count"],
        "Critical": s["n_critical"], "High": s["n_high"],
        "Max score": s["max_risk"] if s["max_risk"] is not None else 0.0,
    } for s in scans[:10]]), hide_index=True, width="stretch")
    if len(finished) < len(scans):
        st.caption("🔄 A scan is in progress — open *New scan* to follow it.")
