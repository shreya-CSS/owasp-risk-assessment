"""Scan history: list, open, delete and compare previous scans."""
from __future__ import annotations

import pandas as pd
import streamlit as st

from modules.scan_comparison import compare_scans
from ui import nav, style
from ui.common import duration, get_manager, priority_label, scan_option_label, short_time, status_label


def _finding_table(rows: list[dict]) -> None:
    if not rows:
        st.caption("None.")
        return
    st.dataframe(pd.DataFrame([{
        "Priority": priority_label(f["priority"]), "Score": f["risk_score"], "Title": f["title"],
        "OWASP": f["owasp_id"] or "Unmapped", "Location": f["affected_url"] or f["asset"],
    } for f in rows]), hide_index=True, width="stretch")


def _comparison(scans: list[dict]) -> None:
    manager = get_manager()
    st.subheader("Compare two scans")
    finished = [s for s in scans if s["status"] not in ("queued", "running")]
    if len(finished) < 2:
        st.info("At least two finished scans are needed for a comparison.")
        return
    by_id = {s["id"]: s for s in finished}
    ids = [s["id"] for s in finished]
    c1, c2 = st.columns(2)
    old_id = c1.selectbox("Baseline (older) scan", ids, index=1, format_func=lambda i: scan_option_label(by_id[i]))
    new_id = c2.selectbox("Comparison (newer) scan", ids, index=0, format_func=lambda i: scan_option_label(by_id[i]))
    if old_id == new_id:
        st.warning("Choose two different scans.")
        return
    if by_id[old_id]["target_url"] != by_id[new_id]["target_url"]:
        st.warning("The scans target different URLs, so most findings will appear as new/resolved.")
    if by_id[old_id]["mode"] != by_id[new_id]["mode"]:
        st.warning("You are comparing a demo scan with a live scan.")
    result = compare_scans(manager.db.get_findings(old_id), manager.db.get_findings(new_id))
    m = st.columns(4)
    m[0].metric("New", len(result["new"]))
    m[1].metric("Resolved", len(result["resolved"]))
    m[2].metric("Persistent", len(result["persistent"]))
    m[3].metric("Highest risk score", f"{result['max_risk_after']:.1f}",
                delta=round(result["max_risk_after"] - result["max_risk_before"], 1), delta_color="inverse")
    tab_new, tab_res, tab_per, tab_chg = st.tabs(["New", "Resolved", "Persistent", "Priority changes"])
    with tab_new:
        _finding_table(result["new"])
    with tab_res:
        _finding_table(result["resolved"])
    with tab_per:
        _finding_table(result["persistent"])
    with tab_chg:
        if result["priority_changes"]:
            st.dataframe(pd.DataFrame(result["priority_changes"]), hide_index=True, width="stretch")
        else:
            st.caption("No priority changes for persistent findings.")
    st.caption("Findings are matched by a fingerprint of issue, location and parameter. Priority can change "
               "because of different declared risk context or merged evidence.")


def render() -> None:
    manager = get_manager()
    style.hero("Scan history", "Every stored assessment — open, report, delete or compare two scans.",
               ["New · Resolved · Persistent", "Priority changes"])
    scans = manager.db.list_scans()
    if not scans:
        st.info("No scans stored yet.")
        return
    mode = st.segmented_control("Show", ["All", "Live", "Demo"], default="All", key="hist_mode")
    if mode in ("Live", "Demo"):
        scans = [s for s in scans if s["mode"] == mode.lower()]

    table = pd.DataFrame([{
        "Started": short_time(s["created_at"]), "Mode": "DEMO" if s["mode"] == "demo" else "live",
        "Target": s["target_url"], "Status": status_label(s["status"]), "Duration": duration(s),
        "Tools": ", ".join(s["config"].get("tools", [])), "Findings": s["findings_count"],
        "Critical": s["n_critical"], "High": s["n_high"], "Medium": s["n_medium"], "Low": s["n_low"],
        "Max score": s["max_risk"] if s["max_risk"] is not None else 0.0,
    } for s in scans])
    event = st.dataframe(table, hide_index=True, width="stretch", on_select="rerun",
                         selection_mode="single-row", key="history_table")
    rows = event.selection.rows if event and event.selection else []
    if rows:
        scan = scans[rows[0]]
        with st.container(border=True):
            st.markdown(f"**Selected:** {scan_option_label(scan)}")
            if scan["error"]:
                st.caption(scan["error"])
            c1, c2, c3 = st.columns(3)
            if c1.button("🔍 Open findings", width="stretch"):
                st.session_state["selected_scan"] = scan["id"]
                nav.go("findings")
            if c2.button("📄 Report", width="stretch"):
                st.session_state["selected_scan"] = scan["id"]
                nav.go("reports")
            confirm = c3.checkbox("Confirm delete", key=f"del_confirm_{scan['id']}")
            if c3.button("🗑️ Delete scan", disabled=not confirm, width="stretch"):
                if manager.db.delete_scan(scan["id"]):
                    st.session_state.pop("selected_scan", None)
                    st.toast("Scan deleted.")
                    st.rerun()
                else:
                    st.error("Running scans cannot be deleted.")
    else:
        st.caption("Select a scan to open, report on or delete it.")
    st.divider()
    _comparison(scans)
