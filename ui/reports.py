"""Report generation: PDF assessment report and CSV export of findings."""
from __future__ import annotations

import streamlit as st

from modules.report_generator import generate_csv, generate_pdf, save_report
from ui import style
from ui.common import demo_banner, get_manager, select_scan


def render() -> None:
    manager = get_manager()
    style.hero("Reports", "Export a structured PDF assessment report or a CSV of all findings.",
               ["PDF", "CSV (injection-safe)", "Limitations included"])
    scans = [s for s in manager.db.list_scans() if s["status"] not in ("queued", "running")]
    if not scans:
        st.info("No finished scans yet.")
        return
    scan = select_scan(scans, key="report_scan")
    demo_banner(scan)
    findings = manager.db.get_findings(scan["id"])
    runs = manager.db.get_tool_runs(scan["id"])
    st.write(f"{len(findings)} finding(s) · status **{scan['status']}** · "
             f"{sum(r['status'] == 'completed' for r in runs)}/{len(runs)} method(s) completed")
    if scan["status"] in ("partial", "failed"):
        st.warning("This scan is incomplete; the report lists the checks that did not run under "
                   "'Assessment limitations'.")

    save_copy = st.checkbox("Also save a copy in the reports/ folder", value=True)
    c1, c2 = st.columns(2)
    with c1, st.container(border=True):
        st.markdown("**PDF assessment report**")
        st.caption("Executive summary, distribution, findings by priority and OWASP category, evidence, "
                   "priority rationale, remediation and limitations.")
        if st.button("Generate PDF", type="primary", width="stretch"):
            try:
                pdf = generate_pdf(scan, findings, runs, manager.mapper.title)
            except Exception as exc:  # report errors must not crash the page
                st.error(f"PDF generation failed ({type(exc).__name__}). Try the CSV export.")
            else:
                st.session_state["pdf_bytes"] = (scan["id"], pdf)
                if save_copy:
                    path = save_report(manager.settings.reports_dir, scan["id"], "pdf", pdf)
                    st.caption(f"Saved: reports/{path.name}")
        cached = st.session_state.get("pdf_bytes")
        if cached and cached[0] == scan["id"]:
            st.download_button("⬇️ Download PDF", cached[1], file_name=f"iva_report_{scan['id'][:12]}.pdf",
                               mime="application/pdf", width="stretch")
    with c2, st.container(border=True):
        st.markdown("**CSV export of findings**")
        st.caption("One row per finding with scanner fields and calculated priority. Formula-like cells are "
                   "escaped to prevent spreadsheet injection.")
        csv_bytes = generate_csv(findings)
        if st.download_button("⬇️ Download CSV", csv_bytes, file_name=f"iva_findings_{scan['id'][:12]}.csv",
                              mime="text/csv", width="stretch") and save_copy:
            save_report(manager.settings.reports_dir, scan["id"], "csv", csv_bytes)
