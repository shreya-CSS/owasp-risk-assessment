"""Intelligent Web Vulnerability Assessment and Risk Prioritization System — Streamlit entry point.

Run:  streamlit run app.py
"""
from __future__ import annotations

import streamlit as st

from ui import about, dashboard, findings, nav, reports, scan_configuration, scan_history, style
from ui.common import TOOL_LABELS, get_manager, tool_availability

st.set_page_config(page_title="IVA — Web Vulnerability Assessment", page_icon="🛡️", layout="wide")
style.inject_css()

manager = get_manager()

pages = [
    st.Page(dashboard.render, title="Dashboard", icon="📊", url_path="dashboard", default=True),
    st.Page(scan_configuration.render, title="New scan", icon="🎯", url_path="new-scan"),
    st.Page(findings.render, title="Findings", icon="🔍", url_path="findings"),
    st.Page(scan_history.render, title="Scan history", icon="🕘", url_path="history"),
    st.Page(reports.render, title="Reports", icon="📄", url_path="reports"),
    st.Page(about.render, title="System & method", icon="⚙️", url_path="system"),
]

nav.PAGES.update(zip(("dashboard", "new-scan", "findings", "history", "reports", "system"), pages))

with st.sidebar:
    st.markdown('<div class="iva-brand">🛡️ IVA Sentinel</div>', unsafe_allow_html=True)
    st.caption("Intelligent Web Vulnerability Assessment & Risk Prioritization")
    available = tool_availability()
    for name, (ok, _) in available.items():
        st.caption(f"{'🟢' if ok else '🔴'} {TOOL_LABELS.get(name, name)}")
    active = manager.active_scan_ids()
    if active:
        st.markdown('<span class="iva-live"><span class="iva-dot"></span> scan running</span>',
                    unsafe_allow_html=True)
    st.caption(f"{manager.mapper.title} · authorized targets only")

st.navigation(pages).run()
