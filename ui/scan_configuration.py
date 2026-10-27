"""New scan: target + method configuration, policy review, authorization, progress and cancel."""
from __future__ import annotations

import streamlit as st

from modules.models import ScanConfig
from modules.scan_manager import ScanBusyError
from modules.target_validation import TargetValidationError
from ui import nav, style
from ui.common import (STATUS_ICONS, TOOL_LABELS, duration, get_manager, status_label, tool_availability,
                       tool_status_line)

TOOL_HELP = {
    "builtin": "Passive GET requests: security headers, cookies, disclosure, CORS, directory listing, errors.",
    "zap": "Needs a running OWASP ZAP (ZAP_API_URL). Spider + passive scan; active scan only if enabled.",
    "nmap": "TCP connect scan of the listed ports with light service detection.",
    "nikto": "Needs Nikto (NIKTO_PATH). Web server checks, DoS tests excluded.",
}


@st.fragment(run_every=2)
def _progress_panel(scan_id: str) -> None:
    manager = get_manager()
    scan = manager.db.get_scan(scan_id)
    if scan is None:
        return
    runs = manager.db.get_tool_runs(scan_id)
    running = scan["status"] in ("queued", "running")
    with st.container(border=True):
        if running:
            left, right = st.columns([1, 4])
            with left:
                style.radar("scanning…")
            with right:
                st.markdown(f"**Scan of `{scan['target_url']}`** — {status_label(scan['status'])} · {duration(scan)}")
        else:
            st.markdown(f"**Scan of `{scan['target_url']}`** — {status_label(scan['status'])} · {duration(scan)}")
        planned = scan["config"].get("tools", [])
        st.progress(len(runs) / max(1, len(planned)), text=scan["progress"] or "Waiting…")
        if runs:
            st.caption(tool_status_line(runs))
        if running:
            if st.button("⏹️ Cancel scan", key=f"cancel_{scan_id}"):
                manager.cancel(scan_id)
                st.toast("Cancellation requested — stopping the current tool.")
        else:
            findings = manager.db.get_findings(scan_id)
            msg = f"{len(findings)} finding(s) recorded."
            if scan["status"] == "completed":
                st.success(f"Scan completed. {msg}")
            elif scan["status"] == "partial":
                st.warning(f"Scan partially completed — some methods did not run. {msg}\n\n{scan['error']}")
            elif scan["status"] == "cancelled":
                st.info(f"Scan cancelled. {msg} Findings collected before cancellation were kept.")
            else:
                st.error(f"Scan failed. {scan['error']}")
            c1, c2 = st.columns(2)
            if c1.button("🔍 View findings", key=f"view_{scan_id}", width="stretch"):
                st.session_state["selected_scan"] = scan_id
                st.session_state.pop("watch_scan", None)
                nav.go("findings")
            if c2.button("Start another scan", key=f"new_{scan_id}", width="stretch"):
                st.session_state.pop("watch_scan", None)
                st.rerun()


def render() -> None:
    manager = get_manager()
    settings = manager.settings
    style.hero("New security assessment", "Configure an authorized target, review the policy decision, "
               "then launch the selected assessment methods.", ["Authorization gate", "Background execution",
                                                                 "Cancellable"])
    watching = st.session_state.get("watch_scan") or manager.active_scan_ids()
    stage = 2 if watching else (1 if st.session_state.get("pending") else 0)
    style.steps([("Target & methods", "URL, tools, options"), ("Review & authorize", "policy + confirmation"),
                 ("Scan", "tools run in background"), ("Results", "findings & report")], stage)
    st.warning("**Authorized use only.** Scan only local labs, systems you own, or targets you have written "
               "permission to test. Unauthorized scanning may be illegal.", icon="⚖️")

    watch = st.session_state.get("watch_scan")
    active = manager.active_scan_ids()
    if not watch and active:
        watch = active[0]
    if watch:
        _progress_panel(watch)
        if manager.db.get_scan(watch) and manager.db.get_scan(watch)["status"] in ("queued", "running"):
            return

    availability = tool_availability()
    with st.form("scan_form"):
        # Fixed key (no changing default): Streamlit derives widget identity from its parameters, so a
        # changing default would silently discard the user's next edit.
        st.session_state.setdefault("target_url", "http://127.0.0.1:8008/")
        url = st.text_input("Target URL", key="target_url",
                            help="http(s) only. Localhost is allowed by default; other hosts must be authorized "
                                 "in IVA_ALLOWED_TARGETS (see System & method).")
        st.markdown("**Assessment methods**")
        selected: list[str] = []
        cols = st.columns(4)
        for col, tool in zip(cols, ("builtin", "zap", "nmap", "nikto")):
            ok, detail = availability.get(tool, (False, "unknown"))
            with col:
                if st.checkbox(TOOL_LABELS[tool], value=(tool == "builtin"), disabled=not ok,
                               help=TOOL_HELP[tool], key=f"tool_{tool}"):
                    selected.append(tool)
                st.caption(("✅ " if ok else "🚫 ") + detail[:120])

        with st.expander("Options", expanded=False):
            c1, c2 = st.columns(2)
            timeout = c1.slider("Per-tool timeout (seconds)", 10, min(900, settings.max_tool_timeout),
                                min(120, settings.max_tool_timeout))
            ports = c2.text_input("Nmap ports", "80,443,8000,8008,8080,8443",
                                  help="Comma-separated ports or ranges, max 1000 ports.")
            nmap_sv = c1.checkbox("Nmap light service/version detection", value=True)
            zap_children = c2.number_input("ZAP spider: max children per node", 1, 200, 20)
            zap_active = st.checkbox(
                "ZAP active scan (sends attack payloads)", value=False, disabled=not settings.allow_active_scan,
                help="Enabled only when IVA_ALLOW_ACTIVE_SCAN=true. Use only against a lab you control.")
        st.markdown("**Risk context** (used by the prioritization engine)")
        c1, c2 = st.columns(2)
        criticality = c1.selectbox("Asset criticality", ["low", "medium", "high"], index=1)
        exposure = c2.selectbox("Exposure", ["lab", "internal", "internet"], index=0,
                                help="How the real application is reachable — a lab target is ranked lower.")
        review = st.form_submit_button("Review scan", type="primary")

    if review:
        config = ScanConfig(tools=selected, tool_timeout=int(timeout), nmap_ports=ports,
                            nmap_service_detection=nmap_sv, zap_active_scan=zap_active,
                            zap_max_children=int(zap_children), asset_criticality=criticality, exposure=exposure)
        try:
            target, config = manager.prepare(url, config)
        except TargetValidationError as exc:
            st.session_state.pop("pending", None)
            st.error(f"**Target rejected:** {exc}")
        else:
            st.session_state["pending"] = {"url": url, "config": config.to_dict(), "target": target.url,
                                           "addresses": list(target.addresses), "reason": target.policy_reason}

    pending = st.session_state.get("pending")
    if pending:
        with st.container(border=True):
            st.subheader("Review before starting")
            cfg = pending["config"]
            st.markdown(
                f"- **Target:** `{pending['target']}` → resolves to `{', '.join(pending['addresses'])}`\n"
                f"- **Why it is permitted:** {pending['reason']}\n"
                f"- **Methods:** {', '.join(TOOL_LABELS[t] for t in cfg['tools'])}\n"
                f"- **Timeout per tool:** {cfg['tool_timeout']} s"
                + (f"\n- **Nmap ports:** `{cfg['nmap_ports']}`" if "nmap" in cfg["tools"] else "")
                + (f"\n- **ZAP mode:** {'ACTIVE + passive' if cfg['zap_active_scan'] else 'passive'}"
                   if "zap" in cfg["tools"] else "")
                + f"\n- **Risk context:** criticality *{cfg['asset_criticality']}*, exposure *{cfg['exposure']}*")
            authorized = st.checkbox("I confirm I am authorized to perform this assessment against this target.",
                                     key="authorized")
            c1, c2 = st.columns([1, 1])
            if c1.button("▶️ Start scan", type="primary", disabled=not authorized, width="stretch"):
                try:
                    scan_id = manager.start_scan(pending["url"], ScanConfig.from_dict(cfg), authorized)
                except (TargetValidationError, ScanBusyError) as exc:
                    st.error(str(exc))
                else:
                    st.session_state["watch_scan"] = scan_id
                    st.session_state["selected_scan"] = scan_id
                    st.session_state.pop("pending", None)
                    st.rerun()
            if c2.button("Discard", width="stretch"):
                st.session_state.pop("pending", None)
                st.rerun()

    with st.expander("🧪 Demo mode (no network access)"):
        st.write("Creates a scan from fixed, clearly-labelled sample findings so the dashboard, risk engine, "
                 "history and reports can be explored without any scanner. Demo scans are stored separately "
                 "and are never shown as real results.")
        if st.button("Load demo scan"):
            scan_id = manager.create_demo_scan()
            st.session_state["selected_scan"] = scan_id
            st.success("Demo scan created. Open *Findings* or switch the dashboard to *Demo scans*.")

    st.caption("Status legend: " + " ".join(f"{icon} {name}" for name, icon in STATUS_ICONS.items()))
