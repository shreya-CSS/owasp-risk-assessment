"""Shared UI helpers: cached services, formatting and small display components."""
from __future__ import annotations

from datetime import datetime, timezone

import streamlit as st

from config.settings import Settings, load_settings
from modules.scan_manager import ScanManager

# Status palette (critical/serious/warning) + blue for Low + muted grey for Informational.
PRIORITY_COLORS = {
    "Critical": "#d03b3b", "High": "#ec835a", "Medium": "#fab219",
    "Low": "#86b6ef", "Informational": "#898781",
}
SEVERITY_COLORS = {
    "critical": "#d03b3b", "high": "#ec835a", "medium": "#fab219", "low": "#86b6ef",
    "info": "#898781", "unrated": "#c3c2b7",
}
PRIORITY_ICONS = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🔵", "Informational": "⚪"}
STATUS_ICONS = {
    "completed": "✅", "partial": "⚠️", "failed": "❌", "cancelled": "⏹️", "queued": "⏳", "running": "🔄",
    "unavailable": "🚫", "timeout": "⏱️", "skipped": "⏭️",
}
TOOL_LABELS = {"builtin": "Built-in HTTP checks", "zap": "OWASP ZAP", "nmap": "Nmap", "nikto": "Nikto"}


@st.cache_resource(show_spinner=False)
def get_manager() -> ScanManager:
    """One ScanManager per Streamlit server process (keeps background scan threads alive)."""
    settings = load_settings()
    manager = ScanManager(settings)
    manager.db.mark_interrupted_scans()
    return manager


def get_settings() -> Settings:
    return get_manager().settings


@st.cache_data(ttl=30, show_spinner=False)
def tool_availability() -> dict[str, tuple[bool, str]]:
    return get_manager().tool_availability()


def priority_label(priority: str) -> str:
    return f"{PRIORITY_ICONS.get(priority, '')} {priority}"


def status_label(status: str) -> str:
    return f"{STATUS_ICONS.get(status, '')} {status}"


def parse_ts(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        return None


def duration(scan: dict) -> str:
    start, end = parse_ts(scan.get("started_at")), parse_ts(scan.get("finished_at"))
    if not start:
        return "-"
    if not end:
        end = datetime.now(timezone.utc).replace(tzinfo=None)
    seconds = int((end - start).total_seconds())
    return f"{seconds // 60}m {seconds % 60:02d}s" if seconds >= 60 else f"{seconds}s"


def short_time(value: str | None) -> str:
    ts = parse_ts(value)
    return ts.strftime("%Y-%m-%d %H:%M UTC") if ts else "-"


def scan_option_label(scan: dict) -> str:
    tag = "[DEMO] " if scan["mode"] == "demo" else ""
    return f"{tag}{short_time(scan['created_at'])} · {scan['target_url']} · {scan['status']}"


def demo_banner(scan: dict) -> None:
    if scan.get("mode") == "demo":
        st.warning("**DEMO DATA** — this scan was built from fixed sample findings. No target was contacted "
                   "and none of these are real scanner discoveries.", icon="🧪")


def select_scan(scans: list[dict], key: str, label: str = "Scan") -> dict | None:
    """Scan picker that remembers the last selection across pages."""
    if not scans:
        return None
    ids = [s["id"] for s in scans]
    preferred = st.session_state.get("selected_scan")
    index = ids.index(preferred) if preferred in ids else 0
    by_id = {s["id"]: s for s in scans}
    chosen = st.selectbox(label, ids, index=index, key=key, format_func=lambda i: scan_option_label(by_id[i]))
    st.session_state["selected_scan"] = chosen
    return by_id[chosen]


def tool_status_line(tool_runs: list[dict]) -> str:
    return "  ·  ".join(f"{STATUS_ICONS.get(r['status'], '')} {TOOL_LABELS.get(r['tool'], r['tool'])}: "
                        f"{r['status']} ({r['findings_count']})" for r in tool_runs)
