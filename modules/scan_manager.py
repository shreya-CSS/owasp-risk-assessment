"""Scan orchestration: validation -> tools -> normalisation -> OWASP mapping -> risk -> SQLite.

Scans run in a background thread so the Streamlit UI stays responsive; progress and
status are written to SQLite and the UI polls it. Cancellation is cooperative: the
current tool's process is killed and remaining tools are skipped.
"""
from __future__ import annotations

import threading

from config.settings import Settings
from modules.database import Database
from modules.finding_normalizer import deduplicate
from modules.http_checks import HttpSecurityChecker
from modules.models import Finding, ScanConfig, ToolResult, utc_now
from modules.nikto_scanner import NiktoScanner
from modules.nmap_scanner import NmapScanner
from modules.owasp_mapper import OwaspMapper, get_mapper
from modules.risk_engine import RiskContext, prioritise
from modules.scanner_base import Scanner
from modules.target_validation import (TargetValidationError, ValidatedTarget, validate_scan_config,
                                       validate_target)
from modules.zap_scanner import ZapScanner

SCANNER_CLASSES: dict[str, type[Scanner]] = {
    "builtin": HttpSecurityChecker,
    "zap": ZapScanner,
    "nmap": NmapScanner,
    "nikto": NiktoScanner,
}


class ScanBusyError(RuntimeError):
    pass


def process_findings(raw: list[Finding], mapper: OwaspMapper, context: RiskContext) -> list[Finding]:
    """Normalise + de-duplicate, map to OWASP, add fallback remediation, then score."""
    findings = deduplicate(raw)
    for finding in findings:
        mapper.map_finding(finding)
        if not finding.remediation:
            guidance = mapper.guidance_for(finding.owasp_id)
            finding.remediation = (f"General guidance for {finding.owasp_id} {finding.owasp_name}: {guidance}"
                                   if guidance else "No specific remediation supplied by the tool; review manually.")
    return prioritise(findings, mapper, context)


def overall_status(results: list[ToolResult], cancelled: bool) -> tuple[str, str]:
    """Derive the scan status from per-tool outcomes. Returns (status, error summary)."""
    failures = [f"{r.tool}: {r.status} — {r.message}" for r in results if r.status != "completed"]
    if cancelled:
        return "cancelled", "Cancelled by user. " + " | ".join(failures)
    completed = [r for r in results if r.status == "completed"]
    if results and len(completed) == len(results):
        return "completed", ""
    if completed:
        return "partial", " | ".join(failures)
    return "failed", " | ".join(failures) or "No assessment method ran."


class ScanManager:
    def __init__(self, settings: Settings, db: Database | None = None,
                 scanners: dict[str, Scanner] | None = None):
        self.settings = settings
        self.db = db or Database(settings.db_path)
        self.scanners = scanners or {name: cls(settings) for name, cls in SCANNER_CLASSES.items()}
        self.mapper = get_mapper(settings.owasp_edition)
        self._cancel: dict[str, threading.Event] = {}
        self._threads: dict[str, threading.Thread] = {}
        self._lock = threading.Lock()

    # -- information --------------------------------------------------------------------
    def tool_availability(self) -> dict[str, tuple[bool, str]]:
        return {name: scanner.availability() for name, scanner in self.scanners.items()}

    def active_scan_ids(self) -> list[str]:
        with self._lock:
            return [sid for sid, t in self._threads.items() if t.is_alive()]

    # -- lifecycle ----------------------------------------------------------------------
    def prepare(self, url: str, config: ScanConfig) -> tuple[ValidatedTarget, ScanConfig]:
        target = validate_target(url, self.settings)
        return target, validate_scan_config(config, self.settings)

    def start_scan(self, url: str, config: ScanConfig, authorized: bool) -> str:
        if not authorized:
            raise TargetValidationError("Confirm that you are authorized to assess this target.")
        target, config = self.prepare(url, config)
        with self._lock:
            running = [sid for sid, t in self._threads.items() if t.is_alive()]
            if len(running) >= self.settings.max_concurrent_scans:
                raise ScanBusyError("Another scan is still running. Wait for it to finish or cancel it.")
            scan_id = self.db.create_scan(target.url, target.host, config, "live", self.settings.owasp_edition,
                                          target.policy_reason)
            event = threading.Event()
            thread = threading.Thread(target=self.run_scan, args=(scan_id, target, config, event),
                                      name=f"scan-{scan_id[:8]}", daemon=True)
            self._cancel[scan_id] = event
            self._threads[scan_id] = thread
            thread.start()
        return scan_id

    def cancel(self, scan_id: str) -> bool:
        event = self._cancel.get(scan_id)
        if event is None or not self._threads.get(scan_id, threading.Thread()).is_alive():
            return False
        event.set()
        self.db.update_scan(scan_id, progress="Cancelling…")
        return True

    def run_scan(self, scan_id: str, target: ValidatedTarget, config: ScanConfig,
                 cancel_event: threading.Event | None = None) -> str:
        """Execute a scan synchronously. Never raises; failures are recorded on the scan."""
        cancel_event = cancel_event or threading.Event()
        self.db.update_scan(scan_id, status="running", started_at=utc_now(), progress="Starting…")
        results: list[ToolResult] = []
        try:
            for index, tool in enumerate(config.tools, start=1):
                scanner = self.scanners[tool]
                if cancel_event.is_set():
                    result = ToolResult(tool=tool, status="skipped", message="Skipped: scan cancelled.")
                else:
                    self.db.update_scan(scan_id, progress=f"Running {scanner.label} ({index}/{len(config.tools)})")
                    try:
                        result = scanner.run(target, config, cancel_event)
                    except Exception as exc:  # adapter bug must not kill the scan; keep detail generic
                        result = ToolResult(tool=tool, status="failed",
                                            message=f"Internal error in {tool} adapter ({type(exc).__name__}).")
                result.finished_at = result.finished_at or utc_now()
                results.append(result)
                self.db.add_tool_run(scan_id, result)

            self.db.update_scan(scan_id, progress="Normalising, mapping and scoring findings…")
            raw = [f for r in results for f in r.findings]
            findings = process_findings(raw, self.mapper, RiskContext.from_config(config))
            self.db.save_findings(scan_id, findings)
            status, error = overall_status([r for r in results if r.status != "skipped"] or results,
                                           cancel_event.is_set())
            self.db.update_scan(scan_id, status=status, error=error[:4000], finished_at=utc_now(),
                                progress=f"Finished: {len(findings)} finding(s).")
            return status
        except Exception as exc:
            self.db.update_scan(scan_id, status="failed", finished_at=utc_now(), progress="Failed",
                                error=f"Scan aborted by an internal error ({type(exc).__name__}).")
            return "failed"
        finally:
            with self._lock:
                self._cancel.pop(scan_id, None)

    def create_demo_scan(self) -> str:
        """Store a clearly-labelled demo scan built from fixed fixture data (no network access)."""
        from modules.demo_data import DEMO_CONFIG, DEMO_TARGET, demo_findings, demo_tool_runs

        scan_id = self.db.create_scan(DEMO_TARGET, "demo-lab.invalid", DEMO_CONFIG, "demo",
                                      self.settings.owasp_edition, "DEMO fixture data — no target was contacted")
        self.db.update_scan(scan_id, status="running", started_at=utc_now())
        raw = demo_findings()
        runs = demo_tool_runs(raw)
        for run in runs:
            self.db.add_tool_run(scan_id, run)
        findings = process_findings(raw, self.mapper, RiskContext.from_config(DEMO_CONFIG))
        self.db.save_findings(scan_id, findings)
        status, error = overall_status(runs, False)
        self.db.update_scan(scan_id, status=status, error=error, finished_at=utc_now(),
                            progress=f"Demo data loaded: {len(findings)} finding(s).")
        return scan_id
