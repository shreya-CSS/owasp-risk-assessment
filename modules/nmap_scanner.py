"""Nmap adapter — TCP connect scan of an explicit, bounded port list.

Fixed, non-aggressive options: -sT (no raw packets / admin rights), -Pn, -T3, optional
light version detection, no NSE scripts, no OS detection. The scan target is the
already-validated IP address, so DNS cannot redirect the scan.
"""
from __future__ import annotations

import threading

from defusedxml import ElementTree as SafeET

from modules.models import Finding, ScanConfig, ToolResult, utc_now
from modules.process_runner import (ToolCancelled, ToolTimeout, describe_exit_code,
                                    resolve_executable, run_command)
from modules.scanner_base import Scanner
from modules.target_validation import ValidatedTarget

WINDOWS_DEFAULT = r"C:\Program Files (x86)\Nmap\nmap.exe"


class NmapError(ValueError):
    pass


def build_nmap_args(executable: str, address: str, ports: str, service_detection: bool, timeout: int) -> list[str]:
    args = [executable, "-sT", "-Pn", "-T3", "--max-retries", "2", "--host-timeout", f"{int(timeout)}s",
            "-p", ports]
    if service_detection:
        args += ["-sV", "--version-light"]
    args += ["-oX", "-", address]
    return args


def parse_nmap_xml(xml_text: str) -> list[Finding]:
    """Turn Nmap XML into findings (one per open port)."""
    try:
        root = SafeET.fromstring(xml_text)
    except Exception as exc:  # defusedxml raises several exception types
        raise NmapError(f"Nmap returned malformed XML: {type(exc).__name__}") from exc
    if root.tag != "nmaprun":
        raise NmapError("Unexpected Nmap XML document")
    findings: list[Finding] = []
    for host in root.findall("host"):
        addr_el = host.find("address")
        address = addr_el.get("addr", "") if addr_el is not None else ""
        for port in host.findall("ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            portid = port.get("portid", "")
            proto = port.get("protocol", "tcp")
            svc = port.find("service")
            name = svc.get("name", "unknown") if svc is not None else "unknown"
            product = " ".join(filter(None, [svc.get("product"), svc.get("version"), svc.get("extrainfo")])) if svc is not None else ""
            evidence = f"{portid}/{proto} open {name}" + (f" — {product}" if product else "")
            findings.append(Finding(
                title=f"Open port {portid}/{proto} ({name})",
                source_tool="nmap",
                scanner_severity="info",
                confidence="confirmed",
                description=("Nmap found this TCP port accepting connections. Each exposed service increases the "
                             "attack surface; confirm it is required and patched."
                             + (f" Service banner: {product}." if product else "")),
                asset=f"{address}:{portid}/{proto}",
                evidence=evidence,
                rule_id=f"nmap-open-{proto}",
                issue_key=f"open-port:{proto}/{portid}",
                remediation="Close or firewall services that are not needed; keep required services patched and "
                            "avoid exposing version banners.",
                detected_at=utc_now(),
            ))
    return findings


class NmapScanner(Scanner):
    name = "nmap"
    label = "Nmap service discovery"
    description = "TCP connect scan of the listed ports with optional light version detection."

    def _executable(self) -> str | None:
        configured = self.settings.nmap_path
        found = resolve_executable(configured, ("nmap",))
        if not found and not configured:
            found = resolve_executable(WINDOWS_DEFAULT, ())
        return found

    def availability(self) -> tuple[bool, str]:
        exe = self._executable()
        if not exe:
            return False, "Nmap was not found. Install it from https://nmap.org/download and set NMAP_PATH if needed."
        try:
            res = run_command([exe, "--version"], timeout=20)
        except (OSError, ToolTimeout) as exc:
            return False, f"Nmap could not be started ({type(exc).__name__})."
        if res.returncode != 0:
            return False, f"Nmap is installed but failed to start: {describe_exit_code(res.returncode)}."
        first = (res.stdout.strip().splitlines() or ["Nmap"])[0]
        return True, first

    def run(self, target: ValidatedTarget, config: ScanConfig, cancel_event: threading.Event) -> ToolResult:
        started = utc_now()
        exe = self._executable()
        if not exe:
            return self.result("unavailable", "Nmap executable not found.", started_at=started)
        args = build_nmap_args(exe, target.scan_address, config.nmap_ports, config.nmap_service_detection,
                               config.tool_timeout)
        display = " ".join(["nmap"] + args[1:])
        try:
            res = run_command(args, timeout=config.tool_timeout + 15, cancel_event=cancel_event)
        except ToolTimeout as exc:
            return self.result("timeout", str(exc), started_at=started, command=display)
        except ToolCancelled:
            return self.result("cancelled", "Cancelled by user.", started_at=started, command=display)
        except OSError as exc:
            return self.result("failed", f"Nmap could not be started ({type(exc).__name__}).",
                               started_at=started, command=display)
        if res.returncode != 0:
            err = res.stderr.strip().splitlines()[-1:] if res.stderr.strip() else []
            return self.result("failed", f"Nmap failed: {describe_exit_code(res.returncode)}. {' '.join(err)}"[:500],
                               started_at=started, exit_code=res.returncode, command=display)
        try:
            findings = parse_nmap_xml(res.stdout)
        except NmapError as exc:
            return self.result("failed", str(exc), started_at=started, exit_code=res.returncode, command=display)
        return self.result("completed", f"{len(findings)} open port(s) found in {res.duration:.1f} s.",
                           findings=findings, started_at=started, exit_code=res.returncode, command=display)
