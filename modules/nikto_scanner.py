"""Nikto adapter — web server checks with JSON output.

Denial-of-service test classes are excluded (-Tuning x6) and the run is bounded by
-maxtime plus a hard process timeout. Nikto does not assign severities, so findings
are stored as 'unrated' and the risk engine documents the baseline it uses.
"""
from __future__ import annotations

import json
import re
import tempfile
import threading
from pathlib import Path
from urllib.parse import urljoin

from modules.models import Finding, ScanConfig, ToolResult, utc_now
from modules.process_runner import (ToolCancelled, ToolTimeout, describe_exit_code,
                                    resolve_executable, run_command)
from modules.scanner_base import Scanner
from modules.target_validation import ValidatedTarget


class NiktoError(ValueError):
    pass


# Messages that describe the same issue as a built-in check, so the two correlate.
_HEADER_MISSING = re.compile(r"suggested security header missing:\s*([a-z-]+)", re.I)
_CWE_REF = re.compile(r"CWE-(\d+)", re.I)
_ISSUE_PATTERNS = (
    (re.compile(r"x-frame-options header is not present", re.I), "header-missing:x-frame-options"),
    (re.compile(r"x-content-type-options header is not set", re.I), "header-missing:x-content-type-options"),
    (re.compile(r"strict-transport-security.*not (defined|set)", re.I), "header-missing:strict-transport-security"),
    (re.compile(r"x-powered-by header", re.I), "disclosure:x-powered-by"),
    (re.compile(r"directory indexing found", re.I), "directory-listing"),
)
_COOKIE_HTTPONLY = re.compile(r"cookie (\S+) created without the httponly flag", re.I)


def build_nikto_command(nikto: str, perl: str | None, url: str, output_file: str, timeout: int,
                        perl_lib: str | None = None) -> list[str]:
    if nikto.lower().endswith(".pl") and perl:
        base = [perl] + (["-I", perl_lib] if perl_lib else []) + [nikto]
    else:
        base = [nikto]
    return base + ["-h", url, "-Format", "json", "-o", output_file, "-maxtime", f"{int(timeout)}s",
                   "-nointeractive", "-ask", "no", "-Tuning", "x6"]


def parse_nikto_json(text: str, base_url: str) -> list[Finding]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise NiktoError("Nikto output is not valid JSON") from exc
    hosts = data if isinstance(data, list) else [data]
    findings: list[Finding] = []
    for host in hosts:
        if not isinstance(host, dict):
            continue
        for vuln in host.get("vulnerabilities", []) or []:
            if not isinstance(vuln, dict):
                continue
            msg = str(vuln.get("msg", "")).strip()
            if not msg:
                continue
            path = str(vuln.get("url", "/") or "/")
            issue_key = ""
            for pattern, key in _ISSUE_PATTERNS:
                if pattern.search(msg):
                    issue_key = key
                    break
            header = _HEADER_MISSING.search(msg)
            if header:
                issue_key = f"header-missing:{header.group(1).lower()}"
            cookie = _COOKIE_HTTPONLY.search(msg)
            if cookie:
                issue_key = f"cookie:no-httponly:{cookie.group(1).strip(';')}"
            refs = vuln.get("references") or ""
            refs_list = [refs] if isinstance(refs, str) and refs else list(refs) if isinstance(refs, list) else []
            osvdb = vuln.get("OSVDB")
            if osvdb and str(osvdb) != "0":
                refs_list.append(f"OSVDB-{osvdb}")
            affected = urljoin(base_url, path)
            cwe = _CWE_REF.search(" ".join(refs_list))
            title = msg if path in ("", "/") or path in msg else f"{path}: {msg}"
            findings.append(Finding(
                title=title[:200],
                cwe_id=int(cwe.group(1)) if cwe else None,
                source_tool="nikto",
                scanner_severity="unrated",
                confidence="unknown",
                description=msg,
                affected_url=affected if not issue_key.startswith("cookie:") else base_url,
                evidence=f"{vuln.get('method', 'GET')} {path}: {msg}",
                rule_id=f"nikto-{vuln.get('id', '')}",
                issue_key=issue_key,
                references=refs_list,
                detected_at=utc_now(),
            ))
    return findings


class NiktoScanner(Scanner):
    name = "nikto"
    label = "Nikto web server checks"
    description = "Nikto checks for server misconfiguration, risky files and outdated software (DoS tests excluded)."

    def _command_base(self) -> tuple[str | None, str | None]:
        nikto = resolve_executable(self.settings.nikto_path, ("nikto", "nikto.pl"))
        perl = None
        if nikto and nikto.lower().endswith(".pl"):
            perl = resolve_executable(self.settings.perl_path, ("perl",))
        return nikto, perl

    def _perl_lib(self, nikto: str) -> str | None:
        """Optional folder with extra Perl modules (e.g. XML::Writer): NIKTO_PERL_LIB, or a
        'perl-lib' folder next to Nikto's 'program' directory."""
        configured = self.settings.nikto_perl_lib
        if configured:
            return configured if Path(configured).is_dir() else None
        candidate = Path(nikto).resolve().parent.parent / "perl-lib"
        return str(candidate) if candidate.is_dir() else None

    def availability(self) -> tuple[bool, str]:
        nikto, perl = self._command_base()
        if not nikto:
            return False, ("Nikto was not found. Clone https://github.com/sullo/nikto and set NIKTO_PATH to "
                           "program/nikto.pl (Perl required).")
        if nikto.lower().endswith(".pl") and not perl:
            return False, "nikto.pl found but Perl is missing. Install Perl or set PERL_PATH."
        return True, f"Nikto at {Path(nikto).name}" + (" (via Perl)" if perl else "")

    def run(self, target: ValidatedTarget, config: ScanConfig, cancel_event: threading.Event) -> ToolResult:
        started = utc_now()
        nikto, perl = self._command_base()
        if not nikto or (nikto.lower().endswith(".pl") and not perl):
            return self.result("unavailable", self.availability()[1], started_at=started)
        with tempfile.TemporaryDirectory(prefix="iva_nikto_") as tmp:
            out_file = str(Path(tmp) / "nikto.json")
            args = build_nikto_command(nikto, perl, target.url, out_file, config.tool_timeout, self._perl_lib(nikto))
            display = " ".join(["nikto"] + args[args.index("-h"):]).replace(out_file, "<tmp>/nikto.json")
            try:
                # Nikto locates nikto.conf, plugins and databases relative to its own folder.
                res = run_command(args, timeout=config.tool_timeout + 30, cancel_event=cancel_event,
                                  cwd=str(Path(nikto).resolve().parent))
            except ToolTimeout as exc:
                return self.result("timeout", str(exc), started_at=started, command=display)
            except ToolCancelled:
                return self.result("cancelled", "Cancelled by user.", started_at=started, command=display)
            except OSError as exc:
                return self.result("failed", f"Nikto could not be started ({type(exc).__name__}).",
                                   started_at=started, command=display)
            path = Path(out_file)
            if not path.exists() or path.stat().st_size == 0:
                detail = (res.stderr or res.stdout).strip().splitlines()[-1:] or [""]
                return self.result("failed", f"Nikto produced no JSON output ({describe_exit_code(res.returncode)}). "
                                             f"{detail[0]}"[:500],
                                   started_at=started, exit_code=res.returncode, command=display)
            try:
                findings = parse_nikto_json(path.read_text(encoding="utf-8", errors="replace"), target.url)
            except NiktoError as exc:
                return self.result("failed", str(exc), started_at=started, exit_code=res.returncode, command=display)
        # Nikto's exit code is not a reliable success signal; the JSON file is.
        note = (" Stopped at the time limit, so some Nikto tests did not run."
                if "maximum execution time" in res.stderr.lower() else "")
        return self.result("completed", f"{len(findings)} item(s) reported.{note}", findings=findings,
                           started_at=started, exit_code=res.returncode, command=display)
