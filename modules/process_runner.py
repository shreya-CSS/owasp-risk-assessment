"""Safe external-process execution for scanner tools.

* argument lists only (shell=False) — user input is never parsed by a shell;
* hard timeout and cooperative cancellation (the child process is killed);
* output is capped so a misbehaving tool cannot exhaust memory.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path

MAX_OUTPUT_BYTES = 20 * 1024 * 1024
# Windows NTSTATUS codes that mean the executable could not start at all.
WINDOWS_START_FAILURES = {
    0xC0000135: "a required DLL is missing (for old Nmap builds, the Visual C++ 2013 x86 runtime)",
    0xC000007B: "the executable or one of its DLLs has the wrong architecture",
    0xC0000142: "a DLL failed to initialise",
}


class ToolTimeout(Exception):
    pass


class ToolCancelled(Exception):
    pass


@dataclass
class ProcessResult:
    returncode: int
    stdout: str
    stderr: str
    duration: float


def resolve_executable(configured: str, default_names: tuple[str, ...]) -> str | None:
    """Return an absolute path to an executable, or None. A configured path must exist."""
    if configured:
        path = Path(configured)
        return str(path) if path.is_file() else None
    for name in default_names:
        found = shutil.which(name)
        if found:
            return found
    return None


def describe_exit_code(code: int) -> str:
    unsigned = code & 0xFFFFFFFF
    reason = WINDOWS_START_FAILURES.get(unsigned)
    return f"exit code {code} — {reason}" if reason else f"exit code {code}"


def run_command(args: list[str], timeout: int, cancel_event: threading.Event | None = None,
                poll_interval: float = 0.25, cwd: str | None = None) -> ProcessResult:
    if not isinstance(args, list) or not args or not all(isinstance(a, str) for a in args):
        raise ValueError("Command must be a non-empty list of strings")
    creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0
    start = time.monotonic()
    # Output goes to temp files rather than pipes so a chatty tool cannot deadlock on a full pipe.
    with tempfile.TemporaryFile() as out_f, tempfile.TemporaryFile() as err_f:
        proc = subprocess.Popen(args, stdout=out_f, stderr=err_f, stdin=subprocess.DEVNULL,
                                shell=False, creationflags=creationflags, cwd=cwd)
        try:
            while proc.poll() is None:
                if cancel_event is not None and cancel_event.is_set():
                    raise ToolCancelled("Cancelled by user")
                if time.monotonic() - start > timeout:
                    raise ToolTimeout(f"Timed out after {timeout} s")
                time.sleep(poll_interval)
        except (ToolCancelled, ToolTimeout):
            proc.kill()
            proc.wait(timeout=10)
            raise
        out_f.seek(0)
        err_f.seek(0)
        stdout = out_f.read(MAX_OUTPUT_BYTES).decode("utf-8", errors="replace")
        stderr = err_f.read(MAX_OUTPUT_BYTES).decode("utf-8", errors="replace")
    return ProcessResult(proc.returncode, stdout, stderr, time.monotonic() - start)
