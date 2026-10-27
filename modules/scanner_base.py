"""Common scanner interface. Every adapter returns a ToolResult and never raises for
expected failures (tool missing, unreachable target, timeout) — those become a
tool status the UI and report can show honestly."""
from __future__ import annotations

import threading
from abc import ABC, abstractmethod

from config.settings import Settings
from modules.models import ScanConfig, ToolResult, utc_now
from modules.target_validation import ValidatedTarget


class Scanner(ABC):
    name: str = ""
    label: str = ""
    description: str = ""

    def __init__(self, settings: Settings):
        self.settings = settings

    @abstractmethod
    def availability(self) -> tuple[bool, str]:
        """(available, human-readable explanation)."""

    @abstractmethod
    def run(self, target: ValidatedTarget, config: ScanConfig,
            cancel_event: threading.Event) -> ToolResult:
        """Execute against an already-validated target."""

    def result(self, status: str, message: str = "", **kwargs) -> ToolResult:
        res = ToolResult(tool=self.name, status=status, message=message, **kwargs)
        res.finished_at = utc_now()
        return res
