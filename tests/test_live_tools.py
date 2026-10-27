"""Optional integration tests against the REAL Nmap / Nikto / ZAP installations and the local
lab server. Skipped unless IVA_LIVE_TOOLS=1 (they take ~3 minutes and need the tools + running ZAP).

    PowerShell:  $env:IVA_LIVE_TOOLS=1; python -m pytest tests/test_live_tools.py -v
"""
import os
import threading

import pytest

from config.settings import load_settings
from modules.models import ScanConfig
from modules.scan_manager import SCANNER_CLASSES
from modules.target_validation import validate_target

pytestmark = pytest.mark.skipif(os.getenv("IVA_LIVE_TOOLS") != "1", reason="set IVA_LIVE_TOOLS=1 to run")


@pytest.mark.parametrize("tool,expected_key", [
    ("nmap", "open-port:tcp/"),
    ("nikto", "header-missing:"),  # Nikto stops at -maxtime; header checks run first
    ("zap", "header-missing:content-security-policy"),
])
def test_real_tool_against_lab(tool, expected_key, lab_url):
    settings = load_settings()  # real .env configuration
    scanner = SCANNER_CLASSES[tool](settings)
    ok, detail = scanner.availability()
    assert ok, detail
    target = validate_target(lab_url, settings)
    config = ScanConfig(tools=[tool], tool_timeout=120, nmap_ports=str(target.port))
    result = scanner.run(target, config, threading.Event())
    assert result.status == "completed", result.message
    assert any(f.issue_key.startswith(expected_key) for f in result.findings), [f.issue_key for f in result.findings]
