from __future__ import annotations

import sys
import threading
from dataclasses import replace
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config.settings import load_settings  # noqa: E402
from modules.database import Database  # noqa: E402
from lab.vulnerable_lab_server import LabHandler  # noqa: E402
from modules.owasp_mapper import get_mapper  # noqa: E402

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def settings(tmp_path):
    """Restrictive defaults, isolated from the developer's .env."""
    base = load_settings()
    return replace(base, db_path=tmp_path / "test.db", reports_dir=tmp_path / "reports",
                   allowed_targets=(), allow_private_networks=False, allow_active_scan=False,
                   zap_api_url="http://127.0.0.1:1", zap_api_key="test-key",
                   nmap_path="", nikto_path="", perl_path="", nikto_perl_lib="")


@pytest.fixture
def db(settings):
    return Database(settings.db_path)


@pytest.fixture
def mapper():
    return get_mapper("2021")


def fake_resolver(mapping: dict[str, list[str]]):
    def resolve(host: str):
        if host not in mapping:
            raise OSError("unresolvable")
        return mapping[host]
    return resolve


@pytest.fixture(scope="session")
def lab_url():
    """The intentionally insecure lab server on a random localhost port."""
    LabHandler.log_message = lambda *a, **k: None
    server = ThreadingHTTPServer(("127.0.0.1", 0), LabHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_address[1]}/"
    server.shutdown()
