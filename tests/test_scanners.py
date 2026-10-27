"""Scanner adapters: parsing, missing tools, failures, timeouts, ZAP API errors and the
built-in checks against the local lab server."""
import sys
import threading
from dataclasses import replace

import pytest
import requests

from modules.http_checks import HttpSecurityChecker
from modules.models import ScanConfig
from modules.nikto_scanner import NiktoScanner, build_nikto_command, parse_nikto_json
from modules.nmap_scanner import NmapError, NmapScanner, build_nmap_args, parse_nmap_xml
from modules.process_runner import ToolCancelled, ToolTimeout, describe_exit_code, run_command
from modules.target_validation import validate_target
from modules.zap_scanner import ZapApiError, ZapClient, ZapScanner, alert_to_finding
from tests.conftest import FIXTURES


# --- process runner --------------------------------------------------------------------

def test_run_command_success():
    res = run_command([sys.executable, "-c", "print('hi')"], timeout=20)
    assert res.returncode == 0 and res.stdout.strip() == "hi"


def test_run_command_timeout_kills_process():
    with pytest.raises(ToolTimeout):
        run_command([sys.executable, "-c", "import time; time.sleep(30)"], timeout=1)


def test_run_command_cancel():
    event = threading.Event()
    threading.Timer(0.5, event.set).start()
    with pytest.raises(ToolCancelled):
        run_command([sys.executable, "-c", "import time; time.sleep(30)"], timeout=20, cancel_event=event)


def test_run_command_rejects_strings_and_shell_metachars_are_literal():
    with pytest.raises(ValueError):
        run_command("echo hi", timeout=5)  # type: ignore[arg-type]
    res = run_command([sys.executable, "-c", "import sys; print(sys.argv[1])", "a; echo pwned && whoami"], timeout=20)
    assert res.stdout.strip() == "a; echo pwned && whoami"


def test_describe_windows_dll_failure():
    assert "DLL" in describe_exit_code(3221225781)


# --- Nmap ------------------------------------------------------------------------------

def test_nmap_xml_parsing():
    findings = parse_nmap_xml((FIXTURES / "nmap_lab.xml").read_text())
    assert len(findings) == 1  # closed port ignored
    f = findings[0]
    assert f.title == "Open port 8008/tcp (http)"
    assert f.issue_key == "open-port:tcp/8008" and f.asset == "127.0.0.1:8008/tcp"
    assert "BaseHTTPServer 0.6" in f.evidence


@pytest.mark.parametrize("xml", ["not xml", "<other/>",
                                 '<!DOCTYPE x [<!ENTITY a "aaaa">]><nmaprun>&a;</nmaprun>'])
def test_nmap_malformed_or_hostile_xml(xml):
    with pytest.raises(NmapError):
        parse_nmap_xml(xml)


def test_nmap_args_are_bounded():
    args = build_nmap_args("nmap", "127.0.0.1", "80,443", True, 60)
    assert args[-1] == "127.0.0.1" and "-sT" in args and "-p" in args
    assert not any(a in args for a in ("-sS", "-O", "-A", "--script"))


def test_nmap_missing_executable(settings, tmp_path):
    s = replace(settings, nmap_path=str(tmp_path / "nope.exe"))
    scanner = NmapScanner(s)
    assert scanner.availability()[0] is False
    target = validate_target("http://127.0.0.1/", s)
    assert scanner.run(target, ScanConfig(tools=["nmap"]), threading.Event()).status == "unavailable"


def test_nmap_nonzero_exit_reported(settings, monkeypatch):
    from modules import nmap_scanner
    from modules.process_runner import ProcessResult
    monkeypatch.setattr(NmapScanner, "_executable", lambda self: "nmap")
    monkeypatch.setattr(nmap_scanner, "run_command", lambda *a, **k: ProcessResult(1, "", "Failed to resolve", 0.1))
    res = NmapScanner(settings).run(validate_target("http://127.0.0.1/", settings),
                                    ScanConfig(tools=["nmap"]), threading.Event())
    assert res.status == "failed" and "exit code 1" in res.message


def test_nmap_timeout_reported(settings, monkeypatch):
    from modules import nmap_scanner

    def boom(*a, **k):
        raise ToolTimeout("Timed out after 5 s")
    monkeypatch.setattr(NmapScanner, "_executable", lambda self: "nmap")
    monkeypatch.setattr(nmap_scanner, "run_command", boom)
    res = NmapScanner(settings).run(validate_target("http://127.0.0.1/", settings),
                                    ScanConfig(tools=["nmap"]), threading.Event())
    assert res.status == "timeout"


# --- Nikto -----------------------------------------------------------------------------

def test_nikto_real_output_parsing():
    findings = parse_nikto_json((FIXTURES / "nikto_lab_2.6.1.json").read_text(), "http://127.0.0.1:8008/")
    keys = {f.issue_key for f in findings}
    assert {"header-missing:content-security-policy", "disclosure:x-powered-by", "directory-listing",
            "cookie:no-httponly:sessionid"} <= keys
    listing = next(f for f in findings if f.issue_key == "directory-listing")
    assert listing.cwe_id == 548 and listing.affected_url == "http://127.0.0.1:8008/files/"
    assert all(f.scanner_severity == "unrated" for f in findings)


def test_nikto_invalid_json():
    from modules.nikto_scanner import NiktoError
    with pytest.raises(NiktoError):
        parse_nikto_json("{broken", "http://x/")


def test_nikto_command_uses_perl_and_lib():
    cmd = build_nikto_command("C:/n/program/nikto.pl", "perl", "http://127.0.0.1/", "out.json", 60, "C:/n/perl-lib")
    assert cmd[:4] == ["perl", "-I", "C:/n/perl-lib", "C:/n/program/nikto.pl"]
    assert "-Tuning" in cmd and cmd[cmd.index("-Tuning") + 1] == "x6"


def test_nikto_missing(settings, tmp_path):
    s = replace(settings, nikto_path=str(tmp_path / "nikto.pl"))
    scanner = NiktoScanner(s)
    assert scanner.availability()[0] is False
    res = scanner.run(validate_target("http://127.0.0.1/", s), ScanConfig(tools=["nikto"]), threading.Event())
    assert res.status == "unavailable"


# --- ZAP -------------------------------------------------------------------------------

class _Resp:
    def __init__(self, status, data):
        self.status_code, self._data = status, data

    def json(self):
        return self._data


class _Session:
    def __init__(self, handler):
        self.handler, self.trust_env, self.calls = handler, True, []

    def get(self, url, params=None, timeout=None):
        self.calls.append((url, dict(params or {})))
        return self.handler(url, params or {})


def test_zap_unavailable(settings):
    ok, msg = ZapScanner(settings).availability()
    assert ok is False and "Cannot reach the ZAP API" in msg
    res = ZapScanner(settings).run(validate_target("http://127.0.0.1/", settings),
                                   ScanConfig(tools=["zap"], tool_timeout=10), threading.Event())
    assert res.status == "unavailable"


def test_zap_bad_api_key():
    client = ZapClient("http://zap", "wrong", _Session(lambda u, p: _Resp(400, {"code": "bad_api_key",
                                                                               "message": "Missing key"})))
    with pytest.raises(ZapApiError, match="API key"):
        client.version()


def test_zap_full_passive_flow(settings, monkeypatch):
    alerts = [
        {"name": "Content Security Policy (CSP) Header Not Set", "risk": "Medium", "confidence": "High",
         "url": "http://127.0.0.1/", "pluginId": "10038", "cweid": "693", "tags": {"OWASP_2021_A05": "x"},
         "solution": "Set CSP", "reference": "https://a\nhttps://b", "evidence": ""},
        {"name": "Ignored", "risk": "Low", "confidence": "False Positive", "url": "http://127.0.0.1/",
         "pluginId": "1"},
    ]

    def handler(url, params):
        assert params.get("apikey") == "test-key"
        if "version" in url:
            return _Resp(200, {"version": "2.17.0"})
        if "spider/action/scan" in url:
            assert params["subtreeOnly"] == "true"
            return _Resp(200, {"scan": "1"})
        if "status" in url:
            return _Resp(200, {"status": "100"})
        if "recordsToScan" in url:
            return _Resp(200, {"recordsToScan": "0"})
        if "alerts" in url:
            return _Resp(200, {"alerts": alerts})
        return _Resp(200, {"Result": "OK"})

    session = _Session(handler)
    monkeypatch.setattr(ZapScanner, "client", lambda self: ZapClient("http://zap", "test-key", session))
    res = ZapScanner(settings).run(validate_target("http://127.0.0.1/", settings),
                                   ScanConfig(tools=["zap"], tool_timeout=30), threading.Event())
    assert res.status == "completed"
    assert len(res.findings) == 1  # false positive skipped
    f = res.findings[0]
    assert f.issue_key == "header-missing:content-security-policy" and f.scanner_severity == "medium"
    assert f.references == ["https://a", "https://b"]
    assert not any("ascan" in url for url, _ in session.calls)  # passive only
    assert any("newSession" in url for url, _ in session.calls)  # no stale alerts from earlier scans


def test_zap_transient_internal_error_retried(monkeypatch):
    monkeypatch.setattr("modules.zap_scanner.time.sleep", lambda s: None)
    replies = iter([_Resp(500, {"code": "internal_error", "message": "Internal Error"}),
                    _Resp(200, {"version": "2.17.0"})])
    client = ZapClient("http://zap", "k", _Session(lambda u, p: next(replies)))
    assert client.version() == "2.17.0"


def test_zap_alert_attack_marks_exploit_evidence():
    f = alert_to_finding({"name": "SQL Injection", "risk": "High", "confidence": "Medium", "attack": "' OR 1=1",
                          "cweid": "89", "pluginId": "40018"})
    assert f.exploit_evidence and f.cwe_id == 89 and "Attack:" in f.evidence


# --- built-in checks against the lab server -------------------------------------------

def test_builtin_checks_find_lab_issues(settings, lab_url):
    target = validate_target(lab_url, settings)
    res = HttpSecurityChecker(settings).run(target, ScanConfig(tools=["builtin"]), threading.Event())
    assert res.status == "completed"
    keys = {f.issue_key for f in res.findings}
    expected = {"header-missing:content-security-policy", "header-missing:x-frame-options",
                "header-missing:x-content-type-options", "disclosure:server-version", "disclosure:x-powered-by",
                "cookie:no-httponly:sessionid", "cookie:no-samesite:sessionid", "transport:cleartext-http",
                "directory-listing", "cors:reflected-origin", "disclosure:error-details"}
    assert expected <= keys, expected - keys
    cors = next(f for f in res.findings if f.issue_key == "cors:reflected-origin")
    assert cors.scanner_severity == "high"
    assert not any("example.org" in f.affected_url for f in res.findings)  # external link not followed


def test_builtin_unreachable_target(settings):
    target = validate_target("http://127.0.0.1:1/", settings)
    res = HttpSecurityChecker(settings).run(target, ScanConfig(tools=["builtin"]), threading.Event())
    assert res.status == "failed" and "Could not connect" in res.message


def test_builtin_does_not_follow_offsite_redirect(settings, monkeypatch):
    class R:
        is_redirect = True
        headers = {"location": "http://169.254.169.254/latest/meta-data/"}

        class raw:  # noqa: N801
            @staticmethod
            def read(*a, **k):
                return b""

        def close(self):
            pass
    calls = []

    def fake_get(self, url, **kw):
        calls.append(url)
        return R()
    monkeypatch.setattr(requests.Session, "get", fake_get)
    checker = HttpSecurityChecker(settings)
    checker._fetch(requests.Session(), "http://127.0.0.1/", ("http", "127.0.0.1", 80), 5)
    assert calls == ["http://127.0.0.1/"]
