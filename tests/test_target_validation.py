from dataclasses import replace

import pytest

from modules.models import ScanConfig
from modules.target_validation import TargetValidationError, validate_scan_config, validate_target
from tests.conftest import fake_resolver


@pytest.mark.parametrize("url", [
    "http://127.0.0.1:8008/", "http://localhost/", "https://127.0.0.1/app?x=1", "http://[::1]:8080/",
])
def test_loopback_targets_allowed(settings, url):
    target = validate_target(url, settings, fake_resolver({"localhost": ["127.0.0.1"]}))
    assert target.policy_reason.startswith("loopback")
    assert target.scheme in ("http", "https")


def test_url_normalised(settings):
    t = validate_target("HTTP://LOCALHOST:80/#frag", settings, fake_resolver({"localhost": ["127.0.0.1"]}))
    assert t.url == "http://localhost/"
    assert t.port == 80


@pytest.mark.parametrize("url,fragment", [
    ("", "Enter a target"),
    ("ftp://127.0.0.1/", "Only http"),
    ("javascript:alert(1)", "Only http"),
    ("file:///etc/passwd", "Only http"),
    ("http://user:pw@127.0.0.1/", "Credentials"),
    ("http://127.0.0.1:99999/", "port"),
    ("http://127.0.0.1/a b", "spaces"),
    ("http://127.0.0.1/\x00", "control"),
    ("http://2130706433/", "numeric"),
    ("http://0x7f.1/", "numeric"),
    ("http://bad_host!/", "invalid"),
    ("http://" + "a" * 2100, "longer"),
])
def test_invalid_urls_rejected(settings, url, fragment):
    with pytest.raises(TargetValidationError) as exc:
        validate_target(url, settings, fake_resolver({}))
    assert fragment.lower() in str(exc.value).lower()


@pytest.mark.parametrize("ip", ["169.254.169.254", "0.0.0.0", "224.0.0.1", "240.0.0.1", "fe80::1"])
def test_always_blocked_even_when_allowlisted(settings, ip):
    s = replace(settings, allowed_targets=(ip, "0.0.0.0/0"), allow_private_networks=True)
    host = f"[{ip}]" if ":" in ip else ip
    with pytest.raises(TargetValidationError):
        validate_target(f"http://{host}/", s, fake_resolver({}))


def test_public_host_rejected_by_default(settings):
    with pytest.raises(TargetValidationError, match="not an authorized target"):
        validate_target("http://example.com/", settings, fake_resolver({"example.com": ["93.184.215.14"]}))


def test_private_network_needs_opt_in(settings):
    resolver = fake_resolver({})
    with pytest.raises(TargetValidationError, match="private-network"):
        validate_target("http://192.168.56.10/", settings, resolver)
    s = replace(settings, allow_private_networks=True)
    assert "private network" in validate_target("http://192.168.56.10/", s, resolver).policy_reason


def test_allowlisted_hostname_and_cidr(settings):
    s = replace(settings, allowed_targets=("lab.example.test", "203.0.113.0/24"))
    resolver = fake_resolver({"lab.example.test": ["198.51.100.7"]})
    assert "explicitly" in validate_target("http://lab.example.test/", s, resolver).policy_reason
    assert "explicitly" in validate_target("http://203.0.113.9/", s, resolver).policy_reason


def test_dns_rebinding_style_mixed_resolution_rejected(settings):
    """A hostname is rejected if ANY resolved address is not permitted."""
    resolver = fake_resolver({"evil.test": ["127.0.0.1", "169.254.169.254"]})
    with pytest.raises(TargetValidationError):
        validate_target("http://evil.test/", settings, resolver)


def test_unresolvable_host_fails_closed(settings):
    with pytest.raises(TargetValidationError, match="resolve"):
        validate_target("http://does-not-exist.test/", settings, fake_resolver({}))


def test_ipv4_mapped_ipv6_unwrapped(settings):
    with pytest.raises(TargetValidationError):
        validate_target("http://[::ffff:169.254.169.254]/", settings, fake_resolver({}))


def test_scan_config_validation(settings):
    ok = validate_scan_config(ScanConfig(tools=["builtin", "nmap"], nmap_ports="80, 443,8000-8010"), settings)
    assert ok.nmap_ports == "80,443,8000-8010"
    bad = [
        ScanConfig(tools=[]),
        ScanConfig(tools=["metasploit"]),
        ScanConfig(tools=["builtin", "builtin"]),
        ScanConfig(tools=["builtin"], tool_timeout=5),
        ScanConfig(tools=["nmap"], nmap_ports="80;rm -rf /"),
        ScanConfig(tools=["nmap"], nmap_ports="1-65535"),
        ScanConfig(tools=["nmap"], nmap_ports="0"),
        ScanConfig(tools=["builtin"], asset_criticality="extreme"),
        ScanConfig(tools=["zap"], zap_active_scan=True),  # disabled in settings
        ScanConfig(tools=["builtin"], zap_active_scan=True),
    ]
    for cfg in bad:
        with pytest.raises(TargetValidationError):
            validate_scan_config(cfg, settings)


def test_active_scan_allowed_when_enabled(settings):
    s = replace(settings, allow_active_scan=True)
    assert validate_scan_config(ScanConfig(tools=["zap"], zap_active_scan=True), s).zap_active_scan
