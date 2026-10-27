"""OWASP ZAP adapter using the ZAP JSON API of a locally running ZAP instance.

Workflow: check API -> new ZAP session -> access URL -> spider (subtree only, limited children) -> wait
for passive scanning -> optional active scan (only if enabled in settings AND chosen
for this scan) -> collect alerts for the target. Alerts marked False Positive in ZAP
are skipped.
"""
from __future__ import annotations

import threading
import time

import requests

from modules.finding_normalizer import normalize_confidence, normalize_severity
from modules.models import Finding, ScanConfig, ToolResult, utc_now
from modules.scanner_base import Scanner
from modules.target_validation import ValidatedTarget

POLL_SECONDS = 2
API_TIMEOUT = 15
PAGE_SIZE = 500
MAX_ALERTS = 5000

# ZAP passive rule IDs that describe the same issue as a built-in check.
ZAP_ISSUE_KEYS = {
    "10038": "header-missing:content-security-policy",
    "10020": "header-missing:x-frame-options",
    "10021": "header-missing:x-content-type-options",
    "10035": "header-missing:strict-transport-security",
    "10036": "disclosure:server-version",
    "10037": "disclosure:x-powered-by",
    "10033": "directory-listing",
}
# Cookie rules: the alert's 'param' is the cookie name.
ZAP_COOKIE_KEYS = {"10010": "cookie:no-httponly", "10011": "cookie:no-secure", "10054": "cookie:no-samesite"}


class ZapApiError(RuntimeError):
    pass


class ZapTransientError(ZapApiError):
    pass


class ZapCancelled(Exception):
    pass


class ZapClient:
    def __init__(self, base_url: str, api_key: str, session: requests.Session | None = None):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.session = session or requests.Session()
        self.session.trust_env = False

    def call(self, component: str, kind: str, name: str, **params: object) -> dict:
        try:
            return self._call(component, kind, name, **params)
        except ZapTransientError:
            time.sleep(2)  # ZAP occasionally answers "Internal Error" while busy; retry once
            return self._call(component, kind, name, **params)

    def _call(self, component: str, kind: str, name: str, **params: object) -> dict:
        url = f"{self.base_url}/JSON/{component}/{kind}/{name}/"
        if self.api_key:
            params["apikey"] = self.api_key
        try:
            resp = self.session.get(url, params=params, timeout=API_TIMEOUT)
        except requests.exceptions.RequestException as exc:
            raise ZapApiError(f"Cannot reach the ZAP API at {self.base_url} ({type(exc).__name__}). "
                              "Start ZAP (daemon or desktop) and check ZAP_API_URL.") from exc
        if resp.status_code in (401, 403):
            raise ZapApiError("ZAP rejected the API key. Check ZAP_API_KEY.")
        try:
            data = resp.json()
        except ValueError as exc:
            raise ZapApiError("ZAP returned a non-JSON response.") from exc
        if resp.status_code != 200 or (isinstance(data, dict) and "code" in data):  # ZAP error envelope
            message = data.get("message") or data.get("code") or f"HTTP {resp.status_code}"
            if "key" in str(message).lower():
                raise ZapApiError("ZAP rejected the API key. Check ZAP_API_KEY.")
            if "internal" in str(message).lower():
                raise ZapTransientError(f"ZAP API error during {component}/{name}: {message}")
            raise ZapApiError(f"ZAP API error during {component}/{name}: {message}")
        return data

    def version(self) -> str:
        return str(self.call("core", "view", "version").get("version", "unknown"))


def alert_to_finding(alert: dict) -> Finding | None:
    confidence = normalize_confidence(alert.get("confidence"))
    if confidence == "false_positive":
        return None
    plugin = str(alert.get("pluginId", ""))
    tags = alert.get("tags") or {}
    cwe = alert.get("cweid")
    try:
        cwe_id = int(cwe) if cwe not in (None, "", "-1", "0") else None
    except (TypeError, ValueError):
        cwe_id = None
    refs = [r.strip() for r in str(alert.get("reference", "")).splitlines() if r.strip()]
    attack = str(alert.get("attack", "") or "")
    evidence = str(alert.get("evidence", "") or "")
    if attack:
        evidence = f"Attack: {attack}\nEvidence: {evidence}" if evidence else f"Attack: {attack}"
    return Finding(
        title=str(alert.get("name") or alert.get("alert") or "ZAP alert"),
        source_tool="zap",
        scanner_severity=normalize_severity(alert.get("risk")),
        confidence=confidence,
        description=str(alert.get("description", "")),
        affected_url=str(alert.get("url", "")),
        parameter=str(alert.get("param", "") or ""),
        evidence=evidence,
        rule_id=f"zap-{plugin}",
        issue_key=(f"{ZAP_COOKIE_KEYS[plugin]}:{alert.get('param', '')}" if plugin in ZAP_COOKIE_KEYS
                   else ZAP_ISSUE_KEYS.get(plugin, "")),
        cwe_id=cwe_id,
        scanner_tags=list(tags.keys()) if isinstance(tags, dict) else [str(t) for t in tags],
        remediation=str(alert.get("solution", "")),
        references=refs,
        exploit_evidence=bool(attack) and confidence in ("confirmed", "high", "medium"),
        detected_at=utc_now(),
    )


class ZapScanner(Scanner):
    name = "zap"
    label = "OWASP ZAP (spider + passive, optional active)"
    description = "Uses a running ZAP instance's API. Active scanning only when explicitly enabled."

    def client(self) -> ZapClient:
        return ZapClient(self.settings.zap_api_url, self.settings.zap_api_key)

    def availability(self) -> tuple[bool, str]:
        try:
            return True, f"ZAP {self.client().version()} at {self.settings.zap_api_url}"
        except ZapApiError as exc:
            return False, str(exc)

    def _wait(self, check, deadline: float, cancel_event: threading.Event, what: str) -> None:
        while not check():
            if cancel_event.is_set():
                raise ZapCancelled()
            if time.monotonic() > deadline:
                raise TimeoutError(f"ZAP {what} did not finish before the timeout")
            time.sleep(POLL_SECONDS)

    def run(self, target: ValidatedTarget, config: ScanConfig, cancel_event: threading.Event) -> ToolResult:
        started = utc_now()
        client = self.client()
        deadline = time.monotonic() + config.tool_timeout
        steps: list[str] = []
        try:
            version = client.version()
            steps.append(f"ZAP {version}")
            # Fresh session per scan: otherwise alerts from earlier scans of the same site are
            # re-reported and resolved issues never disappear. ZAP must be dedicated to this app.
            client.call("core", "action", "newSession", overwrite="true")
            client.call("core", "action", "accessUrl", url=target.url, followRedirects="false")
            spider_id = client.call("spider", "action", "scan", url=target.url, maxChildren=config.zap_max_children,
                                    recurse="true", subtreeOnly="true").get("scan")
            self._wait(lambda: int(client.call("spider", "view", "status", scanId=spider_id).get("status", 0)) >= 100,
                       deadline, cancel_event, "spider")
            steps.append("spider done")
            self._wait(lambda: int(client.call("pscan", "view", "recordsToScan").get("recordsToScan", 0)) == 0,
                       deadline, cancel_event, "passive scan")
            steps.append("passive scan done")
            if config.zap_active_scan:
                if not self.settings.allow_active_scan:
                    return self.result("failed", "Active scan requested but IVA_ALLOW_ACTIVE_SCAN is false.",
                                       started_at=started)
                ascan_id = client.call("ascan", "action", "scan", url=target.url, recurse="true").get("scan")
                try:
                    self._wait(lambda: int(client.call("ascan", "view", "status", scanId=ascan_id).get("status", 0)) >= 100,
                               deadline, cancel_event, "active scan")
                except (ZapCancelled, TimeoutError):
                    client.call("ascan", "action", "stop", scanId=ascan_id)
                    raise
                steps.append("active scan done")
            alerts: list[dict] = []
            start = 0
            while len(alerts) < MAX_ALERTS:
                page = client.call("core", "view", "alerts", baseurl=target.url, start=start,
                                   count=PAGE_SIZE).get("alerts", [])
                alerts.extend(page)
                if len(page) < PAGE_SIZE:
                    break
                start += PAGE_SIZE
        except ZapApiError as exc:
            done = f" Completed before the error: {', '.join(steps)}." if steps else ""
            return self.result("unavailable" if not steps else "failed", f"{exc}.{done}", started_at=started)
        except ZapCancelled:
            return self.result("cancelled", "Cancelled by user. " + ", ".join(steps), started_at=started)
        except TimeoutError as exc:
            return self.result("timeout", f"{exc}. Completed: {', '.join(steps) or 'nothing'}.", started_at=started)
        except (ValueError, TypeError) as exc:
            return self.result("failed", f"Unexpected ZAP response ({type(exc).__name__}).", started_at=started)
        findings = [f for f in (alert_to_finding(a) for a in alerts) if f is not None]
        mode = "active+passive" if config.zap_active_scan else "passive"
        return self.result("completed", f"{len(alerts)} alert(s) ({mode}); {', '.join(steps)}.",
                           findings=findings, started_at=started,
                           command=f"ZAP API {self.settings.zap_api_url}: spider+{mode} {target.url}")
