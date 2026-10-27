"""Built-in passive HTTP security checks (no external tool required).

Only ordinary GET requests are sent: the target page plus up to MAX_PAGES same-origin
links found on it. Redirects are followed manually and only within the same origin,
so the checker cannot be steered to other hosts (SSRF protection).

Checks: security response headers, version/technology disclosure, cookie attributes,
cleartext HTTP, CORS origin handling, directory listing and stack-trace disclosure.
"""
from __future__ import annotations

import re
import threading
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit, urlunsplit

import requests

from modules.models import Finding, ScanConfig, ToolResult, utc_now
from modules.scanner_base import Scanner
from modules.target_validation import ValidatedTarget

MAX_PAGES = 10
MAX_REDIRECTS = 5
MAX_BODY_BYTES = 1024 * 1024
CORS_PROBE_ORIGIN = "https://iva-cors-probe.invalid"
USER_AGENT = "IVA-Assessment/1.0 (authorized security assessment)"

_LISTING = re.compile(r"<title>\s*(index of /|directory listing for)", re.I)
_STACK_TRACE = re.compile(
    r"(Traceback \(most recent call last\)|Fatal error</b>:|Warning</b>:.*on line \d+|"
    r"at [a-z0-9_.$]+\([A-Za-z0-9_]+\.java:\d+\)|Microsoft OLE DB Provider|ORA-\d{5}|"
    r"You have an error in your SQL syntax)", re.I)
_VERSION = re.compile(r"\d+(\.\d+)+")

REMEDIATION = {
    "content-security-policy": "Define a Content-Security-Policy header that restricts script, style and frame sources to trusted origins.",
    "x-frame-options": "Send 'X-Frame-Options: DENY' (or SAMEORIGIN) or a CSP 'frame-ancestors' directive to prevent clickjacking.",
    "x-content-type-options": "Send 'X-Content-Type-Options: nosniff' on all responses.",
    "strict-transport-security": "Send 'Strict-Transport-Security: max-age=31536000; includeSubDomains' on HTTPS responses.",
    "referrer-policy": "Send a Referrer-Policy such as 'strict-origin-when-cross-origin'.",
    "permissions-policy": "Send a Permissions-Policy that disables browser features the site does not use.",
}


class _LinkParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in ("a", "link", "form", "iframe"):
            for name, value in attrs:
                if name in ("href", "src", "action") and value:
                    self.links.append(value)


def _origin(url: str) -> tuple[str, str, int | None]:
    parts = urlsplit(url)
    port = parts.port or (443 if parts.scheme == "https" else 80)
    return parts.scheme, (parts.hostname or "").lower(), port


class HttpSecurityChecker(Scanner):
    name = "builtin"
    label = "Built-in passive HTTP checks"
    description = ("Python checks for security headers, cookies, disclosure, CORS, cleartext "
                   "transport, directory listing and error disclosure. GET requests only.")

    def availability(self) -> tuple[bool, str]:
        return True, "Built into the application."

    # -- HTTP helpers -------------------------------------------------------------------
    def _fetch(self, session: requests.Session, url: str, origin: tuple, timeout: int) -> tuple[requests.Response, bytes, str]:
        current = url
        for _ in range(MAX_REDIRECTS + 1):
            resp = session.get(current, allow_redirects=False, stream=True, timeout=timeout,
                               verify=self.settings.verify_tls, headers={"Origin": CORS_PROBE_ORIGIN})
            body = resp.raw.read(MAX_BODY_BYTES, decode_content=True) or b""
            resp.close()
            if resp.is_redirect and "location" in resp.headers:
                nxt = urljoin(current, resp.headers["location"])
                if _origin(nxt) != origin:
                    return resp, body, current  # never follow a redirect off the authorized origin
                current = nxt
                continue
            return resp, body, current
        return resp, body, current

    # -- checks -------------------------------------------------------------------------
    def _finding(self, **kwargs) -> Finding:
        kwargs.setdefault("confidence", "high")
        return Finding(source_tool=self.name, detected_at=utc_now(), **kwargs)

    def _header_checks(self, resp: requests.Response, url: str, is_https: bool) -> list[Finding]:
        h = resp.headers
        out: list[Finding] = []
        ctype = h.get("content-type", "").lower()
        is_html = "html" in ctype or not ctype
        csp = h.get("content-security-policy", "")

        def missing(header: str, severity: str, cwe: int, title: str, why: str) -> None:
            out.append(self._finding(
                title=title, scanner_severity=severity, affected_url=url, cwe_id=cwe,
                issue_key=f"header-missing:{header}", rule_id=f"IVA-HDR-{header}",
                description=why, evidence=f"Response for {url} has no '{header}' header.",
                remediation=REMEDIATION[header]))

        if is_html and not csp:
            missing("content-security-policy", "medium", 693, "Content-Security-Policy header not set",
                    "Without a CSP the browser has no policy to limit injected scripts, which increases the impact of XSS.")
        if is_html and "x-frame-options" not in h and "frame-ancestors" not in csp.lower():
            missing("x-frame-options", "medium", 1021, "Missing anti-clickjacking protection",
                    "The page can be framed by another site, enabling clickjacking attacks.")
        if h.get("x-content-type-options", "").lower() != "nosniff":
            missing("x-content-type-options", "low", 693, "X-Content-Type-Options header missing",
                    "Browsers may MIME-sniff responses and interpret them as a different content type.")
        if is_https and "strict-transport-security" not in h:
            missing("strict-transport-security", "low", 319, "Strict-Transport-Security header not set",
                    "Browsers are not instructed to always use HTTPS, allowing downgrade attacks.")
        if is_html and "referrer-policy" not in h:
            missing("referrer-policy", "info", 200, "Referrer-Policy header not set",
                    "URLs (possibly containing sensitive parameters) may leak to other sites via the Referer header.")
        if is_html and "permissions-policy" not in h:
            missing("permissions-policy", "info", 693, "Permissions-Policy header not set",
                    "Browser features (camera, geolocation, …) are not explicitly restricted.")

        server = h.get("server", "")
        if server and _VERSION.search(server):
            out.append(self._finding(
                title="Server version disclosed in 'Server' header", scanner_severity="low", affected_url=url,
                cwe_id=497, issue_key="disclosure:server-version", rule_id="IVA-DISC-server",
                description="The Server header reveals software and version, helping attackers find matching exploits.",
                evidence=f"Server: {server}",
                remediation="Configure the web server to omit or genericise the Server header."))
        for header in ("x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"):
            if header in h:
                out.append(self._finding(
                    title=f"Technology disclosed in '{header}' header", scanner_severity="low", affected_url=url,
                    cwe_id=497, issue_key=f"disclosure:{header}", rule_id=f"IVA-DISC-{header}",
                    description="The response reveals the application framework/version.",
                    evidence=f"{header}: {h[header]}",
                    remediation=f"Remove the {header} header in the application or proxy configuration."))

        return out

    def _cors_checks(self, resp: requests.Response, url: str) -> list[Finding]:
        h = resp.headers
        out: list[Finding] = []
        acao = h.get("access-control-allow-origin", "")
        acac = h.get("access-control-allow-credentials", "").lower() == "true"
        if acao == CORS_PROBE_ORIGIN:
            out.append(self._finding(
                title="CORS policy reflects arbitrary origins" + (" with credentials" if acac else ""),
                scanner_severity="high" if acac else "medium", affected_url=url, cwe_id=942,
                issue_key="cors:reflected-origin", rule_id="IVA-CORS-reflect",
                description="The server echoes any Origin in Access-Control-Allow-Origin, so any website can read "
                            "responses" + (" using the victim's cookies." if acac else "."),
                evidence=f"Request Origin: {CORS_PROBE_ORIGIN}\nAccess-Control-Allow-Origin: {acao}\n"
                         f"Access-Control-Allow-Credentials: {h.get('access-control-allow-credentials', '(absent)')}",
                remediation="Allow-list trusted origins explicitly; never reflect the Origin header together with credentials."))
        elif acao == "*":
            out.append(self._finding(
                title="CORS allows any origin (wildcard)", scanner_severity="low", affected_url=url, cwe_id=942,
                issue_key="cors:wildcard", rule_id="IVA-CORS-wildcard",
                description="Any website can read responses from this URL. Acceptable only for genuinely public data.",
                evidence="Access-Control-Allow-Origin: *",
                remediation="Restrict Access-Control-Allow-Origin to the origins that need access."))
        return out

    def _cookie_checks(self, resp: requests.Response, site_url: str, is_https: bool) -> list[Finding]:
        out: list[Finding] = []
        raw_headers = resp.raw.headers.getlist("Set-Cookie") if hasattr(resp.raw.headers, "getlist") else []
        for raw in raw_headers:
            name = raw.split("=", 1)[0].strip()[:100]
            attrs = {a.strip().split("=", 1)[0].lower() for a in raw.split(";")[1:]}
            shown = raw.split(";", 1)[0][:40] + ("…" if len(raw) > 40 else "")
            evidence = f"Set-Cookie: {shown}; attributes: {', '.join(sorted(attrs)) or '(none)'}"
            if "httponly" not in attrs:
                out.append(self._finding(
                    title=f"Cookie '{name}' without HttpOnly flag", scanner_severity="low", affected_url=site_url,
                    cwe_id=1004, issue_key=f"cookie:no-httponly:{name}", rule_id="IVA-COOKIE-httponly",
                    description="JavaScript can read this cookie, so an XSS flaw could steal it.", evidence=evidence,
                    remediation="Set the HttpOnly attribute on cookies that scripts do not need."))
            if is_https and "secure" not in attrs:
                out.append(self._finding(
                    title=f"Cookie '{name}' without Secure flag", scanner_severity="low", affected_url=site_url,
                    cwe_id=614, issue_key=f"cookie:no-secure:{name}", rule_id="IVA-COOKIE-secure",
                    description="The cookie may be sent over unencrypted connections.", evidence=evidence,
                    remediation="Set the Secure attribute on all cookies of HTTPS sites."))
            if "samesite" not in attrs:
                out.append(self._finding(
                    title=f"Cookie '{name}' without SameSite attribute", scanner_severity="low", affected_url=site_url,
                    cwe_id=1275, issue_key=f"cookie:no-samesite:{name}", rule_id="IVA-COOKIE-samesite",
                    description="Without SameSite the cookie is sent on cross-site requests, aiding CSRF.",
                    evidence=evidence, remediation="Set SameSite=Lax or SameSite=Strict."))
        return out

    def _body_checks(self, body: bytes, url: str) -> list[Finding]:
        out: list[Finding] = []
        text = body[:MAX_BODY_BYTES].decode("utf-8", errors="replace")
        if _LISTING.search(text):
            out.append(self._finding(
                title="Directory listing enabled", scanner_severity="medium", affected_url=url, cwe_id=548,
                issue_key="directory-listing", rule_id="IVA-LISTING",
                description="The server lists directory contents, exposing files that may not be meant to be public.",
                evidence=_LISTING.search(text).group(0),
                remediation="Disable automatic directory indexes in the web server configuration."))
        match = _STACK_TRACE.search(text)
        if match:
            out.append(self._finding(
                title="Error message or stack trace disclosed", scanner_severity="medium", affected_url=url,
                cwe_id=209, issue_key="disclosure:error-details", rule_id="IVA-ERR",
                confidence="medium",
                description="The response contains internal error details that reveal implementation information.",
                evidence=match.group(0)[:200],
                remediation="Show generic error pages to users and log details server-side only."))
        return out

    # -- main ---------------------------------------------------------------------------
    def run(self, target: ValidatedTarget, config: ScanConfig, cancel_event: threading.Event) -> ToolResult:
        started = utc_now()
        timeout = max(3, min(15, config.tool_timeout))
        origin = (target.scheme, target.host, target.port)
        is_https = target.scheme == "https"
        findings: list[Finding] = []
        session = requests.Session()
        session.headers["User-Agent"] = USER_AGENT
        session.trust_env = False  # never route through proxies from the environment
        try:
            resp, body, final_url = self._fetch(session, target.url, origin, timeout)
        except requests.exceptions.SSLError:
            return self.result("failed", "TLS certificate verification failed. For a local lab with a self-signed "
                                         "certificate set IVA_VERIFY_TLS=false.", started_at=started)
        except requests.exceptions.Timeout:
            return self.result("timeout", f"The target did not respond within {timeout} s.", started_at=started)
        except requests.exceptions.RequestException as exc:
            return self.result("failed", f"Could not connect to the target ({type(exc).__name__}). "
                                         "Check that it is running and reachable.", started_at=started)

        findings += self._header_checks(resp, final_url, is_https)
        findings += self._cors_checks(resp, final_url)
        findings += self._cookie_checks(resp, target.url, is_https)
        findings += self._body_checks(body, final_url)
        if not is_https:
            findings.append(self._finding(
                title="Content served over unencrypted HTTP", scanner_severity="low", affected_url=target.url,
                cwe_id=319, issue_key="transport:cleartext-http", rule_id="IVA-TLS",
                description="Traffic, including any credentials or session cookies, can be read or modified in transit.",
                evidence=f"Target URL scheme is http:// ({target.url}).",
                remediation="Serve the application only over HTTPS and redirect HTTP to HTTPS."))

        visited = {final_url, target.url}
        parser = _LinkParser()
        try:
            parser.feed(body.decode("utf-8", errors="replace"))
        except Exception:  # malformed HTML must not abort the scan
            pass
        pages_checked = 1
        for link in parser.links:
            if pages_checked >= MAX_PAGES or cancel_event.is_set():
                break
            absolute = urljoin(final_url, link)
            parts = urlsplit(absolute)
            absolute = urlunsplit((parts.scheme, parts.netloc, parts.path or "/", parts.query, ""))
            if absolute in visited or parts.scheme not in ("http", "https") or _origin(absolute) != origin:
                continue
            visited.add(absolute)
            try:
                sub_resp, sub_body, sub_url = self._fetch(session, absolute, origin, timeout)
            except requests.exceptions.RequestException:
                continue
            pages_checked += 1
            findings += self._cookie_checks(sub_resp, target.url, is_https)
            findings += self._cors_checks(sub_resp, sub_url)
            findings += self._body_checks(sub_body, sub_url)

        status = "cancelled" if cancel_event.is_set() else "completed"
        return self.result(status, f"Checked {pages_checked} page(s) on {target.host}.",
                           findings=findings, started_at=started, exit_code=None,
                           command=f"GET {target.url} (+ up to {MAX_PAGES - 1} same-origin links)")
