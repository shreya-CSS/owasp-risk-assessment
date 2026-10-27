"""INTENTIONALLY INSECURE local lab web server — for testing the assessment tool only.

It binds to 127.0.0.1 so it is not reachable from other machines. Each route carries
a known misconfiguration, which gives a reproducible "expected findings" list:

  /          no security headers, X-Powered-By banner, cookie without HttpOnly/SameSite
  /login     second cookie without flags
  /files/    simulated directory listing ("Index of /files/")
  /api/data  CORS reflects any Origin with credentials
  /error     HTTP 500 with a (fake) Python stack trace

Run:  python lab/vulnerable_lab_server.py [--port 8008]
"""
from __future__ import annotations

import argparse
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

INDEX = b"""<!doctype html><html><head><title>IVA Lab App</title></head><body>
<h1>IVA deliberately vulnerable lab</h1>
<p>Local testing target. Do not expose to a network.</p>
<ul>
<li><a href="/login">Login</a></li>
<li><a href="/files/">Files</a></li>
<li><a href="/api/data">API</a></li>
<li><a href="/error">Report a problem</a></li>
<li><a href="https://example.org/">External link (must not be followed)</a></li>
</ul></body></html>"""

LISTING = b"""<!doctype html><html><head><title>Index of /files/</title></head><body>
<h1>Index of /files/</h1><ul><li><a href="backup.zip">backup.zip</a></li>
<li><a href="config.old">config.old</a></li></ul></body></html>"""

ERROR = b"""<html><body><h1>500 Internal Server Error</h1><pre>
Traceback (most recent call last):
  File "/srv/app/views.py", line 42, in report
    db.execute(query)
sqlite3.OperationalError: near "WHERE": syntax error
</pre></body></html>"""


class LabHandler(BaseHTTPRequestHandler):
    server_version = "LabHTTP/1.0"  # appears in the Server header with a version (intentional)

    def _send(self, status: int, body: bytes, ctype: str = "text/html; charset=utf-8",
              extra: list[tuple[str, str]] | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Powered-By", "PHP/5.6.40 (simulated)")
        for name, value in extra or []:
            self.send_header(name, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802 (http.server API)
        path = self.path.split("?", 1)[0]
        if path == "/":
            self._send(200, INDEX, extra=[("Set-Cookie", "sessionid=lab-session-123; Path=/")])
        elif path == "/login":
            self._send(200, b"<html><body><form method=post><input name=user></form></body></html>",
                       extra=[("Set-Cookie", "csrftoken=lab-token; Path=/")])
        elif path == "/files/":
            self._send(200, LISTING)
        elif path == "/api/data":
            origin = self.headers.get("Origin", "")
            extra = [("Access-Control-Allow-Origin", origin), ("Access-Control-Allow-Credentials", "true")] if origin else []
            self._send(200, b'{"items": [1, 2, 3]}', "application/json", extra)
        elif path == "/error":
            self._send(500, ERROR)
        else:
            self._send(404, b"<html><body>Not found</body></html>")

    do_HEAD = do_GET

    def log_message(self, fmt: str, *args) -> None:
        print(f"[lab] {self.address_string()} {fmt % args}", flush=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--port", type=int, default=8008)
    args = parser.parse_args()
    sys.stdout.reconfigure(errors="replace")  # Windows consoles cannot print every character
    server = ThreadingHTTPServer(("127.0.0.1", args.port), LabHandler)
    print(f"Lab server (INTENTIONALLY INSECURE) on http://127.0.0.1:{args.port}/ - Ctrl+C to stop", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
