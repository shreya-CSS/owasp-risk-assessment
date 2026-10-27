"""Start OWASP ZAP as a headless daemon bound to localhost, using ZAP_HOME / ZAP_API_URL /
ZAP_API_KEY from .env, then wait until its API answers.

Usage:  python scripts/start_zap.py          (leave the window open; Ctrl+C stops ZAP)
"""
from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config.settings import load_settings  # noqa: E402
from modules.zap_scanner import ZapApiError, ZapClient  # noqa: E402


def main() -> int:
    sys.stdout.reconfigure(line_buffering=True)
    settings = load_settings()
    zap_home = Path(os.getenv("ZAP_HOME", ""))
    launcher = zap_home / ("zap.bat" if os.name == "nt" else "zap.sh")
    if not launcher.is_file():
        print(f"ZAP launcher not found at {launcher}. Set ZAP_HOME in .env.")
        return 1
    if not settings.zap_api_key:
        print("ZAP_API_KEY is empty in .env — refusing to start ZAP without an API key.")
        return 1
    parts = urlsplit(settings.zap_api_url)
    host, port = parts.hostname or "127.0.0.1", parts.port or 8080
    if host not in ("127.0.0.1", "localhost"):
        print("ZAP_API_URL must point to localhost; the ZAP API must not be exposed to the network.")
        return 1

    client = ZapClient(settings.zap_api_url, settings.zap_api_key)
    try:
        print(f"ZAP already running: version {client.version()}")
        return 0
    except ZapApiError:
        pass

    args = [str(launcher), "-daemon", "-host", host, "-port", str(port),
            "-config", f"api.key={settings.zap_api_key}",
            "-config", "api.addrs.addr.name=127.0.0.1", "-config", "api.addrs.addr.regex=false"]
    print(f"Starting ZAP daemon on {host}:{port} …")
    proc = subprocess.Popen(args, cwd=str(zap_home), stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
    for _ in range(90):
        time.sleep(2)
        if proc.poll() is not None:
            print(f"ZAP exited early (code {proc.returncode}). Check Java 17+ is installed.")
            return 1
        try:
            print(f"ZAP {client.version()} is ready at {settings.zap_api_url}. Keep this window open.")
            break
        except ZapApiError:
            continue
    else:
        print("ZAP did not become ready within 180 s.")
        proc.terminate()
        return 1
    try:
        proc.wait()
    except KeyboardInterrupt:
        print("Stopping ZAP …")
        try:
            client.call("core", "action", "shutdown")
        except ZapApiError:
            proc.terminate()
    return 0


if __name__ == "__main__":
    sys.exit(main())
