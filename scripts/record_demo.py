"""Record a demo video of the running app and capture screenshots of every screen.

Prerequisites: the app is running (streamlit run app.py, port 8501), ZAP is running
(python scripts/start_zap.py) and Playwright's Chromium is installed. The script starts
the local lab server itself and performs a REAL scan of it through the UI.

    python scripts/record_demo.py            -> IVA_Demo.mp4 (root) + docs/screenshots/*.png
"""
from __future__ import annotations

import shutil
import subprocess
import sys
import time
from pathlib import Path

from playwright.sync_api import Page, sync_playwright

ROOT = Path(__file__).resolve().parent.parent
SHOTS = ROOT / "docs" / "screenshots"
VIDEO_TMP = ROOT / "data" / "_video_tmp"
APP = "http://127.0.0.1:8501"
LAB = "http://127.0.0.1:8008/"
VIEW = {"width": 1440, "height": 900}


def pause(page: Page, ms: int = 1500) -> None:
    page.wait_for_timeout(ms)


def shot(page: Page, name: str) -> None:
    page.screenshot(path=str(SHOTS / f"{name}.png"))


def scroll(page: Page, steps: int, dy: int = 220, delay: int = 350) -> None:
    page.mouse.move(900, 500)
    for _ in range(steps):
        page.mouse.wheel(0, dy)
        page.wait_for_timeout(delay)


def scroll_top(page: Page) -> None:
    page.mouse.move(900, 500)
    page.mouse.wheel(0, -20000)
    pause(page, 600)


def goto_page(page: Page, label: str) -> None:
    page.get_by_role("link", name=label).first.click()
    pause(page, 3500)


def main() -> int:
    SHOTS.mkdir(parents=True, exist_ok=True)
    shutil.rmtree(VIDEO_TMP, ignore_errors=True)
    lab = subprocess.Popen([sys.executable, str(ROOT / "lab" / "vulnerable_lab_server.py"), "--port", "8008"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1.5)
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch()
            ctx = browser.new_context(viewport=VIEW, record_video_dir=str(VIDEO_TMP), record_video_size=VIEW)
            page = ctx.new_page()

            # 1. Dashboard
            page.goto(APP + "/")
            pause(page, 7000)
            shot(page, "01_dashboard_top")
            scroll(page, 5)
            shot(page, "02_dashboard_owasp")
            scroll(page, 6)
            shot(page, "03_dashboard_activity")
            scroll_top(page)

            # 2. System & method
            goto_page(page, "System & method")
            shot(page, "04_system_status")
            scroll(page, 6)
            shot(page, "05_system_method")
            scroll_top(page)

            # 3. New scan: rejected target, then a real scan of the lab
            goto_page(page, "New scan")
            shot(page, "06_new_scan_form")
            url = page.get_by_role("textbox", name="Target URL")
            url.fill("")
            url.type("http://169.254.169.254/latest/meta-data/", delay=40)
            url.press("Tab")
            page.get_by_role("button", name="Review scan").click()
            pause(page, 2500)
            shot(page, "07_target_rejected")

            url.fill("")
            url.type(LAB, delay=50)
            url.press("Tab")  # Streamlit commits a text input on blur
            for tool in ("OWASP ZAP", "Nmap"):
                page.get_by_text(tool, exact=True).click()
                pause(page, 500)
            page.get_by_text("Options", exact=True).click()
            pause(page, 800)
            ports = page.get_by_role("textbox", name="Nmap ports")
            ports.fill("8008")
            ports.press("Tab")
            pause(page, 1000)
            page.get_by_role("button", name="Review scan").click()
            pause(page, 3000)
            scroll(page, 4)
            shot(page, "08_review_authorize")
            page.get_by_text("I confirm I am authorized").click()
            pause(page, 1200)
            page.get_by_role("button", name="Start scan").click()
            pause(page, 4000)
            scroll_top(page)
            shot(page, "09_scan_running")
            page.wait_for_selector("text=Scan completed", timeout=240000)
            pause(page, 2000)
            shot(page, "10_scan_completed")

            # 4. Findings
            page.get_by_role("button", name="View findings").click()
            pause(page, 5000)
            shot(page, "11_findings_table")
            scroll(page, 5)
            shot(page, "12_finding_detail")
            scroll(page, 5)
            shot(page, "13_finding_evidence")
            scroll_top(page)
            page.get_by_role("textbox", name="Search").fill("Content-Security")
            page.keyboard.press("Enter")
            pause(page, 3500)
            scroll(page, 4)
            shot(page, "14_cross_tool_finding")
            scroll_top(page)

            # 5. Dashboard again (now includes the new scan)
            goto_page(page, "Dashboard")
            pause(page, 2000)
            scroll(page, 3)
            shot(page, "15_dashboard_after_scan")
            scroll(page, 9, delay=300)
            scroll_top(page)

            # 6. History & comparison
            goto_page(page, "Scan history")
            shot(page, "16_scan_history")
            scroll(page, 5)
            shot(page, "17_scan_comparison")
            scroll_top(page)

            # 7. Reports
            goto_page(page, "Reports")
            page.get_by_role("button", name="Generate PDF").click()
            pause(page, 5000)
            shot(page, "18_reports")
            pause(page, 2000)

            video_path = page.video.path()
            ctx.close()
            browser.close()
    finally:
        lab.terminate()

    webm = Path(video_path)
    out = ROOT / "IVA_Demo.mp4"
    try:
        import imageio_ffmpeg
        subprocess.run([imageio_ffmpeg.get_ffmpeg_exe(), "-y", "-loglevel", "error", "-i", str(webm),
                        "-c:v", "libx264", "-pix_fmt", "yuv420p", "-crf", "23", "-movflags", "+faststart", str(out)],
                       check=True)
        print(f"Video: {out}")
    except Exception as exc:  # fall back to the WebM Playwright produced
        out = ROOT / "IVA_Demo.webm"
        shutil.copy(webm, out)
        print(f"MP4 conversion unavailable ({type(exc).__name__}); video saved as {out}")
    shutil.rmtree(VIDEO_TMP, ignore_errors=True)
    print(f"Screenshots: {SHOTS}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
