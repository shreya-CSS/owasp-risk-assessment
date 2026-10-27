"""Headless render of the app and every page (Streamlit AppTest) against a temporary database,
both empty and with a demo scan loaded."""
import pytest
from streamlit.testing.v1 import AppTest

PAGES = ["dashboard", "scan_configuration", "findings", "scan_history", "reports", "about"]


def _page_script(page: str) -> None:
    import importlib
    importlib.import_module(f"ui.{page}").render()


@pytest.fixture
def isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("IVA_DB_PATH", str(tmp_path / "ui.db"))
    monkeypatch.setenv("ZAP_API_URL", "http://127.0.0.1:1")
    monkeypatch.setenv("NIKTO_PATH", str(tmp_path / "missing-nikto.pl"))
    from ui.common import get_manager, tool_availability
    get_manager.clear()
    tool_availability.clear()
    yield get_manager
    get_manager.clear()
    tool_availability.clear()


def test_main_app_renders_empty_dashboard(isolated):
    at = AppTest.from_file("app.py", default_timeout=60).run()
    assert not at.exception
    assert any("No live scans yet" in i.value for i in at.info)


@pytest.mark.parametrize("with_demo", [False, True])
@pytest.mark.parametrize("page", PAGES)
def test_each_page_renders(isolated, page, with_demo):
    if with_demo:
        isolated().create_demo_scan()
    at = AppTest.from_function(_page_script, args=(page,), default_timeout=60).run()
    assert not at.exception, [e.value for e in at.exception]


def test_findings_page_shows_demo_banner_and_details(isolated):
    isolated().create_demo_scan()
    at = AppTest.from_function(_page_script, args=("findings",), default_timeout=60).run()
    assert any("DEMO DATA" in w.value for w in at.warning)
    assert any("Why this priority" in m.value for m in at.markdown)


def test_new_scan_rejects_unauthorized_target(isolated):
    at = AppTest.from_function(_page_script, args=("scan_configuration",), default_timeout=60).run()
    at.text_input[0].set_value("http://169.254.169.254/latest/meta-data/")
    at.button[0].click().run()  # "Review scan" form submit
    assert any("Target rejected" in e.value for e in at.error)


def test_new_scan_accepts_corrected_target_after_rejection(isolated):
    """Regression: editing the URL after a rejection must not be discarded."""
    at = AppTest.from_function(_page_script, args=("scan_configuration",), default_timeout=60).run()
    at.text_input[0].set_value("http://169.254.169.254/")
    at.button[0].click().run()
    assert any("Target rejected" in e.value for e in at.error)
    at.text_input[0].set_value("http://127.0.0.1:8008/")
    at.button[0].click().run()
    assert not at.error
    assert any("Review before starting" in h.value for h in at.subheader)
