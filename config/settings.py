"""Application settings loaded from environment variables (and an optional .env file).

All security-relevant switches default to the most restrictive value. See .env.example
for documentation of every variable.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent

try:  # python-dotenv is optional; environment variables work without it
    from dotenv import load_dotenv

    load_dotenv(PROJECT_ROOT / ".env", override=False)
except ImportError:  # pragma: no cover
    pass


def _bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _int(name: str, default: int, minimum: int, maximum: int) -> int:
    raw = os.getenv(name)
    try:
        value = int(raw) if raw not in (None, "") else default
    except ValueError:
        value = default
    return max(minimum, min(maximum, value))


def _list(name: str) -> tuple[str, ...]:
    raw = os.getenv(name, "")
    return tuple(item.strip().lower() for item in raw.split(",") if item.strip())


def _path(name: str, default: Path) -> Path:
    raw = os.getenv(name)
    path = Path(raw) if raw else default
    return path if path.is_absolute() else (PROJECT_ROOT / path)


@dataclass(frozen=True)
class Settings:
    db_path: Path
    reports_dir: Path
    # Target authorization policy
    allowed_targets: tuple[str, ...] = ()
    allow_private_networks: bool = False
    allow_active_scan: bool = False
    verify_tls: bool = True
    # Limits
    default_tool_timeout: int = 300
    max_tool_timeout: int = 1800
    max_concurrent_scans: int = 1
    # External tools
    zap_api_url: str = "http://127.0.0.1:8080"
    zap_api_key: str = field(default="", repr=False)
    nmap_path: str = ""
    nikto_path: str = ""
    perl_path: str = ""
    nikto_perl_lib: str = ""
    # OWASP reference edition used for categorisation
    owasp_edition: str = "2021"


def load_settings() -> Settings:
    """Build a Settings object from the current environment."""
    return Settings(
        db_path=_path("IVA_DB_PATH", PROJECT_ROOT / "data" / "iva.db"),
        reports_dir=_path("IVA_REPORTS_DIR", PROJECT_ROOT / "reports"),
        allowed_targets=_list("IVA_ALLOWED_TARGETS"),
        allow_private_networks=_bool("IVA_ALLOW_PRIVATE_NETWORKS", False),
        allow_active_scan=_bool("IVA_ALLOW_ACTIVE_SCAN", False),
        verify_tls=_bool("IVA_VERIFY_TLS", True),
        default_tool_timeout=_int("IVA_TOOL_TIMEOUT", 300, 10, 1800),
        max_tool_timeout=_int("IVA_MAX_TOOL_TIMEOUT", 1800, 30, 7200),
        max_concurrent_scans=_int("IVA_MAX_CONCURRENT_SCANS", 1, 1, 4),
        zap_api_url=os.getenv("ZAP_API_URL", "http://127.0.0.1:8080").rstrip("/"),
        zap_api_key=os.getenv("ZAP_API_KEY", ""),
        nmap_path=os.getenv("NMAP_PATH", ""),
        nikto_path=os.getenv("NIKTO_PATH", ""),
        perl_path=os.getenv("PERL_PATH", ""),
        nikto_perl_lib=os.getenv("NIKTO_PERL_LIB", ""),
        owasp_edition=os.getenv("OWASP_EDITION", "2021").strip() or "2021",
    )
