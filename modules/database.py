"""SQLite persistence: scans, tool runs and findings.

Every query is parameterised. Connections are short-lived (one per operation) so
the background scan thread and the Streamlit UI never share a connection.
"""
from __future__ import annotations

import json
import sqlite3
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from modules.models import Finding, ScanConfig, ToolResult, utc_now

SCHEMA_VERSION = 2
# Forward-only migrations for databases created by an older version: version -> statements
MIGRATIONS = {
    2: ["ALTER TABLE findings ADD COLUMN locations_json TEXT NOT NULL DEFAULT '[]'"],
}

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id            TEXT PRIMARY KEY,
    target_url    TEXT NOT NULL,
    target_host   TEXT NOT NULL,
    policy_reason TEXT NOT NULL DEFAULT '',
    mode          TEXT NOT NULL CHECK (mode IN ('live', 'demo')),
    status        TEXT NOT NULL CHECK (status IN ('queued','running','completed','partial','failed','cancelled')),
    config_json   TEXT NOT NULL,
    owasp_edition TEXT NOT NULL,
    created_at    TEXT NOT NULL,
    started_at    TEXT,
    finished_at   TEXT,
    progress      TEXT NOT NULL DEFAULT '',
    error         TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_scans_created ON scans(created_at);
CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target_url);

CREATE TABLE IF NOT EXISTS tool_runs (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id        TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    tool           TEXT NOT NULL,
    status         TEXT NOT NULL,
    started_at     TEXT,
    finished_at    TEXT,
    exit_code      INTEGER,
    findings_count INTEGER NOT NULL DEFAULT 0,
    message        TEXT NOT NULL DEFAULT '',
    command        TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_tool_runs_scan ON tool_runs(scan_id);

CREATE TABLE IF NOT EXISTS findings (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id          TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    fingerprint      TEXT NOT NULL,
    title            TEXT NOT NULL,
    description      TEXT NOT NULL DEFAULT '',
    affected_url     TEXT NOT NULL DEFAULT '',
    asset            TEXT NOT NULL DEFAULT '',
    parameter        TEXT NOT NULL DEFAULT '',
    source_tool      TEXT NOT NULL,
    sources_json     TEXT NOT NULL DEFAULT '[]',
    locations_json   TEXT NOT NULL DEFAULT '[]',
    rule_id          TEXT NOT NULL DEFAULT '',
    issue_key        TEXT NOT NULL DEFAULT '',
    evidence         TEXT NOT NULL DEFAULT '',
    scanner_severity TEXT NOT NULL,
    confidence       TEXT NOT NULL,
    cwe_id           INTEGER,
    cvss_score       REAL,
    tags_json        TEXT NOT NULL DEFAULT '[]',
    owasp_id         TEXT NOT NULL DEFAULT '',
    owasp_name       TEXT NOT NULL DEFAULT '',
    owasp_status     TEXT NOT NULL DEFAULT 'unmapped',
    owasp_basis      TEXT NOT NULL DEFAULT '',
    risk_score       REAL NOT NULL DEFAULT 0,
    priority         TEXT NOT NULL,
    rationale_json   TEXT NOT NULL DEFAULT '[]',
    remediation      TEXT NOT NULL DEFAULT '',
    references_json  TEXT NOT NULL DEFAULT '[]',
    exploit_evidence INTEGER NOT NULL DEFAULT 0,
    occurrences      INTEGER NOT NULL DEFAULT 1,
    detected_at      TEXT NOT NULL,
    UNIQUE (scan_id, fingerprint)
);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_priority ON findings(priority);
CREATE INDEX IF NOT EXISTS idx_findings_owasp ON findings(owasp_id);
"""

ACTIVE_STATUSES = ("queued", "running")


class Database:
    def __init__(self, path: Path | str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.initialize()

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.path, timeout=15)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        try:
            with conn:  # commits on success, rolls back on exception
                yield conn
        finally:
            conn.close()

    def initialize(self) -> None:
        """Create tables if missing. Safe to run repeatedly; never drops data."""
        with self.connect() as conn:
            conn.execute("PRAGMA journal_mode = WAL")
            current = conn.execute("PRAGMA user_version").fetchone()[0]
            existing = conn.execute("SELECT name FROM sqlite_master WHERE name = 'findings'").fetchone()
            if existing and current < SCHEMA_VERSION:
                for version in range(current + 1, SCHEMA_VERSION + 1):
                    for statement in MIGRATIONS.get(version, []):
                        conn.execute(statement)
            conn.executescript(SCHEMA)
            conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")

    # ----- scans -----------------------------------------------------------------
    def create_scan(self, target_url: str, target_host: str, config: ScanConfig, mode: str,
                    owasp_edition: str, policy_reason: str = "") -> str:
        scan_id = uuid.uuid4().hex
        with self.connect() as conn:
            conn.execute(
                "INSERT INTO scans (id, target_url, target_host, policy_reason, mode, status, config_json,"
                " owasp_edition, created_at) VALUES (?, ?, ?, ?, ?, 'queued', ?, ?, ?)",
                (scan_id, target_url, target_host, policy_reason, mode, json.dumps(config.to_dict()),
                 owasp_edition, utc_now()),
            )
        return scan_id

    def update_scan(self, scan_id: str, **fields: object) -> None:
        allowed = {"status", "started_at", "finished_at", "progress", "error"}
        cols = [k for k in fields if k in allowed]
        if not cols:
            return
        assignments = ", ".join(f"{col} = ?" for col in cols)  # column names from the allow-list only
        with self.connect() as conn:
            conn.execute(f"UPDATE scans SET {assignments} WHERE id = ?",
                         [fields[c] for c in cols] + [scan_id])

    def get_scan(self, scan_id: str) -> dict | None:
        with self.connect() as conn:
            row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        return _scan_row(row) if row else None

    def list_scans(self, mode: str | None = None, limit: int = 500) -> list[dict]:
        query = (
            "SELECT s.*, COUNT(f.id) AS findings_count,"
            " SUM(f.priority = 'Critical') AS n_critical, SUM(f.priority = 'High') AS n_high,"
            " SUM(f.priority = 'Medium') AS n_medium, SUM(f.priority = 'Low') AS n_low,"
            " SUM(f.priority = 'Informational') AS n_info, MAX(f.risk_score) AS max_risk"
            " FROM scans s LEFT JOIN findings f ON f.scan_id = s.id"
        )
        params: list[object] = []
        if mode:
            query += " WHERE s.mode = ?"
            params.append(mode)
        query += " GROUP BY s.id ORDER BY s.created_at DESC LIMIT ?"
        params.append(int(limit))
        with self.connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [_scan_row(r) for r in rows]

    def delete_scan(self, scan_id: str) -> bool:
        with self.connect() as conn:
            cur = conn.execute("DELETE FROM scans WHERE id = ? AND status NOT IN ('queued','running')",
                               (scan_id,))
        return cur.rowcount > 0

    def mark_interrupted_scans(self) -> int:
        """Scans left queued/running by a previous process can never finish; mark them failed."""
        with self.connect() as conn:
            cur = conn.execute(
                "UPDATE scans SET status = 'failed', finished_at = ?, "
                "error = 'Interrupted: the application stopped before the scan finished.' "
                "WHERE status IN ('queued', 'running')",
                (utc_now(),),
            )
        return cur.rowcount

    # ----- tool runs -------------------------------------------------------------
    def add_tool_run(self, scan_id: str, result: ToolResult) -> None:
        with self.connect() as conn:
            conn.execute(
                "INSERT INTO tool_runs (scan_id, tool, status, started_at, finished_at, exit_code,"
                " findings_count, message, command) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (scan_id, result.tool, result.status, result.started_at, result.finished_at or utc_now(),
                 result.exit_code, len(result.findings), result.message[:4000], result.command[:1000]),
            )

    def get_tool_runs(self, scan_id: str) -> list[dict]:
        with self.connect() as conn:
            rows = conn.execute("SELECT * FROM tool_runs WHERE scan_id = ? ORDER BY id", (scan_id,)).fetchall()
        return [dict(r) for r in rows]

    # ----- findings --------------------------------------------------------------
    def save_findings(self, scan_id: str, findings: list[Finding]) -> None:
        rows = [
            (scan_id, f.fingerprint, f.title, f.description, f.affected_url, f.asset, f.parameter,
             f.source_tool, json.dumps(f.sources), json.dumps(f.locations), f.rule_id, f.issue_key, f.evidence,
             f.scanner_severity, f.confidence, f.cwe_id, f.cvss_score, json.dumps(f.scanner_tags),
             f.owasp_id, f.owasp_name, f.owasp_status, f.owasp_basis, f.risk_score, f.priority,
             json.dumps(f.rationale), f.remediation, json.dumps(f.references), int(f.exploit_evidence),
             f.occurrences, f.detected_at)
            for f in findings
        ]
        with self.connect() as conn:
            conn.executemany(
                "INSERT OR REPLACE INTO findings (scan_id, fingerprint, title, description, affected_url,"
                " asset, parameter, source_tool, sources_json, locations_json, rule_id, issue_key, evidence,"
                " scanner_severity, confidence, cwe_id, cvss_score, tags_json, owasp_id, owasp_name,"
                " owasp_status, owasp_basis, risk_score, priority, rationale_json, remediation,"
                " references_json, exploit_evidence, occurrences, detected_at)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                rows,
            )

    def get_findings(self, scan_id: str) -> list[dict]:
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT * FROM findings WHERE scan_id = ? ORDER BY CASE priority"
                " WHEN 'Critical' THEN 0 WHEN 'High' THEN 1 WHEN 'Medium' THEN 2 WHEN 'Low' THEN 3"
                " ELSE 4 END, risk_score DESC, title",
                (scan_id,),
            ).fetchall()
        return [_finding_row(r) for r in rows]

    def get_all_findings(self, mode: str | None = None) -> list[dict]:
        query = ("SELECT f.*, s.target_url, s.mode, s.created_at AS scan_created_at"
                 " FROM findings f JOIN scans s ON s.id = f.scan_id")
        params: tuple = ()
        if mode:
            query += " WHERE s.mode = ?"
            params = (mode,)
        with self.connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [_finding_row(r) for r in rows]


def _scan_row(row: sqlite3.Row) -> dict:
    data = dict(row)
    data["config"] = json.loads(data.pop("config_json") or "{}")
    for key in ("findings_count", "n_critical", "n_high", "n_medium", "n_low", "n_info"):
        if key in data:
            data[key] = int(data[key] or 0)
    return data


def _finding_row(row: sqlite3.Row) -> dict:
    data = dict(row)
    for key, new in (("sources_json", "sources"), ("locations_json", "locations"), ("tags_json", "tags"),
                     ("rationale_json", "rationale"), ("references_json", "references")):
        data[new] = json.loads(data.pop(key) or "[]")
    data["exploit_evidence"] = bool(data["exploit_evidence"])
    return data
