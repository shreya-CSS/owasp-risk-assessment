"""PDF and CSV report generation from persisted scan data.

Scanner output is untrusted: PDF text is reduced to the core-font character set and
CSV cells that start with formula characters are neutralised (CSV injection).
"""
from __future__ import annotations

import csv
import io
import re
import unicodedata
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from fpdf import FPDF

from modules.models import PRIORITY_LEVELS

PRIORITY_COLORS = {
    "Critical": (208, 59, 59), "High": (236, 131, 90), "Medium": (250, 178, 25),
    "Low": (134, 182, 239), "Informational": (137, 135, 129),
}
CSV_COLUMNS = (
    "priority", "risk_score", "scanner_severity", "confidence", "title", "owasp_id", "owasp_name",
    "owasp_status", "affected_url", "locations", "asset", "parameter", "sources", "occurrences", "cwe_id", "evidence",
    "remediation", "detected_at",
)
STANDARD_LIMITATIONS = [
    "Automated tools cannot find every vulnerability; business-logic and authorization flaws usually need manual testing.",
    "Findings are reported by tools and have not been manually verified unless stated; false positives are possible.",
    "OWASP categories marked 'potential' are keyword-based suggestions and need analyst confirmation.",
    "The risk priority is a documented heuristic using declared asset context; it is not a CVSS score.",
    "Results reflect the target's state at scan time only.",
]
_SCAN_ID = re.compile(r"^[0-9a-f]{32}$")
_REPLACEMENTS = {"—": "-", "–": "-", "‘": "'", "’": "'", "“": '"', "”": '"',
                 "…": "...", "→": "->", "•": "*", " ": " "}


def pdf_text(value: object, max_len: int = 3000) -> str:
    text = str(value or "")
    for src, dst in _REPLACEMENTS.items():
        text = text.replace(src, dst)
    text = unicodedata.normalize("NFKD", text).encode("latin-1", "replace").decode("latin-1")
    text = "".join(ch if ch in "\n\t" or 32 <= ord(ch) < 127 or 160 <= ord(ch) <= 255 else "?" for ch in text)
    # break very long unbroken tokens (URLs, base64) so the PDF line breaker can wrap them
    text = re.sub(r"(\S{80})(?=\S)", r"\1 ", text)
    return text[:max_len]


def csv_safe(value: object) -> str:
    text = "" if value is None else str(value)
    return "'" + text if text[:1] in ("=", "+", "-", "@", "\t", "\r") else text


def generate_csv(findings: list[dict]) -> bytes:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(CSV_COLUMNS)
    for f in findings:
        row = dict(f)
        row["sources"] = "; ".join(f.get("sources", []))
        row["locations"] = "; ".join(f.get("locations", []))
        writer.writerow([csv_safe(row.get(col, "")) for col in CSV_COLUMNS])
    return buf.getvalue().encode("utf-8-sig")  # BOM so Excel opens UTF-8 correctly


def _locations_text(f: dict, limit: int = 8) -> str:
    locs = f.get("locations") or [f["affected_url"] or f["asset"] or "-"]
    more = f" (+{len(locs) - limit} more)" if len(locs) > limit else ""
    return ", ".join(locs[:limit]) + more


def summarize(findings: list[dict]) -> dict:
    prio = Counter(f["priority"] for f in findings)
    sev = Counter(f["scanner_severity"] for f in findings)
    owasp = Counter((f["owasp_id"] or "Unmapped") for f in findings)
    return {
        "total": len(findings),
        "by_priority": {p: prio.get(p, 0) for p in PRIORITY_LEVELS},
        "by_severity": dict(sev),
        "by_owasp": dict(sorted(owasp.items())),
        "max_risk": max((f["risk_score"] for f in findings), default=0.0),
    }


def executive_summary(scan: dict, findings: list[dict], tool_runs: list[dict]) -> str:
    s = summarize(findings)
    ok = [r["tool"] for r in tool_runs if r["status"] == "completed"]
    not_ok = [f"{r['tool']} ({r['status']})" for r in tool_runs if r["status"] != "completed"]
    if scan["status"] == "failed":
        return ("The assessment did not complete: no assessment method ran successfully, so no conclusion about the "
                "target's security can be drawn. See 'Assessment limitations' for the reasons.")
    parts = [f"The assessment of {scan['target_url']} finished with status '{scan['status']}'."]
    if s["total"] == 0:
        parts.append("The methods that ran reported no findings. This does not prove the absence of vulnerabilities.")
    else:
        counts = ", ".join(f"{n} {p}" for p, n in s["by_priority"].items() if n)
        parts.append(f"{s['total']} distinct finding(s) were recorded ({counts}); highest risk score {s['max_risk']:.1f}/100.")
        urgent = s["by_priority"]["Critical"] + s["by_priority"]["High"]
        if urgent:
            parts.append(f"{urgent} finding(s) are Critical/High priority and should be remediated first.")
    parts.append(f"Methods completed: {', '.join(ok) or 'none'}.")
    if not_ok:
        parts.append(f"Not completed: {', '.join(not_ok)}; coverage is therefore partial.")
    return " ".join(parts)


class _ReportPDF(FPDF):
    def __init__(self, demo: bool):
        super().__init__(format="A4")
        self.demo = demo
        self.set_auto_page_break(True, margin=18)
        self.set_margins(16, 16, 16)

    def header(self) -> None:
        self.set_font("Helvetica", "", 8)
        self.set_text_color(110, 110, 110)
        label = "Web Vulnerability Assessment Report"
        if self.demo:
            label += "  |  DEMO DATA - NOT REAL SCANNER OUTPUT"
        self.cell(0, 5, label, new_x="LMARGIN", new_y="NEXT")
        self.ln(2)
        self.set_text_color(0, 0, 0)

    def footer(self) -> None:
        self.set_y(-12)
        self.set_font("Helvetica", "", 8)
        self.set_text_color(110, 110, 110)
        self.cell(0, 5, f"Page {self.page_no()}/{{nb}}  -  Confidential: authorized assessment only", align="C")


def _h1(pdf: FPDF, text: str) -> None:
    pdf.ln(3)
    pdf.set_font("Helvetica", "B", 14)
    pdf.cell(0, 8, pdf_text(text), new_x="LMARGIN", new_y="NEXT")
    pdf.set_draw_color(200, 200, 200)
    pdf.line(pdf.l_margin, pdf.get_y(), pdf.w - pdf.r_margin, pdf.get_y())
    pdf.ln(2)


def _para(pdf: FPDF, text: str, size: int = 10, style: str = "") -> None:
    pdf.set_font("Helvetica", style, size)
    pdf.multi_cell(0, 5, pdf_text(text), new_x="LMARGIN", new_y="NEXT")


def _kv(pdf: FPDF, rows: list[tuple[str, str]]) -> None:
    for key, value in rows:
        pdf.set_font("Helvetica", "B", 9)
        pdf.cell(45, 5.5, pdf_text(key))
        pdf.set_font("Helvetica", "", 9)
        pdf.multi_cell(0, 5.5, pdf_text(value), new_x="LMARGIN", new_y="NEXT")


def _bar_chart(pdf: FPDF, counts: dict[str, int]) -> None:
    total = max(counts.values(), default=0) or 1
    width = pdf.w - pdf.l_margin - pdf.r_margin - 50
    for level, n in counts.items():
        y = pdf.get_y()
        pdf.set_font("Helvetica", "", 9)
        pdf.cell(32, 6, level)
        pdf.set_fill_color(*PRIORITY_COLORS[level])
        bar = width * n / total
        if bar > 0:
            pdf.rect(pdf.l_margin + 32, y + 1, bar, 4, style="F")
        pdf.set_xy(pdf.l_margin + 34 + bar, y)
        pdf.cell(15, 6, str(n), new_x="LMARGIN", new_y="NEXT")


def _table(pdf: FPDF, headers: list[str], rows: list[list[str]], widths: list[float]) -> None:
    pdf.set_font("Helvetica", "B", 8)
    pdf.set_fill_color(235, 235, 232)
    for h, w in zip(headers, widths):
        pdf.cell(w, 6, h, border=1, fill=True)
    pdf.ln()
    pdf.set_font("Helvetica", "", 8)
    for row in rows:
        for value, w in zip(row, widths):
            text = pdf_text(value)
            while text and pdf.get_string_width(text) > w - 2:
                text = text[:-2]
            pdf.cell(w, 5.5, text, border=1)
        pdf.ln()


def generate_pdf(scan: dict, findings: list[dict], tool_runs: list[dict], owasp_title: str) -> bytes:
    demo = scan.get("mode") == "demo"
    pdf = _ReportPDF(demo)
    pdf.alias_nb_pages()
    pdf.add_page()
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    summary = summarize(findings)
    config = scan.get("config", {})

    # 1. Title
    pdf.set_font("Helvetica", "B", 20)
    pdf.multi_cell(0, 10, "Web Vulnerability Assessment Report", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 10)
    pdf.cell(0, 6, f"Generated: {generated}   |   Classification reference: {pdf_text(owasp_title)}",
             new_x="LMARGIN", new_y="NEXT")
    if demo:
        pdf.set_fill_color(250, 178, 25)
        pdf.set_font("Helvetica", "B", 10)
        pdf.multi_cell(0, 7, "DEMO REPORT: built from fixed sample data. No target was contacted and these are "
                             "NOT real scanner findings.", fill=True, new_x="LMARGIN", new_y="NEXT")

    # 2-3. Target, configuration, status, tools
    _h1(pdf, "1. Target and scan configuration")
    _kv(pdf, [
        ("Target", scan["target_url"]),
        ("Authorization basis", scan.get("policy_reason", "")),
        ("Scan ID", scan["id"]),
        ("Status", scan["status"]),
        ("Started / finished", f"{scan.get('started_at') or '-'}  /  {scan.get('finished_at') or '-'}"),
        ("Methods selected", ", ".join(config.get("tools", []))),
        ("Tool timeout", f"{config.get('tool_timeout', '-')} s"),
        ("Declared context", f"asset criticality '{config.get('asset_criticality', '-')}', "
                             f"exposure '{config.get('exposure', '-')}'"),
        ("ZAP active scan", "yes" if config.get("zap_active_scan") else "no (passive only)"),
    ])
    pdf.ln(2)
    _table(pdf, ["Tool", "Status", "Findings", "Message"],
           [[r["tool"], r["status"], str(r["findings_count"]), r["message"]] for r in tool_runs],
           [22, 24, 18, pdf.w - pdf.l_margin - pdf.r_margin - 64])

    # 4-5. Executive summary + distribution
    _h1(pdf, "2. Executive summary")
    _para(pdf, executive_summary(scan, findings, tool_runs))
    pdf.ln(2)
    _para(pdf, "Findings by calculated priority", 10, "B")
    _bar_chart(pdf, summary["by_priority"])
    pdf.ln(1)
    sev = summary["by_severity"]
    _para(pdf, "Scanner-reported severity (as given by the tools): " +
          (", ".join(f"{k}: {v}" for k, v in sorted(sev.items())) or "none"), 9)

    # 6. Findings by severity and OWASP category
    _h1(pdf, "3. Findings overview")
    _para(pdf, "OWASP category distribution", 10, "B")
    _table(pdf, ["OWASP category", "Findings"],
           [[k, str(v)] for k, v in summary["by_owasp"].items()] or [["(none)", "0"]], [120, 25])
    pdf.ln(2)
    _para(pdf, "Prioritised finding list", 10, "B")
    full = pdf.w - pdf.l_margin - pdf.r_margin
    _table(pdf, ["#", "Priority", "Score", "Title", "OWASP"],
           [[str(i), f["priority"], f"{f['risk_score']:.1f}", f["title"], f["owasp_id"] or "-"]
            for i, f in enumerate(findings, 1)] or [["-", "-", "-", "No findings", "-"]],
           [8, 24, 14, full - 72, 26])

    # 7-9. Details, rationale, remediation
    _h1(pdf, "4. Finding details")
    if not findings:
        _para(pdf, "No findings were recorded.")
    for i, f in enumerate(findings, 1):
        if pdf.get_y() > pdf.h - 60:
            pdf.add_page()
        pdf.set_fill_color(*PRIORITY_COLORS.get(f["priority"], (200, 200, 200)))
        pdf.set_font("Helvetica", "B", 11)
        pdf.multi_cell(0, 7, pdf_text(f"{i}. [{f['priority']}] {f['title']}"), fill=True,
                       new_x="LMARGIN", new_y="NEXT")
        mapping = f"{f['owasp_id']} {f['owasp_name']} ({f['owasp_status']})" if f["owasp_id"] else "Unmapped"
        _kv(pdf, [
            ("Risk score", f"{f['risk_score']:.1f}/100 (application-calculated)"),
            ("Scanner severity", f"{f['scanner_severity']} (confidence: {f['confidence']})"),
            ("OWASP category", mapping),
            ("Mapping basis", f["owasp_basis"]),
            ("Affected", _locations_text(f)),
            ("Parameter", f["parameter"] or "-"),
            ("Detected by", ", ".join(f["sources"]) + (f" ({f['occurrences']} raw alerts merged)" if f["occurrences"] > 1 else "")),
            ("CWE", f"CWE-{f['cwe_id']}" if f["cwe_id"] else "-"),
        ])
        if f["description"]:
            _para(pdf, "Description", 9, "B")
            _para(pdf, f["description"], 9)
        if f["evidence"]:
            _para(pdf, "Evidence (as reported by the tool)", 9, "B")
            pdf.set_font("Courier", "", 8)
            pdf.multi_cell(0, 4.5, pdf_text(f["evidence"], 1500), new_x="LMARGIN", new_y="NEXT")
        _para(pdf, "Priority rationale", 9, "B")
        for step in f["rationale"]:
            _para(pdf, f"- {step['factor']}: {step['effect']} - {step['detail']}", 8)
        _para(pdf, "Recommended remediation", 9, "B")
        _para(pdf, f["remediation"], 9)
        if f["references"]:
            _para(pdf, "References: " + "; ".join(f["references"][:5]), 8)
        pdf.ln(3)

    # 10. Limitations
    _h1(pdf, "5. Assessment limitations")
    failed = [r for r in tool_runs if r["status"] != "completed"]
    if failed:
        _para(pdf, "Checks that did not complete:", 10, "B")
        for r in failed:
            _para(pdf, f"- {r['tool']}: {r['status']} - {r['message']}", 9)
    if scan.get("error"):
        _para(pdf, f"Scan notes: {scan['error']}", 9)
    for item in STANDARD_LIMITATIONS:
        _para(pdf, f"- {item}", 9)
    if demo:
        _para(pdf, "- This report was generated from DEMO fixture data and does not describe any real system.", 9, "B")

    return bytes(pdf.output())


def safe_report_path(reports_dir: Path, scan_id: str, extension: str) -> Path:
    """Build a report path that is guaranteed to stay inside reports_dir."""
    if not _SCAN_ID.match(scan_id or ""):
        raise ValueError("Invalid scan id")
    if extension not in ("pdf", "csv"):
        raise ValueError("Unsupported report format")
    reports_dir = reports_dir.resolve()
    reports_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = (reports_dir / f"iva_report_{scan_id[:12]}_{stamp}.{extension}").resolve()
    if path.parent != reports_dir:
        raise ValueError("Report path escapes the reports directory")
    return path


def save_report(reports_dir: Path, scan_id: str, extension: str, content: bytes) -> Path:
    path = safe_report_path(reports_dir, scan_id, extension)
    path.write_bytes(content)
    return path
