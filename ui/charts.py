"""Plotly figures for the dashboard: single-axis charts with direct labels, styled for the
dark theme. Colour carries meaning only together with a text label."""
from __future__ import annotations

from collections import Counter

import plotly.graph_objects as go

from modules.models import PRIORITY_LEVELS, SCANNER_SEVERITIES
from ui.common import PRIORITY_COLORS, SEVERITY_COLORS, TOOL_LABELS

_CYAN = "#22d3ee"
_INK = "#c8d3e6"
_MUTED = "#94a3b8"
_GRID = "rgba(148,163,184,0.16)"


def _layout(fig: go.Figure, height: int) -> go.Figure:
    fig.update_layout(
        height=height, margin=dict(l=8, r=28, t=8, b=8), showlegend=False,
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", bargap=0.35,
        font=dict(color=_INK, size=12), hoverlabel=dict(font_size=12, bgcolor="#121a30"),
    )
    fig.update_xaxes(showgrid=True, gridcolor=_GRID, zeroline=False, rangemode="tozero", color=_MUTED)
    fig.update_yaxes(showgrid=False, autorange="reversed", color=_INK)
    return fig


def _hbar(labels: list[str], values: list[int], colors: list[str] | str, hover_name: str) -> go.Figure:
    return go.Figure(go.Bar(
        x=values, y=labels, orientation="h", marker=dict(color=colors, cornerradius=4),
        text=values, textposition="outside", cliponaxis=False, textfont=dict(color=_INK),
        hovertemplate=f"%{{y}}<br>{hover_name}: %{{x}}<extra></extra>",
    ))


def priority_chart(findings: list[dict]) -> go.Figure:
    counts = Counter(f["priority"] for f in findings)
    return _layout(_hbar(list(PRIORITY_LEVELS), [counts.get(p, 0) for p in PRIORITY_LEVELS],
                         [PRIORITY_COLORS[p] for p in PRIORITY_LEVELS], "Findings"), 240)


def severity_chart(findings: list[dict]) -> go.Figure:
    counts = Counter(f["scanner_severity"] for f in findings)
    levels = [s for s in SCANNER_SEVERITIES if counts.get(s) or s != "unrated"]
    return _layout(_hbar(levels, [counts.get(s, 0) for s in levels], [SEVERITY_COLORS[s] for s in levels],
                         "Findings"), 240)


def owasp_chart(findings: list[dict]) -> go.Figure:
    counts = Counter(f"{f['owasp_id']} {f['owasp_name']}" if f["owasp_id"] else "Unmapped" for f in findings)
    labels = sorted(counts, key=lambda k: (k == "Unmapped", k))
    return _layout(_hbar(labels, [counts[k] for k in labels], _CYAN, "Findings"), max(180, 34 * len(labels) + 30))


def tool_agreement_chart(findings: list[dict]) -> go.Figure:
    """How many findings were confirmed by 1, 2, 3 … independent tools (cross-tool correlation)."""
    counts = Counter(len(f["sources"]) for f in findings)
    labels = [f"{n} tool{'s' if n > 1 else ''}" for n in sorted(counts)]
    return _layout(_hbar(labels, [counts[n] for n in sorted(counts)], "#a78bfa", "Findings"),
                   max(150, 44 * len(labels) + 30))


def tool_chart(findings: list[dict]) -> go.Figure:
    counts = Counter(s.split(" ")[0] for f in findings for s in f["sources"])
    labels = sorted(counts, key=lambda t: -counts[t])
    return _layout(_hbar([TOOL_LABELS.get(t, t) for t in labels], [counts[t] for t in labels], _CYAN,
                         "Findings reported"), max(150, 40 * len(labels) + 30))


def risk_gauge(score: float, label: str) -> go.Figure:
    steps = [(0, 15, "rgba(137,135,129,.35)"), (15, 35, "rgba(134,182,239,.35)"), (35, 60, "rgba(250,178,25,.35)"),
             (60, 80, "rgba(236,131,90,.40)"), (80, 100, "rgba(208,59,59,.45)")]
    fig = go.Figure(go.Indicator(
        mode="gauge+number", value=round(score, 1), number=dict(suffix=" / 100", font=dict(size=30, color=_INK)),
        title=dict(text=label, font=dict(size=13, color=_MUTED)),
        gauge=dict(axis=dict(range=[0, 100], tickcolor=_MUTED, tickfont=dict(color=_MUTED)),
                   bar=dict(color="#e6edf7", thickness=0.22), bgcolor="rgba(0,0,0,0)", borderwidth=0,
                   steps=[dict(range=[a, b], color=c) for a, b, c in steps]),
    ))
    fig.update_layout(height=250, margin=dict(l=34, r=40, t=40, b=10), paper_bgcolor="rgba(0,0,0,0)",
                      font=dict(color=_INK))
    return fig


def trend_chart(scans: list[dict]) -> go.Figure:
    """Findings per finished scan over time (oldest -> newest)."""
    ordered = sorted(scans, key=lambda s: s["created_at"])
    fig = go.Figure(go.Scatter(
        x=[s["created_at"].replace("T", " ").rstrip("Z") for s in ordered], y=[s["findings_count"] for s in ordered],
        mode="lines+markers", line=dict(color=_CYAN, width=2), marker=dict(size=9, color=_CYAN,
                                                                           line=dict(color="#0a0f1e", width=2)),
        hovertemplate="%{x}<br>Findings: %{y}<extra></extra>",
    ))
    fig.update_layout(height=230, margin=dict(l=8, r=16, t=8, b=8), showlegend=False,
                      paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font=dict(color=_INK))
    fig.update_xaxes(showgrid=False, color=_MUTED)
    fig.update_yaxes(showgrid=True, gridcolor=_GRID, rangemode="tozero", color=_MUTED, title="Findings")
    return fig
