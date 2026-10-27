"""Global look & feel: a dark security-operations theme injected as CSS, plus small HTML
components (hero banner, KPI cards, pills, step indicator, OWASP heat-grid).

Every dynamic value passed into these HTML snippets is escaped with html.escape —
scanner output never reaches the page as markup.
"""
from __future__ import annotations

import html

import streamlit as st

PRIORITY_CLASS = {"Critical": "crit", "High": "high", "Medium": "med", "Low": "low", "Informational": "info"}

_CSS = """
<style>
:root {
  --iva-bg: #0a0f1e; --iva-panel: #121a30; --iva-panel-2: #18223d; --iva-line: rgba(148,163,184,.16);
  --iva-text: #e6edf7; --iva-muted: #94a3b8; --iva-cyan: #22d3ee; --iva-violet: #a78bfa;
  --iva-crit: #d03b3b; --iva-high: #ec835a; --iva-med: #fab219; --iva-low: #86b6ef; --iva-info: #898781;
}
.stApp {
  background:
    radial-gradient(1200px 500px at 85% -10%, rgba(167,139,250,.14), transparent 60%),
    radial-gradient(900px 400px at -10% 10%, rgba(34,211,238,.10), transparent 60%),
    var(--iva-bg);
}
.block-container { padding-top: 2.2rem; max-width: 1350px; }
section[data-testid="stSidebar"] {
  background: linear-gradient(180deg, #0d1528 0%, #0a0f1e 100%);
  border-right: 1px solid var(--iva-line);
}
h1, h2, h3 { letter-spacing: -.01em; }
h2, h3 { color: var(--iva-text); }
div[data-testid="stVerticalBlockBorderWrapper"] { border-color: var(--iva-line) !important; border-radius: 14px; }
div[data-testid="stMetric"] {
  background: linear-gradient(160deg, var(--iva-panel-2), var(--iva-panel));
  border: 1px solid var(--iva-line); border-radius: 14px; padding: 14px 16px;
}
.stButton > button, .stDownloadButton > button { border-radius: 10px; font-weight: 600; }
.stButton > button[kind="primary"], .stFormSubmitButton > button[kind="primary"] {
  background: linear-gradient(90deg, #06b6d4, #8b5cf6); border: 0; color: #fff;
  box-shadow: 0 6px 24px rgba(34,211,238,.25);
}

/* hero */
.iva-hero {
  position: relative; overflow: hidden; border-radius: 18px; padding: 26px 30px; margin-bottom: 18px;
  background: linear-gradient(120deg, rgba(6,182,212,.22), rgba(139,92,246,.22) 60%, rgba(10,15,30,.4));
  border: 1px solid rgba(34,211,238,.25);
}
.iva-hero::after {
  content: ""; position: absolute; inset: 0; pointer-events: none;
  background-image: linear-gradient(rgba(255,255,255,.035) 1px, transparent 1px),
                    linear-gradient(90deg, rgba(255,255,255,.035) 1px, transparent 1px);
  background-size: 28px 28px;
}
.iva-hero h1 { margin: 0; font-size: 2.05rem; line-height: 1.15;
  background: linear-gradient(90deg, #e6edf7, #a5f3fc 45%, #c4b5fd); -webkit-background-clip: text;
  background-clip: text; color: transparent; }
.iva-hero p { margin: 6px 0 0; color: var(--iva-muted); font-size: .98rem; }
.iva-chips { margin-top: 12px; display: flex; gap: 8px; flex-wrap: wrap; }
.iva-chip { font-size: .78rem; padding: 3px 10px; border-radius: 999px; background: rgba(15,23,42,.6);
  border: 1px solid var(--iva-line); color: var(--iva-text); }
.iva-live { display: inline-flex; align-items: center; gap: 7px; }
.iva-dot { width: 8px; height: 8px; border-radius: 50%; background: #34d399;
  box-shadow: 0 0 0 0 rgba(52,211,153,.7); animation: iva-pulse 1.8s infinite; }
@keyframes iva-pulse { 0% { box-shadow: 0 0 0 0 rgba(52,211,153,.7); }
  70% { box-shadow: 0 0 0 9px rgba(52,211,153,0); } 100% { box-shadow: 0 0 0 0 rgba(52,211,153,0); } }

/* KPI cards */
.iva-kpis { display: grid; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr)); gap: 12px; margin: 4px 0 18px; }
.iva-kpi { position: relative; border-radius: 14px; padding: 14px 16px 12px; overflow: hidden;
  background: linear-gradient(160deg, var(--iva-panel-2), var(--iva-panel)); border: 1px solid var(--iva-line); }
.iva-kpi::before { content: ""; position: absolute; left: 0; top: 0; bottom: 0; width: 4px; background: var(--accent, var(--iva-cyan)); }
.iva-kpi .lbl { color: var(--iva-muted); font-size: .78rem; text-transform: uppercase; letter-spacing: .06em; }
.iva-kpi .val { font-size: 1.9rem; font-weight: 700; color: var(--iva-text); line-height: 1.2; margin-top: 2px; }
.iva-kpi .sub { color: var(--iva-muted); font-size: .8rem; }

/* pills */
.iva-pill { display: inline-block; padding: 2px 10px; border-radius: 999px; font-size: .78rem; font-weight: 700;
  color: #0b0b0b; }
.iva-pill.crit { background: var(--iva-crit); color: #fff; } .iva-pill.high { background: var(--iva-high); }
.iva-pill.med { background: var(--iva-med); } .iva-pill.low { background: var(--iva-low); }
.iva-pill.info { background: var(--iva-info); color: #fff; }

/* section title */
.iva-section { display: flex; align-items: center; gap: 10px; margin: 22px 0 8px; }
.iva-section .bar { width: 4px; height: 20px; border-radius: 4px; background: linear-gradient(var(--iva-cyan), var(--iva-violet)); }
.iva-section .t { font-size: 1.15rem; font-weight: 700; color: var(--iva-text); }
.iva-section .s { color: var(--iva-muted); font-size: .85rem; }

/* steps */
.iva-steps { display: flex; gap: 8px; margin: 6px 0 16px; flex-wrap: wrap; }
.iva-step { flex: 1; min-width: 140px; padding: 10px 12px; border-radius: 12px; border: 1px solid var(--iva-line);
  background: var(--iva-panel); color: var(--iva-muted); font-size: .85rem; }
.iva-step b { display: block; color: var(--iva-text); font-size: .92rem; }
.iva-step.on { border-color: rgba(34,211,238,.6); background: linear-gradient(160deg, rgba(34,211,238,.16), var(--iva-panel)); }
.iva-step.done { border-color: rgba(52,211,153,.5); }

/* OWASP heat grid */
.iva-grid { display: grid; grid-template-columns: repeat(5, 1fr); gap: 10px; }
@media (max-width: 900px) { .iva-grid { grid-template-columns: repeat(2, 1fr); } }
.iva-tile { border-radius: 12px; padding: 12px; border: 1px solid var(--iva-line); min-height: 92px;
  background: rgba(34,211,238, var(--a, .04)); }
.iva-tile .id { font-weight: 800; color: var(--iva-text); font-size: .95rem; }
.iva-tile .nm { color: var(--iva-muted); font-size: .76rem; line-height: 1.25; margin-top: 2px; }
.iva-tile .n { font-size: 1.5rem; font-weight: 800; color: var(--iva-text); margin-top: 4px; }
.iva-tile.zero .n { color: var(--iva-muted); }

/* finding header */
.iva-fhead { border-radius: 14px; padding: 16px 18px; margin-bottom: 10px; border: 1px solid var(--iva-line);
  background: linear-gradient(120deg, color-mix(in srgb, var(--c) 22%, transparent), var(--iva-panel) 70%); }
.iva-fhead .ti { font-size: 1.25rem; font-weight: 700; color: var(--iva-text); margin-top: 6px; }
.iva-fhead .me { color: var(--iva-muted); font-size: .85rem; margin-top: 4px; }

/* radar while scanning */
.iva-radar { width: 92px; height: 92px; border-radius: 50%; position: relative; margin: 4px auto;
  border: 1px solid rgba(34,211,238,.45);
  background: radial-gradient(circle, rgba(34,211,238,.12) 0 30%, transparent 31%),
              radial-gradient(circle, transparent 0 60%, rgba(34,211,238,.10) 61% 62%, transparent 63%); }
.iva-radar::after { content: ""; position: absolute; inset: 0; border-radius: 50%;
  background: conic-gradient(from 0deg, rgba(34,211,238,.55), transparent 25%); animation: iva-spin 2.2s linear infinite; }
@keyframes iva-spin { to { transform: rotate(360deg); } }
.iva-brand { font-weight: 800; font-size: 1.25rem;
  background: linear-gradient(90deg, #22d3ee, #a78bfa); -webkit-background-clip: text; background-clip: text; color: transparent; }
</style>
"""


def inject_css() -> None:
    st.markdown(_CSS, unsafe_allow_html=True)


def _e(value: object) -> str:
    return html.escape(str(value))


def hero(title: str, subtitle: str, chips: list[str] | None = None, live: bool = False) -> None:
    chip_html = "".join(f'<span class="iva-chip">{_e(c)}</span>' for c in chips or [])
    if live:
        chip_html = '<span class="iva-chip iva-live"><span class="iva-dot"></span>Live data</span>' + chip_html
    st.markdown(f'<div class="iva-hero"><h1>{_e(title)}</h1><p>{_e(subtitle)}</p>'
                f'<div class="iva-chips">{chip_html}</div></div>', unsafe_allow_html=True)


def kpis(cards: list[tuple[str, object, str, str]]) -> None:
    """cards: (label, value, sub-text, accent CSS colour)."""
    body = "".join(f'<div class="iva-kpi" style="--accent:{_e(accent)}"><div class="lbl">{_e(label)}</div>'
                   f'<div class="val">{_e(value)}</div><div class="sub">{_e(sub)}</div></div>'
                   for label, value, sub, accent in cards)
    st.markdown(f'<div class="iva-kpis">{body}</div>', unsafe_allow_html=True)


def section(title: str, subtitle: str = "") -> None:
    sub = f'<span class="s">{_e(subtitle)}</span>' if subtitle else ""
    st.markdown(f'<div class="iva-section"><span class="bar"></span><span class="t">{_e(title)}</span>{sub}</div>',
                unsafe_allow_html=True)


def pill(priority: str) -> str:
    return f'<span class="iva-pill {PRIORITY_CLASS.get(priority, "info")}">{_e(priority)}</span>'


def steps(labels: list[tuple[str, str]], current: int) -> None:
    items = []
    for i, (name, hint) in enumerate(labels):
        cls = "on" if i == current else ("done" if i < current else "")
        mark = "✓ " if i < current else f"{i + 1}. "
        items.append(f'<div class="iva-step {cls}"><b>{mark}{_e(name)}</b>{_e(hint)}</div>')
    st.markdown(f'<div class="iva-steps">{"".join(items)}</div>', unsafe_allow_html=True)


def owasp_grid(counts: dict[str, int], names: dict[str, str]) -> None:
    peak = max(counts.values(), default=0) or 1
    tiles = []
    for cat_id, name in names.items():
        n = counts.get(cat_id, 0)
        alpha = 0.04 + 0.42 * (n / peak) if n else 0.03
        tiles.append(f'<div class="iva-tile {"zero" if not n else ""}" style="--a:{alpha:.2f}">'
                     f'<div class="id">{_e(cat_id)}</div><div class="nm">{_e(name)}</div>'
                     f'<div class="n">{n}</div></div>')
    st.markdown(f'<div class="iva-grid">{"".join(tiles)}</div>', unsafe_allow_html=True)


def finding_header(title: str, priority: str, color: str, meta: str) -> None:
    st.markdown(f'<div class="iva-fhead" style="--c:{_e(color)}">{pill(priority)}'
                f'<div class="ti">{_e(title)}</div><div class="me">{_e(meta)}</div></div>', unsafe_allow_html=True)


def radar(caption: str) -> None:
    st.markdown(f'<div class="iva-radar"></div><div style="text-align:center;color:#94a3b8;font-size:.85rem">'
                f'{_e(caption)}</div>', unsafe_allow_html=True)
