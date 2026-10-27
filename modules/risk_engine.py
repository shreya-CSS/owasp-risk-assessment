"""Deterministic, explainable risk-priority engine.

score = clamp(0..100,
          base(scanner severity, or scanner-supplied CVSS x 10)
        x confidence multiplier
        + OWASP category impact weight (full if mapped, half if only a potential mapping)
        + exploit evidence bonus (scanner reports a successful attack payload)
        + declared asset criticality (high +10 / medium 0 / low -10)
        + declared exposure (internet +5 / internal 0 / lab -5)
        + spread bonus (same issue at 5 or more distinct locations: +5))

priority: >=80 Critical, >=60 High, >=35 Medium, >=15 Low, else Informational,
capped at one level above the scanner's own severity so context can raise urgency
but never turn a low-severity observation into a critical one.

Every factor that changes the score is recorded in Finding.rationale.
"""
from __future__ import annotations

from dataclasses import dataclass

from modules.models import PRIORITY_LEVELS, Finding, ScanConfig
from modules.owasp_mapper import OwaspMapper

SEVERITY_BASE = {"critical": 90, "high": 70, "medium": 45, "low": 20, "info": 5, "unrated": 20}
CONFIDENCE_MULTIPLIER = {"confirmed": 1.0, "high": 1.0, "medium": 0.85, "low": 0.6, "unknown": 0.8}
CRITICALITY_ADJUST = {"high": 10, "medium": 0, "low": -10}
EXPOSURE_ADJUST = {"internet": 5, "internal": 0, "lab": -5}
EXPLOIT_BONUS = 10
SPREAD_THRESHOLD = 5
SPREAD_BONUS = 5
PRIORITY_THRESHOLDS = ((80, "Critical"), (60, "High"), (35, "Medium"), (15, "Low"))
# Priority level that scanner severity alone implies (the "baseline" ranking).
SEVERITY_TO_PRIORITY = {
    "critical": "Critical", "high": "High", "medium": "Medium", "low": "Low",
    "info": "Informational", "unrated": "Low",
}


@dataclass(frozen=True)
class RiskContext:
    asset_criticality: str = "medium"
    exposure: str = "internal"

    @classmethod
    def from_config(cls, config: ScanConfig) -> "RiskContext":
        return cls(asset_criticality=config.asset_criticality, exposure=config.exposure)


def score_to_priority(score: float) -> str:
    for threshold, level in PRIORITY_THRESHOLDS:
        if score >= threshold:
            return level
    return "Informational"


def _level_index(level: str) -> int:
    return PRIORITY_LEVELS.index(level)  # 0 = Critical ... 4 = Informational


def score_finding(finding: Finding, mapper: OwaspMapper, context: RiskContext) -> Finding:
    rationale: list[dict] = []

    if finding.cvss_score is not None:
        base = float(finding.cvss_score) * 10
        rationale.append({"factor": "Base (scanner CVSS)", "effect": f"{base:.0f}",
                          "detail": f"Scanner-supplied CVSS {finding.cvss_score:.1f} x 10."})
    else:
        base = SEVERITY_BASE[finding.scanner_severity]
        detail = f"Scanner severity '{finding.scanner_severity}'."
        if finding.scanner_severity == "unrated":
            detail = "The tool does not rate severity; the Low baseline (20) is used."
        rationale.append({"factor": "Base (scanner severity)", "effect": f"{base}", "detail": detail})

    multiplier = CONFIDENCE_MULTIPLIER[finding.confidence]
    score = base * multiplier
    if multiplier != 1.0:
        rationale.append({"factor": "Evidence confidence", "effect": f"x{multiplier}",
                          "detail": f"Scanner confidence '{finding.confidence}'."})

    weight = mapper.impact_weight(finding.owasp_id)
    if weight and finding.owasp_status in ("mapped", "potential"):
        applied = weight if finding.owasp_status == "mapped" else weight // 2
        score += applied
        rationale.append({"factor": "Category impact", "effect": f"+{applied}",
                          "detail": f"{finding.owasp_id} {finding.owasp_name} "
                                    f"(mapping status: {finding.owasp_status})."})

    if finding.exploit_evidence:
        score += EXPLOIT_BONUS
        rationale.append({"factor": "Exploitability", "effect": f"+{EXPLOIT_BONUS}",
                          "detail": "Scanner reports a successful attack payload/response."})

    crit = CRITICALITY_ADJUST[context.asset_criticality]
    if crit:
        score += crit
        rationale.append({"factor": "Asset criticality", "effect": f"{crit:+d}",
                          "detail": f"Declared '{context.asset_criticality}' at scan time."})

    exposure = EXPOSURE_ADJUST[context.exposure]
    if exposure:
        score += exposure
        rationale.append({"factor": "Exposure", "effect": f"{exposure:+d}",
                          "detail": f"Declared '{context.exposure}' at scan time."})

    if len(finding.locations) >= SPREAD_THRESHOLD:
        score += SPREAD_BONUS
        rationale.append({"factor": "Spread", "effect": f"+{SPREAD_BONUS}",
                          "detail": f"Affects {len(finding.locations)} locations in this scan."})

    score = round(max(0.0, min(100.0, score)), 1)
    priority = score_to_priority(score)

    baseline = SEVERITY_TO_PRIORITY[finding.scanner_severity]
    cap_index = max(0, _level_index(baseline) - 1)
    if _level_index(priority) < cap_index:
        capped = PRIORITY_LEVELS[cap_index]
        rationale.append({"factor": "Guardrail", "effect": f"cap {capped}",
                          "detail": f"Priority limited to one level above the scanner's own rating ({baseline})."})
        priority = capped

    rationale.append({"factor": "Result", "effect": f"{score} -> {priority}",
                      "detail": f"Severity-only ranking would give {baseline}."})
    finding.risk_score = score
    finding.priority = priority
    finding.rationale = rationale
    return finding


def prioritise(findings: list[Finding], mapper: OwaspMapper, context: RiskContext) -> list[Finding]:
    scored = [score_finding(f, mapper, context) for f in findings]
    return sorted(scored, key=lambda f: (_level_index(f.priority), -f.risk_score, f.title))
