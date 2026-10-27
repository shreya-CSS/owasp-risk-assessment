"""Rule-based OWASP Top 10 categorisation.

Decision order (first match wins), each recorded as the mapping basis:
1. An OWASP tag supplied by the scanner itself (e.g. ZAP "OWASP_2021_A05")  -> mapped
2. A project rule on the tool-independent issue key (checks whose meaning
   is known exactly, e.g. "header-missing:*")                               -> as configured
3. The finding's CWE appears in the edition's published CWE list            -> mapped
4. A title keyword rule                                                     -> potential
5. Nothing applies                                                          -> unmapped

Mappings live in config/owasp_<edition>.json so they can be reviewed and changed
without touching code.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from config.settings import PROJECT_ROOT
from modules.models import Finding


@dataclass(frozen=True)
class OwaspCategory:
    id: str
    name: str
    impact_weight: int
    guidance: str


class OwaspMapper:
    def __init__(self, mapping: dict):
        self.edition: str = mapping["edition"]
        self.title: str = mapping["title"]
        self.tag_prefix: str = mapping.get("scanner_tag_prefix", "")
        self.categories: dict[str, OwaspCategory] = {}
        self.cwe_index: dict[int, str] = {}
        for cat_id, data in mapping["categories"].items():
            self.categories[cat_id] = OwaspCategory(
                id=cat_id, name=data["name"], impact_weight=int(data.get("impact_weight", 0)),
                guidance=data.get("guidance", ""),
            )
            for cwe in data.get("cwes", []):
                self.cwe_index.setdefault(int(cwe), cat_id)
        self.rules: list[dict] = mapping.get("rules", [])

    def label(self, cat_id: str) -> str:
        cat = self.categories.get(cat_id)
        return f"{cat_id}:{self.edition} {cat.name}" if cat else ""

    def _apply(self, finding: Finding, cat_id: str, status: str, basis: str) -> Finding:
        cat = self.categories[cat_id]
        finding.owasp_id = f"{cat_id}:{self.edition}"
        finding.owasp_name = cat.name
        finding.owasp_status = status
        finding.owasp_basis = basis
        return finding

    def map_finding(self, finding: Finding) -> Finding:
        if self.tag_prefix:
            for tag in finding.scanner_tags:
                if tag.upper().startswith(self.tag_prefix.upper()):
                    cat_id = tag[len(self.tag_prefix):len(self.tag_prefix) + 3].upper()
                    if cat_id in self.categories:
                        return self._apply(finding, cat_id, "mapped", f"Scanner-supplied tag {tag}.")
        key = finding.issue_key.lower()
        title = finding.title.lower()
        for rule in self.rules:
            prefix = rule.get("issue_key_prefix")
            if prefix and key.startswith(prefix):
                return self._apply(finding, rule["category"], rule["status"], rule["basis"])
        if finding.cwe_id and finding.cwe_id in self.cwe_index:
            cat_id = self.cwe_index[finding.cwe_id]
            return self._apply(
                finding, cat_id, "mapped",
                f"CWE-{finding.cwe_id} is listed under {cat_id} in the {self.title} CWE mapping.",
            )
        for rule in self.rules:
            keywords = rule.get("keywords")
            if keywords and any(word in title for word in keywords):
                return self._apply(finding, rule["category"], "potential", rule["basis"])
        finding.owasp_id = ""
        finding.owasp_name = ""
        finding.owasp_status = "unmapped"
        finding.owasp_basis = "No mapping rule applies; evidence is insufficient to assign a category."
        return finding

    def guidance_for(self, owasp_id: str) -> str:
        cat = self.categories.get(owasp_id.split(":", 1)[0]) if owasp_id else None
        return cat.guidance if cat else ""

    def impact_weight(self, owasp_id: str) -> int:
        cat = self.categories.get(owasp_id.split(":", 1)[0]) if owasp_id else None
        return cat.impact_weight if cat else 0


def load_mapping_file(path: Path) -> dict:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


@lru_cache(maxsize=4)
def get_mapper(edition: str = "2021") -> OwaspMapper:
    if not edition.isalnum():
        raise ValueError("Invalid OWASP edition identifier")
    path = PROJECT_ROOT / "config" / f"owasp_{edition}.json"
    if not path.exists():
        raise FileNotFoundError(f"No OWASP mapping file for edition {edition}: {path.name}")
    return OwaspMapper(load_mapping_file(path))
