"""
IoC/context resolver -- Layer C ("IoC -> known technique association") plus
a SAGE-specific extra source, wired to two pieces of already-debugged
internal threat intel rather than a hand-typed lookup dict:

1. Tool/malware alias table, imported directly from
   `../tiered_approach/tier1_build.py` -- built from the live STIX
   malware/tool `uses` relationships, with a hard-won stoplist for alias
   collisions with common English words (`ping`, `page`, `chaos`, ...) found
   during probing. High precision, per `../results.md`.

2. `../bridge_table_validated.json` -- the 34-row MicroAttackStage -> ATT&CK
   bridge, validated with 0 problems against live STIX
   (`../results.md` section 1b). This is SAGE's *own* existing
   classification (`signatures/alert_signatures.py` assigns every alert a
   `MicroAttackStage` today, independent of this experiment) -- the closest
   thing this repo has to "internal threat intel" for a rule the extractor
   has already seen. Used only when the caller supplies a
   `micro_attack_stage` (real SAGE alerts always have one; it is not derived
   from the mapper's own output).
"""
import json
import os
import sys
from typing import Dict, List, Optional, Set

from .models import ExtractedRule

HERE = os.path.dirname(os.path.abspath(__file__))
MITRE_MAPPING_ROOT = os.path.normpath(os.path.join(HERE, "..", ".."))
TIERED_DIR = os.path.join(MITRE_MAPPING_ROOT, "tiered_approach")
BRIDGE_TABLE_PATH = os.path.join(MITRE_MAPPING_ROOT, "bridge_table_validated.json")

for p in (MITRE_MAPPING_ROOT, TIERED_DIR):
    if p not in sys.path:
        sys.path.insert(0, p)

import attack_data  # noqa: E402
import tier1_build  # noqa: E402

ALIAS_CONFIDENCE = 0.75
BRIDGE_CONFIDENCE = {"high": 0.7, "ambiguous": 0.4, "none": 0.0}


class IoCResolver:
    def __init__(self):
        objs = attack_data.load_bundle()
        self._alias_table = tier1_build.build_alias_table(objs)
        self._bridge_table = self._load_bridge_table()

    @staticmethod
    def _load_bridge_table() -> dict:
        if not os.path.exists(BRIDGE_TABLE_PATH):
            return {}
        with open(BRIDGE_TABLE_PATH, encoding="utf-8") as fh:
            return json.load(fh)

    def resolve(self, rule: ExtractedRule) -> Dict[str, object]:
        """Returns {"techniques": [...], "evidence": [...], "confidence": float,
        "source": "ioc_alias" | "bridge_table" | None}. Alias hits take
        priority over the bridge table when both fire, since alias matches
        are keyed on rule-specific content while the bridge table is a
        coarse per-stage default."""
        text = " ".join(filter(None, [rule.title, rule.raw_content]))
        hits = tier1_build.match_signature(text, self._alias_table)
        if hits:
            techniques: Set[str] = set()
            for techs in hits.values():
                techniques |= techs
            return {
                "techniques": sorted(techniques),
                "evidence": [f"tool/malware alias match: {alias}" for alias in sorted(hits)],
                "confidence": ALIAS_CONFIDENCE,
                "source": "ioc_alias",
            }

        stage = rule.micro_attack_stage
        if stage and stage in self._bridge_table:
            entry = self._bridge_table[stage]
            resolved = entry.get("resolved_ids", [])
            if resolved and entry.get("kind") == "technique":
                conf = BRIDGE_CONFIDENCE.get(entry.get("confidence"), 0.0)
                if conf > 0:
                    return {
                        "techniques": resolved,
                        "evidence": [f"bridge table: {stage} -> {entry.get('note')}"],
                        "confidence": conf,
                        "source": "bridge_table",
                    }

        return {"techniques": [], "evidence": [], "confidence": 0.0, "source": None}
