"""
IoC/context resolver -- Layer C ("IoC -> known technique association"),
wired to the tool/malware alias table (`alias_table.py`, adapted from
../archive/tiered_approach/tier1_build.py) -- built from the live STIX
malware/tool `uses` relationships, with a hard-won stoplist for alias
collisions with common English words (`ping`, `page`, `chaos`, ...) found
during probing. High precision, per `../archive/results.md`.

Previously also consulted `data/bridge_table_validated.json`, a MicroAttackStage
-> ATT&CK lookup keyed on SAGE's own coarse alert classification. Removed: at
500-row scale (see ../STATUS.md effort 9) it fired on 70% of scoreable rows at
only 34.8% accuracy -- both the largest bucket and the weakest of the
high-volume sources, a structural ceiling from mapping ~12 broad stages onto
52+ specific techniques, not something tunable. `micro_attack_stage` is no
longer read anywhere in this package.
"""
from typing import Dict, Set

from . import alias_table as alias_table_mod
from . import attack_data
from .models import ExtractedRule

ALIAS_CONFIDENCE = 0.75


class IoCResolver:
    def __init__(self):
        objs = attack_data.load_bundle()
        self._alias_table = alias_table_mod.build_alias_table(objs)

    def resolve(self, rule: ExtractedRule) -> Dict[str, object]:
        """Returns {"techniques": [...], "evidence": [...], "confidence": float,
        "source": "ioc_alias" | None}."""
        text = " ".join(filter(None, [rule.title, rule.raw_content]))
        hits = alias_table_mod.match_signature(text, self._alias_table)
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

        return {"techniques": [], "evidence": [], "confidence": 0.0, "source": None}
