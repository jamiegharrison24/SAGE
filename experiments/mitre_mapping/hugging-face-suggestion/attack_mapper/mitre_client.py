"""
Thin wrapper around `../attack_data.py`, which already reads the local STIX
Enterprise ATT&CK bundle committed at `../enterprise-attack.json` (53MB, no
network fetch needed). Do not re-download or reimplement STIX parsing here.
"""
import os
import sys
from typing import Dict, List, Optional

HERE = os.path.dirname(os.path.abspath(__file__))
MITRE_MAPPING_ROOT = os.path.normpath(os.path.join(HERE, "..", ".."))
if MITRE_MAPPING_ROOT not in sys.path:
    sys.path.insert(0, MITRE_MAPPING_ROOT)

import attack_data  # noqa: E402


class MitreAttackClient:
    """Loads once per process; ~700 techniques, indexed by ID."""

    def __init__(self):
        objs = attack_data.load_bundle()
        self.techniques: Dict[str, dict] = attack_data.load_techniques(objs)
        self._shortname_to_taid = attack_data.load_tactics(objs)

    def get_technique(self, technique_id: str) -> Optional[dict]:
        return self.techniques.get(technique_id.upper())

    def get_all_techniques(self) -> Dict[str, dict]:
        return self.techniques

    def get_name(self, technique_id: str) -> str:
        tech = self.get_technique(technique_id)
        return tech["name"] if tech else technique_id

    def get_tactics(self, technique_id: str) -> List[str]:
        tech = self.get_technique(technique_id)
        if not tech:
            return []
        return attack_data.technique_tactics(tech, self._shortname_to_taid)

    def exists(self, technique_id: str) -> bool:
        return technique_id.upper() in self.techniques

    def technique_text(self, technique_id: str) -> str:
        """name + description + detection guidance, for embedding/similarity."""
        tech = self.get_technique(technique_id)
        if not tech:
            return ""
        return " ".join([
            tech.get("name", ""),
            tech.get("description", "") or "",
            tech.get("x_mitre_detection", "") or "",
        ])
