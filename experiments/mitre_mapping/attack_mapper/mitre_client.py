"""
Thin wrapper around `attack_data.py`, which reads the local STIX Enterprise
ATT&CK bundle at `data/enterprise-attack.json` (53MB, gitignored, no network
fetch needed at runtime). Do not re-download or reimplement STIX parsing here.
"""
from typing import Dict, List, Optional

from . import attack_data


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
