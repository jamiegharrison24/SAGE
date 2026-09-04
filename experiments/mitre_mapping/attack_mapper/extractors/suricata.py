"""
Suricata/Snort extractor -- the primary format (SAGE ingests Suricata IDS
alerts; see repo CLAUDE.md).

Two input shapes, both handled here:

1. A full rule body: `alert tcp ... (msg:"..."; content:"..."; metadata: ...;
   mitre_technique_id T1190; ...)`. Parsed directly for content/pcre/
   classtype/metadata, including any `mitre_technique_id`/`mitre_tactic_id`
   the rule already carries (harvested as `declared_technique_ids` -- Tier 0
   in ../../archive/tiered_approach/strategy.md: these are ~100% precision
   when present and should short-circuit inference, not compete with it).

2. A bare signature name/title string, e.g. "ET SCAN Potential VNC Scan
   5800-5820". This is what SAGE's own alert stream and the hand-audited
   ground truth (`../data/hand_audit_sample*.csv`) actually consist of --
   Suricata alerts as ingested by `sage.py` carry only the rule's `msg`
   text, not its body. `strategy.md` is explicit that rule bodies carry far
   more signal than titles, so this path looks the title up against
   `../data/emerging-all.rules` (the ET ruleset, gitignored -- see
   ../STATUS.md for how it's fetched) and, on a hit, re-parses the full
   body. `rule.body_matched` records which path actually ran, per
   `MappedRule.processing_steps`.
"""
import os
import re
from typing import Dict, Optional

from ..models import ExtractedRule, IoC, IoCType, RuleFormat
from .base import BaseExtractor

HERE = os.path.dirname(os.path.abspath(__file__))
RULES_PATH = os.path.normpath(os.path.join(HERE, "..", "data", "emerging-all.rules"))

VENDOR_PREFIXES = (
    "ET ", "ETPRO ", "GPL ", "SURICATA ", "MALWARE-CNC", "SERVER-", "BROWSER-",
    "FILE-", "POLICY-", "INDICATOR-", "OS-", "PROTOCOL-", "APP-DETECT", "EXPLOIT-KIT",
)

_MSG_RE = re.compile(r'msg\s*:\s*"((?:[^"\\]|\\.)*)"')
_CONTENT_RE = re.compile(r'content\s*:\s*"((?:[^"\\]|\\.)*)"')
_PCRE_RE = re.compile(r'pcre\s*:\s*"((?:[^"\\]|\\.)*)"')
_CLASSTYPE_RE = re.compile(r"classtype\s*:\s*([\w-]+)")
_METADATA_RE = re.compile(r"metadata\s*:\s*(.*?);", re.DOTALL)
_REFERENCE_RE = re.compile(r"reference\s*:\s*(\w+),\s*([^;]+);")
_HEADER_RE = re.compile(
    r"^\s*(?:#\s*)?(alert|drop|reject|pass)\s+(\w+)\s+(\S+)\s+(\S+)\s*(->|<>)\s*(\S+)\s+(\S+)"
)


class SuricataExtractor(BaseExtractor):
    format = RuleFormat.SURICATA

    _rule_index: Optional[Dict[str, str]] = None  # msg text -> raw rule line, lazy/shared

    def can_extract(self, raw_content: str) -> bool:
        stripped = raw_content.strip()
        if not stripped:
            return False
        if "msg:" in stripped and "(" in stripped and ")" in stripped:
            return True
        first_line = stripped.splitlines()[0]
        return first_line.upper().startswith(VENDOR_PREFIXES)

    def extract(self, raw_content: str, source_path: Optional[str] = None) -> ExtractedRule:
        stripped = raw_content.strip()

        if "msg:" in stripped and "(" in stripped:
            body = stripped
            body_matched = True  # full rule body given directly
        else:
            looked_up = self._lookup_body(stripped)
            if looked_up:
                body = looked_up
                body_matched = True
            else:
                return self._name_only(stripped, source_path)

        return self._parse_body(body, source_path, body_matched)

    # -- body lookup -----------------------------------------------------

    @classmethod
    def _lookup_body(cls, title: str) -> Optional[str]:
        if cls._rule_index is None:
            cls._rule_index = cls._build_index()
        return cls._rule_index.get(title)

    @staticmethod
    def _build_index() -> Dict[str, str]:
        index: Dict[str, str] = {}
        if not os.path.exists(RULES_PATH):
            return index
        with open(RULES_PATH, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                m = _MSG_RE.search(line)
                if m:
                    index[m.group(1)] = line
        return index

    # -- parsing -----------------------------------------------------------

    def _name_only(self, title: str, source_path: Optional[str]) -> ExtractedRule:
        return ExtractedRule(
            raw_content=title,
            format=self.format,
            title=title,
            iocs=self._iocs_from_title(title),
            source_path=source_path,
            body_matched=False,
        )

    def _parse_body(self, body: str, source_path: Optional[str], body_matched: bool) -> ExtractedRule:
        msg_m = _MSG_RE.search(body)
        title = msg_m.group(1) if msg_m else None

        contents = [m.replace("\\", "") for m in _CONTENT_RE.findall(body)]
        pcres = _PCRE_RE.findall(body)
        classtype_m = _CLASSTYPE_RE.search(body)
        references = [f"{kind}:{val}" for kind, val in _REFERENCE_RE.findall(body)]

        metadata = self._parse_metadata(body)
        declared = self._declared_techniques(metadata)

        header_m = _HEADER_RE.match(body)
        platform = None
        if header_m:
            dst = header_m.group(6)
            platform = "network"
            if "SQL" in dst or "ORACLE" in dst:
                platform = "database"

        iocs = self._iocs_from_title(title or body)
        for c in contents:
            iocs.append(IoC(value=c, type=IoCType.NETWORK, context="content"))
        for p in pcres:
            iocs.append(IoC(value=p, type=IoCType.NETWORK, context="pcre"))

        tags = []
        if classtype_m:
            tags.append(f"classtype:{classtype_m.group(1)}")
        if "tag" in metadata:
            tags.append(f"tag:{metadata['tag']}")

        return ExtractedRule(
            raw_content=body,
            format=self.format,
            title=title,
            description=metadata.get("tag"),
            logsource="network/suricata",
            platform=platform,
            iocs=iocs,
            search_patterns=contents + pcres,
            conditions=[classtype_m.group(1)] if classtype_m else [],
            severity=metadata.get("signature_severity"),
            references=references,
            tags=tags,
            declared_technique_ids=declared,
            source_path=source_path,
            body_matched=body_matched,
        )

    @staticmethod
    def _parse_metadata(body: str) -> Dict[str, str]:
        m = _METADATA_RE.search(body)
        if not m:
            return {}
        out: Dict[str, str] = {}
        for pair in m.group(1).split(","):
            parts = pair.strip().split(None, 1)
            if len(parts) == 2:
                key, val = parts
                out[key] = val
        return out

    @staticmethod
    def _declared_techniques(metadata: Dict[str, str]) -> list:
        declared = []
        tech = metadata.get("mitre_technique_id")
        if tech:
            declared.append(tech.strip())
        return declared

    @staticmethod
    def _iocs_from_title(title: str) -> list:
        iocs = []
        cve_m = re.search(r"CVE-\d{4}-\d{4,7}", title, re.IGNORECASE)
        if cve_m:
            iocs.append(IoC(value=cve_m.group(0).upper(), type=IoCType.CVE, context="title"))
        port_m = re.search(r"\b(?:port\s*)?(\d{2,5})\b", title, re.IGNORECASE)
        if port_m and any(k in title.lower() for k in ("port", "scan")):
            iocs.append(IoC(value=port_m.group(1), type=IoCType.PORT, context="title"))
        return iocs
