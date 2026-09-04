"""
Sigma rule extractor. No Sigma rules are vendored in this repo (SAGE is
Suricata-only) so this is exercised via `../../tests/test_extractors.py`
fixtures, not a local corpus. Pulling SigmaHQ's rule set is a separate,
not-yet-taken step -- see ../../findings.md -- useful for broadening
technique-label coverage (per `../../tiered_approach/embedding_swap_findings.md`),
not required for the extractor itself to work.
"""
import re
from typing import Any, List, Optional

import yaml

from ..models import ExtractedRule, IoC, IoCType, RuleFormat
from .base import BaseExtractor

_TECHNIQUE_TAG_RE = re.compile(r"^attack\.t(\d{4}(?:\.\d{3})?)$", re.IGNORECASE)

_FIELD_TYPE_MAP = (
    (("image", "path", "parentimage"), IoCType.PROCESS),
    (("commandline", "command_line"), IoCType.COMMAND_LINE),
    (("registry",), IoCType.REGISTRY),
    (("hash", "hashes", "md5", "sha1", "sha256"), IoCType.HASH),
    (("eventid", "event_id"), IoCType.EVENT_ID),
    (("destinationip", "sourceip", "ip"), IoCType.IP),
    (("destinationhostname", "domain", "queryname"), IoCType.DOMAIN),
)


def _field_ioc_type(field_name: str) -> Optional[IoCType]:
    lowered = field_name.lower()
    for keys, ioc_type in _FIELD_TYPE_MAP:
        if any(k in lowered for k in keys):
            return ioc_type
    return None


class SigmaExtractor(BaseExtractor):
    format = RuleFormat.SIGMA

    def can_extract(self, raw_content: str) -> bool:
        try:
            parsed = yaml.safe_load(raw_content)
        except yaml.YAMLError:
            return False
        return isinstance(parsed, dict) and "detection" in parsed and "logsource" in parsed

    def extract(self, raw_content: str, source_path: Optional[str] = None) -> ExtractedRule:
        parsed = yaml.safe_load(raw_content)
        detection = parsed.get("detection", {}) or {}
        logsource = parsed.get("logsource", {}) or {}
        tags = parsed.get("tags", []) or []

        iocs = self._extract_iocs(detection)
        patterns = self._extract_patterns(detection)
        declared = self._declared_techniques(tags)

        ls_parts = [logsource.get("product", ""), logsource.get("service", "")]
        logsource_str = "/".join(p for p in ls_parts if p)

        return ExtractedRule(
            raw_content=raw_content,
            format=self.format,
            title=parsed.get("title"),
            description=parsed.get("description"),
            logsource=logsource_str or None,
            platform=logsource.get("product"),
            iocs=iocs,
            search_patterns=patterns,
            conditions=[str(detection.get("condition", ""))],
            severity=parsed.get("level"),
            references=parsed.get("references", []) or [],
            tags=tags,
            declared_technique_ids=declared,
            source_path=source_path,
        )

    def _extract_iocs(self, detection: dict) -> List[IoC]:
        iocs: List[IoC] = []
        for key, value in detection.items():
            if key in ("condition", "timeframe"):
                continue
            iocs.extend(self._parse_selection(value))
        return iocs

    def _parse_selection(self, value: Any) -> List[IoC]:
        iocs: List[IoC] = []
        if isinstance(value, dict):
            for field, val in value.items():
                field_name = field.split("|")[0]  # strip Sigma modifiers e.g. "Image|endswith"
                ioc_type = _field_ioc_type(field_name)
                if ioc_type is None:
                    continue
                values = val if isinstance(val, list) else [val]
                for v in values:
                    iocs.append(IoC(value=str(v), type=ioc_type, context=field_name))
        elif isinstance(value, list):
            for item in value:
                iocs.extend(self._parse_selection(item))
        return iocs

    @staticmethod
    def _extract_patterns(detection: dict) -> List[str]:
        patterns: List[str] = []
        for key, value in detection.items():
            if key in ("condition", "timeframe"):
                continue
            if isinstance(value, (str, int)):
                patterns.append(str(value))
            elif isinstance(value, list):
                patterns.extend(str(v) for v in value if isinstance(v, (str, int)))
            elif isinstance(value, dict):
                for v in value.values():
                    vs = v if isinstance(v, list) else [v]
                    patterns.extend(str(x) for x in vs if isinstance(x, (str, int)))
        return patterns

    @staticmethod
    def _declared_techniques(tags: List[str]) -> List[str]:
        declared = []
        for tag in tags:
            m = _TECHNIQUE_TAG_RE.match(tag.strip())
            if m:
                declared.append(f"T{m.group(1)}")
        return declared
