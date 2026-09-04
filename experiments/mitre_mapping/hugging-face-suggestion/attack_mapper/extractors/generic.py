"""Fallback extractor: treats any input as opaque text and pulls only
obviously-structured tokens (CVEs) out of it. Always matches -- must stay
last in the extractor list."""
import re
from typing import List, Optional

from ..models import ExtractedRule, IoC, IoCType, RuleFormat
from .base import BaseExtractor

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


class GenericExtractor(BaseExtractor):
    format = RuleFormat.GENERIC

    def can_extract(self, raw_content: str) -> bool:
        return True

    def extract(self, raw_content: str, source_path: Optional[str] = None) -> ExtractedRule:
        stripped = raw_content.strip()
        iocs: List[IoC] = [
            IoC(value=m.group(0).upper(), type=IoCType.CVE, context="text")
            for m in _CVE_RE.finditer(stripped)
        ]
        return ExtractedRule(
            raw_content=stripped,
            format=self.format,
            title=stripped[:200] or None,
            iocs=iocs,
            source_path=source_path,
        )
