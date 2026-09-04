from abc import ABC, abstractmethod
from typing import Optional

from ..models import ExtractedRule, RuleFormat


class BaseExtractor(ABC):
    """Format-agnostic extraction contract. GenericExtractor.can_extract
    always returns True, so it must stay last in the extractor list -- it's
    the fallback, not a competing match."""

    format: RuleFormat

    @abstractmethod
    def can_extract(self, raw_content: str) -> bool:
        ...

    @abstractmethod
    def extract(self, raw_content: str, source_path: Optional[str] = None) -> ExtractedRule:
        ...
