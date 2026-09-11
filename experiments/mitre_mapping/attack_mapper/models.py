"""
Pydantic data models for the generalisable rule -> ATT&CK mapper.

Adapted from the HF-chat sketch in `../generalisable mitre mapper.md`, trimmed
to what this experiment actually implements (see `../findings.md`).
"""
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class RuleFormat(str, Enum):
    SURICATA = "suricata"
    SIGMA = "sigma"
    GENERIC = "generic"


class ValidationStatus(str, Enum):
    AUTOMATED_VALIDATED = "auto_validated"
    AUTOMATED_INFERRED = "auto_inferred"
    PENDING_REVIEW = "pending_review"


class IoCType(str, Enum):
    PROCESS = "process"
    FILE = "file"
    REGISTRY = "registry"
    NETWORK = "network"
    IP = "ip"
    DOMAIN = "domain"
    HASH = "hash"
    COMMAND_LINE = "command_line"
    EVENT_ID = "event_id"
    TOOL_NAME = "tool_name"
    CVE = "cve"
    PORT = "port"


class IoC(BaseModel):
    value: str
    type: IoCType
    context: Optional[str] = None


class ExtractedRule(BaseModel):
    raw_content: str
    format: RuleFormat
    title: Optional[str] = None
    description: Optional[str] = None
    logsource: Optional[str] = None
    platform: Optional[str] = None

    iocs: List[IoC] = Field(default_factory=list)
    search_patterns: List[str] = Field(default_factory=list)
    conditions: List[str] = Field(default_factory=list)

    severity: Optional[str] = None
    references: List[str] = Field(default_factory=list)
    tags: List[str] = Field(default_factory=list)

    # Pre-existing ATT&CK mapping, if the rule format already carries one
    # (Tier 0 in tiered_approach/strategy.md) -- e.g. ET's own
    # `metadata: mitre_technique_id T1190`. Harvested at extraction time so
    # the pipeline can short-circuit to it instead of treating it as one more
    # inference candidate.
    declared_technique_ids: List[str] = Field(default_factory=list)

    source_path: Optional[str] = None
    body_matched: bool = False  # True if a Suricata rule body was found and parsed, not just the title


class TechniqueMapping(BaseModel):
    technique_id: str
    technique_name: str
    tactics: List[str] = Field(default_factory=list)
    confidence: float = Field(ge=0.0, le=1.0)
    # reasoner.py's cascade, in priority order. `bridge_table` (effort 10) and
    # `embedding` (effort 11, replaced by knn_corpus) are both gone. A Layer D
    # pass that confirms a prior candidate blends into "{source}+llm"; one it
    # introduces itself is plain "llm".
    source: str  # "declared" | "ioc_alias" | "supervised_classifier" | "knn_corpus" | "llm" | "<source>+llm"
    evidence: List[str] = Field(default_factory=list)
    is_primary: bool = False


class BehavioralNarrative(BaseModel):
    narrative: str
    attack_stage: Optional[str] = None
    data_source_hints: List[str] = Field(default_factory=list)


class MappedRule(BaseModel):
    rule: ExtractedRule
    narrative: BehavioralNarrative
    mappings: List[TechniqueMapping] = Field(default_factory=list)

    overall_confidence: float = Field(ge=0.0, le=1.0, default=0.0)
    validation_status: ValidationStatus = ValidationStatus.AUTOMATED_INFERRED
    human_review_required: bool = True
    review_reason: Optional[str] = None

    pipeline_version: str = "0.1.0"
    processing_steps: List[Dict[str, Any]] = Field(default_factory=list)
    processed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
