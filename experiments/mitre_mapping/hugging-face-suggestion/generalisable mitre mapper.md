```python
"""
attack_mapper/
├── __init__.py
├── core/
│   ├── __init__.py
│   ├── models.py          # Pydantic data models
│   ├── pipeline.py        # Main orchestration
│   ├── config.py          # Settings & constants
│   └── exceptions.py      # Custom exceptions
├── extractors/
│   ├── __init__.py
│   ├── base.py            # Abstract base extractor
│   ├── sigma.py           # Sigma/YAML rules
│   ├── splunk.py          # SPL queries
│   ├── kql.py             # Azure Sentinel KQL
│   ├── elastic.py         # Elastic DSL
│   ├── suricata.py        # IDS rules
│   └── generic.py         # Fallback regex-based
├── enrichment/
│   ├── __init__.py
│   ├── ioc_resolver.py    # IoC → context lookup
│   ├── mitre_client.py    # ATT&CK CTI API client
│   ├── threat_intel.py    # MISP/VirusTotal/etc
│   └── llm_client.py      # OpenAI/Anthropic/Llama
├── inference/
│   ├── __init__.py
│   ├── embedder.py        # Sentence transformer embeddings
│   ├── classifier.py      # Multi-label technique classifier
│   ├── reasoner.py        # LLM chain-of-thought mapper
│   └── validator.py       # Output validation & hallucination check
├── normalization/
│   ├── __init__.py
│   ├── narrative.py       # Rule → behavioral narrative
│   ├── behavior_graph.py  # Behavioral abstraction graph
│   └── datasource_map.py  # Log source → technique constraints
├── output/
│   ├── __init__.py
│   ├── formatter.py       # JSON/Navigator/Sigma tags
│   └── coverage.py        # Coverage gap analysis
├── tests/
│   ├── __init__.py
│   ├── test_pipeline.py
│   ├── test_extractors.py
│   └── fixtures/          # Sample rules in all formats
├── scripts/
│   ├── ingest_rules.py    # Batch ingestion CLI
│   ├── validate_maps.py   # Validation against ground truth
│   └── export_navigator.py # Generate ATT&CK Navigator layer
├── pyproject.toml
├── requirements.txt
└── README.md
"""

# ============================================================================
# core/models.py
# ============================================================================

from pydantic import BaseModel, Field
from typing import List, Dict, Optional, Any, Set
from enum import Enum
from datetime import datetime


class RuleFormat(str, Enum):
    SIGMA = "sigma"
    SPLUNK = "splunk"
    KQL = "kql"
    ELASTIC = "elastic"
    SURICATA = "suricata"
    SNORT = "snort"
    YARA = "yara"
    GENERIC = "generic"


class ValidationStatus(str, Enum):
    MANUAL = "manual"                    # Human-validated
    AUTOMATED_VALIDATED = "auto_validated"  # Passed automated tests
    AUTOMATED_INFERRED = "auto_inferred"      # ML/LLM inferred, unvalidated
    PENDING_REVIEW = "pending_review"       # Flagged for human review


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
    USER = "user"
    SERVICE = "service"


class IoC(BaseModel):
    value: str
    type: IoCType
    context: Optional[str] = None  # e.g., "parent process", "target registry"


class ExtractedRule(BaseModel):
    raw_content: str
    format: RuleFormat
    title: Optional[str] = None
    description: Optional[str] = None
    author: Optional[str] = None
    logsource: Optional[str] = None       # e.g., "windows/sysmon"
    platform: Optional[str] = None        # windows, linux, macos, network
    
    # Core behavioral extraction
    iocs: List[IoC] = []
    search_patterns: List[str] = []       # Raw query terms, regexes, etc.
    conditions: List[str] = []            # Logical conditions (AND/OR/NOT)
    temporal_windows: Optional[str] = None # Time-based aggregations
    thresholds: Optional[Dict[str, Any]] = None  # count > 5, etc.
    
    # Metadata
    severity: Optional[str] = None
    confidence: Optional[float] = None   # Rule author's confidence
    references: List[str] = []
    tags: List[str] = []                  # Pre-existing tags (may be wrong)
    
    # Provenance
    source_path: Optional[str] = None
    ingestion_time: datetime = Field(default_factory=datetime.utcnow)


class TechniqueMapping(BaseModel):
    technique_id: str                     # e.g., "T1059.001"
    technique_name: str
    tactic: str                           # e.g., "execution"
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: List[str] = []             # Why this technique was chosen
    is_primary: bool = False
    
    # Granularity tracking
    subtechnique_of: Optional[str] = None  # Parent technique if sub-technique


class BehavioralNarrative(BaseModel):
    narrative: str                        # Natural language description
    inferred_intent: Optional[str] = None   # "Adversary is trying to..."
    attack_stage: Optional[str] = None     # reconnaissance, initial_access, etc.
    data_sources: List[str] = []           # MITRE ATT&CK data source objects
    mitigations: List[str] = []          # Relevant D3FEND/ATT&CK mitigations


class MappedRule(BaseModel):
    rule: ExtractedRule
    narrative: BehavioralNarrative
    mappings: List[TechniqueMapping] = []
    
    # Quality & validation
    overall_confidence: float = Field(ge=0.0, le=1.0)
    validation_status: ValidationStatus = ValidationStatus.AUTOMATED_INFERRED
    human_review_required: bool = True
    review_reason: Optional[str] = None   # Why flagged for review
    
    # Audit trail
    pipeline_version: str
    processing_steps: List[Dict[str, Any]] = []  # Full trace for debugging


class CoverageGap(BaseModel):
    technique_id: str
    technique_name: str
    priority: str  # critical, high, medium, low
    reason: str
    related_threat_actors: List[str] = []
    recommended_data_sources: List[str] = []


# ============================================================================
# core/config.py
# ============================================================================

import os
from typing import List
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # ATT&CK
    ATTACK_VERSION: str = "v16.0"
    ATTACK_STIX_URL: str = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
    MITRE_CACHE_DIR: str = "./cache/mitre"
    
    # LLM
    LLM_PROVIDER: str = "openai"  # openai, anthropic, azure, local
    LLM_MODEL: str = "gpt-4-turbo"
    LLM_API_KEY: Optional[str] = None
    LLM_TEMPERATURE: float = 0.1  # Low temp for deterministic mapping
    LLM_MAX_TOKENS: int = 4096
    
    # Embeddings
    EMBEDDING_MODEL: str = "sentence-transformers/all-MiniLM-L6-v2"
    EMBEDDING_DEVICE: str = "cpu"  # cuda if available
    
    # Enrichment
    MISP_URL: Optional[str] = None
    MISP_API_KEY: Optional[str] = None
    VIRUSTOTAL_API_KEY: Optional[str] = None
    ENABLE_WEB_SEARCH: bool = False  # RAM-style IoC enrichment
    
    # Validation thresholds
    MIN_CONFIDENCE_FOR_AUTO: float = 0.85
    MIN_EVIDENCE_COUNT: int = 2
    MAX_TECHNIQUES_PER_RULE: int = 4
    
    # Pipeline
    PARALLEL_WORKERS: int = 4
    BATCH_SIZE: int = 50
    
    class Config:
        env_file = ".env"


settings = Settings()


# ============================================================================
# core/exceptions.py
# ============================================================================

class AttackMapperError(Exception):
    """Base exception."""
    pass


class ExtractionError(AttackMapperError):
    """Failed to parse/extract from rule format."""
    pass


class EnrichmentError(AttackMapperError):
    """IoC enrichment failed."""
    pass


class InferenceError(AttackMapperError):
    """Technique inference failed."""
    pass


class ValidationError(AttackMapperError):
    """Output validation failed (hallucination detected)."""
    pass


# ============================================================================
# extractors/base.py
# ============================================================================

from abc import ABC, abstractmethod
from typing import Optional


class BaseExtractor(ABC):
    """Abstract base for all rule format extractors."""
    
    format: RuleFormat
    
    @abstractmethod
    def can_extract(self, raw_content: str) -> bool:
        """Quick check if this extractor handles this content."""
        pass
    
    @abstractmethod
    def extract(self, raw_content: str, source_path: Optional[str] = None) -> ExtractedRule:
        """Extract behavioral indicators from raw rule content."""
        pass
    
    def _normalize_logsource(self, raw: str) -> str:
        """Normalize various logsource representations."""
        # Override in subclasses
        return raw.lower().strip()


# ============================================================================
# extractors/sigma.py  (example implementation)
# ============================================================================

import yaml
import re
from typing import Optional


class SigmaExtractor(BaseExtractor):
    format = RuleFormat.SIGMA
    
    def can_extract(self, raw_content: str) -> bool:
        try:
            parsed = yaml.safe_load(raw_content)
            return "detection" in parsed and "logsource" in parsed
        except:
            return False
    
    def extract(self, raw_content: str, source_path: Optional[str] = None) -> ExtractedRule:
        try:
            parsed = yaml.safe_load(raw_content)
        except yaml.YAMLError as e:
            raise ExtractionError(f"Invalid YAML: {e}")
        
        detection = parsed.get("detection", {})
        logsource = parsed.get("logsource", {})
        
        # Extract IoCs from detection selections
        iocs = self._extract_iocs_from_detection(detection)
        
        # Extract search patterns
        patterns = self._extract_patterns(detection)
        
        # Build rule
        return ExtractedRule(
            raw_content=raw_content,
            format=self.format,
            title=parsed.get("title"),
            description=parsed.get("description"),
            author=parsed.get("author"),
            logsource=f"{logsource.get('product', '')}/{logsource.get('service', '')}".strip("/"),
            platform=logsource.get("product"),
            iocs=iocs,
            search_patterns=patterns,
            conditions=[detection.get("condition", "")],
            severity=parsed.get("level"),
            references=parsed.get("references", []),
            tags=parsed.get("tags", []),
            source_path=source_path
        )
    
    def _extract_iocs_from_detection(self, detection: dict) -> List[IoC]:
        iocs = []
        for key, value in detection.items():
            if key in ("condition", "timeframe"):
                continue
            
            # Recursively extract field:value pairs
            iocs.extend(self._parse_selection(key, value))
        return iocs
    
    def _parse_selection(self, name: str, value: Any) -> List[IoC]:
        """Parse a Sigma selection block into IoCs."""
        iocs = []
        
        if isinstance(value, dict):
            for field, val in value.items():
                field_lower = field.lower()
                
                # Process image/path fields
                if "image" in field_lower or "path" in field_lower:
                    if isinstance(val, list):
                        for v in val:
                            iocs.append(IoC(value=v, type=IoCType.PROCESS, context=field))
                    else:
                        iocs.append(IoC(value=val, type=IoCType.PROCESS, context=field))
                
                # Command line
                elif "commandline" in field_lower or "command_line" in field_lower:
                    iocs.append(IoC(value=str(val), type=IoCType.COMMAND_LINE, context=field))
                
                # Registry
                elif "registry" in field_lower:
                    iocs.append(IoC(value=str(val), type=IoCType.REGISTRY, context=field))
                
                # IP/Network
                elif "ip" in field_lower or "destinationip" in field_lower:
                    iocs.append(IoC(value=str(val), type=IoCType.IP, context=field))
                
                # Event ID
                elif "eventid" in field_lower or "event_id" in field_lower:
                    iocs.append(IoC(value=str(val), type=IoCType.EVENT_ID, context=field))
                
                # File hash
                elif "hash" in field_lower:
                    iocs.append(IoC(value=str(val), type=IoCType.HASH, context=field))
        
        elif isinstance(value, list):
            for item in value:
                iocs.extend(self._parse_selection(name, item))
        
        return iocs
    
    def _extract_patterns(self, detection: dict) -> List[str]:
        """Extract raw search strings/patterns."""
        patterns = []
        for key, value in detection.items():
            if isinstance(value, (str, int)):
                patterns.append(str(value))
            elif isinstance(value, list):
                patterns.extend(str(v) for v in value if isinstance(v, (str, int)))
        return patterns


# ============================================================================
# enrichment/ioc_resolver.py
# ============================================================================

from typing import Dict, List, Optional
import hashlib
import json


class IoCResolver:
    """Resolves IoCs to known technique associations via cached threat intel."""
    
    def __init__(self, cache_dir: str = "./cache/iocs"):
        self.cache_dir = cache_dir
        self._load_known_iocs()
    
    def _load_known_iocs(self):
        """Load known IoC→technique mappings."""
        # In production, load from MISP, VirusTotal, internal DB
        self.known_iocs = {
            # Process names → techniques
            "soaphound.exe": ["T1087", "T1083", "T1482"],
            "mimikatz.exe": ["T1003", "T1098", "T1558"],
            "procdump.exe": ["T1003.001"],
            "certutil.exe": ["T1105", "T1027"],
            "powershell.exe": ["T1059.001"],
            "cmd.exe": ["T1059.003"],
            "wscript.exe": ["T1059.005"],
            "cscript.exe": ["T1059.005"],
            "mshta.exe": ["T1059.005", "T1218.005"],
            "regsvr32.exe": ["T1218.010"],
            "rundll32.exe": ["T1218.011"],
            
            # Command-line indicators
            "-encodedcommand": ["T1027", "T1059.001"],
            "-enc": ["T1027", "T1059.001"],
            "invoke-expression": ["T1059.001"],
            "iex": ["T1059.001"],
            "downloadstring": ["T1105", "T1059.001"],
            "net user": ["T1136"],
            "net localgroup": ["T1136"],
            "whoami": ["T1033"],
            "systeminfo": ["T1082"],
            "tasklist": ["T1057"],
            "vssadmin delete shadows": ["T1490"],
            "wbadmin delete catalog": ["T1490"],
            "bcdedit /set {default} bootstatuspolicy ignoreallfailures": ["T1490"],
            
            # Event IDs → techniques (Windows)
            "4688": ["T1059"],  # Process creation
            "4624": ["T1078"],  # Logon
            "4625": ["T1110"],  # Failed logon
            "4672": ["T1078"],  # Special privileges
            "4720": ["T1136"],  # User created
            "4728": ["T1098"],  # Member added to group
            "7045": ["T1543.003"],  # Service installed
            "4697": ["T1543"],  # Service creation
        }
    
    def resolve(self, ioc: IoC) -> Dict[str, Any]:
        """Resolve single IoC to known technique associations."""
        results = {
            "techniques": [],
            "confidence_boost": 0.0,
            "context": []
        }
        
        value_lower = ioc.value.lower()
        
        # Direct match
        if value_lower in self.known_iocs:
            results["techniques"] = self.known_iocs[value_lower]
            results["confidence_boost"] = 0.3
            results["context"].append(f"Known IoC: {value_lower}")
            return results
        
        # Partial match (for paths, command lines)
        for known, techniques in self.known_iocs.items():
            if known in value_lower:
                results["techniques"].extend(techniques)
                results["confidence_boost"] = max(results["confidence_boost"], 0.15)
                results["context"].append(f"Partial match: {known} in {value_lower}")
        
        # Deduplicate
        results["techniques"] = list(set(results["techniques"]))
        return results
    
    def resolve_batch(self, iocs: List[IoC]) -> Dict[str, Any]:
        """Resolve multiple IoCs, aggregate results."""
        all_techniques = {}
        total_boost = 0.0
        contexts = []
        
        for ioc in iocs:
            result = self.resolve(ioc)
            for tech in result["techniques"]:
                all_techniques[tech] = all_techniques.get(tech, 0) + 1
            total_boost = max(total_boost, result["confidence_boost"])
            contexts.extend(result["context"])
        
        return {
            "techniques": sorted(all_techniques.keys(), key=lambda t: -all_techniques[t]),
            "technique_scores": all_techniques,
            "confidence_boost": total_boost,
            "contexts": contexts
        }


# ============================================================================
# enrichment/mitre_client.py
# ============================================================================

import requests
import json
import os
from typing import Dict, List, Optional
from datetime import datetime, timedelta


class MitreAttackClient:
    """Client for MITRE ATT&CK CTI data with local caching."""
    
    def __init__(self, cache_dir: str = "./cache/mitre"):
        self.cache_dir = cache_dir
        self.stix_data = None
        self.techniques = {}      # id -> technique object
        self.tactics = {}         # id -> tactic object
        self.data_sources = {}    # name -> data source object
        self.embeddings_cache = {}  # technique_id -> embedding vector
        
        os.makedirs(cache_dir, exist_ok=True)
        self._load_or_fetch()
    
    def _load_or_fetch(self):
        """Load from cache or fetch fresh STIX bundle."""
        cache_file = os.path.join(self.cache_dir, "enterprise-attack.json")
        
        if os.path.exists(cache_file) and self._cache_fresh(cache_file):
            with open(cache_file, 'r') as f:
                self.stix_data = json.load(f)
        else:
            response = requests.get(settings.ATTACK_STIX_URL, timeout=60)
            response.raise_for_status()
            self.stix_data = response.json()
            with open(cache_file, 'w') as f:
                json.dump(self.stix_data, f)
        
        self._index_objects()
    
    def _cache_fresh(self, cache_file: str, max_age_days: int = 7) -> bool:
        mtime = datetime.fromtimestamp(os.path.getmtime(cache_file))
        return datetime.now() - mtime < timedelta(days=max_age_days)
    
    def _index_objects(self):
        """Index STIX objects for fast lookup."""
        for obj in self.stix_data.get("objects", []):
            obj_type = obj.get("type")
            
            if obj_type == "attack-pattern":
                tech_id = None
                for ext in obj.get("external_references", []):
                    if ext.get("source_name") == "mitre-attack":
                        tech_id = ext.get("external_id")
                        break
                
                if tech_id and tech_id.startswith("T"):
                    self.techniques[tech_id] = {
                        "id": tech_id,
                        "name": obj.get("name"),
                        "description": obj.get("description", ""),
                        "tactics": [phase.get("phase_name") for phase in obj.get("kill_chain_phases", [])],
                        "data_sources": self._extract_data_sources(obj),
                        "platforms": obj.get("x_mitre_platforms", []),
                        "is_subtechnique": obj.get("x_mitre_is_subtechnique", False),
                        "parent": None
                    }
                    
                    # Link sub-techniques
                    if "." in tech_id:
                        parent = tech_id.split(".")[0]
                        self.techniques[tech_id]["parent"] = parent
            
            elif obj_type == "x-mitre-tactic":
                tactic_id = None
                for ext in obj.get("external_references", []):
                    if ext.get("source_name") == "mitre-attack":
                        tactic_id = ext.get("external_id")
                        break
                if tactic_id:
                    self.tactics[tactic_id] = {
                        "id": tactic_id,
                        "name": obj.get("name"),
                        "shortname": obj.get("x_mitre_shortname")
                    }
            
            elif obj_type == "x-mitre-data-source":
                self.data_sources[obj.get("name", "").lower()] = {
                    "name": obj.get("name"),
                    "description": obj.get("description", ""),
                    "components": [c.get("name") for c in obj.get("x_mitre_data_source_components", [])]
                }
        
        # Build parent→subtechnique links
        for tech_id, tech in self.techniques.items():
            if tech["is_subtechnique"] and tech["parent"]:
                parent = self.techniques.get(tech["parent"])
                if parent:
                    if "subtechniques" not in parent:
                        parent["subtechniques"] = []
                    parent["subtechniques"].append(tech_id)
    
    def _extract_data_sources(self, obj: dict) -> List[str]:
        sources = []
        for source in obj.get("x_mitre_data_sources", []):
            if isinstance(source, str):
                sources.append(source)
            elif isinstance(source, dict):
                sources.append(source.get("name", ""))
        return [s for s in sources if s]
    
    def get_technique(self, tech_id: str) -> Optional[dict]:
        return self.techniques.get(tech_id)
    
    def get_all_techniques(self) -> Dict[str, dict]:
        return self.techniques
    
    def get_tactics_for_technique(self, tech_id: str) -> List[str]:
        tech = self.techniques.get(tech_id)
        return tech["tactics"] if tech else []
    
    def get_data_source_constraints(self, logsource: str) -> List[str]:
        """Given a log source name, return likely technique categories."""
        # Map common log sources to ATT&CK data sources
        mapping = {
            "process_creation": ["Process", "Command"],
            "network_connection": ["Network Traffic"],
            "dns": ["Network Traffic"],
            "file_event": ["File"],
            "registry_event": ["Windows Registry"],
            "image_load": ["Module"],
            "driver_load": ["Kernel"],
            "sysmon": ["Process", "Network Traffic", "File", "Windows Registry"],
            "security": ["Logon Session", "Account"],
            "powershell": ["Script"],
            "winevent": ["Windows Event Log"],
        }
        return mapping.get(logsource.lower(), [])
    
    def search_by_keyword(self, keyword: str) -> List[str]:
        """Find technique IDs matching a keyword in name/description."""
        matches = []
        keyword_lower = keyword.lower()
        for tech_id, tech in self.techniques.items():
            if (keyword_lower in tech["name"].lower() or 
                keyword_lower in tech["description"].lower()):
                matches.append(tech_id)
        return matches


# ============================================================================
# normalization/narrative.py
# ============================================================================

from typing import List


class NarrativeGenerator:
    """Converts extracted rule + IoC context into behavioral narrative."""
    
    def __init__(self, mitre_client: MitreAttackClient, llm_client=None):
        self.mitre = mitre_client
        self.llm = llm_client
    
    def generate(self, rule: ExtractedRule, ioc_context: dict) -> BehavioralNarrative:
        """Generate narrative from rule extraction and IoC enrichment."""
        
        # Build structured prompt for LLM or template-based generation
        components = []
        
        # Title & description
        if rule.title:
            components.append(f"Rule title: {rule.title}")
        if rule.description:
            components.append(f"Description: {rule.description}")
        
        # Log source context
        if rule.logsource:
            components.append(f"Log source: {rule.logsource}")
            ds_constraints = self.mitre.get_data_source_constraints(rule.logsource)
            if ds_constraints:
                components.append(f"Detectable from data sources: {', '.join(ds_constraints)}")
        
        # IoC context
        if ioc_context.get("contexts"):
            components.append("Known threat intelligence context:")
            for ctx in ioc_context["contexts"]:
                components.append(f"  - {ctx}")
        
        # Extracted patterns
        if rule.search_patterns:
            components.append(f"Search patterns: {', '.join(rule.search_patterns[:5])}")
        
        # Build base narrative
        base_narrative = "\n".join(components)
        
        # If LLM available, refine into natural language
        if self.llm:
            narrative = self._llm_refine(base_narrative, rule)
        else:
            narrative = self._template_refine(base_narrative, rule)
        
        # Infer attack stage
        attack_stage = self._infer_attack_stage(narrative, rule)
        
        # Determine data sources
        data_sources = self._infer_data_sources(rule)
        
        return BehavioralNarrative(
            narrative=narrative,
            inferred_intent=self._extract_intent(narrative),
            attack_stage=attack_stage,
            data_sources=data_sources,
            mitigations=[]  # Could link to D3FEND
        )
    
    def _llm_refine(self, base_narrative: str, rule: ExtractedRule) -> str:
        """Use LLM to convert structured info into behavioral narrative."""
        prompt = f"""Convert this security detection rule into a clear behavioral narrative.
Describe what attacker behavior this rule detects, at what stage of the attack,
and what evidence it looks for.

{base_narrative}

Respond with only the narrative, 2-4 sentences, focused on the adversary action."""
        
        return self.llm.generate(prompt)
    
    def _template_refine(self, base_narrative: str, rule: ExtractedRule) -> str:
        """Fallback template-based narrative without LLM."""
        parts = []
        
        if rule.title:
            parts.append(f"This rule detects {rule.title.lower()}.")
        
        # Describe what it watches
        if rule.logsource:
            parts.append(f"It monitors {rule.logsource} telemetry.")
        
        # Describe IoCs
        if rule.iocs:
            ioc_desc = ", ".join(f"{ioc.type.value} '{ioc.value}'" for ioc in rule.iocs[:3])
            parts.append(f"It triggers on indicators including {ioc_desc}.")
        
        # Describe intent from description
        if rule.description:
            # Truncate and clean
            desc = rule.description[:200]
            parts.append(f"The detection intent is: {desc}")
        
        return " ".join(parts)
    
    def _infer_attack_stage(self, narrative: str, rule: ExtractedRule) -> Optional[str]:
        """Map narrative to attack stage using keywords."""
        stage_keywords = {
            "reconnaissance": ["recon", "scan", "enumerate", "discovery", "whoami", "systeminfo"],
            "initial_access": ["login", "phish", "exploit", "delivery", "macro", "spear"],
            "execution": ["execute", "run", "launch", "spawn", "shell", "script", "command"],
            "persistence": ["persist", "schedule", "service", "registry run", "startup", "wmi"],
            "privilege_escalation": ["elevate", "token", "uac bypass", "sudo", "impersonate"],
            "defense_evasion": ["evade", "hide", "obfuscate", "encode", "delete log", "clear"],
            "credential_access": ["credential", "password", "hash", "kerberos", "mimikatz", "dump"],
            "lateral_movement": ["lateral", "psexec", "wmiexec", "smbexec", "remote"],
            "collection": ["collect", "archive", "compress", "screenshot", "clipboard"],
            "exfiltration": ["exfil", "upload", "dns tunnel", "cloud sync", "transfer"],
            "impact": ["encrypt", "ransom", "wipe", "delete shadow", "destroy", "denial"]
        }
        
        narrative_lower = narrative.lower()
        for stage, keywords in stage_keywords.items():
            if any(kw in narrative_lower for kw in keywords):
                return stage
        
        # Fallback to tactic from tags
        for tag in rule.tags:
            if tag.startswith("attack."):
                return tag.replace("attack.", "")
        
        return None
    
    def _infer_data_sources(self, rule: ExtractedRule) -> List[str]:
        """Infer MITRE data sources from logsource and platform."""
        if not rule.logsource:
            return []
        return self.mitre.get_data_source_constraints(rule.logsource)
    
    def _extract_intent(self, narrative: str) -> Optional[str]:
        """Extract adversary intent from narrative."""
        # Simple heuristic: look for "to" phrases
        # In production, use NLP parsing
        return None


# ============================================================================
# inference/embedder.py
# ============================================================================

from sentence_transformers import SentenceTransformer
import numpy as np
from typing import List, Dict
import torch


class TechniqueEmbedder:
    """Embeds technique descriptions and rule narratives for similarity scoring."""
    
    def __init__(self, model_name: str = settings.EMBEDDING_MODEL):
        self.device = "cuda" if torch.cuda.is_available() else "cpu"
        self.model = SentenceTransformer(model_name, device=self.device)
        self.technique_embeddings: Dict[str, np.ndarray] = {}
        self._precompute_techniques()
    
    def _precompute_techniques(self):
        """Pre-compute embeddings for all ATT&CK techniques."""
        # This would load from MitreAttackClient
        pass  # Implementation depends on integration
    
    def embed_text(self, text: str) -> np.ndarray:
        """Embed arbitrary text."""
        return self.model.encode(text, convert_to_numpy=True)
    
    def embed_rule(self, rule: ExtractedRule, narrative: BehavioralNarrative) -> np.ndarray:
        """Create composite embedding for rule + narrative."""
        # Combine title, description, narrative, and IoCs
        texts = []
        if rule.title:
            texts.append(rule.title)
        if rule.description:
            texts.append(rule.description)
        texts.append(narrative.narrative)
        
        # Add IoC values as context
        for ioc in rule.iocs:
            texts.append(f"{ioc.type.value}: {ioc.value}")
        
        combined = " | ".join(texts)
        return self.embed_text(combined)
    
    def find_similar_techniques(
        self, 
        rule_embedding: np.ndarray, 
        top_k: int = 10
    ) -> List[Dict[str, Any]]:
        """Find most similar techniques by cosine similarity."""
        results = []
        for tech_id, tech_emb in self.technique_embeddings.items():
            similarity = np.dot(rule_embedding, tech_emb) / (
                np.linalg.norm(rule_embedding) * np.linalg.norm(tech_emb)
            )
            results.append({
                "technique_id": tech_id,
                "similarity": float(similarity)
            })
        
        results.sort(key=lambda x: x["similarity"], reverse=True)
        return results[:top_k]


# ============================================================================
# inference/reasoner.py
# ============================================================================

from typing import List, Dict, Any
import json


class TechniqueReasoner:
    """LLM-based chain-of-thought technique inference with validation."""
    
    def __init__(self, llm_client, mitre_client: MitreAttackClient):
        self.llm = llm_client
        self.mitre = mitre_client
    
    def infer(
        self,
        rule: ExtractedRule,
        narrative: BehavioralNarrative,
        ioc_results: Dict[str, Any],
        similar_techniques: List[Dict[str, Any]]
    ) -> List[TechniqueMapping]:
        """Multi-stage inference to map rule to techniques."""
        
        # Stage 1: Generate candidate pool
        candidates = self._generate_candidates(
            narrative, ioc_results, similar_techniques
        )
        
        # Stage 2: LLM reasoning with chain-of-thought
        reasoned = self._reason_candidates(rule, narrative, candidates)
        
        # Stage 3: Validate against MITRE definitions
        validated = self._validate_candidates(reasoned)
        
        return validated
    
    def _generate_candidates(
        self,
        narrative: BehavioralNarrative,
        ioc_results: Dict[str, Any],
        similar_techniques: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Pool all candidate techniques from multiple sources."""
        candidates = {}
        
        # From IoC resolution
        for tech_id in ioc_results.get("techniques", []):
            candidates[tech_id] = {
                "source": "ioc",
                "score": ioc_results["technique_scores"].get(tech_id, 1),
                "evidence": ioc_results.get("contexts", [])
            }
        
        # From embedding similarity
        for sim in similar_techniques:
            tech_id = sim["technique_id"]
            if tech_id in candidates:
                candidates[tech_id]["sources"].append("embedding")
                candidates[tech_id]["score"] += sim["similarity"] * 10
            else:
                candidates[tech_id] = {
                    "source": "embedding",
                    "score": sim["similarity"] * 10,
                    "evidence": [f"Semantic similarity: {sim['similarity']:.3f}"]
                }
        
        # From attack stage inference
        if narrative.attack_stage:
            stage_tactics = {
                "reconnaissance": ["TA0043"],
                "initial_access": ["TA0001"],
                "execution": ["TA0002"],
                "persistence": ["TA0003"],
                "privilege_escalation": ["TA0004"],
                "defense_evasion": ["TA0005"],
                "credential_access": ["TA0006"],
                "discovery": ["TA0007"],
                "lateral_movement": ["TA0008"],
                "collection": ["TA0009"],
                "exfiltration": ["TA0010"],
                "command_and_control": ["TA0011"],
                "impact": ["TA0040"]
            }
            # Could narrow candidates by tactic
        
        # From data source constraints
        for ds in narrative.data_sources:
            # Find techniques using this data source
            pass  # Would query MITRE CTI
        
        return list(candidates.values())
    
    def _reason_candidates(
        self,
        rule: ExtractedRule,
        narrative: BehavioralNarrative,
        candidates: List[Dict[str, Any]]
    ) -> List[TechniqueMapping]:
        """Use LLM to reason about which candidates actually apply."""
        
        # Build rich prompt
        candidate_str = "\n".join([
            f"- {c.get('technique_id', 'T????')}: score={c.get('score', 0):.2f}, "
            f"evidence={c.get('evidence', [])}"
            for c in candidates[:15]  # Top candidates only
        ])
        
        prompt = f"""You are a cybersecurity detection engineer mapping detection rules to MITRE ATT&CK.

Rule Information:
- Title: {rule.title or 'N/A'}
- Description: {rule.description or 'N/A'}
- Log Source: {rule.logsource or 'N/A'}
- Platform: {rule.platform or 'N/A'}

Behavioral Narrative:
{narrative.narrative}

Candidate Techniques (from automated analysis):
{candidate_str}

Task: Select the 1-4 most relevant MITRE ATT&CK techniques/sub-techniques for this rule.
For each selection, provide:
1. Technique ID (must be valid, e.g., T1059.001)
2. Confidence (0.0-1.0)
3. Reasoning based on specific rule elements

Rules:
- Be conservative. Only select if there is clear evidence.
- Prefer sub-techniques over parent techniques when possible.
- Consider the log source — some techniques cannot be detected from certain data.
- If uncertain, select fewer techniques with higher confidence.

Respond in JSON format:
{{
  "mappings": [
    {{
      "technique_id": "T1059.001",
      "confidence": 0.92,
      "reasoning": "Rule detects encoded PowerShell commands via -EncodedCommand flag, directly matching PowerShell sub-technique under Command and Scripting Interpreter",
      "is_primary": true
    }}
  ]
}}"""

        response = self.llm.generate(prompt, json_mode=True)
        parsed = json.loads(response)
        
        mappings = []
        for m in parsed.get("mappings", []):
            tech = self.mitre.get_technique(m["technique_id"])
            if tech:
                mappings.append(TechniqueMapping(
                    technique_id=m["technique_id"],
                    technique_name=tech["name"],
                    tactic=tech["tactics"][0] if tech["tactics"] else "unknown",
                    confidence=m["confidence"],
                    evidence=[m["reasoning"]],
                    is_primary=m.get("is_primary", False),
                    subtechnique_of=tech.get("parent")
                ))
        
        return mappings
    
    def _validate_candidates(self, candidates: List[TechniqueMapping]) -> List[TechniqueMapping]:
        """Final validation: check technique IDs exist, deduplicate, cap count."""
        valid = []
        seen = set()
        
        for c in candidates:
            # Verify technique exists in our MITRE data
            tech = self.mitre.get_technique(c.technique_id)
            if not tech:
                continue
            
            # Deduplicate
            if c.technique_id in seen:
                continue
            seen.add(c.technique_id)
            
            # Confidence threshold
            if c.confidence < 0.3:
                continue
            
            valid.append(c)
        
        # Sort by confidence, cap at max
        valid.sort(key=lambda x: x.confidence, reverse=True)
        return valid[:settings.MAX_TECHNIQUES_PER_RULE]


# ============================================================================
# core/pipeline.py
# ============================================================================

from typing import List, Optional, Callable
from concurrent.futures import ThreadPoolExecutor
import logging


class AttackMapperPipeline:
    """Main orchestration pipeline for rule→ATT&CK mapping."""
    
    def __init__(
        self,
        extractors: List[BaseExtractor] = None,
        mitre_client: Optional[MitreAttackClient] = None,
        ioc_resolver: Optional[IoCResolver] = None,
        narrative_gen: Optional[NarrativeGenerator] = None,
        embedder: Optional[TechniqueEmbedder] = None,
        reasoner: Optional[TechniqueReasoner] = None,
        llm_client = None
    ):
        self.extractors = extractors or self._default_extractors()
        self.mitre = mitre_client or MitreAttackClient()
        self.ioc_resolver = ioc_resolver or IoCResolver()
        self.narrative_gen = narrative_gen or NarrativeGenerator(self.mitre, llm_client)
        self.embedder = embedder or TechniqueEmbedder()
        self.reasoner = reasoner or TechniqueReasoner(llm_client, self.mitre)
        self.llm = llm_client
        
        self.logger = logging.getLogger(__name__)
    
    def _default_extractors(self) -> List[BaseExtractor]:
        from .extractors.sigma import SigmaExtractor
        from .extractors.splunk import SplunkExtractor
        from .extractors.kql import KQLExtractor
        from .extractors.generic import GenericExtractor
        return [
            SigmaExtractor(),
            SplunkExtractor(),
            KQLExtractor(),
            GenericExtractor()  # Fallback
        ]
    
    def process_rule(self, raw_content: str, source_path: Optional[str] = None) -> MappedRule:
        """Process a single rule through the full pipeline."""
        steps = []
        
        # Step 1: Extract
        extractor = self._find_extractor(raw_content)
        if not extractor:
            raise ExtractionError("No suitable extractor found for rule format")
        
        rule = extractor.extract(raw_content, source_path)
        steps.append({"step": "extract", "extractor": extractor.format.value})
        
        # Step 2: IoC Enrichment
        ioc_results = self.ioc_resolver.resolve_batch(rule.iocs)
        steps.append({
            "step": "ioc_enrichment",
            "techniques_found": ioc_results["techniques"],
            "confidence_boost": ioc_results["confidence_boost"]
        })
        
        # Step 3: Narrative Generation
        narrative = self.narrative_gen.generate(rule, ioc_results)
        steps.append({"step": "narrative", "attack_stage": narrative.attack_stage})
        
        # Step 4: Embedding Similarity
        rule_emb = self.embedder.embed_rule(rule, narrative)
        similar = self.embedder.find_similar_techniques(rule_emb)
        steps.append({"step": "embedding", "top_similar": [s["technique_id"] for s in similar[:5]]})
        
        # Step 5: LLM Reasoning
        mappings = self.reasoner.infer(rule, narrative, ioc_results, similar)
        steps.append({
            "step": "reasoning",
            "mappings_count": len(mappings),
            "primary": next((m.technique_id for m in mappings if m.is_primary), None)
        })
        
        # Step 6: Quality Assessment & Validation Status
        overall_conf, review_required, review_reason = self._assess_quality(
            rule, mappings, ioc_results
        )
        
        return MappedRule(
            rule=rule,
            narrative=narrative,
            mappings=mappings,
            overall_confidence=overall_conf,
            validation_status=(
                ValidationStatus.AUTOMATED_INFERRED if review_required 
                else ValidationStatus.AUTOMATED_VALIDATED
            ),
            human_review_required=review_required,
            review_reason=review_reason,
            pipeline_version="1.0.0",
            processing_steps=steps
        )
    
    def _find_extractor(self, raw_content: str) -> Optional[BaseExtractor]:
        """Find first extractor that can handle this content."""
        for ext in self.extractors:
            if ext.can_extract(raw_content):
                return ext
        return None
    
    def _assess_quality(
        self,
        rule: ExtractedRule,
        mappings: List[TechniqueMapping],
        ioc_results: Dict[str, Any]
    ) -> tuple[float, bool, Optional[str]]:
        """Determine if mapping needs human review."""
        
        if not mappings:
            return 0.0, True, "No techniques inferred"
        
        # Confidence-based
        max_conf = max(m.confidence for m in mappings)
        if max_conf < settings.MIN_CONFIDENCE_FOR_AUTO:
            return max_conf, True, f"Max confidence {max_conf:.2f} below threshold {settings.MIN_CONFIDENCE_FOR_AUTO}"
        
        # Evidence-based
        primary = next((m for m in mappings if m.is_primary), mappings[0])
        if len(primary.evidence) < settings.MIN_EVIDENCE_COUNT:
            return max_conf, True, "Insufficient evidence for primary mapping"
        
        # Conflict detection: IoC says one thing, embedding says another
        ioc_techs = set(ioc_results.get("techniques", []))
        mapping_techs = {m.technique_id for m in mappings}
        if ioc_techs and not ioc_techs.intersection(mapping_techs):
            return max_conf, True, f"IoC techniques {ioc_techs} diverge from inferred {mapping_techs}"
        
        # Pre-existing tag mismatch
        for tag in rule.tags:
            if tag.startswith("attack.t"):
                existing_id = tag.replace("attack.", "").upper()
                if existing_id not in mapping_techs:
                    return max_conf, True, f"Pre-existing tag {existing_id} not in inferred mappings"
        
        return max_conf, False, None
    
    def process_batch(
        self,
        rules: List[tuple[str, Optional[str]]],
        callback: Optional[Callable[[MappedRule], None]] = None
    ) -> List[MappedRule]:
        """Process multiple rules with parallelization."""
        results = []
        
        with ThreadPoolExecutor(max_workers=settings.PARALLEL_WORKERS) as executor:
            futures = [
                executor.submit(self.process_rule, content, path)
                for content, path in rules
            ]
            for future in futures:
                try:
                    result = future.result()
                    results.append(result)
                    if callback:
                        callback(result)
                except Exception as e:
                    self.logger.error(f"Pipeline failed: {e}")
                    # Could append error result
        
        return results
    
    def analyze_coverage(self, mapped_rules: List[MappedRule]) -> List[CoverageGap]:
        """Identify coverage gaps from a set of mapped rules."""
        covered = set()
        for mr in mapped_rules:
            for m in mr.mappings:
                if m.confidence >= settings.MIN_CONFIDENCE_FOR_AUTO:
                    covered.add(m.technique_id)
        
        # Compare against priority techniques (from threat intel)
        # This would integrate with your threat actor profiles
        gaps = []
        # Implementation depends on organizational threat model
        
        return gaps


# ============================================================================
# output/formatter.py
# ============================================================================

import json


class OutputFormatter:
    """Format mapped rules for various consumers."""
    
    def to_sigma_tags(self, mapped: MappedRule) -> List[str]:
        """Generate Sigma-style tags from mapping."""
        tags = []
        for m in mapped.mappings:
            tags.append(f"attack.{m.tactic}")
            tags.append(f"attack.{m.technique_id.lower()}")
        return list(dict.fromkeys(tags))  # Preserve order, dedupe
    
    def to_navigator_layer(self, mapped_rules: List[MappedRule]) -> dict:
        """Generate ATT&CK Navigator layer JSON."""
        techniques = {}
        for mr in mapped_rules:
            for m in mr.mappings:
                tid = m.technique_id
                if tid not in techniques:
                    techniques[tid] = {
                        "techniqueID": tid,
                        "score": 0,
                        "comment": []
                    }
                techniques[tid]["score"] += 1
                techniques[tid]["comment"].append(mr.rule.title or "Untitled")
        
        return {
            "name": "Detection Coverage",
            "versions": {
                "attack": "16",
                "navigator": "5.1.0",
                "layer": "4.5"
            },
            "domain": "enterprise-attack",
            "techniques": [
                {
                    **v,
                    "comment": " | ".join(v["comment"][:5])
                }
                for v in techniques.values()
            ],
            "gradient": {
                "colors": ["#ffffff", "#66b1ff", "#ff6666"],
                "minValue": 0,
                "maxValue": max((t["score"] for t in techniques.values()), default=1)
            }
        }
    
    def to_jsonl(self, mapped_rules: List[MappedRule], path: str):
        """Export as JSONL for downstream processing."""
        with open(path, 'w') as f:
            for mr in mapped_rules:
                f.write(json.dumps(mr.model_dump(), default=str) + "\n")


# ============================================================================
# scripts/ingest_rules.py  (CLI entry point)
# ============================================================================

"""
#!/usr/bin/env python3
\"\"\"Batch ingest and map rules from directory or file.\"\"\"

import argparse
import os
import glob
from attack_mapper.core.pipeline import AttackMapperPipeline
from attack_mapper.output.formatter import OutputFormatter


def main():
    parser = argparse.ArgumentParser(description="Map detection rules to MITRE ATT&CK")
    parser.add_argument("input", help="Input file or directory")
    parser.add_argument("-o", "--output", default="mapped_rules.jsonl")
    parser.add_argument("--navigator", help="Output ATT&CK Navigator layer JSON")
    parser.add_argument("--format", choices=["auto", "sigma", "splunk", "kql"], default="auto")
    args = parser.parse_args()
    
    # Collect rules
    rules = []
    if os.path.isdir(args.input):
        patterns = ["*.yml", "*.yaml", "*.spl", "*.kusto", "*.txt"]
        for pattern in patterns:
            for path in glob.glob(os.path.join(args.input, "**", pattern), recursive=True):
                with open(path) as f:
                    rules.append((f.read(), path))
    else:
        with open(args.input) as f:
            rules.append((f.read(), args.input))
    
    # Run pipeline
    pipeline = AttackMapperPipeline()
    results = pipeline.process_batch(rules)
    
    # Export
    formatter = OutputFormatter()
    formatter.to_jsonl(results, args.output)
    
    if args.navigator:
        layer = formatter.to_navigator_layer(results)
        with open(args.navigator, 'w') as f:
            json.dump(layer, f, indent=2)
    
    # Stats
    total = len(results)
    reviewed = sum(1 for r in results if r.human_review_required)
    mapped = sum(1 for r in results if r.mappings)
    print(f"Processed: {total}")
    print(f"With mappings: {mapped}")
    print(f"Flagged for review: {reviewed} ({reviewed/total*100:.1f}%)")


if __name__ == "__main__":
    main()
"""


# ============================================================================
# requirements.txt
# ============================================================================

"""
pydantic>=2.0
pydantic-settings>=2.0
sentence-transformers>=2.2.0
torch>=2.0
numpy>=1.24
requests>=2.31
pyyaml>=6.0
openai>=1.0
anthropic>=0.18
python-dotenv>=1.0
"""


# ============================================================================
# pyproject.toml
# ============================================================================

"""
[build-system]
requires = ["setuptools>=61.0", "wheel"]
build-backend = "setuptools.build_meta"

[project]
name = "attack-mapper"
version = "1.0.0"
description = "Generalisable MITRE ATT&CK detection rule mapper"
requires-python = ">=3.10"
dependencies = [
    "pydantic>=2.0",
    "pydantic-settings>=2.0",
    "sentence-transformers>=2.2.0",
    "torch>=2.0",
    "numpy>=1.24",
    "requests>=2.31",
    "pyyaml>=6.0",
    "openai>=1.0",
    "anthropic>=0.18",
    "python-dotenv>=1.0",
]

[project.scripts]
attack-mapper = "attack_mapper.scripts.ingest_rules:main"
"""


# ============================================================================
# README.md (key sections)
# ============================================================================

"""
# Attack Mapper

Generalisable MITRE ATT&CK mapping for any detection ruleset.

## Architecture

1. **Extract** — Parse rule syntax (Sigma, SPL, KQL, etc.) into behavioral indicators
2. **Enrich** — Resolve IoCs to known technique associations via threat intel
3. **Narrate** — Convert structured rule into behavioral narrative (LLM or template)
4. **Embed** — Compute semantic similarity between narrative and all ATT&CK techniques
5. **Reason** — LLM chain-of-thought selects final techniques with confidence
6. **Validate** — Cross-check against MITRE definitions, flag low-confidence for review

## Usage

```bash
# Single rule
python -m attack_mapper.scripts.ingest_rules path/to/rule.yml

# Batch directory
python -m attack_mapper.scripts.ingest_rules ./rules/ -o output.jsonl --navigator layer.json

# As library
from attack_mapper.core.pipeline import AttackMapperPipeline

pipeline = AttackMapperPipeline()
result = pipeline.process_rule(open("rule.yml").read())
print(result.mappings)
```

## Extending

Add new extractors by subclassing `BaseExtractor`. The pipeline auto-detects format.

## Validation

Ground truth validation:
```bash
python -m attack_mapper.scripts.validate_maps --ground-truth labels.jsonl --predictions output.jsonl
```
"""
```
