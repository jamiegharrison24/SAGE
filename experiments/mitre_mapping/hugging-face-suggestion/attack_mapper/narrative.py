"""
Template-based narrative generation (Phase 3 of the HF plan, "LLM or
template" fallback path). This is the *working default* in this experiment:
no LLM provider is configured anywhere in this environment (see
`llm_client.py`), so every narrative produced by `pipeline.py` today comes
from here, not from an LLM. `pipeline.py` records which path ran in
`MappedRule.processing_steps`.

Reuses `../tiered_approach/normalize.py`'s canonicalization (vendor-prefix
strip, entity placeholders, abbreviation expansion) rather than
reimplementing it -- that file's docstring is explicit that normalization
"moves the numbers more than most model tuning".
"""
import os
import sys

from .models import BehavioralNarrative, ExtractedRule

HERE = os.path.dirname(os.path.abspath(__file__))
TIERED_DIR = os.path.normpath(os.path.join(HERE, "..", "..", "tiered_approach"))
if TIERED_DIR not in sys.path:
    sys.path.insert(0, TIERED_DIR)

from normalize import canonicalize  # noqa: E402

_STAGE_KEYWORDS = {
    "reconnaissance": ["recon", "scan", "enumerate", "discovery", "whoami", "systeminfo"],
    "initial_access": ["login", "phish", "exploit", "delivery", "macro"],
    "execution": ["execute", "shell", "script", "command", "rce"],
    "persistence": ["persist", "schedule", "service", "startup"],
    "privilege_escalation": ["privilege", "escalation", "uac", "sudo"],
    "defense_evasion": ["evade", "obfuscate", "encode", "clear log"],
    "credential_access": ["credential", "password", "hash", "brute force"],
    "discovery": ["enumeration", "discovery", "scan"],
    "lateral_movement": ["lateral", "psexec", "smb", "remote desktop"],
    "collection": ["collect", "capture", "sniff"],
    "exfiltration": ["exfiltration", "upload", "tunnel"],
    "command_and_control": ["command and control", "c2", "cnc", "beacon"],
    "impact": ["denial of service", "ransom", "wipe", "destroy"],
}


def generate(rule: ExtractedRule, ioc_evidence: list) -> BehavioralNarrative:
    parts = []
    if rule.title:
        parts.append(f"Detects: {canonicalize(rule.title)}.")
    if rule.logsource:
        parts.append(f"Log source: {rule.logsource}.")
    if rule.body_matched and rule.search_patterns:
        sample = ", ".join(rule.search_patterns[:3])
        parts.append(f"Matches on: {sample}.")
    if ioc_evidence:
        parts.append("Known context: " + "; ".join(ioc_evidence[:3]) + ".")
    if rule.micro_attack_stage:
        parts.append(f"SAGE's existing stage classification: {rule.micro_attack_stage}.")

    narrative_text = " ".join(parts) if parts else canonicalize(rule.raw_content[:200])
    stage = _infer_stage(narrative_text)

    return BehavioralNarrative(
        narrative=narrative_text,
        attack_stage=stage,
        data_source_hints=[rule.logsource] if rule.logsource else [],
    )


def _infer_stage(text: str) -> str:
    lowered = text.lower()
    for stage, keywords in _STAGE_KEYWORDS.items():
        if any(kw in lowered for kw in keywords):
            return stage
    return "unknown"
