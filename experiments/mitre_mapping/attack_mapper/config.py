"""
Pipeline settings. Plain dataclass, not pydantic-settings -- that package
isn't installed in this environment and a settings dataclass with hardcoded
defaults is all six knobs below need.
"""
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Settings:
    # Confidence thresholds
    min_confidence_for_auto: float = 0.85
    max_techniques_per_rule: int = 4

    # Effort 4's ET+Sigma-trained Tier 2 classifier (classifier_resolver.py),
    # stacked in as a candidate source between the high-precision IoC/bridge
    # sources and the embedding fallback -- see ../STATUS.md and
    # ../findings.md for the standalone numbers (38.0% top-1, vs. embedding's
    # 0.0% in the same breakdown) that motivate this ordering.
    classifier_confidence_cap: float = 0.5

    # kNN retrieval over the labeled ET+Sigma corpus (knn_resolver.py), the
    # lowest-priority source. Replaced the old zero-shot embedding layer, which
    # compared rule text against MITRE *description* prose and measured 4.5%
    # top-1 on the 500-row set; retrieving against labeled *rule text* instead
    # measures 36.3% micro / 19.7% macro standalone. Still capped below the
    # classifier, since it only fires where everything above found nothing.
    embedding_model: str = "sentence-transformers/all-MiniLM-L6-v2"
    knn_confidence_cap: float = 0.45

    # LLM reasoning layer (optional; see llm_client.py). No provider is
    # configured by default -- there is no API key anywhere in this
    # environment, so the reasoner runs in template-only mode unless a
    # client is explicitly passed in.
    llm_provider: Optional[str] = None

    # Layer D gating (see STATUS.md "effort 6"): effort 6 found the LLM
    # reprocessing every row and fully overriding prior confidence caused a
    # 20-point regression (53.8% -> 33.8%). Layer D now only fires when the
    # best prior candidate's confidence is below this threshold -- i.e. rows
    # that fell through to tier2_combined/embedding, not ones already
    # answered with high precision by declared/ioc_alias -- and blends
    # rather than replaces confidence (see reasoner._llm_refine).
    llm_gate_confidence: float = 0.5
