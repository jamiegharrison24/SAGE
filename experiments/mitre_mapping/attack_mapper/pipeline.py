"""
Main orchestration (Phase "Implementation Architecture" in the HF plan).
Ties extractors -> IoC resolution -> narrative -> ET+Sigma classifier ->
embedding fallback -> reasoning into one `MappedRule` per rule, with a full
`processing_steps` audit trail -- the piece the user flagged as critical for
debugging why a mapping was chosen.
"""
import time
from typing import List, Optional

from .classifier_resolver import ClassifierResolver
from .config import Settings
from .embedder import TechniqueEmbedder
from .extractors import DEFAULT_EXTRACTORS, BaseExtractor
from .ioc_resolver import IoCResolver
from .llm_client import LLMClient, default_client
from . import narrative as narrative_mod
from .mitre_client import MitreAttackClient
from .models import ExtractedRule, MappedRule, ValidationStatus
from .reasoner import TechniqueReasoner


class ExtractionError(Exception):
    pass


class AttackMapperPipeline:
    def __init__(
        self,
        extractors: Optional[List[BaseExtractor]] = None,
        mitre_client: Optional[MitreAttackClient] = None,
        ioc_resolver: Optional[IoCResolver] = None,
        embedder: Optional[TechniqueEmbedder] = None,
        classifier: Optional[ClassifierResolver] = None,
        llm_client: Optional[LLMClient] = None,
        settings: Optional[Settings] = None,
        use_embedder: bool = True,
        use_classifier: bool = True,
    ):
        self.extractors = extractors or DEFAULT_EXTRACTORS
        self.settings = settings or Settings()
        self.mitre = mitre_client or MitreAttackClient()
        self.ioc_resolver = ioc_resolver or IoCResolver()
        self.llm = llm_client or default_client()
        self.embedder = embedder or (TechniqueEmbedder(self.mitre) if use_embedder else None)
        self.classifier = classifier or (ClassifierResolver() if use_classifier else None)
        self.reasoner = TechniqueReasoner(self.mitre, self.llm, self.settings)

    def process_rule(
        self,
        raw_content: str,
        source_path: Optional[str] = None,
        micro_attack_stage: Optional[str] = None,
    ) -> MappedRule:
        steps = []
        t0 = time.monotonic()

        extractor = self._find_extractor(raw_content)
        if extractor is None:
            raise ExtractionError("No extractor matched (GenericExtractor should always match)")
        rule = extractor.extract(raw_content, source_path)
        if micro_attack_stage:
            rule = rule.model_copy(update={"micro_attack_stage": micro_attack_stage})
        steps.append({
            "step": "extract",
            "extractor": extractor.format.value,
            "body_matched": rule.body_matched,
            "declared_technique_ids": rule.declared_technique_ids,
        })

        ioc_result = self.ioc_resolver.resolve(rule)
        steps.append({
            "step": "ioc_resolve",
            "source": ioc_result["source"],
            "techniques": ioc_result["techniques"],
        })

        bn = narrative_mod.generate(rule, ioc_result["evidence"])
        steps.append({"step": "narrative", "attack_stage": bn.attack_stage, "generator": "template"})

        higher_priority_fired = bool(rule.declared_technique_ids or ioc_result["techniques"])

        classifier_predictions = []
        if self.classifier is not None and not higher_priority_fired:
            classifier_predictions = self.classifier.predict(rule.title or rule.raw_content)
            steps.append({
                "step": "classifier",
                "model": "tier2_combined (ET+Sigma)",
                "top": [p["technique_id"] for p in classifier_predictions],
            })
        else:
            classifier_skip_reason = (
                "higher-priority source already fired" if higher_priority_fired
                else "no classifier configured"
            )
            steps.append({"step": "classifier", "status": "skipped", "reason": classifier_skip_reason})

        similar = []
        if self.embedder is not None and not higher_priority_fired and not classifier_predictions:
            similar = self.embedder.find_similar(bn.narrative)
            steps.append({"step": "embedding", "top": [s["technique_id"] for s in similar[:5]]})
        else:
            if self.embedder is None:
                reason = "no embedder configured"
            elif higher_priority_fired:
                reason = "higher-priority source already fired"
            else:
                reason = "classifier already answered"
            steps.append({"step": "embedding", "status": "skipped", "reason": reason})

        mappings = self.reasoner.infer(rule, bn, ioc_result, similar, steps, classifier_predictions)

        overall_conf, review_required, reason = self._assess(mappings)
        steps.append({
            "step": "quality_assessment",
            "overall_confidence": overall_conf,
            "human_review_required": review_required,
            "elapsed_ms": round((time.monotonic() - t0) * 1000, 1),
        })

        return MappedRule(
            rule=rule,
            narrative=bn,
            mappings=mappings,
            overall_confidence=overall_conf,
            validation_status=(
                ValidationStatus.AUTOMATED_INFERRED if review_required
                else ValidationStatus.AUTOMATED_VALIDATED
            ),
            human_review_required=review_required,
            review_reason=reason,
            processing_steps=steps,
        )

    def process_batch(self, rules: List[tuple]) -> List[MappedRule]:
        """rules: list of (raw_content, source_path, micro_attack_stage)."""
        out = []
        for item in rules:
            raw_content, source_path, stage = (list(item) + [None, None])[:3]
            out.append(self.process_rule(raw_content, source_path, stage))
        return out

    def _find_extractor(self, raw_content: str) -> Optional[BaseExtractor]:
        for ext in self.extractors:
            if ext.can_extract(raw_content):
                return ext
        return None

    def _assess(self, mappings) -> tuple:
        if not mappings:
            return 0.0, True, "no techniques inferred"
        top = mappings[0]
        if top.confidence < self.settings.min_confidence_for_auto:
            return top.confidence, True, (
                f"top confidence {top.confidence:.2f} below threshold "
                f"{self.settings.min_confidence_for_auto}"
            )
        return top.confidence, False, None
