"""
Candidate fusion (Phase 4/5 of the HF plan) -- picks final TechniqueMapping
objects from the sources `pipeline.py` gathers, in priority order:

  1. declared   -- Tier 0: the rule format's own ATT&CK tag (ET metadata,
                   Sigma `attack.txxxx` tags). ~100% precision when present.
  2. ioc_alias  -- Layer C, from `ioc_resolver.py`'s tool/malware alias
                   table. High precision, narrow recall.
  3. supervised_classifier -- the live-trained dual TF-IDF + LinearSVC
                   classifier, from `classifier_resolver.py`. Standalone 38.0%
                   top-1 (see ../STATUS.md) -- weaker than the sources above,
                   stronger than raw similarity, so it sits between them.
                   **Renamed from `tier2_combined`** (2026-09-11): "tier2" was
                   its slot in the archived Tier 0-4 approach and "combined"
                   meant the ET+Sigma corpus, so by effort 12 neither half of
                   the name described it. Docs written before that date, and
                   `validation_report_llm.md`, still use the old name for
                   results measured under it.
  4. knn_corpus -- nearest-neighbour retrieval over the labeled ET+Sigma
                   corpus, from `knn_resolver.py`. Replaced the old zero-shot
                   `embedding` layer, which compared rule text against MITRE
                   *description* prose and measured 4.5% top-1 on the 500-row
                   set; retrieving against labeled rule text instead measures
                   36.3% micro / 19.7% macro standalone. Capped at
                   `Settings.knn_confidence_cap`.
  5. llm        -- Layer D, only if `llm_client.is_configured`. Skipped (and
                   logged as skipped) otherwise -- see llm_client.py.

Fixes two bugs in the HF sketch's `_generate_candidates`/`_reason_candidates`:
the sketch built `list(candidates.values())`, dropping the technique_id key
that `_reason_candidates` then needed (rendering every candidate as
`T????` in the LLM prompt); and it appended to a `"sources"` list on a dict
that was initialized with `"source"` (singular), which raises `KeyError` the
first time an IoC and an embedding candidate collide on the same technique.
Here candidates are keyed by technique_id throughout and evidence is
accumulated on one consistent list field.
"""
import json
import math
from typing import Dict, List, Optional

from .config import Settings
from .llm_client import LLMClient
from .mitre_client import MitreAttackClient
from .models import BehavioralNarrative, ExtractedRule, TechniqueMapping


def _sigmoid(x: float) -> float:
    return 1.0 / (1.0 + math.exp(-x))


class TechniqueReasoner:
    def __init__(self, mitre_client: MitreAttackClient, llm_client: LLMClient, settings: Settings):
        self.mitre = mitre_client
        self.llm = llm_client
        self.settings = settings

    def infer(
        self,
        rule: ExtractedRule,
        narrative: BehavioralNarrative,
        ioc_result: dict,
        knn_predictions: List[dict],
        steps: List[dict],
        classifier_predictions: Optional[List[dict]] = None,
    ) -> List[TechniqueMapping]:
        candidates: Dict[str, dict] = {}

        for tid in rule.declared_technique_ids:
            if not self.mitre.exists(tid):
                continue
            self._add(candidates, tid, 1.0, "declared", "rule format's own ATT&CK tag")

        if not candidates and ioc_result.get("techniques"):
            for tid in ioc_result["techniques"]:
                if not self.mitre.exists(tid):
                    continue
                for ev in ioc_result["evidence"]:
                    self._add(candidates, tid, ioc_result["confidence"], ioc_result["source"], ev)

        if not candidates and classifier_predictions:
            for pred in classifier_predictions:
                tid = pred["technique_id"]
                if not self.mitre.exists(tid):
                    continue
                conf = _sigmoid(pred["score"]) * self.settings.classifier_confidence_cap
                self._add(
                    candidates, tid, conf, "supervised_classifier",
                    f"ET+Sigma classifier margin: {pred['score']:.3f}",
                )

        if not candidates:
            for pred in knn_predictions:
                tid = pred["technique_id"]
                if not self.mitre.exists(tid):
                    continue
                conf = min(max(pred["confidence"], 0.0), 1.0) * self.settings.knn_confidence_cap
                self._add(candidates, tid, conf, "knn_corpus", pred["evidence"])

        top_confidence = max((c["confidence"] for c in candidates.values()), default=0.0)
        if self.llm.is_configured and candidates and top_confidence < self.settings.llm_gate_confidence:
            candidates = self._llm_refine(rule, narrative, candidates, steps)
        elif not self.llm.is_configured:
            steps.append({"step": "llm_reasoning", "status": "skipped", "reason": "no LLM client configured"})
        else:
            steps.append({
                "step": "llm_reasoning", "status": "skipped",
                "reason": f"top prior confidence {top_confidence:.2f} >= gate {self.settings.llm_gate_confidence:.2f}",
            })

        mappings = [
            TechniqueMapping(
                technique_id=tid,
                technique_name=self.mitre.get_name(tid),
                tactics=self.mitre.get_tactics(tid),
                confidence=min(c["confidence"], 1.0),
                source=c["source"],
                evidence=c["evidence"],
            )
            for tid, c in candidates.items()
        ]
        mappings.sort(key=lambda m: m.confidence, reverse=True)
        mappings = mappings[: self.settings.max_techniques_per_rule]
        if mappings:
            mappings[0].is_primary = True
        return mappings

    @staticmethod
    def _add(candidates: Dict[str, dict], tid: str, confidence: float, source: str, evidence: str):
        entry = candidates.setdefault(tid, {"confidence": 0.0, "source": source, "evidence": []})
        entry["confidence"] = max(entry["confidence"], confidence)
        entry["evidence"].append(evidence)

    def _llm_refine(
        self,
        rule: ExtractedRule,
        narrative: BehavioralNarrative,
        candidates: Dict[str, dict],
        steps: List[dict],
    ) -> Dict[str, dict]:
        """Chain-of-thought validation over the candidate pool. Only called
        when the prior top confidence is below `Settings.llm_gate_confidence`
        (see `infer`) -- effort 6 found that reprocessing every row and fully
        replacing confidence caused a 20-point regression. Blends rather than
        replaces: a technique the LLM confirms gets its confidence averaged
        with the prior, not overwritten; a prior candidate the LLM doesn't
        mention is kept as-is rather than dropped; a technique the LLM
        proposes that wasn't already a candidate is added at its own
        confidence."""
        candidate_lines = "\n".join(
            f"- {tid}: prior_confidence={c['confidence']:.2f}, evidence={c['evidence']}"
            for tid, c in candidates.items()
        )
        prompt = f"""You are a detection engineer mapping a rule to MITRE ATT&CK.

Rule title: {rule.title or 'N/A'}
Behavioral narrative: {narrative.narrative}

Candidate techniques:
{candidate_lines}

Select which candidates are actually correct, adjust confidence (0-1), and
add one sentence of reasoning each. Respond as JSON:
{{"mappings": [{{"technique_id": "T1190", "confidence": 0.9, "reasoning": "..."}}]}}"""

        try:
            raw = self.llm.generate(prompt, json_mode=True)
            parsed = json.loads(raw)
        except Exception as exc:
            steps.append({"step": "llm_reasoning", "status": "error", "error": str(exc)})
            return candidates

        blended: Dict[str, dict] = dict(candidates)
        for m in parsed.get("mappings", []):
            tid = m.get("technique_id")
            if not tid or not self.mitre.exists(tid):
                continue
            llm_conf = float(m.get("confidence", 0.0))
            reasoning = m.get("reasoning", "")
            prior = candidates.get(tid)
            if prior is None:
                blended[tid] = {"confidence": llm_conf, "source": "llm", "evidence": [reasoning]}
            else:
                blended[tid] = {
                    "confidence": (prior["confidence"] + llm_conf) / 2,
                    "source": f"{prior['source']}+llm",
                    "evidence": prior["evidence"] + [reasoning],
                }
        steps.append({"step": "llm_reasoning", "status": "ok", "blended": list(blended.keys())})
        return blended
