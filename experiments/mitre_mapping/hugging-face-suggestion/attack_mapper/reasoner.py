"""
Candidate fusion (Phase 4/5 of the HF plan) -- picks final TechniqueMapping
objects from the sources `pipeline.py` gathers, in priority order:

  1. declared   -- Tier 0: the rule format's own ATT&CK tag (ET metadata,
                   Sigma `attack.txxxx` tags). ~100% precision when present.
  2. ioc_alias / bridge_table -- Layer C / SAGE-internal-intel, from
                   `ioc_resolver.py`. High precision, narrow recall.
  3. tier2_combined -- effort 4's ET+Sigma-trained classifier, from
                   `classifier_resolver.py`. Standalone 38.0% top-1 (see
                   ../STATUS.md) -- weaker than the sources above, stronger
                   than raw embedding similarity, so it sits between them.
  4. embedding  -- Layer A, from `embedder.py`. Low precision fallback, only
                   used when nothing above fired, and capped at
                   `Settings.embedding_confidence_cap` (see its docstring
                   for why: known ~6-8% top-1 on this corpus).
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
        similar: List[dict],
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
                    candidates, tid, conf, "tier2_combined",
                    f"ET+Sigma classifier margin: {pred['score']:.3f}",
                )

        if not candidates:
            for sim in similar:
                tid = sim["technique_id"]
                if not self.mitre.exists(tid):
                    continue
                conf = min(max(sim["similarity"], 0.0), 1.0) * self.settings.embedding_confidence_cap
                self._add(candidates, tid, conf, "embedding", f"semantic similarity: {sim['similarity']:.3f}")

        if self.llm.is_configured and candidates:
            candidates = self._llm_refine(rule, narrative, candidates, steps)
        else:
            steps.append({"step": "llm_reasoning", "status": "skipped", "reason": "no LLM client configured"})

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
        """Chain-of-thought validation over the candidate pool. Untested in
        this environment (no LLM configured) -- exercised only when a real
        client is wired in via AttackMapperPipeline(llm_client=...)."""
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

        refined: Dict[str, dict] = {}
        for m in parsed.get("mappings", []):
            tid = m.get("technique_id")
            if not tid or not self.mitre.exists(tid):
                continue
            refined[tid] = {
                "confidence": float(m.get("confidence", 0.0)),
                "source": "llm",
                "evidence": [m.get("reasoning", "")],
            }
        steps.append({"step": "llm_reasoning", "status": "ok", "kept": list(refined.keys())})
        return refined or candidates
