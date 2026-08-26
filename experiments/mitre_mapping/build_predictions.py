"""
Embeds every MITRE ATT&CK Enterprise technique (name + description, from
techniques.json produced by fetch_techniques.py) with basel/ATTACK-BERT, then
embeds every unique Suricata signature string in signatures/alert_signatures.py
the same way and reports the top-3 closest techniques by cosine similarity.

Also runs the same top-3 lookup over the signatures that appear in the raw
alert corpora but are NOT covered by signatures/alert_signatures.py (i.e. the
ones alert_loading.py silently defaults to NON_MALICIOUS -- see
coverage_check.py / uncovered_signatures.txt), and appends them to the same
predictions.csv as a second, separately labeled section.

Writes experiments/mitre_mapping/predictions.csv with two sections:
    signature, predicted_technique_1, score_1, predicted_technique_2, score_2,
    predicted_technique_3, score_3
  followed by a blank line, an "# uncovered" marker row, a repeated header,
  then the same columns for the uncovered signatures.

Standalone -- does not touch the production pipeline.

Usage: python3 experiments/mitre_mapping/build_predictions.py
"""
import csv
import json
import os
import sys

import numpy as np
from sentence_transformers import SentenceTransformer

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, REPO_ROOT)

import signatures.alert_signatures as sig_module  # noqa: E402

TECHNIQUES_JSON = os.path.join(HERE, "techniques.json")
UNCOVERED_TXT = os.path.join(HERE, "uncovered_signatures.txt")
PREDICTIONS_CSV = os.path.join(HERE, "predictions.csv")
MODEL_NAME = "basel/ATTACK-BERT"
TOP_K = 3

FIELDNAMES = ["signature"]
for _rank in range(1, TOP_K + 1):
    FIELDNAMES += [f"predicted_technique_{_rank}", f"score_{_rank}"]


def unique_signatures():
    """Union of every string key/entry across all signature containers in
    signatures/alert_signatures.py (dicts and lists), excluding
    attack_stage_mapping whose keys are MicroAttackStage enums, not strings."""
    all_sigs = set()
    for name in dir(sig_module):
        if name.startswith("_") or name == "attack_stage_mapping":
            continue
        value = getattr(sig_module, name)
        if isinstance(value, dict):
            all_sigs |= {k for k in value.keys() if isinstance(k, str)}
        elif isinstance(value, list):
            all_sigs |= {x for x in value if isinstance(x, str)}
    return sorted(all_sigs)


def load_uncovered_signatures():
    if not os.path.exists(UNCOVERED_TXT):
        raise FileNotFoundError(
            f"{UNCOVERED_TXT} not found -- run coverage_check.py first to generate it."
        )
    with open(UNCOVERED_TXT, "r") as fh:
        return sorted(line.rstrip("\n") for line in fh if line.strip())


def load_techniques():
    with open(TECHNIQUES_JSON, "r") as fh:
        techniques = json.load(fh)
    texts = [f"{t['name']}: {t['description']}" for t in techniques]
    labels = [f"{t['technique_id']} {t['name']}" for t in techniques]
    return texts, labels


def predict(model, signatures, technique_embeddings, technique_labels, label):
    print(f"Embedding {len(signatures)} {label} signatures...")
    signature_embeddings = model.encode(signatures, normalize_embeddings=True, show_progress_bar=True)

    # Cosine similarity == dot product since embeddings are L2-normalized.
    similarity = signature_embeddings @ technique_embeddings.T

    rows = []
    for i, sig in enumerate(signatures):
        top_idx = np.argsort(-similarity[i])[:TOP_K]
        row = {"signature": sig}
        for rank, idx in enumerate(top_idx, start=1):
            row[f"predicted_technique_{rank}"] = technique_labels[idx]
            row[f"score_{rank}"] = round(float(similarity[i, idx]), 4)
        rows.append(row)
    return rows


def main():
    technique_texts, technique_labels = load_techniques()
    signatures = unique_signatures()
    uncovered_signatures = load_uncovered_signatures()
    print(
        f"Loaded {len(technique_texts)} techniques, {len(signatures)} hardcoded "
        f"signatures, {len(uncovered_signatures)} uncovered signatures."
    )

    model = SentenceTransformer(MODEL_NAME)

    print("Embedding techniques...")
    technique_embeddings = model.encode(technique_texts, normalize_embeddings=True, show_progress_bar=True)

    covered_rows = predict(model, signatures, technique_embeddings, technique_labels, "hardcoded")
    uncovered_rows = predict(model, uncovered_signatures, technique_embeddings, technique_labels, "uncovered")

    with open(PREDICTIONS_CSV, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=FIELDNAMES)
        writer.writeheader()
        writer.writerows(covered_rows)

        fh.write("\n")
        fh.write("# uncovered -- signatures found in the raw alert corpora but absent from "
                 "signatures/alert_signatures.py (see coverage_check.py)\n")
        writer = csv.DictWriter(fh, fieldnames=FIELDNAMES)
        writer.writeheader()
        writer.writerows(uncovered_rows)

    print(
        f"Wrote {len(covered_rows)} hardcoded + {len(uncovered_rows)} uncovered rows "
        f"-> {PREDICTIONS_CSV}"
    )


if __name__ == "__main__":
    main()
