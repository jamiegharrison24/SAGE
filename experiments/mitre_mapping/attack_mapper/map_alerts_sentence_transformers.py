"""Map alert signatures to the closest MITRE ATT&CK technique or tactic.

The input CSV must contain a ``signature`` column.  The mapper embeds each
signature and each ATT&CK name/description with sentence-transformers, then
uses cosine similarity to select the closest ATT&CK code.

By default, output is written beside the input as
``labeled_set_v2_sentence_transformer_mappings.csv``.
"""

import argparse
import csv
import json
import os
from typing import Dict, List, Tuple

import numpy as np
from sentence_transformers import SentenceTransformer


HERE = os.path.dirname(os.path.abspath(__file__))
MITRE_MAPPING_DIR = os.path.dirname(HERE)
DEFAULT_INPUT = os.path.join(HERE, "data", "labeled_set_v2.csv")
DEFAULT_OUTPUT = os.path.join(
    HERE, "data", "labeled_set_v2_sentence_transformer_mappings.csv"
)
STIX_BUNDLE = os.path.join(MITRE_MAPPING_DIR, "enterprise-attack.json")
TECHNIQUES_JSON_CANDIDATES = (
    os.path.join(HERE, "data", "techniques.json"),
    os.path.join(MITRE_MAPPING_DIR, "archive", "techniques.json"),
)
DEFAULT_MODEL = "sentence-transformers/all-MiniLM-L6-v2"


def external_id(obj: dict) -> str:
    for reference in obj.get("external_references", []):
        if reference.get("source_name") == "mitre-attack":
            return reference.get("external_id", "")
    return ""


def load_candidates() -> List[Dict[str, str]]:
    """Load techniques and tactics from the local Enterprise ATT&CK bundle."""
    if os.path.exists(STIX_BUNDLE):
        with open(STIX_BUNDLE, encoding="utf-8") as handle:
            objects = json.load(handle).get("objects", [])

        candidates = []
        for obj in objects:
            object_type = obj.get("type")
            if object_type == "attack-pattern":
                code = external_id(obj)
                candidate_type = "technique"
            elif object_type == "x-mitre-tactic":
                code = external_id(obj)
                candidate_type = "tactic"
            else:
                continue

            if not code or obj.get("revoked") or obj.get("x_mitre_deprecated"):
                continue
            name = obj.get("name", "").strip()
            description = (obj.get("description") or "").strip()
            if name and description:
                candidates.append(
                    {
                        "code": code,
                        "name": name,
                        "type": candidate_type,
                        "text": f"{name}: {description}",
                    }
                )
        if candidates:
            return sorted(candidates, key=lambda item: item["code"])

    for path in TECHNIQUES_JSON_CANDIDATES:
        if not os.path.exists(path):
            continue
        with open(path, encoding="utf-8") as handle:
            techniques = json.load(handle)
        return [
            {
                "code": item["technique_id"],
                "name": item["name"],
                "type": "technique",
                "text": f"{item['name']}: {item['description']}",
            }
            for item in techniques
            if item.get("technique_id", "").startswith("T")
        ]

    raise FileNotFoundError(
        "No ATT&CK corpus found. Expected enterprise-attack.json or techniques.json."
    )


def load_alerts(path: str) -> List[str]:
    with open(path, newline="", encoding="utf-8-sig") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames or "signature" not in reader.fieldnames:
            raise ValueError("Input CSV must contain a 'signature' column.")
        return [row["signature"].strip() for row in reader if row.get("signature", "").strip()]


def map_alerts(
    alerts: List[str], candidates: List[Dict[str, str]], model_name: str, top_k: int = 1
) -> List[Tuple[str, Dict[str, str], float]]:
    model = SentenceTransformer(model_name)
    candidate_embeddings = model.encode(
        [candidate["text"] for candidate in candidates],
        batch_size=64,
        convert_to_numpy=True,
        normalize_embeddings=True,
        show_progress_bar=True,
    )
    alert_embeddings = model.encode(
        alerts,
        batch_size=64,
        convert_to_numpy=True,
        normalize_embeddings=True,
        show_progress_bar=True,
    )
    return search_candidates(alerts, candidates, alert_embeddings, candidate_embeddings, top_k)


def search_candidates(
    alerts: List[str],
    candidates: List[Dict[str, str]],
    alert_embeddings: np.ndarray,
    candidate_embeddings: np.ndarray,
    top_k: int = 1,
) -> List[Tuple[str, Dict[str, str], float]]:
    """Rank ATT&CK candidates by cosine similarity using a FAISS flat index.

    The supplied embeddings must be normalized; inner product then equals
    cosine similarity, matching the previous dense-matrix implementation.
    """
    if top_k < 1:
        raise ValueError("top_k must be at least 1")
    if not candidates:
        raise ValueError("At least one ATT&CK candidate is required")

    try:
        import faiss
    except ImportError as exc:
        raise RuntimeError(
            "FAISS is required for description search. Install dependencies with "
            "'pip install -r requirements.txt' in Linux or WSL."
        ) from exc

    candidate_embeddings = np.ascontiguousarray(candidate_embeddings, dtype=np.float32)
    alert_embeddings = np.ascontiguousarray(alert_embeddings, dtype=np.float32)
    index = faiss.IndexFlatIP(candidate_embeddings.shape[1])
    index.add(candidate_embeddings)
    similarities, candidate_indices = index.search(
        alert_embeddings, min(top_k, len(candidates))
    )

    return [
        (alert, candidates[int(candidate_index)], float(similarity))
        for alert, row_indices, row_similarities in zip(
            alerts, candidate_indices, similarities
        )
        for candidate_index, similarity in zip(row_indices, row_similarities)
        if candidate_index >= 0
    ]


def write_output(path: str, mappings: List[Tuple[str, Dict[str, str], float]]) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=["alert", "mapped_code", "mapped_name", "mapped_type", "similarity"],
        )
        writer.writeheader()
        for alert, candidate, similarity in mappings:
            writer.writerow(
                {
                    "alert": alert,
                    "mapped_code": candidate["code"],
                    "mapped_name": candidate["name"],
                    "mapped_type": candidate["type"],
                    "similarity": f"{similarity:.6f}",
                }
            )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", default=DEFAULT_INPUT, help="Input labelled alert CSV")
    parser.add_argument("--output", default=DEFAULT_OUTPUT, help="Output mapping CSV")
    parser.add_argument("--model", default=DEFAULT_MODEL, help="Sentence-transformers model")
    parser.add_argument(
        "--top-k", type=int, default=1,
        help="Number of ranked ATT&CK technique/tactic matches per alert",
    )
    args = parser.parse_args()

    candidates = load_candidates()
    alerts = load_alerts(args.input)
    mappings = map_alerts(alerts, candidates, args.model, top_k=args.top_k)
    write_output(args.output, mappings)
    print(f"Mapped {len(alerts)} alerts against {len(candidates)} ATT&CK candidates.")
    print(f"Wrote {args.output}")


if __name__ == "__main__":
    main()