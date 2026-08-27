"""
Phase 3, methods 1-6. Run under WSL (needs sentence-transformers/torch):

  wsl.exe -d Ubuntu -- bash -lc \
    "cd /mnt/d/Projects/SAGE/SAGE/experiments/mitre_mapping && python3 run_methods.py"

Method 1 (ATTACK-BERT, full list) is NOT regenerated -- reuses predictions.csv
as instructed. Methods 2-6 are computed here and written to
predictions_method{2..6}.csv in the same 3-column-per-rank shape as
predictions.csv: signature, pred_1, score_1, pred_2, score_2, pred_3, score_3
(pred_N is "TID Name"; for k-NN methods 5/6 pred_2/3 are left blank -- those
only produce one best answer, per the task).
"""
import csv
import json
import os
import sys

import numpy as np
from sentence_transformers import SentenceTransformer

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

TECHNIQUES_PATH = os.path.join(HERE, "techniques.json")
CANDIDATES_PATH = os.path.join(HERE, "candidate_techniques.json")
GT_PATH = os.path.join(HERE, "ground_truth_signatures.csv")

MODELS = {
    "attackbert": "basel/ATTACK-BERT",
    "minilm": "sentence-transformers/all-MiniLM-L6-v2",
}


def load_techniques():
    with open(TECHNIQUES_PATH, encoding="utf-8") as fh:
        techs = json.load(fh)
    return {t["technique_id"]: t for t in techs}


def load_candidates():
    with open(CANDIDATES_PATH, encoding="utf-8") as fh:
        return set(json.load(fh)["filtered_ids"])


def load_ground_truth_signatures():
    with open(GT_PATH, newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def embed(model, texts, batch_size=64):
    return model.encode(texts, batch_size=batch_size, show_progress_bar=True,
                         convert_to_numpy=True, normalize_embeddings=True)


def nn_method(model_key, model_name, techs, tech_ids, use_filtered, filtered_ids, sigs, out_path):
    print(f"\n=== {out_path} ({model_name}, {'filtered' if use_filtered else 'full'} candidate list) ===")
    model = SentenceTransformer(model_name)

    ids = [t for t in tech_ids if (t in filtered_ids if use_filtered else True)]
    texts = [f"{techs[t]['name']}: {techs[t]['description']}" for t in ids]
    tech_emb = embed(model, texts)

    sig_texts = [r["signature"] for r in sigs]
    sig_emb = embed(model, sig_texts)

    sims = sig_emb @ tech_emb.T  # cosine since normalized

    rows = []
    for i, r in enumerate(sigs):
        order = np.argsort(-sims[i])[:3]
        row = [r["signature"]]
        for rank_idx in order:
            tid = ids[rank_idx]
            row += [f"{tid} {techs[tid]['name']}", f"{sims[i][rank_idx]:.4f}"]
        while len(row) < 7:
            row += ["", ""]
        rows.append(row)

    with open(out_path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["signature", "predicted_technique_1", "score_1",
                     "predicted_technique_2", "score_2", "predicted_technique_3", "score_3"])
        w.writerows(rows)
    print(f"Wrote {len(rows)} rows to {out_path}")


def knn_method(model_key, model_name, sigs, out_path, k=5):
    print(f"\n=== {out_path} (k-NN k={k}, {model_name}, leave-one-out over labelled signatures) ===")
    model = SentenceTransformer(model_name)
    sig_texts = [r["signature"] for r in sigs]
    sig_emb = embed(model, sig_texts)
    sims = sig_emb @ sig_emb.T

    # each row's own resolved id (primary): technique id(s) joined, or tactic id, else None
    labels = []
    for r in sigs:
        if r["gt_kind"] in ("technique_scoreable", "tactic_only") and r["gt_ids"]:
            labels.append(r["gt_ids"].split(";")[0])
        else:
            labels.append(None)

    rows = []
    for i, r in enumerate(sigs):
        sim_row = sims[i].copy()
        sim_row[i] = -np.inf  # leave-one-out: exclude self
        order = np.argsort(-sim_row)
        neighbor_idxs = [j for j in order if labels[j] is not None][:k]

        if not neighbor_idxs:
            rows.append([r["signature"], "", "", "", "", "", ""])
            continue

        # vote: count, tie-break by best similarity among that label's voters, then lexicographic id
        vote_count = {}
        vote_best_sim = {}
        for j in neighbor_idxs:
            lbl = labels[j]
            vote_count[lbl] = vote_count.get(lbl, 0) + 1
            vote_best_sim[lbl] = max(vote_best_sim.get(lbl, -np.inf), sim_row[j])

        winner = sorted(vote_count.keys(),
                         key=lambda lbl: (-vote_count[lbl], -vote_best_sim[lbl], lbl))[0]
        rows.append([r["signature"], winner, f"{vote_count[winner]}/{k}", "", "", "", ""])

    with open(out_path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["signature", "predicted_technique_1", "score_1",
                     "predicted_technique_2", "score_2", "predicted_technique_3", "score_3"])
        w.writerows(rows)
    print(f"Wrote {len(rows)} rows to {out_path}")


def main():
    techs = load_techniques()
    tech_ids = sorted(techs.keys())
    filtered_ids = load_candidates()
    sigs = load_ground_truth_signatures()
    print(f"{len(sigs)} ground-truth signatures, {len(tech_ids)} full techniques, "
          f"{len(filtered_ids)} filtered candidates")

    # method 2: ATTACK-BERT, filtered list
    nn_method("attackbert", MODELS["attackbert"], techs, tech_ids, True, filtered_ids, sigs,
               os.path.join(HERE, "predictions_method2.csv"))
    # method 3: MiniLM, full list
    nn_method("minilm", MODELS["minilm"], techs, tech_ids, False, filtered_ids, sigs,
               os.path.join(HERE, "predictions_method3.csv"))
    # method 4: MiniLM, filtered list
    nn_method("minilm", MODELS["minilm"], techs, tech_ids, True, filtered_ids, sigs,
               os.path.join(HERE, "predictions_method4.csv"))
    # method 5: k-NN over labelled sigs, ATTACK-BERT embeddings
    knn_method("attackbert", MODELS["attackbert"], sigs, os.path.join(HERE, "predictions_method5.csv"))
    # method 6: k-NN over labelled sigs, MiniLM embeddings
    knn_method("minilm", MODELS["minilm"], sigs, os.path.join(HERE, "predictions_method6.csv"))


if __name__ == "__main__":
    main()
