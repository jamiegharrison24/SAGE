"""Turn the observed-alert label batches into a training corpus file.

Effort 18's labels (`label_queue/labeled_batch09-14.csv`) cover every
signature that fires in the three alert datasets. This converts the scoreable
ones into the `msg,technique_ids,tactic_ids` schema `corpora.py` loads, so the
classifier and the kNN layer can train on them.

Two rules, both deliberate:

  * **Declines are dropped, not coerced.** `CONVENTION.md`'s grammar allows
    `ambiguous: X / Y`, `(none) - non-malicious` and tactic-only `TA####`
    answers, and none of the three has a representation in a schema whose key
    column is a technique ID. Coercing them (picking the first of an
    ambiguous pair, mapping `(none)` to nothing) would silently manufacture
    labels the labeller explicitly declined to give. The count that drops is
    printed, because the corpus otherwise acquires only the confident subset
    and the selection bias would be invisible.

  * **Tactics come from the STIX bundle**, via each technique's own
    `kill_chain_phases` -- not hand-assigned, and not inherited from SAGE's
    `MicroAttackStage`, which would import the Action-Intent Framework's
    judgment into a file that exists to be independent of it.

Usage:
    python build_alert_corpus.py            # writes data/alert_labeled_corpus.csv
    python build_alert_corpus.py --dry-run  # report only
    python build_alert_corpus.py --oracle   # writes data/alert_oracle_corpus.csv
"""
import argparse
import csv
import glob
import gzip
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from attack_mapper import attack_data  # noqa: E402

DATA = os.path.join(HERE, "attack_mapper", "data")
QUEUE = os.path.join(HERE, "label_queue")
OUT = os.path.join(DATA, "alert_labeled_corpus.csv")

# Batches 09-14 are effort 18's: the observed-alert signatures. Batches 01-08
# are the eval set's own labelling passes and must NOT become training data --
# that is the leakage this file exists to stay clear of.
BATCHES = ("09", "10", "11", "12", "13", "14")

# --oracle mode additionally pulls the eval set's own labelling passes
# (batches 01-08, hand_audit_sample*, labeled_set_v2). That is DELIBERATE
# train/test contamination and the resulting accuracy number is meaningless
# as a measure of mapping ability -- it exists so the downstream
# AIF-vs-ATT&CK study has a mapper that actually works on this data, which
# is an assumption of that study rather than a result of it. Never quote an
# oracle-mode score as mapper accuracy; effort 19's clean corpus is the one
# that measures anything.
ORACLE_GLOBS = (
    os.path.join(QUEUE, "labeled_batch*.csv"),
    os.path.join(DATA, "hand_audit_sample*.csv"),
    os.path.join(DATA, "labeled_set_v2.csv"),
)
ORACLE_OUT = os.path.join(DATA, "alert_oracle_corpus.csv")

TECH_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")


def _signature_of(rec):
    """One record -> its alert signature, across all three dataset schemas.

    The three alert datasets are NOT the same shape, and a reader written
    against one returns *zero rows* for the others without raising:

      cptc-2017  {"result": {"alert.signature": ...}}       (Splunk, flattened)
      cptc-2018  {"_raw": "<suricata eve json string>"}     (Splunk, raw)
      ccdc       {"alert": {"signature": ...}}              (native EVE)

    Getting this wrong is what produced a confident "168 unique signatures,
    100% coverage" when the true figure was 530 -- see REPORT.md §9.
    """
    if not isinstance(rec, dict):
        return None
    result = rec.get("result")
    if isinstance(result, dict):
        if result.get("alert.signature"):
            return result["alert.signature"]
        raw = result.get("_raw")
        if raw:
            try:
                return json.loads(raw).get("alert", {}).get("signature")
            except Exception:
                return None
    raw = rec.get("_raw")
    if raw:
        try:
            return json.loads(raw).get("alert", {}).get("signature")
        except Exception:
            return None
    alert = rec.get("alert")
    if isinstance(alert, dict):
        return alert.get("signature")
    return None


def observed_signatures():
    """Every distinct signature that actually fires in `alerts/`.

    Asserts that every dataset directory yields a non-zero count: a schema
    this reader does not handle shows up as a silent zero, which is exactly
    the failure mode the docstring above describes.
    """
    root = os.path.normpath(os.path.join(HERE, "..", "..", "alerts"))
    out = set()
    for ds in sorted(os.listdir(root)):
        ds_dir = os.path.join(root, ds)
        if not os.path.isdir(ds_dir):
            continue
        before = len(out)
        for fn in sorted(glob.glob(os.path.join(ds_dir, "*.json.gz"))):
            with gzip.open(fn, "rt", encoding="utf-8", errors="replace") as fh:
                try:
                    data = json.load(fh)
                except Exception:
                    continue
            if not isinstance(data, list):
                continue
            for rec in data:
                sig = _signature_of(rec)
                if sig:
                    out.add(sig.strip())
        if len(out) == before:
            raise SystemExit(
                f"{ds}: parsed 0 signatures. Its JSON shape is not one of the "
                f"three _signature_of() handles -- fix the reader rather than "
                f"letting the dataset drop out silently."
            )
    return out


def scoreable(value):
    """A single technique ID, or None for any of the convention's declines."""
    v = (value or "").strip()
    if not v or v.startswith("ambiguous") or v.startswith("(none)") or v.startswith("TA"):
        return None
    return v if TECH_RE.match(v) else None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--oracle", action="store_true",
                    help="include the eval set's own labels and restrict to "
                         "signatures observed in alerts/ -- deliberately "
                         "contaminated, for the downstream pipeline study only")
    args = ap.parse_args()

    techniques = attack_data.load_techniques()
    shortnames = attack_data.load_tactics()

    if args.oracle:
        paths = sorted({p for g in ORACLE_GLOBS for p in glob.glob(g)})
        observed = observed_signatures()
        print(f"oracle mode: {len(paths)} label files, "
              f"{len(observed)} signatures observed in alerts/")
    else:
        paths = [os.path.join(QUEUE, f"labeled_batch{n}.csv") for n in BATCHES]
        observed = None

    rows, dropped, unknown, unobserved = [], [], [], 0
    for path in paths:
        if not os.path.exists(path):
            continue
        for r in csv.DictReader(open(path, encoding="utf-8")):
            sig = (r.get("signature") or "").strip()
            tid = scoreable(r.get("proposed_technique"))
            if not sig:
                continue
            if observed is not None and sig not in observed:
                # Oracle mode trains the mapper for THIS data; a labelled
                # signature that never fires here adds nothing to the
                # downstream study and would drag in the rest of the
                # 773-signature frame.
                unobserved += 1
                continue
            if tid is None:
                dropped.append((sig, (r.get("proposed_technique") or "").strip()))
                continue
            obj = techniques.get(tid)
            if obj is None:
                # An ID the STIX bundle does not carry would train the
                # classifier on a class the catalogue cannot name. Effort 7's
                # off-list failure, entering through the corpus instead.
                unknown.append((sig, tid))
                continue
            tas = attack_data.technique_tactics(obj, shortnames)
            rows.append((sig, tid, ";".join(tas)))

    seen, deduped = set(), []
    for sig, tid, tas in rows:
        if sig in seen:
            continue
        seen.add(sig)
        deduped.append((sig, tid, tas))

    print(f"scoreable rows:        {len(rows)}")
    print(f"  after dedupe:        {len(deduped)}")
    print(f"dropped (declines):    {len(dropped)}")
    for _, v in dropped[:6]:
        print(f"    e.g. {v}")
    print(f"dropped (off-catalogue): {len(unknown)}")
    for s, t in unknown[:6]:
        print(f"    {t}  {s[:60]}")
    no_tactic = [r for r in deduped if not r[2]]
    print(f"rows with no tactic:   {len(no_tactic)}")
    if args.oracle:
        print(f"skipped (labelled but never fires in alerts/): {unobserved}")

    if args.dry_run:
        return 0

    out_path = ORACLE_OUT if args.oracle else OUT
    with open(out_path, "w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["msg", "technique_ids", "tactic_ids"])
        for sig, tid, tas in deduped:
            w.writerow([sig, tid, tas])
    print(f"\nwrote {out_path}  ({len(deduped)} rows)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
