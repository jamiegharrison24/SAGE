"""
Step 2 trial: does a zero-shot NER actually fire usefully on terse Suricata
signature titles?

Per `../../entity_normalisation_plan.md` §5 Step 2, this answers four questions
BEFORE any integration. It does not touch `normalize.py`.

  1. Does it fire at all on ~8-word vendor shorthand? (the failure mode that
     has sunk every prose-trained model in this branch)
  2. Does it get multi-word entities -- "Nmap Scripting Engine", "Grim's Ping"?
  3. Does it false-positive on ET category tokens -- WEB_SERVER,
     CURRENT_EVENTS, WEB_SPECIFIC_APPS -- which look like entities and are not?
  4. Does declaring "network protocol" actually catch SMB/DNS/RDP, or only
     tools?

Baseline to beat, from Step 1's dictionaries: 53% precision at 72.5% coverage
(`../entity_dicts/findings.md`).

Two title sets are used, deliberately:
  * RANDOM -- 30 titles sampled with a fixed seed from the 397 scoreable eval
    rows. This is the unbiased headline; it is what coverage/precision are
    quoted from.
  * PROBE -- a small hand-picked set carrying entities Step 1 got wrong or
    missed, used only for the four qualitative questions above. Quoting
    accuracy from a hand-picked set would be cherry-picking, so it is not.

Usage:
    python trial.py                       # GLiNER medium v2.1 (default)
    python trial.py --model urchade/gliner_large-v2.1
    python trial.py --threshold 0.35
"""
import argparse
import csv
import glob
import os
import random
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.normpath(os.path.join(HERE, "..", "data"))

# Declared at inference -- the whole point of zero-shot NER. These map onto the
# entity classes measured as our headroom in the plan's §1: tool (2.5% covered
# today), protocol/service (21.9%), product/vendor (24.9%).
LABELS = [
    "hacking tool",
    "software product",
    "network protocol",
    "malware family",
    "company",
]

# Entities Step 1 got wrong or missed entirely -- see ../entity_dicts/findings.md.
PROBE = [
    "ET SCAN Nmap Scripting Engine User-Agent Detected (Nmap Scripting Engine)",
    "ET SCAN Modified Sipvicious User-Agent Detected (sundayddr)",
    "ET SCAN Grim's Ping ftp scanning tool",
    "ET SCAN Nessus User Agent",
    "ET EXPLOIT FortiOS SSL VPN - Information Disclosure (CVE-2018-13379)",
    "ET WEB_SERVER Coldfusion cfcexplorer Directory Traversal",
    "ET DOS Possible SolarWinds TFTP Server Read Request Denial Of Service Attempt",
    "ET EXPLOIT F5 BIG-IP rsync cmi authorized_keys successful exfiltration",
    "ET CURRENT_EVENTS Nuclear EK Landing Apr 08 2015",
    "ET WEB_SPECIFIC_APPS Joomla 3.7.0 - Sql Injection (CVE-2017-8917)",
    "GPL NETBIOS SMB-DS ADMIN$ share access",
    "ET POLICY MS Remote Desktop Administrator Login Request",
]


def parse_proposed(cell):
    cell = cell.strip()
    if cell.startswith("ambiguous") or cell.startswith("(none)") or cell == "":
        return None
    return set(re.findall(r"T\d{4}(?:\.\d{3})?", cell)) or None


def load_scoreable_titles():
    rows = []
    for fn in sorted(glob.glob(os.path.join(DATA, "hand_audit_sample*.csv"))):
        rows += list(csv.DictReader(open(fn, encoding="utf-8")))
    p = os.path.join(DATA, "labeled_set_v2.csv")
    if os.path.exists(p):
        rows += list(csv.DictReader(open(p, encoding="utf-8")))
    return [r["signature"] for r in rows
            if parse_proposed(r["proposed_technique"]) is not None]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default="urchade/gliner_medium-v2.1",
                    help="apache-2.0 only: v2/v2.1. gliner_base and v0/v1 are cc-by-nc-4.0")
    ap.add_argument("--threshold", type=float, default=0.5)
    ap.add_argument("--sample", type=int, default=30)
    ap.add_argument("--seed", type=int, default=11)
    args = ap.parse_args()

    print(f"loading {args.model} (first run downloads ~500MB) ...")
    from gliner import GLiNER
    model = GLiNER.from_pretrained(args.model)
    print("loaded.\n")

    def tag(text):
        ents = model.predict_entities(text, LABELS, threshold=args.threshold)
        return sorted(ents, key=lambda e: e["start"])

    random.seed(args.seed)
    titles = load_scoreable_titles()
    sample = random.sample(titles, min(args.sample, len(titles)))

    print("=" * 78)
    print(f"RANDOM SAMPLE ({len(sample)} titles, seed {args.seed}) -- the unbiased headline")
    print("=" * 78)
    fired = 0
    total_ents = 0
    out_rows = []
    for t in sample:
        ents = tag(t)
        if ents:
            fired += 1
        total_ents += len(ents)
        rendered = ", ".join(f"{e['text']!r}->{e['label']} ({e['score']:.2f})" for e in ents) or "(none)"
        print(f"\n  {t[:74]}")
        print(f"     {rendered}")
        for e in ents:
            out_rows.append((t, e["text"], e["label"], f"{e['score']:.3f}", ""))

    n = len(sample)
    print("\n" + "-" * 78)
    print(f"Q1  fired on {fired}/{n} titles ({fired / n:.0%});  {total_ents} entities total")

    print("\n" + "=" * 78)
    print("PROBE SET -- qualitative only, NOT used for accuracy")
    print("=" * 78)
    for t in PROBE:
        ents = tag(t)
        rendered = ", ".join(f"{e['text']!r}->{e['label']}" for e in ents) or "(none)"
        print(f"\n  {t[:74]}")
        print(f"     {rendered}")

    out = os.path.join(HERE, "trial_sample.csv")
    with open(out, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["signature", "entity", "label", "score", "verdict"])
        w.writerows(out_rows)
    print(f"\n\nwrote {len(out_rows)} random-sample entities for hand review -> {out}")


if __name__ == "__main__":
    sys.exit(main())
