"""
Tier 0: harvest labels already present in ET Open's rule metadata.

Two outputs:
  - et_labeled_corpus.csv: EVERY ET rule with mitre_technique_id/tactic_id
    metadata (~26.6k rows) -- this is the free labeled corpus Tier 2 trains
    on, independent of our own 773-signature ground truth.
  - tier0_hits.csv: exact msg-text matches between the ET corpus and our 773
    SAGE signatures -- Tier 0's direct contribution to the final pipeline.

Usage: python tier0_build.py
Requires emerging-all.rules in this directory (fetched from
https://rules.emergingthreats.net/open/suricata-7.0/emerging-all.rules).
"""
import csv
import os
import re
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
RULES_PATH = os.path.join(HERE, "emerging-all.rules")
RULES_URL = "https://rules.emergingthreats.net/open/suricata-7.0/emerging-all.rules"
GT_PATH = os.path.join(os.path.dirname(HERE), "ground_truth_signatures.csv")
CORPUS_OUT = os.path.join(HERE, "et_labeled_corpus.csv")
TIER0_HITS_OUT = os.path.join(HERE, "tier0_hits.csv")

MSG_RE = re.compile(r'msg:\s*"((?:[^"\\]|\\.)*)"')
TECH_RE = re.compile(r"mitre_technique_id\s+([^,;]+)")
TACTIC_RE = re.compile(r"mitre_tactic_id\s+([^,;]+)")


def ensure_rules_file():
    if not os.path.exists(RULES_PATH):
        print(f"Downloading {RULES_URL} ...")
        urllib.request.urlretrieve(RULES_URL, RULES_PATH)
    return RULES_PATH


def parse_ids(cell):
    """'T1071.001' or 'T1071.001, T1105' style-separated ids -> list, dedup, order-preserving."""
    parts = re.split(r"[,\s]+", cell.strip())
    out = []
    for p in parts:
        p = p.strip()
        if p and p not in out:
            out.append(p)
    return out


def parse_rules(path):
    """Returns {msg_text: (technique_ids, tactic_ids)} for every rule that
    carries mitre metadata. Last rule with a given msg wins (ET dedups msg
    text in practice; collisions are rare)."""
    text = open(path, encoding="utf-8", errors="replace").read()
    out = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = MSG_RE.search(line)
        if not m:
            continue
        tm = TECH_RE.search(line)
        ta = TACTIC_RE.search(line)
        if not (tm or ta):
            continue
        msg = m.group(1).replace('\\"', '"')
        techs = parse_ids(tm.group(1)) if tm else []
        tactics = parse_ids(ta.group(1)) if ta else []
        out[msg] = (techs, tactics)
    return out


def main():
    ensure_rules_file()
    labeled = parse_rules(RULES_PATH)
    print(f"ET rules with mitre metadata: {len(labeled)} unique messages")

    with open(CORPUS_OUT, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["msg", "technique_ids", "tactic_ids"])
        for msg, (techs, tactics) in labeled.items():
            w.writerow([msg, ";".join(techs), ";".join(tactics)])
    print(f"Wrote {CORPUS_OUT}")

    with open(GT_PATH, encoding="utf-8") as fh:
        sigs = [row["signature"] for row in csv.DictReader(fh)]

    hits = 0
    with open(TIER0_HITS_OUT, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["signature", "technique_ids", "tactic_ids"])
        for sig in sigs:
            if sig in labeled:
                techs, tactics = labeled[sig]
                w.writerow([sig, ";".join(techs), ";".join(tactics)])
                hits += 1
    print(f"Tier 0 exact-match hits on our 773 signatures: {hits}")
    print(f"Wrote {TIER0_HITS_OUT}")


if __name__ == "__main__":
    main()
