"""
Hand verdicts for `compare_ner.py`'s sample, and the scoring that follows.

**These verdicts were assigned by Claude, not by Jamie.** Effort 13 described
its equivalent as "hand-verdicted"; those verdicts were never written back to
`trial_sample.csv` (34 rows, empty `verdict` column), so they cannot be
audited. This file exists so these ones can be -- every judgement is visible
and overridable in one place. Spot-check before quoting.

They are keyed to the sample tagged on `normalize.entity_key(title)`, i.e. the
vendor-prefix-stripped string the pipeline actually hands the tagger. An
earlier pass of this comparison ran on raw titles and had to be discarded: it
credited both models with spans (`ET DOS`, `ETPRO EXPLOIT`) that cannot occur
in production, which inflated NuNER's error count by roughly a third.

Three categories, not two. Effort 13 scored binary and folded "span right,
type wrong" into the false positives, which loses the distinction that matters
for the integration design: a generic `<ENTITY>` marker does not care about
the type, so a type error costs nothing there, while a boundary that swallows
`DOS` does.

  TP    exact named entity, correct type
  SPAN  a real entity is recovered, but the type is wrong or the boundary is
        off (`DOS LibuPnP`, `EDGE OOB`, `Powershell` typed as a hacking tool)
  FP    not a named entity at all -- ruleset category tokens (`SCAN`,
        `WEB_SERVER`, `TROJAN`), technique names (`CRLF Injection`, `Brute
        Force Attack`), generic nouns (`inbound`, `backdoor`, `Web
        Application`), field/file fragments (`pwd`, `passwd`, `UDN`, `514`)

`strict` precision counts TP only; `lenient` counts TP+SPAN, which is the
number relevant to a generic-marker design.

The decisive column is neither. The generalisation this work was for lives on
*rare* entities (`nmap` -> `masscan`, `fortios` -> `coldfusion`), so TPs are
split by corpus document frequency and a model earns the 26-minute pass only
by winning on RARE.

That split is **measured**, not taken from a hand-written protocol list, and
the measurement matters: `Cisco` and `IBM` are not protocols, and `SMB`
(0.151%) and `NTP` (0.009%) are not common. Effort 13's post-mortem attributed
its null to the surviving spans being protocols "already high-frequency tokens
shared across the corpus" -- of the entities scored here only `HTTP` (12.286%)
actually is. That claim was read off eval-set tag counts rather than corpus DF.
A gate resting on an assumed split is not a gate.

Usage: python -m attack_mapper.entity_ner.verdicts
"""
import csv
import os
import re
import sys
from collections import Counter

from .marker_rate import corpus_texts

HERE = os.path.dirname(os.path.abspath(__file__))
SAMPLE = os.path.join(HERE, "compare_sample_gliner-nuner-securebert.csv")

TP, SPAN, FP = "TP", "SPAN", "FP"

# An entity appearing in more than this share of corpus rows is already a
# token the model sees everywhere; marking it adds no information it lacked.
RARE_DF = 0.01

# Keyed by (model, row index within the CSV) -> verdict. Index rather than
# text because the same string recurs with different verdicts in different
# titles. `load()` asserts every scored row resolves, so a re-run with
# different `--models` fails loudly instead of quietly scoring blanks.
VERDICTS = {
    "gliner": {
        0: TP,      # AlstraSoft -> company
        1: FP,      # WEB_SERVER -- ruleset category token
        2: FP,      # URI
        3: FP,      # Web Exploit -- generic
        4: TP,      # SQL Server
        5: FP,      # URI
        6: SPAN,    # Powershell -> hacking tool (product)
        7: TP,      # SMB
        8: TP,      # RDP
        9: FP,      # CRLF Injection -- technique, not entity
        10: FP,     # URL
        11: TP,     # IBM
        12: TP,     # NTP
        13: SPAN,   # Powershell -> hacking tool (product)
        14: TP,     # SMB
        15: SPAN,   # MS Remote Desktop Administrator -- over by one word
        16: FP,     # TROJAN -- ruleset category token
        17: FP,     # pwd -- fragment of service.pwd
        18: FP,     # URI
        19: FP,     # inbound
        20: FP,     # UDN -- a UPnP field name
        21: TP,     # Cisco
        22: TP,     # UDP
        23: FP,     # SCAN -- ruleset category token
        24: FP,     # Inbound
        25: TP,     # NTP
        26: TP,     # Cisco
        27: TP,     # SIP
        28: FP,     # passwd -- path fragment
        29: TP,     # HTTP
        30: TP,     # NFS
        31: SPAN,   # EDGE OOB Access -- swallows the vuln name
    },
    "nuner": {
        32: FP,     # EXPLOIT -- ruleset category token
        33: TP,     # AlstraSoft
        34: TP,     # AskMe -- AlstraSoft AskMe is a real product
        35: FP,     # SQL -- fragment of "SQL Injection"
        36: FP,     # Injection Attempt -- technique
        37: FP,     # URI
        38: FP,     # Web Exploit
        39: TP,     # SQL Server
        40: FP,     # URI
        41: FP,     # WEB_CLIENT -- ruleset category token
        42: SPAN,   # Wscript -> hacking tool (product)
        43: TP,     # Powershell -> software product
        44: TP,     # SMB
        45: TP,     # RDP
        46: FP,     # WEB_SERVER CRLF Injection -- category + technique
        47: FP,     # URL
        48: FP,     # DOS -- ruleset category token
        49: TP,     # IBM
        50: TP,     # Tivoli Endpoint
        51: TP,     # NTP
        52: TP,     # Powershell -> software product
        53: TP,     # SMB
        54: SPAN,   # MS Remote Desktop Administrator -- over by one word
        55: SPAN,   # SpamAssassin -> malware family (product)
        56: SPAN,   # Milter Plugin -- splits SpamAssassin Milter Plugin
        57: FP,     # Remote Arbitrary Command Injection Attempt -- technique
        58: FP,     # TROJAN
        59: FP,     # User-Agent -- a header name
        60: FP,     # WEB_SERVER
        61: FP,     # SCAN
        62: SPAN,   # PHP -> network protocol (language/product)
        63: FP,     # backdoor -- generic
        64: FP,     # scan attempt
        65: FP,     # URI
        66: SPAN,   # DOS LibuPnP -- category token contaminates the boundary
        67: FP,     # ST UDN
        68: TP,     # Linux Kernel
        69: FP,     # keyring object exploit
        70: FP,     # DOS
        71: TP,     # Cisco
        72: FP,     # 514 -- a port number
        73: TP,     # UDP
        74: FP,     # flood
        75: FP,     # DoS
        76: SPAN,   # Rapid POP3S Connections -- over by two words
        77: FP,     # Brute Force Attack -- technique
        78: FP,     # DOS
        79: SPAN,   # SMBLoris -- named vuln, typed malware family
        80: TP,     # NBSS -- NetBIOS Session Service
        81: FP,     # Mem Exhaustion Vuln
        82: FP,     # Web Application -- generic
        83: TP,     # NTP
        84: TP,     # ASA 5500 Series Adaptive Security Appliance
        85: FP,     # Remote
        86: TP,     # SIP
        87: FP,     # Inspection Device
        88: TP,     # HTTP
        89: SPAN,   # NFS RPC -- two protocols fused into one span
        90: FP,     # EXPLOIT
        91: SPAN,   # EDGE OOB -- swallows part of the vuln name
    },
}


def load():
    rows = list(csv.DictReader(open(SAMPLE, encoding="utf-8")))
    missing = []
    for i, r in enumerate(rows):
        r["idx"] = i
        r["score"] = float(r["score"])
        if r["model"] == "securebert":
            r["verdict"] = ""      # sanity check only; scored by label mix
            continue
        r["verdict"] = VERDICTS.get(r["model"], {}).get(i, "")
        if not r["verdict"]:
            missing.append((i, r["model"], r["entity"]))
    if missing:
        raise SystemExit(
            f"{len(missing)} scored rows have no verdict -- the CSV and "
            f"VERDICTS have drifted (row indices shift when --models changes).\n"
            + "\n".join(f"  {i}: [{m}] {e!r}" for i, m, e in missing[:10])
        )
    return rows


def doc_frequency(entities):
    """Share of corpus rows containing each entity, as a whole token run.

    Measured rather than assumed. `Cisco` and `IBM` are not protocols but are
    not rare either, and the rare/common split is what gates the corpus pass.
    """
    texts = [t.lower() for t in corpus_texts()]
    n = len(texts)
    out = {}
    for e in entities:
        pat = re.compile(r"\b" + re.escape(e.strip().lower()) + r"\b")
        out[e] = sum(1 for t in texts if pat.search(t)) / n if n else 0.0
    return out, n


def score(rows, df, threshold=0.0):
    kept = [r for r in rows if r["score"] >= threshold]
    c = Counter(r["verdict"] for r in kept)
    n = len(kept)
    if not n:
        return None
    tps = [r for r in kept if r["verdict"] == TP]
    return {
        "n": n,
        "tp": c[TP], "span": c[SPAN], "fp": c[FP],
        "strict": c[TP] / n,
        "lenient": (c[TP] + c[SPAN]) / n,
        # Default 1.0 = "common": df is measured over TP entities only, so a
        # future caller that splits SPAN rows too must widen `ents` in main()
        # rather than rely on this fallback.
        "rare_tp": sum(1 for r in tps if df.get(r["entity"], 1.0) < RARE_DF),
        "common_tp": sum(1 for r in tps if df.get(r["entity"], 1.0) >= RARE_DF),
    }


def main():
    rows = load()
    scored = [r for r in rows if r["verdict"]]
    n_titles = len({r["signature"] for r in rows})

    print(f"sample: {n_titles} titles, tagged on entity_key() "
          f"(trial.py seed 11)\n")

    print("measuring corpus document frequency ...", flush=True)
    ents = sorted({r["entity"] for r in scored if r["verdict"] == TP})
    df, n_corpus = doc_frequency(ents)
    print(f"  {len(ents)} distinct TP entities over {n_corpus} corpus rows; "
          f"rare = DF < {RARE_DF:.0%}\n")

    print("=" * 78)
    print("Verdicted arms -- all entities, no threshold")
    print("=" * 78)
    print(f"{'model':>10} {'ents':>6} {'TP':>5} {'SPAN':>6} {'FP':>5} "
          f"{'strict':>8} {'lenient':>9} {'rare TP':>9} {'common TP':>10}")
    for model in ("gliner", "nuner"):
        mrows = [r for r in scored if r["model"] == model]
        s = score(mrows, df)
        print(f"{model:>10} {s['n']:>6} {s['tp']:>5} {s['span']:>6} {s['fp']:>5} "
              f"{s['strict']:>7.0%} {s['lenient']:>8.0%} "
              f"{s['rare_tp']:>9} {s['common_tp']:>10}")

    print("\n" + "=" * 78)
    print("Threshold sweep -- the lever effort 13 used to reach its 73%")
    print("=" * 78)
    for model in ("gliner", "nuner"):
        mrows = [r for r in scored if r["model"] == model]
        base = score(mrows, df)
        print(f"\n  [{model}]")
        print(f"  {'thresh':>7} {'kept':>5} {'strict':>8} {'lenient':>9} "
              f"{'rare TP':>9} {'common TP':>10} {'TP recall':>10}")
        for t in (0.50, 0.60, 0.70, 0.80, 0.85, 0.90, 0.95):
            s = score(mrows, df, t)
            if not s:
                continue
            recall = s["tp"] / base["tp"] if base["tp"] else 0
            print(f"  {t:>7.2f} {s['n']:>5} {s['strict']:>7.0%} "
                  f"{s['lenient']:>8.0%} {s['rare_tp']:>9} {s['common_tp']:>10} "
                  f"{recall:>9.0%}")

    print("\n" + "=" * 78)
    print("TP entities by measured corpus DF -- the column that gates the pass")
    print("=" * 78)
    for model in ("gliner", "nuner"):
        got = sorted({r["entity"] for r in scored
                      if r["model"] == model and r["verdict"] == TP},
                     key=lambda e: df[e])
        print(f"\n  [{model}]")
        for e in got:
            mark = "RARE " if df[e] < RARE_DF else "common"
            print(f"    {mark} {df[e]:>7.3%}  {e}")

    # The gate turns on where "rare" is cut, and the cut is a judgement call,
    # so show the whole curve instead of defending one number. Reported at
    # both the permissive threshold and effort 13's operating point.
    print("\n" + "=" * 78)
    print("Gate sensitivity -- rare TP count vs where the DF cut is drawn")
    print("=" * 78)
    cuts = (0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05)
    for thresh in (0.50, 0.85):
        print(f"\n  at model threshold {thresh:.2f}")
        print("  " + "DF cut".rjust(9)
              + "".join(f"{c:>9.2%}" for c in cuts))
        for model in ("gliner", "nuner"):
            mrows = [r for r in scored
                     if r["model"] == model and r["score"] >= thresh]
            tps = [r for r in mrows if r["verdict"] == TP]
            counts = [sum(1 for r in tps if df.get(r["entity"], 1.0) < c)
                      for c in cuts]
            print(f"  {model:>9}" + "".join(f"{n:>9}" for n in counts))

    only = {}
    for model in ("gliner", "nuner"):
        only[model] = {r["entity"].lower() for r in scored
                       if r["model"] == model and r["verdict"] in (TP, SPAN)}
    print("\n  nuner finds, gliner misses: "
          + ", ".join(sorted(only["nuner"] - only["gliner"])))
    print("\n  gliner finds, nuner misses: "
          + ", ".join(sorted(only["gliner"] - only["nuner"])))

    # SecureBERT is a sanity check with a fixed schema, so it gets the one
    # question the plan actually recorded rather than a precision score.
    sb = [r for r in rows if r["model"] == "securebert"]
    if sb:
        print("\n" + "=" * 78)
        print("SecureBERT2.0-NER -- sanity check only (plan section 5: wrong schema)")
        print("=" * 78)
        print(f"  {len(sb)} entities over {n_titles} titles, label distribution:")
        for lbl, c in Counter(r["label"] for r in sb).most_common():
            print(f"    {lbl:>16} {c:>4}")
        sysents = sorted({r["entity"].strip() for r in sb if r["label"] == "System"})
        print("\n  open question -- does `System` cover software products?")
        print(f"  {len(sysents)} distinct System spans:\n    " + ", ".join(sysents))
        cats = {"DOS", "SCAN", "EXPLOIT", "TROJAN", "POLICY", "WEB_SERVER",
                "WEB_CLIENT", "WEB_SPECIFIC_APPS", "ATTACK_RESPONSE", "LINUX"}
        hits = sum(1 for r in sb if r["entity"].strip().upper() in cats)
        print(f"\n  ruleset category tokens tagged as entities: {hits}/{len(sb)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
