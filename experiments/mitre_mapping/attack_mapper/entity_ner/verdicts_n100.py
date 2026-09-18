"""
Robustness check: re-run the span-level comparison (`comparison_findings.md`)
on a larger, independently-drawn sample -- 100 titles (seed 42) instead of the
original 30 (seed 11) -- to check whether SecureModernBERT-NER's win holds up
beyond a small draw, per Jamie's request after the initial addendum.

Self-contained rather than folded into `verdicts.py`: that file's VERDICTS
dict is keyed by (model name, row index) against ONE fixed CSV
(`compare_sample_gliner-nuner-securebert.csv`); this pass used a differently-
named output file (`compare_sample_gliner-nuner-securemodernbert.csv`, from
`compare_ner.py --models gliner,nuner,securemodernbert --sample 100 --seed
42`) whose row indices for "gliner"/"nuner" would collide with the originals
if merged into the same dict. Scoring logic (TP/SPAN/FP rubric, strict/
lenient, rare-vs-common split via corpus DF) is identical to `verdicts.py`;
only the sample and verdicts differ.

**These verdicts were assigned by Claude, not by Jamie** -- same caveat as
`verdicts.py`. Spot-check before quoting.

Usage: python -m attack_mapper.entity_ner.verdicts_n100
"""
import csv
import os
import re
import sys
from collections import Counter

from .df_table import DFTable
from .marker_rate import corpus_texts

HERE = os.path.dirname(os.path.abspath(__file__))
SAMPLE = os.path.join(HERE, "compare_sample_gliner-nuner-securemodernbert.csv")

TP, SPAN, FP = "TP", "SPAN", "FP"
RARE_DF = 0.01
MODELS = ("gliner", "nuner", "securemodernbert")

# Row indices are GLOBAL within this single CSV (compare_ner.py writes one
# model's titles-worth of rows after another into the same file): gliner
# 0-120, nuner 121-317, securemodernbert 318-436. Do not restart at 0 per
# model -- that was verdicts.py's per-file convention, not this file's.
VERDICTS = {
    # ---- gliner (0-120) ----
    0: TP, 1: TP, 2: TP, 3: SPAN, 4: TP, 5: TP, 6: FP, 7: TP, 8: TP, 9: TP,
    10: FP, 11: FP, 12: TP, 13: TP, 14: SPAN, 15: TP, 16: SPAN, 17: SPAN,
    18: SPAN, 19: FP, 20: SPAN, 21: SPAN, 22: FP, 23: FP, 24: TP, 25: FP,
    26: TP, 27: TP, 28: FP, 29: TP, 30: TP, 31: TP, 32: TP, 33: TP, 34: SPAN,
    35: TP, 36: SPAN, 37: TP, 38: TP, 39: FP, 40: TP, 41: TP, 42: FP, 43: TP,
    44: FP, 45: SPAN, 46: SPAN, 47: TP, 48: TP, 49: TP, 50: FP, 51: SPAN,
    52: TP, 53: FP, 54: FP, 55: SPAN, 56: TP, 57: FP, 58: TP, 59: FP, 60: FP,
    61: SPAN, 62: TP, 63: FP, 64: FP, 65: SPAN, 66: FP, 67: TP, 68: TP,
    69: TP, 70: TP, 71: FP, 72: TP, 73: SPAN, 74: TP, 75: FP, 76: TP, 77: TP,
    78: FP, 79: FP, 80: TP, 81: FP, 82: TP, 83: FP, 84: TP, 85: TP, 86: TP,
    87: FP, 88: FP, 89: FP, 90: FP, 91: FP, 92: TP, 93: SPAN, 94: TP,
    95: SPAN, 96: FP, 97: TP, 98: TP, 99: TP, 100: SPAN, 101: SPAN, 102: TP,
    103: TP, 104: FP, 105: TP, 106: FP, 107: FP, 108: FP, 109: TP, 110: TP,
    111: TP, 112: FP, 113: FP, 114: TP, 115: TP, 116: TP, 117: SPAN, 118: FP,
    119: TP, 120: SPAN,
    # ---- nuner (121-317, local 0-196 + 121) ----
    121: FP, 122: TP, 123: TP, 124: TP, 125: FP, 126: SPAN, 127: FP,
    128: TP, 129: FP, 130: SPAN, 131: FP, 132: TP, 133: FP, 134: SPAN,
    135: TP, 136: TP, 137: FP, 138: TP, 139: TP, 140: FP, 141: FP, 142: SPAN,
    143: FP, 144: FP, 145: SPAN, 146: FP, 147: TP, 148: SPAN, 149: SPAN,
    150: TP, 151: FP, 152: SPAN, 153: FP, 154: FP, 155: SPAN, 156: TP,
    157: TP, 158: FP, 159: TP, 160: TP, 161: FP, 162: TP, 163: FP, 164: TP,
    165: SPAN, 166: FP, 167: SPAN, 168: SPAN, 169: TP, 170: TP, 171: FP,
    172: TP, 173: FP, 174: SPAN, 175: SPAN, 176: TP, 177: TP, 178: FP,
    179: FP, 180: SPAN, 181: TP, 182: FP, 183: TP, 184: SPAN, 185: FP,
    186: FP, 187: FP, 188: FP, 189: FP, 190: TP, 191: FP, 192: SPAN,
    193: TP, 194: FP, 195: FP, 196: FP, 197: FP, 198: FP, 199: SPAN,
    200: FP, 201: FP, 202: FP, 203: FP, 204: TP, 205: TP, 206: FP, 207: FP,
    208: TP, 209: TP, 210: FP, 211: FP, 212: FP, 213: TP, 214: SPAN,
    215: FP, 216: TP, 217: TP, 218: TP, 219: FP, 220: FP, 221: TP, 222: FP,
    223: FP, 224: TP, 225: TP, 226: TP, 227: FP, 228: TP, 229: FP, 230: FP,
    231: FP, 232: TP, 233: FP, 234: FP, 235: TP, 236: TP, 237: FP, 238: TP,
    239: TP, 240: SPAN, 241: FP, 242: FP, 243: TP, 244: TP, 245: TP,
    246: TP, 247: TP, 248: FP, 249: TP, 250: TP, 251: FP, 252: FP, 253: FP,
    254: TP, 255: TP, 256: TP, 257: FP, 258: FP, 259: SPAN, 260: FP,
    261: TP, 262: TP, 263: FP, 264: FP, 265: TP, 266: TP, 267: FP, 268: FP,
    269: TP, 270: FP, 271: FP, 272: FP, 273: FP, 274: SPAN, 275: TP,
    276: FP, 277: FP, 278: FP, 279: FP, 280: SPAN, 281: TP, 282: FP,
    283: FP, 284: TP, 285: TP, 286: SPAN, 287: FP, 288: FP, 289: SPAN,
    290: TP, 291: SPAN, 292: FP, 293: TP, 294: TP, 295: TP, 296: FP,
    297: SPAN, 298: FP, 299: SPAN, 300: TP, 301: FP, 302: SPAN, 303: FP,
    304: SPAN, 305: TP, 306: SPAN, 307: TP, 308: FP, 309: FP, 310: FP,
    311: FP, 312: TP, 313: FP, 314: FP, 315: SPAN, 316: TP, 317: SPAN,
    # ---- securemodernbert (318-436, local 0-118 + 318) ----
    318: TP, 319: TP, 320: SPAN, 321: TP, 322: FP, 323: FP, 324: TP,
    325: FP, 326: TP, 327: FP, 328: FP, 329: TP, 330: FP, 331: TP,
    332: TP, 333: TP, 334: TP, 335: SPAN, 336: TP, 337: SPAN, 338: SPAN,
    339: FP, 340: TP, 341: TP, 342: TP, 343: TP, 344: TP, 345: FP, 346: TP,
    347: TP, 348: TP, 349: TP, 350: SPAN, 351: FP, 352: SPAN, 353: TP,
    354: TP, 355: FP, 356: TP, 357: TP, 358: SPAN, 359: TP, 360: SPAN,
    361: FP, 362: TP, 363: FP, 364: TP, 365: FP, 366: FP, 367: SPAN,
    368: SPAN, 369: FP, 370: TP, 371: FP, 372: TP, 373: FP, 374: FP,
    375: TP, 376: TP, 377: FP, 378: TP, 379: TP, 380: TP, 381: TP,
    382: FP, 383: FP, 384: TP, 385: FP, 386: TP, 387: TP, 388: TP,
    389: TP, 390: TP, 391: SPAN, 392: FP, 393: TP, 394: FP, 395: FP,
    396: TP, 397: TP, 398: FP, 399: TP, 400: TP, 401: FP, 402: TP,
    403: SPAN, 404: TP, 405: TP, 406: TP, 407: SPAN, 408: FP, 409: FP,
    410: FP, 411: TP, 412: SPAN, 413: FP, 414: TP, 415: TP, 416: FP,
    417: TP, 418: SPAN, 419: SPAN, 420: TP, 421: TP, 422: FP, 423: TP,
    424: TP, 425: TP, 426: TP, 427: TP, 428: FP, 429: TP, 430: FP,
    431: FP, 432: TP, 433: TP, 434: TP, 435: TP, 436: FP,
}


def load():
    rows = list(csv.DictReader(open(SAMPLE, encoding="utf-8")))
    missing = []
    for i, r in enumerate(rows):
        r["idx"] = i
        r["score"] = float(r["score"])
        r["verdict"] = VERDICTS.get(i, "")
        if not r["verdict"]:
            missing.append((i, r["model"], r["entity"]))
    if missing:
        raise SystemExit(
            f"{len(missing)} scored rows have no verdict.\n"
            + "\n".join(f"  {i}: [{m}] {e!r}" for i, m, e in missing[:10])
        )
    return rows


def doc_frequency(entities, table):
    return {e: table.df(e) for e in entities}


def score(rows, df):
    n = len(rows)
    if not n:
        return None
    c = Counter(r["verdict"] for r in rows)
    tps = [r for r in rows if r["verdict"] == TP]
    # entity strings carry a leading space from the token classifiers' spans
    # (" Microsoft", not "Microsoft"); df keys are built from .strip()'d
    # entities, so lookups here must strip too or every lookup misses and
    # silently falls back to the 1.0 "common" default.
    return {
        "n": n, "tp": c[TP], "span": c[SPAN], "fp": c[FP],
        "strict": c[TP] / n, "lenient": (c[TP] + c[SPAN]) / n,
        "rare_tp": sum(1 for r in tps
                       if df.get(r["entity"].strip(), 1.0) < RARE_DF),
        "common_tp": sum(1 for r in tps
                         if df.get(r["entity"].strip(), 1.0) >= RARE_DF),
    }


def noise_burden(rows, texts):
    fps = sorted({r["entity"].strip() for r in rows if r["verdict"] == FP})
    pats = [re.compile(r"\b" + re.escape(e.lower()) + r"\b") for e in fps]
    union = sum(1 for t in texts if any(p.search(t) for p in pats))
    return fps, union


def main():
    rows = load()
    table = DFTable()
    ents = sorted({r["entity"].strip() for r in rows if r["verdict"] == TP})
    df = doc_frequency(ents, table)
    texts = [t.lower() for t in corpus_texts()]
    n_corpus = len(texts)
    n_titles = len({r["signature"] for r in rows})

    print(f"sample: {n_titles} titles (seed 42, n=100 draw), "
          f"{table.meta['n_docs']} corpus docs\n")

    print("=" * 78)
    print(f"{'model':>17} {'ents':>6} {'TP':>5} {'SPAN':>6} {'FP':>5} "
          f"{'strict':>8} {'lenient':>9} {'rare TP':>9} {'common TP':>10}")
    for model in MODELS:
        mrows = [r for r in rows if r["model"] == model]
        s = score(mrows, df)
        print(f"{model:>17} {s['n']:>6} {s['tp']:>5} {s['span']:>6} {s['fp']:>5} "
              f"{s['strict']:>7.0%} {s['lenient']:>8.0%} "
              f"{s['rare_tp']:>9} {s['common_tp']:>10}")

    print("\n" + "=" * 78)
    print("Noise burden -- share of corpus rows containing >=1 FP string")
    print("=" * 78)
    for model in MODELS:
        mrows = [r for r in rows if r["model"] == model]
        fps, union = noise_burden(mrows, texts)
        print(f"  {model:>17}  {len(fps):>3} distinct FP strings, "
              f"union burden {union}/{n_corpus} = {union / n_corpus:.2%}")

    print("\n" + "=" * 78)
    print("Gate sensitivity -- rare TP count vs where the DF cut is drawn")
    print("=" * 78)
    cuts = (0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05)
    print("  " + "DF cut".rjust(9) + "".join(f"{c:>9.2%}" for c in cuts))
    for model in MODELS:
        tps = [r for r in rows if r["model"] == model and r["verdict"] == TP]
        counts = [sum(1 for r in tps if df.get(r["entity"].strip(), 1.0) < c)
                  for c in cuts]
        print(f"  {model:>17}" + "".join(f"{n:>9}" for n in counts))
    return 0


if __name__ == "__main__":
    sys.exit(main())
