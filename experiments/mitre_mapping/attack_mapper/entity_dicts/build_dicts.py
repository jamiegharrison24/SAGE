"""
Build a typed entity gazetteer from three public, redistributable dictionaries,
for the entity-aware normalisation work (`../../entity_normalisation_plan.md`,
Step 1).

Why these three: `alias_table.py`'s ATT&CK-STIX gazetteer reaches only 2.5% of
scoreable eval rows, because the ATT&CK bundle models malware and named tools
and has no object type for "SMB" or "WordPress". Protocol (21.9%) and
product/vendor (24.9%) entities are structurally absent from it. These sources
carry exactly those classes and are all committable rather than live services:

| source | entries | licence | class |
|---|---:|---|---|
| MISP galaxy `tool.json` | 620 | CC0 1.0 | tool / malware names |
| IANA service-names-port-numbers | 7,329 | public registry | protocol / service |
| tiiuae/cpedict (distilled NVD CPE) | 63,577 products | Apache-2.0 | product / vendor |

**Matching policy is the whole game here** -- see the plan's §3.4 for the
measured collision rates that motivated it. Quality is inverse to size: MISP's
620 entries had zero generic-word collisions on probing, IANA's 7,329 had ~20,
and CPE's 63,577 had 22 of 44 probe words plus 804 junk entries of <=3 chars.
A flat match list over CPE would fire on `time`, `access`, `core`, `file`,
`data`, `web`, `mail`, `user` and `server`. So entries are filtered by minimum
length, form, and a generic-word stoplist, with per-source trust tiers.

What this cannot do: a dictionary answers "is this string a known entity name",
never "is this token an entity *in this context*". That residual ambiguity is
what Step 2's NER is for, and this script's measured precision is the baseline
Step 2 must beat.

Usage:
    python build_dicts.py            # fetch (cached), build, write gazetteer
    python build_dicts.py --refetch  # force re-download of the three sources

Writes ../data/entity_gazetteer.csv (name,type,source) and caches the raw
downloads under ./sources/ (gitignored).
"""
import argparse
import csv
import json
import os
import re
import sys

from sklearn.feature_extraction.text import ENGLISH_STOP_WORDS

HERE = os.path.dirname(os.path.abspath(__file__))
SOURCES_DIR = os.path.join(HERE, "sources")
OUT_PATH = os.path.normpath(os.path.join(HERE, "..", "data", "entity_gazetteer.csv"))

MISP_TOOL_URL = "https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/tool.json"
IANA_URL = ("https://www.iana.org/assignments/service-names-port-numbers/"
            "service-names-port-numbers.csv")
CPEDICT_URL = "https://raw.githubusercontent.com/tiiuae/cpedict/main/data/cpes.csv"

MIN_LEN = 4
_VALID_RE = re.compile(r"^[a-z][a-z0-9_.+-]*$")

# IDS/networking boilerplate that is a legitimate dictionary entry somewhere but
# is overwhelmingly an ordinary word in signature text. Bounded by design --
# curating this is tractable where curating 63,577 CPE products is not.
DOMAIN_GENERIC = set("""
server client service services file files data web mail user users admin access
core base link time name names host hosts port ports print printer login logout
auth authentication session sessions news echo talk daytime systat who chat
search store games music video photo work home box app apps job jobs task tasks
event events alert alerts check client console control manager management
monitor monitoring network networks node nodes object objects open close
package packages page pages path paths point points policy process processes
profile program project query queue record records remote report reports
request response resource resources root route router rule rules sample
schedule screen script scripts secure security select send server session
setup share shared shell site sites source space stack start state statistics
status stop stream string style system systems table target team temp test
tests text thread time timer title token tool tools total track traffic
transfer tree type types unit update upgrade upload usage value version view
virtual visual voice wait watch window windows word work world write zone
info error debug trace warning general common standard simple basic advanced
public private local global static dynamic active passive primary secondary
one two three now next last first second third good best free full half
light dark small large long short high low fast slow easy hard real live
main master slave group groups member members owner admin default custom
""".split())

STOPLIST = {w.lower() for w in ENGLISH_STOP_WORDS} | DOMAIN_GENERIC


def fetch(url, filename, refetch=False):
    """Download to ./sources/, reusing the cached copy unless --refetch."""
    os.makedirs(SOURCES_DIR, exist_ok=True)
    path = os.path.join(SOURCES_DIR, filename)
    if os.path.exists(path) and not refetch:
        return path
    import urllib.request
    print(f"  downloading {filename} ...")
    urllib.request.urlretrieve(url, path)
    return path


def acceptable(name, min_len=MIN_LEN):
    """Shared form filter: long enough, letter-leading, not a generic word.

    Rejects the CPE junk (`-`, `_`, `1.0`, `2fa`) and the common-English
    collisions measured in the plan's §3.4.
    """
    if len(name) < min_len:
        return False
    if not _VALID_RE.match(name):
        return False
    if name in STOPLIST:
        return False
    return True


def load_misp_tools(path):
    """MISP galaxy tool cluster. Highest-trust source -- zero generic-word
    collisions on probing -- so only the shared form filter is applied."""
    with open(path, encoding="utf-8") as fh:
        doc = json.load(fh)
    out = {}
    for entry in doc.get("values", []):
        for name in [entry.get("value")] + list(entry.get("meta", {}).get("synonyms", []) or []):
            if not name:
                continue
            n = name.strip().lower()
            if acceptable(n):
                out[n] = "tool"
    return out


def load_iana_services(path):
    """IANA service names. Medium trust -- real protocols (`http`, `smb`, `ssh`)
    sit alongside ordinary words (`who`, `auth`, `login`, `echo`, `daytime`),
    so the stoplist does most of the work here."""
    out = {}
    with open(path, encoding="utf-8", errors="replace") as fh:
        for row in csv.DictReader(fh):
            name = (row.get("Service Name") or "").strip().lower()
            if name and acceptable(name, min_len=3):  # 3 keeps dns/ftp/smb
                out.setdefault(name, "service")
    return out


def load_cpe(path):
    """Distilled NVD CPE vendor/product pairs. Lowest trust -- filtered hardest.

    Known limitation: `tiiuae/cpedict` distils CPE to vendor/product only and
    drops the CPE 2.3 `part` field (a/o/h), so application, OS and hardware
    cannot be distinguished here. Everything is typed `product`. The full NVD
    dictionary retains `part` if that distinction is later needed.
    """
    products, vendors = {}, {}
    with open(path, encoding="utf-8", errors="replace") as fh:
        for row in csv.DictReader(fh):
            p = (row.get("product") or "").strip().lower()
            v = (row.get("vendor") or "").strip().lower()
            if acceptable(p, min_len=5):  # hardest gate: the noisiest source
                products.setdefault(p, "product")
            if acceptable(v, min_len=5):
                vendors.setdefault(v, "vendor")
    products.update({k: t for k, t in vendors.items() if k not in products})
    return products


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--refetch", action="store_true", help="force re-download")
    args = ap.parse_args()

    print("fetching sources (cached under ./sources/)...")
    misp_path = fetch(MISP_TOOL_URL, "misp_tool.json", args.refetch)
    iana_path = fetch(IANA_URL, "iana_services.csv", args.refetch)
    cpe_path = fetch(CPEDICT_URL, "cpes.csv", args.refetch)

    loaders = [
        ("misp_galaxy", load_misp_tools, misp_path),
        ("iana", load_iana_services, iana_path),
        ("cpedict", load_cpe, cpe_path),
    ]

    # Highest-trust source wins a name collision, so `misp_galaxy` is applied
    # first and later sources only fill gaps.
    gazetteer = {}
    for source, loader, path in loaders:
        entries = loader(path)
        added = 0
        for name, etype in entries.items():
            if name not in gazetteer:
                gazetteer[name] = (etype, source)
                added += 1
        print(f"  {source:12s} {len(entries):6d} accepted, {added:6d} new")

    rows = sorted((n, t, s) for n, (t, s) in gazetteer.items())
    with open(OUT_PATH, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["name", "type", "source"])
        w.writerows(rows)

    print(f"\ngazetteer: {len(rows)} entries -> {OUT_PATH}")
    by_type = {}
    for _n, t, _s in rows:
        by_type[t] = by_type.get(t, 0) + 1
    print("by type:", by_type)


if __name__ == "__main__":
    sys.exit(main())
