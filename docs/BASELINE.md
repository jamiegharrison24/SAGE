# Reproducible Baseline (Task A1)

> Part of the [documentation index](README.md). See also the project
> [`README.md`](../README.md) for running SAGE.

This document pins the locked, reproducible baseline for the SAGE extension
project. Both project members confirm SAGE runs from a clean checkout and
produces attack graphs at this reference point. All later work (MITRE mapping,
evaluation framework) is measured against this baseline.

## Pinned reference

| Item        | Value                                                     |
|-------------|-----------------------------------------------------------|
| Commit      | `20aa5ed99bfee77143d88ffdb19ed43a108810eb` — merge of PR #2, includes the NationalTeam1 data fix |
| Tag         | `baseline-v1`                                             |
| Fork        | https://github.com/jamiegharrison24/SAGE.git (`origin`)   |
| Upstream    | https://github.com/tudelft-cda-lab/SAGE.git (`upstream`)  |
| Branch      | `main`                                                    |

> **Note:** the earlier candidate commit `9cd327f` predates the CPTC-2017
> data-integrity fix (see *Dataset integrity* below) and must **not** be used as
> the baseline. Pin the tag to the commit that includes the fix.

To check out the exact baseline:

```bash
git clone https://github.com/jamiegharrison24/SAGE.git
cd SAGE
git checkout baseline-v1
```

## Environment

SAGE runs in a Linux environment. Toby runs it natively on Linux; Jamie runs it
via WSL (Ubuntu) on Windows 11 — see `WINDOWS_SETUP.md` for the Windows/WSL
setup. There is no native-Windows runtime: FlexFringe is a Linux binary, so a
native-Windows collaborator without WSL cannot run this baseline as-is.

Known-good toolchain (confirm against your machine):

- Python 3.10+ with packages from `requirements.txt` (`graphviz`, `requests`, `numpy`, `matplotlib`)
- Graphviz 2.43+ (`dot` must be on PATH)
- `bc`
- FlexFringe binary at `FlexFringe/flexfringe` — Linux ELF x86-64, committed to the repo
- FlexFringe config at `FlexFringe/ini/spdfa-config.ini`

## One-time data prep

Alert files ship compressed; decompress before the first run:

```bash
find alerts/ -type f -name '*.gz' | xargs gunzip
```

Datasets available under `alerts/`: `cptc-2017` (10 teams, `NationalTeam1`–`NationalTeam10`), `cptc-2018`, `ccdc`.

## Dataset integrity

SAGE selects alert files with `glob.glob(path + "/*.json")` (`sage.py`), so any
alert file whose name does not end in exactly `.json` is silently skipped.

- **CPTC-2017 must contain 10 team files** named `NationalTeam1.json`–`NationalTeam10.json`
  (shipped as `.json.gz`). Earlier, `NationalTeam1` was committed as
  `NationalTeam1.json__` (plus a `NationalTeam1.json__.gz`), which did not match
  the glob — so NationalTeam1 was excluded and the pre-fix baseline was built from
  only 9 teams. This is corrected in the pinned baseline commit.
- When adding or renaming alert files, confirm the count and that every file ends
  in `.json.gz`; do not commit decompressed `.json` files.

## Baseline run commands

```bash
python sage.py alerts/cptc-2017/ exp-2017 --dataset cptc
python sage.py alerts/cptc-2018/ exp-2018 -t 2.0 -w 200 --dataset cptc
python sage.py alerts/ccdc/ exp-ccdc --dataset other --keep-files
```

Each run produces a trace file (`<name>.txt`), a rendered model
(`<name>.txt.png`), and an attack-graph directory (`<name>AGs/`) containing the
per-victim `.png`/`.svg` graphs. The `exp-2017` run on the corrected baseline
processes all 10 CPTC-2017 teams. Baseline artifacts must be regenerated from the
fixed data (the pre-fix `exp-2017AGs/` reflected only 9 teams and are stale).

## Verification checklist (A1)

- [x] SAGE runs from a clean checkout under version control
- [x] Line endings normalized to LF (`.gitattributes`) — no cross-machine diff churn
- [x] Both members confirm a clean run (Toby: native Linux; Jamie: WSL)
- [x] CPTC-2017 data-integrity fix applied (all 10 teams; NationalTeam1 restored)
- [x] Baseline artifacts regenerated from corrected data (10 CPTC-2017 teams)
- [x] Baseline commit pinned above and tagged `baseline-v1`, pushed

## Notes

- Pin `baseline-v1` to the commit that includes the CPTC-2017 data fix; do not use
  `9cd327f` (pre-fix, 9 teams).
- Do not rewrite or force-push over the pinned baseline commit; later comparisons
  depend on it.
- If the toolchain versions above change materially, cut a new tag rather than
  moving `baseline-v1`.
