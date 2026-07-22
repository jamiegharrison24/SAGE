# Reproducible Baseline (Task A1)

This document pins the locked, reproducible baseline for the SAGE extension
project. Both project members confirm SAGE runs from a clean checkout and
produces attack graphs at this reference point. All later work (MITRE mapping,
evaluation framework) is measured against this baseline.

## Pinned reference

| Item        | Value                                                     |
|-------------|-----------------------------------------------------------|
| Commit      | `9cd327f` (`Normalize line endings to LF`)                |
| Tag         | `baseline-v1`                                             |
| Fork        | https://github.com/jamiegharrison24/SAGE.git (`origin`)   |
| Upstream    | https://github.com/tudelft-cda-lab/SAGE.git (`upstream`)  |
| Branch      | `main`                                                    |

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

Datasets available under `alerts/`: `cptc-2017`, `cptc-2018`, `ccdc`.

## Baseline run commands

```bash
python sage.py alerts/cptc-2017/ exp-2017 --dataset cptc
python sage.py alerts/cptc-2018/ exp-2018 -t 2.0 -w 200 --dataset cptc
python sage.py alerts/ccdc/ exp-ccdc --dataset other --keep-files
```

Each run produces a trace file (`<name>.txt`), a rendered model
(`<name>.txt.png`), and an attack-graph directory (`<name>AGs/`) containing the
per-victim `.png`/`.svg` graphs. The `exp-2017` run on this baseline produces
attack graphs for the CPTC-2017 victims (confirmed).

## Verification checklist (A1)

- [x] SAGE runs from a clean checkout under version control
- [x] Generates attack graphs (`exp-2017AGs/` populated)
- [x] Line endings normalized to LF (`.gitattributes`) — no cross-machine diff churn
- [x] Both members confirm a clean run (Toby: native Linux; Jamie: WSL)
- [ ] Baseline tagged `baseline-v1` and pushed (`git push origin main --tags`)

## Notes

- Do not rewrite or force-push over commit `9cd327f`; later comparisons depend on it.
- If the toolchain versions above change materially, cut a new tag rather than
  moving `baseline-v1`.
