# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

SAGE (IntruSion Alert-driven Attack Graph Extractor) is a Python tool that processes Suricata IDS alerts to automatically generate attack graphs. It uses a probabilistic automaton model (S-PDFA, via the external FlexFringe tool) to learn attacker behavior patterns from alert sequences and visualizes them as directed attack graphs.

This repository is a fork (`origin`: `jamiegharrison24/SAGE`, `upstream`: `tudelft-cda-lab/SAGE`) used for an honours extension project. A locked, reproducible reference point is pinned as tag `baseline-v1` — see `BASELINE.md` before making comparative changes.

## Environment

SAGE runs in a **Linux environment**. Contributors run it either natively on Linux/macOS or, on Windows, inside **WSL (Ubuntu)** — there is no native-Windows runtime because FlexFringe is a Linux binary. Windows contributors should follow `WINDOWS_SETUP.md`.

## Setup Requirements

The FlexFringe binary (`FlexFringe/flexfringe`, a Linux ELF x86-64) and its config (`FlexFringe/ini/spdfa-config.ini`) are **committed to the repo**, so a fresh checkout is runnable without building FlexFringe from source. The setup scripts install the remaining dependencies:

- **Automated setup**: run `./setup.sh` (Linux / WSL / macOS) or `setup.ps1` (Windows) to install system deps, Python packages, and build FlexFringe if the committed binary is missing or incompatible.
- **Python packages** (`requirements.txt`): `graphviz`, `requests`, `numpy`, `matplotlib` — install with `pip install -r requirements.txt`.
- **System tools**: `graphviz` (`dot` command must be in PATH), `bc`.
- **Alert data**: ships gzipped; decompress before the first run with `find alerts/ -type f -name '*.gz' | xargs gunzip`.
- **FlexFringe (only if rebuilding)**: source at https://github.com/tudelft-cda-lab/FlexFringe; place the compiled binary at `FlexFringe/flexfringe` and config at `FlexFringe/ini/spdfa-config.ini`.

## Version Control

- **Line endings**: `.gitattributes` normalizes all text files to **LF** in the repo (contributors work across native Linux and Windows/WSL). Do not commit CRLF; if you see spurious full-file diffs, run `git add --renormalize .`.
- **Baseline**: do not rewrite or force-push over the `baseline-v1` commit — later evaluation depends on it. Cut a new tag rather than moving the baseline.

## Commands

**Run SAGE:**
```bash
python sage.py alerts/cptc-2017/ exp-2017 --dataset cptc
python sage.py alerts/cptc-2018/ exp-2018 -t 2.0 -w 200 --dataset cptc
python sage.py alerts/ccdc/ exp-ccdc --dataset other --keep-files
```

**Run Python unit tests:**
```bash
python tests.py
```

**Run style check (PEP 8):**
```bash
pycodestyle --ignore=E501,W503,W504 *.py
pycodestyle --ignore=E501,W503,W504 signatures/*.py
```

**Regression/integration tests** (shell scripts in `test-scripts/`):
```bash
./test-scripts/test-ags.sh orig-2017 updated-2017      # Compare AGs between two runs
./test-scripts/test-sinks.sh updated-2017              # Test sink properties
```

## Architecture & Pipeline

The pipeline in `sage.py` (which acts as the main script) runs these steps in sequence:

1. **Load IANA port mapping** (`sage.py:load_iana_mapping`) — downloads CSV from IANA to resolve port numbers to service names.

2. **Load & parse alerts** (`sage.py:load_data`, `_parse`, `_remove_duplicates`) — reads JSON alert files (one per attacker/team), maps Suricata signatures to `MicroAttackStage` enum values, filters duplicates within a time window (`-t` parameter).

3. **Group alerts by attacker-victim pair** (`sage.py:group_alerts_per_team`) — reorganizes alerts keyed by `(src_ip, dst_ip)` tuples; for CPTC dataset applies special IP filtering.

4. **Episode generation** (`episode_sequence_generation.py:aggregate_into_episodes`) — aggregates alerts in sliding windows (`-w` parameter, default 150s), detects "episodes" using derivative/slope analysis of alert frequencies per attack stage. Each episode = one attacker action at a given MicroAttackStage.

5. **Episode sequences** (`episode_sequence_generation.py:host_episode_sequences`, `break_into_subbehaviors`) — reorganizes episodes per attacker host; cuts sequences at severity transitions to create "subsequences" representing distinct attack attempts.

6. **Trace generation** (`model_learning.py:generate_traces`) — converts episode subsequences into FlexFringe trace format: reversed `mcat|mserv` symbol sequences (reversed to create an S-PDFA emphasizing high-severity endpoints).

7. **S-PDFA learning** (`model_learning.py:flexfringe`) — invokes the FlexFringe binary to learn a probabilistic DFA from traces; produces `.ff.final.json` (main model) and `.ff.finalsinks.json` (sink states).

8. **Model loading & traversal** (`model_learning.py:load_model`, `traverse`, `encode_sequences`) — loads the JSON model into a `defaultdict` DFA; traverses each episode trace to assign state IDs; medium/high-severity sinks are tracked separately.

9. **Attack graph generation** (`ag_generation.py:make_attack_graphs`) — for each victim IP × high-severity objective, collects all attack attempts reaching that objective, then writes GraphViz `.dot` files and renders `.png`/`.svg` outputs into `<experiment_name>AGs/` directory.

## Key Data Structures

- **Alert tuple**: `(diff_dt, src_ip, src_port, dst_ip, dst_port, sig, cat, host, datetime, mcat_int)`
- **Episode tuple**: `(start_time, end_time, mcat, raw_events, volume, period, services, unique_signatures, (first_ts, last_ts))`
- **State sequence episode**: `(start_time, end_time, mcat, state_ID, mserv, unique_signatures, (first_ts, last_ts))`
- **DFA model**: `defaultdict(defaultdict(str))` mapping `state_id → symbol → next_state_id`

## Attack Stage Classification

`signatures/` contains the attack stage classification logic:
- `attack_stages.py`: `MicroAttackStage` and `MacroAttackStage` enums. Severity is encoded in the integer value: 1-digit = low, 2-digit = medium, 3-digit = high.
- `mappings.py`: bidirectional mappings between integer codes, string names, short symbols (`small_mapping` used in FlexFringe traces), and verbose display names.
- `alert_signatures.py`: dictionaries mapping Suricata signature strings to `MicroAttackStage` values.

## PR Labels for CI

The GitHub Actions workflow (`test.yml`) checks PR labels:
- `changes-ags`: skip regression tests (use when AGs intentionally change)
- `changes-ids`: run regression tests ignoring state IDs (use when S-PDFA structure changes but behavior is equivalent)
