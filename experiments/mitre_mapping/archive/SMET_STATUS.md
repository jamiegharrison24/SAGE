# SMET (method 7) install status — RESOLVED

**Update:** unblocked by installing a user-space Miniconda (no root needed)
and creating a Python 3.9 conda env (`~/miniconda3/envs/smet`), where
`torch==1.12.1` has wheels and `allennlp==2.10.1` installs cleanly. Two
further issues in the abandoned `Pattern`/`Pattern3` dependency (not
allennlp/torch) had to be patched — see `results.md` §6 for the full
account, including the two 1-line fixes applied to the *installed package*,
never to SMET's own source. Full results now in `results.md` §3/§5/§6 and
`predictions_method7.csv`. The original blocker analysis is kept below for
the record.

---

Cloned successfully: `experiments/mitre_mapping/SMET/` (github.com/basel-a/SMET, MIT license).

`SMET/requirements.txt` pins `allennlp==2.10.1`, which requires
`torch<1.13.0,>=1.10.0`. The only Python available in this environment's WSL
Ubuntu is 3.12.3, and no `torch` wheel below 2.2.0 exists for cp312:

```
$ python3 -m pip install --user 'allennlp==2.10.1' 'allennlp-models==2.10.1'
...
ERROR: Could not find a version that satisfies the requirement torch<1.13.0,>=1.10.0 (from allennlp) (from versions: 2.2.0, 2.2.1, 2.2.2, 2.3.0, 2.3.1, 2.4.0, 2.4.1, 2.5.0, 2.5.1, 2.6.0, 2.7.0, 2.7.1, 2.8.0, 2.9.0, 2.9.1, 2.10.0, 2.11.0, 2.12.0, 2.12.1, 2.13.0)
ERROR: No matching distribution found for torch<1.13.0,>=1.10.0
```

allennlp 2.10.1 (released 2022) was never built against Python 3.12. `SMET.py`
imports `nlp_general.NLP`, which does SRL (semantic role labeling) via
allennlp under the hood (`get_verbs_tag`/`add_arg0_from_parent` operate on
`srl['verbs']`/`B-V` BIO tags, the standard AllenNLP SRL predictor output
shape) — this is load-bearing for `map_attack_vector()`, not an optional
import, so it cannot be stubbed out without rewriting SMET's own pipeline
(out of scope: the task asks to call SMET's pipeline as-is).

Attempted to install Python 3.10 as an isolated venv interpreter to satisfy
the pin: `apt-get install python3.10` requires root, and this session has no
passwordless sudo (`sudo -n apt-get ...` → `sudo: a password is required`).
No other Python <3.11 interpreter is present on the machine (checked native
Windows Python 3.13, and WSL Ubuntu 3.12 only).

**Result: method 7 could not be run.** `results.md`'s master table marks it
N/A with a pointer to this file, rather than silently omitting the row.
Everything else SMET needed (repo clone, `LR_ATT&CK_model_V2.pkl`,
`id2ATT&CK_V2.json`, `sentence-transformers`, `spacy`+`en_core_web_lg`)
installed fine — allennlp/torch-version is the sole blocker.

If this needs to be unblocked later: get access to a Python 3.9/3.10
interpreter (pyenv, conda, or a machine with sudo) and `pip install -r
experiments/mitre_mapping/SMET/requirements.txt` there.
