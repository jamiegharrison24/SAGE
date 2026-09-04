# Archived — superseded by ../attack_mapper

Everything under this directory is effort 1 (the original 7-method
comparison: `results.md`, `SMET_STATUS.md`, and the `bad_call_table.*`/
`build_*.py`/`score.py`/etc. scripts that produced it) and effort 2
(`tiered_approach/`, the Tier 0-4 pipeline). Both are superseded by
`../attack_mapper`, the active approach — see `../STATUS.md` for the full
history and current numbers.

Kept for the record: real completed research, cited by name in
`../findings.md` and `../attack_mapper/sigma_corpus/findings.md` (e.g. the
class-imbalance finding in `tiered_approach/embedding_swap_findings.md` is
what motivated the Sigma-corpus pull). Not being iterated on.

Everything here is internally self-consistent and was left otherwise
unmodified by the move — each script's own relative-path assumptions
(`ROOT = os.path.dirname(HERE)` etc.) still resolve within this directory,
so they remain individually reproducible. `tiered_approach/
tier2_classifier_combined.py` is the one exception worth knowing about: it
reads `sigma_corpus/sigma_labeled_corpus.csv` here, which is a frozen copy
of the file `../attack_mapper` actually uses — see
`../attack_mapper/sigma_corpus/findings.md` for why both copies exist.
