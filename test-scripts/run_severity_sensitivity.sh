#!/bin/bash
# SEVERITY SENSITIVITY: how much of the AIF-vs-ATT&CK gap is our tier table?
#
# ATT&CK publishes no severity ordering for tactics, so the medium/high
# boundary in signatures/mitre_stages.py is this project's judgement. The
# attack-graph count depends on it directly -- graphs are generated per
# high-severity objective. This run varies ONLY that boundary, holding the
# vocabulary, labels, commit, IANA snapshot and seed constant, so the
# difference between arms is attributable to the tiering alone.
#
#   kill-chain   objectives = Impact / Exfiltration / C2      (current default)
#   aif-aligned  + initial-access, lateral-movement promoted  (AIF's objective
#                definition, so exploitation terminates a graph as it does in
#                AIF -- constructed to reproduce the baseline, not independent)
#   impact-only  objectives = Impact / Exfiltration only      (strictest reading)
#
# Each variant is generated to signatures/mitre_mapping_var_<name>.py, which is
# gitignored. Writing to the tracked hybrid table instead would dirty the
# worktree, and the harness refuses to measure a dirty tree -- correctly, since
# the result could not then be attributed to a commit. The consequence is that
# every arm records the same commit SHA; experiments/mitre_mapping/REPORT.md
# 8a.9 explains the variant.json stamp that disambiguates them.
#
# Results are read with:
#   python compare_arms.py ../eval-sensitivity --dataset cptc-2017
#
# Linux/WSL only -- FlexFringe is a Linux binary (see docs/WINDOWS_SETUP.md).
cd "$(dirname "$0")/.." || exit 1

WORKTREE=$(pwd)
OUT="${OUT:-$(cd .. && pwd)/eval-sensitivity}"
DATASET="${DATASET:-cptc-2017}"
VARIANTS="${VARIANTS:-kill-chain aif-aligned impact-only}"

export PYTHONHASHSEED=0
export PYTHONUNBUFFERED=1

echo "=========== ARM: aif (baseline) ==========="
git checkout -- flexfringe.log 2>/dev/null
mkdir -p "$OUT/aif"
SAGE_TAXONOMY=aif python3 -m evaluation run --dataset "$DATASET" \
    --worktree "$WORKTREE" --baseline-dir "$OUT/aif" \
    --run-root "$OUT/aif/runs" --heldout 2>&1 | tail -n 3
echo "EXIT=${PIPESTATUS[0]}"

for variant in $VARIANTS; do
    slug="${variant//-/}"                      # module names cannot contain '-'
    echo "=========== VARIANT: $variant ==========="
    SAGE_SEVERITY_VARIANT="$variant" python3 -m signatures.build_mitre_mapping \
        --level hybrid --unmapped catchall \
        --out "signatures/mitre_mapping_var_${slug}.py" 2>&1 \
        | grep -E "^ +(low|medium|high):"
    git checkout -- flexfringe.log 2>/dev/null
    # Mirror the harness's own check (evaluation/runner.py:assert_worktree_clean):
    # TRACKED modifications only. The generated tables are untracked and
    # gitignored, which is the whole point of writing them to a var_* path.
    # Editing any tracked file while this runs -- a report, a note -- will
    # abort the arm; that has happened, hence the explicit message.
    dirty=$(git status --porcelain | grep -v '^??')
    if [ -n "$dirty" ]; then
        echo "REFUSING: tracked files modified, harness would reject the run --"
        echo "$dirty" | head -n 3
        continue
    fi
    mkdir -p "$OUT/$variant"
    SAGE_TAXONOMY="mitre_var_${slug}" SAGE_SEVERITY_VARIANT="$variant" \
        python3 -m evaluation run --dataset "$DATASET" \
        --worktree "$WORKTREE" --baseline-dir "$OUT/$variant" \
        --run-root "$OUT/$variant/runs" --heldout 2>&1 | tail -n 3
    echo "EXIT=${PIPESTATUS[0]}"
done

git checkout -- flexfringe.log 2>/dev/null

# The deciding input is a gitignored file, so the commit SHA the harness
# records cannot tell the arms apart. Stamp each one with the table that
# produced it.
python3 test-scripts/stamp_severity_variants.py "$OUT"

echo "=== records ==="
ls -1 "$OUT"/*/metrics-"$DATASET".json 2>/dev/null | sed "s|$OUT/||"
