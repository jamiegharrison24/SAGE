#!/bin/bash
# Full evaluation matrix for every taxonomy/severity arm.
#
# The severity-sensitivity runner measures one reference cell per arm, which is
# enough to compare attack-graph structure and nothing else. The evaluation
# approach this project defines is multi-dimensional -- model behaviour, output
# quality, computational cost -- and model behaviour needs the other cells:
# repeat runs (output variance), noise injection (robustness) and parameter
# sweeps (sensitivity). Without them the framework is demonstrated on one
# configuration and claimed for all of them.
#
# Mirrors the baseline matrix in docs/BASELINE_METRICS.md exactly, so the arms
# are comparable to baseline/metrics-*.json cell for cell:
#
#   cptc-2017, cptc-2018   61 cells: reference + 48 noise + 7 sweep + 5 repeat
#   ccdc                   13 cells: the same without noise injection, which
#                          docs/FINDINGS.md records as a deliberate reduction
#
# Four arms x that matrix is ~540 cells, on the order of 14 hours. Cells are
# fingerprinted and cached per arm run-root, so an interrupted run resumes
# rather than restarting -- but the run-root must stay per-arm, because sharing
# one silently served another arm's cells early in this work.
#
# Each arm ends with the same three artifacts the baseline directory holds:
# metrics-<ds>.json, report-<ds>.md, dashboard-<ds>.html.
#
# Linux/WSL only -- FlexFringe is a Linux binary (see docs/WINDOWS_SETUP.md).
cd "$(dirname "$0")/.." || exit 1

WORKTREE=$(pwd)
OUT="${OUT:-$(cd .. && pwd)/eval-sensitivity}"
DATASETS="${DATASETS:-cptc-2017 cptc-2018 ccdc}"
ARMS="${ARMS:-aif kill-chain aif-aligned impact-only}"
REPEATS="${REPEATS:-5}"

export PYTHONHASHSEED=0
export PYTHONUNBUFFERED=1

taxonomy_for() {
    case "$1" in
        aif) echo "aif" ;;
        *)   echo "mitre_var_${1//-/}" ;;
    esac
}

for arm in $ARMS; do
    taxonomy=$(taxonomy_for "$arm")
    variant="$arm"
    [ "$arm" = "aif" ] && variant="kill-chain"   # unused by the AIF path

    echo "############################################################"
    echo "# ARM: $arm   (SAGE_TAXONOMY=$taxonomy)"
    echo "############################################################"

    if [ "$arm" != "aif" ]; then
        SAGE_SEVERITY_VARIANT="$variant" python3 -m signatures.build_mitre_mapping \
            --level hybrid --unmapped catchall \
            --out "signatures/mitre_mapping_${taxonomy#mitre_}.py" 2>&1 \
            | grep -E "^ +(low|medium|high):"
    fi

    git checkout -- flexfringe.log 2>/dev/null
    dirty=$(git status --porcelain | grep -v '^??')
    if [ -n "$dirty" ]; then
        echo "REFUSING: tracked files modified, the harness would reject every cell --"
        echo "$dirty" | head -n 3
        exit 1
    fi

    mkdir -p "$OUT/$arm"
    for dataset in $DATASETS; do
        # ccdc omits noise injection, matching the baseline's reduced matrix.
        noise="--perturb"
        [ "$dataset" = "ccdc" ] && noise=""

        echo "---- $arm / $dataset ----"
        date '+      started %H:%M:%S'
        SAGE_TAXONOMY="$taxonomy" SAGE_SEVERITY_VARIANT="$variant" \
            python3 -m evaluation run --dataset "$dataset" \
            --worktree "$WORKTREE" --baseline-dir "$OUT/$arm" \
            --run-root "$OUT/$arm/runs" \
            --heldout --sweep --repeats "$REPEATS" $noise 2>&1 | tail -n 4
        echo "      EXIT=${PIPESTATUS[0]}"
        git checkout -- flexfringe.log 2>/dev/null

        # The same three artifacts the baseline directory holds, from the same
        # renderers -- so an arm's dashboard is comparable to the baseline's
        # rather than merely similar to it.
        SAGE_TAXONOMY="$taxonomy" SAGE_SEVERITY_VARIANT="$variant" \
            python3 -m evaluation report --dataset "$dataset" \
            --baseline-dir "$OUT/$arm" \
            --markdown "$OUT/$arm/report-$dataset.md" \
            --dashboard "$OUT/$arm/dashboard-$dataset.html" 2>&1 | tail -n 2
        date '+      finished %H:%M:%S'
    done
done

git checkout -- flexfringe.log 2>/dev/null
python3 test-scripts/stamp_severity_variants.py "$OUT"
python3 -m evaluation.arm_dashboard "$OUT" --out experiments/mitre_mapping/arms.html

echo "############################################################"
echo "# artifacts"
ls -1 "$OUT"/*/dashboard-*.html "$OUT"/*/report-*.md 2>/dev/null | sed "s|$OUT/||"
