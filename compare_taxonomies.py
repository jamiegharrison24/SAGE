"""Compare what each annotation taxonomy does to the alert stream.

Runs the pipeline up to (not including) FlexFringe for each taxonomy arm and
reports what changed. Everything before model learning is pure Python, so this
runs anywhere -- FlexFringe is a Linux ELF and the S-PDFA stage needs WSL.

What it measures, and why each matters for the AIF-vs-ATT&CK comparison:

  * **alerts surviving** -- the `drop` arms discard signatures ATT&CK has no
    vocabulary for, so the ATT&CK graphs are built from a smaller stream
    before any modelling difference is considered.
  * **episodes / subsequences** -- subsequences are cut at severity DROPS, so
    a taxonomy that assigns severity differently cuts them differently. This
    is the first place a taxonomy change alters structure.
  * **distinct trace symbols** -- the FlexFringe alphabet. A larger alphabet
    means sparser transitions and more sink states; the baseline already
    resolves 38% of scored steps through sinks.
  * **objectives present** -- high-severity codes are what attack graphs are
    generated per, so this is how many graph *types* each arm can produce.

Usage:
    python compare_taxonomies.py alerts/cptc-2017 --dataset cptc
"""
import argparse
import os
import subprocess
import sys

ARMS = ("aif", "mitre_hybrid_drop", "mitre_hybrid_catchall",
        "mitre_tactic_drop", "mitre_tactic_catchall")

CHILD = r'''
import os, sys, collections
sys.path.insert(0, %(root)r)
from pipeline import PipelineConfig, load_alerts, build_episode_subsequences
from signatures import taxonomy

cfg = PipelineConfig(path_to_json_files=%(path)r, experiment_name="_taxcmp",
                     dataset_name=%(dataset)r)
_, team_alerts, _, team_start_times, team_data = load_alerts(cfg)
team_episodes, episode_subsequences = build_episode_subsequences(
    team_data, team_start_times, cfg)

alerts = sum(len(v) for v in team_alerts)

# team_episodes: list (one per team) of {attacker-victim: [episode, ...]}
episodes = 0
for team in team_episodes:
    if isinstance(team, dict):
        episodes += sum(len(v) for v in team.values())

# episode_subsequences: flat dict {"t0-src->dst-N": subsequence}, where the
# -N suffix is the subsequence index and the value is ONE subsequence -- a
# list of episode tuples whose index 2 carries the stage code.
subseqs = len(episode_subsequences)
symbols = set()
objectives = set()
for sub in episode_subsequences.values():
    for ep in sub:
        mcat = ep[2]
        try:
            symbols.add(taxonomy.trace_symbol(mcat))
        except KeyError:
            continue
        if len(str(mcat)) == 3:
            objectives.add(taxonomy.code_to_label(mcat))
print("RESULT", alerts, episodes, subseqs, len(symbols), "|".join(sorted(objectives)))
'''


def run_arm(arm, path, dataset, root):
    env = dict(os.environ, SAGE_TAXONOMY=arm, PYTHONIOENCODING="utf-8")
    code = CHILD % {"root": root, "path": path, "dataset": dataset}
    proc = subprocess.run([sys.executable, "-c", code], env=env,
                          capture_output=True, text=True, encoding="utf-8",
                          errors="replace")
    for line in (proc.stdout or "").splitlines():
        if line.startswith("RESULT"):
            _, alerts, episodes, subseqs, symbols, objs = line.split(" ", 5)
            return dict(alerts=int(alerts), episodes=int(episodes),
                        subseqs=int(subseqs), symbols=int(symbols),
                        objectives=[o for o in objs.split("|") if o])
    sys.stderr.write(f"\n--- {arm} failed ---\n{proc.stdout[-1500:]}\n{proc.stderr[-2000:]}\n")
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("path")
    ap.add_argument("--dataset", default="cptc")
    ap.add_argument("--arms", nargs="*", default=list(ARMS))
    args = ap.parse_args()

    root = os.path.dirname(os.path.abspath(__file__))
    rows = {}
    for arm in args.arms:
        print(f"running {arm} ...", flush=True)
        rows[arm] = run_arm(arm, args.path, args.dataset, root)

    print(f"\n{'arm':<24s} {'alerts':>9s} {'episodes':>9s} {'subseqs':>8s} "
          f"{'symbols':>8s}  objectives")
    base = rows.get("aif")
    for arm in args.arms:
        r = rows.get(arm)
        if not r:
            print(f"{arm:<24s} {'FAILED':>9s}")
            continue
        delta = ""
        if base and arm != "aif" and base["alerts"]:
            pct = 100.0 * (r["alerts"] - base["alerts"]) / base["alerts"]
            delta = f"  ({pct:+.1f}% alerts)"
        objs = ", ".join(r["objectives"][:4]) or "(none)"
        more = f" +{len(r['objectives']) - 4}" if len(r["objectives"]) > 4 else ""
        print(f"{arm:<24s} {r['alerts']:>9d} {r['episodes']:>9d} "
              f"{r['subseqs']:>8d} {r['symbols']:>8d}  "
              f"{len(r['objectives'])}: {objs}{more}{delta}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
