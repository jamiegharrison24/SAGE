# Known Issues

Identified during codebase review (2026-03-17).

---

## Critical

### 1. Command injection via `os.system()`
**Files:** `sage.py:316,325-326,358-367`, `ag_generation.py:325-326`
`path_to_traces` (from `experiment_name`) and `victim` (from alert file content) are concatenated directly into shell commands. A malicious alert file with a crafted victim IP or a malicious `experiment_name` argument can inject shell commands.
**Fix:** Replace all `os.system("cmd " + var)` with `subprocess.run(["cmd", var])`.

### 2. No HTTP timeout on IANA download
**File:** `sage.py:58`
`requests.get(IANA_CSV_FILE)` can hang indefinitely.
**Fix:** Add `timeout=30`.

---

## High

### 3. `IndexError` on empty alert list after filtering
**File:** `sage.py:217`
`parsed_alerts[0]` is accessed without a length check. If all alerts are filtered out (wrong path, all NON_MALICIOUS, all duplicates), this raises `IndexError`.
**Fix:** Add `if not parsed_alerts: continue` before line 217.

### 4. Misleading comment in `_remove_duplicates()`
**File:** `sage.py:175`
Comment says `# Same suricata category` but index `[5]` is `sig` (signature), not `cat` (category, which is index `[6]`).
**Fix:** Correct comment to `# Same suricata signature`.

### 5. `IndexError` on low-severity node in `make_attack_graphs()`
**File:** `ag_generation.py:305`
`vname.split('|')[2]` is accessed unconditionally. Low-severity nodes have only 2 parts (`mcat|mserv`), no state_id, so this raises `IndexError`.
**Fix:** Guard with `len(vname.split('|')) > 2`.

---

## Medium

### 6. No `if __name__ == '__main__'` guard in `sage.py`
**File:** `sage.py`
The entire pipeline runs at import time (argument parsing, HTTP download, file I/O, subprocess calls). This makes it impossible to import or unit test any helper function in `sage.py`.
**Fix:** Wrap the pipeline in `if __name__ == '__main__':`.

### 7. Implicit global `dataset_name` across modules
**Files:** `sage.py:148,252`
`dataset_name` is set at module level and used as an implicit global inside `_parse()` and `group_alerts_per_team()`. These functions cannot be tested independently.
**Fix:** Pass `dataset_name` as an explicit parameter.

### 8. Fragile FlexFringe JSON fixer
**File:** `sage.py:318-341`
Trailing commas in FlexFringe's JSON output are patched with regex + `rsplit`. This is brittle and will silently corrupt the model file if FlexFringe's output format changes.
**Fix:** Use a tolerant JSON parser (e.g. `json5`) or fix the issue upstream in FlexFringe.

### 9. O(n²) `_most_frequent()`
**File:** `model_learning.py:17-29`
Calls `serv.count(s)` (O(n) scan) for every element in `serv`. Called per episode per trace.
**Fix:** Replace with `collections.Counter(serv).most_common()`.

### 10. Silently discarded subprocess errors
**Files:** `sage.py:316,358-367`, `ag_generation.py:325-326`
All `os.system()` return codes are ignored. If `dot` or `rm` fails, the pipeline continues silently.
**Fix:** Use `subprocess.run()` and check `returncode`.

---

## Low

### 11. Dead code: unreachable `len(episodes) == 1` branch
**File:** `episode_sequence_generation.py:258`
`if len(episodes) < 2: continue` at line 250 makes the `len(episodes) == 1` check at line 258 unreachable.

### 12. Unused variable `new_state`
**File:** `model_learning.py:201`
`new_state = [int(x) for x in state_list][::-1]` is computed but never used. Leftover from a refactor.

### 13. Dead code: sink state visual formatting never triggers
**File:** `ag_generation.py:79,268,279`
Three separate code paths are documented with `TODO: this check is always False/True`. The `|Sink` state_id branch (line 82) is never reachable, meaning sink state dotted-style formatting has never worked as intended.

### 14. Hard cap at 10 teams with no validation
**File:** `ag_generation.py:203`
`tcols` only defines colors for `t0`–`t9`. An 11th JSON file causes `KeyError`. The limit is undocumented.

### 15. Division by zero in `_print_simplicity()`
**File:** `ag_generation.py:189`
`vertices / float(edges)` raises `ZeroDivisionError` when there are no edges. Currently commented out at call site but still live code.
