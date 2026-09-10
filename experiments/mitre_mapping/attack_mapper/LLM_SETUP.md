# LLM setup (optional)

The pipeline runs fully without an LLM configured -- `llm_client.NullLLMClient`
is the default, and `reasoner.py` logs the reasoning layer as skipped rather
than silently proceeding. The 53.8% top-1 baseline everywhere in `findings.md`
and `STATUS.md` was produced with no LLM at all. This doc is for wiring one
in -- and for the record, per `findings.md`'s "LLM layer tested" section,
doing so has so far made results *worse* (33.8% top-1 with `llama3.2:3b`),
not better. Read that section before assuming this is a pure upside to add.

**Nothing here goes in the repo.** Model weights are multi-gigabyte binary
blobs that live in Ollama's own cache directory, never in
`experiments/mitre_mapping/`. `.gitignore` doesn't even need an entry for
them -- they're outside the repo entirely.

## Local, free: Ollama

Recommended default -- no API key, no per-call cost, nothing leaves your
machine. Setup:

**Update:** `llama3.1:8b` has now been scored too (on a 31GB machine, gating/
blending fix applied to `reasoner.py`) — still a regression (46.2% top-1,
down from 53.8% off), for a different reason than `llama3.2:3b`'s. See
"The actual result" below and `findings.md`'s "Update: gating fix +
llama3.1:8b" section.

1. **Install.** On Windows:
   ```powershell
   winget install --id Ollama.Ollama -e
   ```
   (or download from https://ollama.com). This installs the app and starts
   a background server on `http://localhost:11434`.

2. **Pick where models are stored.** Ollama defaults to
   `%USERPROFILE%\.ollama\models` -- i.e. your `C:` drive, or whatever
   drive your user profile is on. Models are multi-gigabyte, so if that
   drive is tight on space, redirect the cache **before** pulling anything:
   ```powershell
   [Environment]::SetEnvironmentVariable("OLLAMA_MODELS", "D:\ollama-models", "User")
   ```
   Then restart the Ollama server so it picks up the new setting (kill the
   `ollama`/`ollama app` processes and relaunch, or just reboot/re-login).
   Check where a model actually lives with `ollama list` plus
   `Get-ChildItem $env:OLLAMA_MODELS` (or the default path if unset) --
   don't assume; verify.

3. **Pull a model, sized to your actual RAM.**
   ```powershell
   ollama pull llama3.2:3b      # ~2GB -- fits comfortably on a 16GB machine
                                 # alongside a normal desktop load; what was
                                 # actually used to produce the 33.8% result
   ollama pull llama3.1:8b      # ~4.9GB -- untested end-to-end here, see below
   ollama pull qwen2.5:14b      # ~9GB -- only if you have 32GB+ RAM or a GPU
   ```
   Layer D's job (`reasoner.py`'s `_llm_refine`) is picking techniques from
   a JSON candidate list and returning JSON back -- instruction-following
   and JSON reliability matter more here than raw model size, in theory.
   In practice the only model actually scored so far (`llama3.2:3b`) did
   *worse* than no LLM at all -- see "the actual result" below before
   assuming a bigger model fixes that; the regression may be more about
   `reasoner.py`'s design than model size.

4. **Verify.**
   ```powershell
   ollama list
   curl http://localhost:11434/api/version
   ```

   **Memory troubleshooting.** `classifier_resolver.py`'s training step
   (`n_jobs`-parallel `OneVsRestClassifier` over ~30k rows) plus a loaded
   Ollama model can add up fast on a small machine -- this combination
   triggered a Windows out-of-memory kill on a 16GB laptop with `llama3.1:8b`
   before `classifier_training.py`'s `n_jobs` was capped at 4 (was `-1`,
   i.e. one worker per CPU core, each holding its own copy of the training
   matrices). If you hit OOM kills: check `Get-Process ollama,llama-server`
   for an orphaned inference process left over from a killed run (`Stop-Process
   -Force` it -- it won't clean itself up), and prefer a smaller model over
   fighting for headroom.

5. **Wire it in.** Ollama exposes an OpenAI-compatible endpoint, so
   `llm_client.OpenAIClient` works against it directly via `base_url` --
   no separate adapter needed:
   ```python
   from attack_mapper.llm_client import OpenAIClient
   from attack_mapper.pipeline import AttackMapperPipeline

   llm = OpenAIClient(
       api_key="ollama",  # unchecked by Ollama, but the SDK requires a non-empty string
       model="llama3.2:3b",
       base_url="http://localhost:11434/v1",
   )
   pipeline = AttackMapperPipeline(llm_client=llm)
   ```
   Or use the `ollama_client()` convenience factory in `llm_client.py`,
   which does exactly this with sensible defaults. Simpler still,
   `validate.py` has a `--llm ollama [--llm-model NAME]` flag that does the
   above and writes results to `validation_report_llm.md` (kept separate
   from the committed no-LLM `validation_report.md` so the two stay
   diffable).

   Requires the `openai` Python package (`pip install openai`) -- the
   import is deferred inside `OpenAIClient.__init__` so the rest of the
   pipeline doesn't need it installed.

## Hosted: OpenAI / Anthropic

```python
from attack_mapper.llm_client import OpenAIClient, AnthropicClient

llm = OpenAIClient(api_key="sk-...", model="gpt-4-turbo")
# or
llm = AnthropicClient(api_key="sk-ant-...", model="claude-sonnet-5")
```

Costs per call, and your rule text/narratives leave your machine. Neither
has been exercised in this research branch -- no credentials have ever been
available in this environment.

## The actual results

`python validate.py --llm ollama --llm-model llama3.2:3b`: **33.8% top-1
(27/80), down from 53.8% with the LLM off.** Full writeup, root-cause
analysis, and what's untried in `findings.md`'s "LLM layer tested" section
-- short version: `reasoner.py`'s `_llm_refine` currently fires on *every*
row with any candidate at all (which, thanks to the embedding fallback, is
every row), and fully replaces rather than blends the prior confidence --
so a high-precision `declared`/`bridge_table` answer can get silently
overridden by the LLM's own (often wrong, confidently-stated) guess.
`T1190` hub-collapse rose from 16% to 30% of rows, and self-reported
confidence was uncorrelated with correctness (0.80 avg on misses, 0.83 on
hits).

`llama3.1:8b` -- the model this doc originally recommended as the better
option, which OOM-killed before finishing on the 16GB machine above -- has
since been scored on a 31GB machine, with the gate/blend fix from that
paragraph applied first (`Settings.llm_gate_confidence` in `config.py`;
`_llm_refine` now blends rather than replaces). **Result: 46.2% top-1
(37/80), still down from 53.8% off, but a smaller regression than
`llama3.2:3b`'s (8 points vs. 20).** The design bugs are confirmed fixed
(33/100 rows now skip the LLM entirely; blended rows often keep the correct
prior) -- the residual loss is a third failure mode: the LLM proposing a
technique outside the candidate list it was shown, at 0.80-0.95 confidence,
which then wins the top-1 sort against a correct-but-lower-confidence prior
(9 of 43 miss rows). See `findings.md`'s "Update: gating fix + llama3.1:8b"
section for the full breakdown. Untried next step: reject/down-weight any
`technique_id` in the LLM's JSON response that wasn't in the candidates it
was given, rather than treating it as a legitimate new candidate.
