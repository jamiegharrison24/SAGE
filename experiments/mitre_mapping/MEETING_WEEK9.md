# Week 9 supervisor meeting — run sheet

Built to be read *while talking*. Ordered to lead with the strongest item, not
in the order the four were asked. Detail you only need if pressed is in the
appendix at the bottom.

**Don't build slides.** Screen-share the artifacts — they answer "did you
actually do it" in a way a bullet cannot. Keep this file open as your notes.

**Open before you start:**

| # | What | Where |
|---|---|---|
| 1 | Arm comparison | `experiments/mitre_mapping/arms.html` |
| 2 | Mapper results | `experiments/mitre_mapping/mapping.html` |
| 3 | Graph pair, victim 10.0.0.110 | `../eval-sensitivity/{aif,aif-aligned}/runs/cells/cptc-2017-reference/cptc-2017-referenceAGs/` |

---

## 0–2 min · The framing claim

**SAY**, once, plainly:

> SAGE reads severity at three points. AIF publishes severity as part of its
> model. **ATT&CK publishes none.** So substituting ATT&CK forces us to invent
> a severity model — and that invented model, not the taxonomy, dominates the
> output.

Everything else hangs off this. Don't rush it.

**Then define the four arms before any table goes on screen** — they are the
column headers everywhere, and they are meaningless cold. One line each:

| arm | what it is | counts as an *objective* |
|---|---|---|
| **aif** | SAGE as published — the baseline. Severity comes from the Action-Intent Framework, which publishes it. | exploitation onwards: 13 stages incl. exfiltration, delivery |
| **kill-chain** | ATT&CK read literally. Our first tiering. | Impact, Exfiltration, Command-and-Control |
| **aif-aligned** | ATT&CK, tiered so exploitation ends a graph the way it does in AIF. | + **Initial Access**, **Lateral Movement** |
| **impact-only** | ATT&CK, strictest reading. | Impact, Exfiltration only |

**SAY:** *An "objective" is a high-severity state — reaching one ends an attack
graph, so which tactics sit in that tier decides what gets drawn. The three
ATT&CK arms share one vocabulary and one label set. **The only thing that
differs between them is that last column.***

> If they ask why `aif-aligned` isn't just "the right answer": it was built to
> reproduce AIF's objective definition, so it can't also be the independent
> evidence that AIF's definition is correct.

---

## 2–8 min · Item 3 — AIF → ATT&CK

**SHOW:** `arms.html`. Cards run **Terms, The arms, ccdc, cptc-2017,
cptc-2018** — datasets are alphabetical, so **scroll past ccdc** to the card
headed **cptc-2017**. Point at **two rows only**.

| cptc-2017 | aif | kill-chain | aif-aligned |
|---|---:|---:|---:|
| attack graphs | 104 | 9 | **115** |
| victims | 36 | 7 | **41** |

**SAY:** *Same labels, same signatures, same pipeline code. Two tactics
re-tiered. That's the whole difference.*

**THEN SHOW:** the graph pair — victim 10.0.0.110, same alerts, both arms.

Open these two side by side. Both are in
`../eval-sensitivity/<arm>/runs/cells/cptc-2017-reference/cptc-2017-referenceAGs/`,
and they are the cleanest comparison because they share a victim *and* a
service:

| arm | file |
|---|---|
| `aif` | `…-victim-10.0.0.110-DATADELIVERYhttp.png` |
| `aif-aligned` | `…-victim-10.0.0.110-T1190http.png` |

(every filename begins `cptc-2017-reference.txt-attack-graph-for`)

**SAY:** *Same host, same HTTP traffic. AIF says "data delivery". ATT&CK says
T1190 — Exploit Public-Facing Application.*

The rest of that victim's graphs, if they want more: AIF also has
`DATAEXFILTRATIONhttp` and `NETWORKDOSssdp`; `aif-aligned` also has
`T1078.001snmp` (Valid Accounts: Default Accounts).

**Stop there.** Don't walk the rest of the table.

> Also true if it comes up: tactic, hybrid *and* technique levels are built and
> switchable at runtime (`SAGE_TAXONOMY`); the ask was tactics only.

---

## 8–14 min · Item 4 — Results and evaluation

**SHOW:** still in `arms.html`, inside the **cptc-2017** card, scroll to the
sub-heading **"Robustness under injected noise"**. (There are two on the page —
the other is under cptc-2018; use the cptc-2017 one to stay consistent with
what you just showed.)

**SAY:** *Noise invents attack graphs, it doesn't destroy them. Worst single
loss anywhere in 540 cells is 13 graphs, against +281 gained in that same cell.
So Jaccard can't be quoted alone — 0.053 reads as catastrophic loss and is the
reverse.*

**THEN — the Objective 3 moment. Four numbers:**

| cptc-2018 | aif | kill-chain |
|---|---:|---:|
| perplexity (held-out) | 35.90 | **21.68** |
| attack graphs | 75 | **10** |

> Perplexity = how well the learned model predicts alert sequences it has not
> seen. Lower is better. It is the *only* metric the original SAGE paper
> reports, which is why this table matters.

**SAY:** *Perplexity improves 40% while graph coverage falls 87%. Given only
the perplexity column, you'd call this an improvement. That's your argument for
the extended metrics, demonstrated rather than asserted.*

**If asked what else the matrix gave:** determinism holds under every taxonomy
— 699 graphs byte-identical over 5 repeats, all 12 combinations.

---

## 14–20 min · Item 1 — NER, replacing low-level artefacts

**SHOW:** `mapping.html`, the **second card, headed "How the mapper works"** —
the five-box flow diagram inside it. Show this *before* the NER results: it
pre-empts most of the "how does it actually work" questions, and the NER work
makes no sense until they can see where in the chain it sits.

**Set it up in one line first:**

> *Given one IDS rule in prose, predict its ATT&CK technique. Five sources try
> in priority order — and it's **first-match-wins**, not a vote. Each stage is
> guarded, so if the one above it answers, the rest never run for that
> signature.*

**Then walk the five, one sentence each:**

| # | source | what it does | claimed / right |
|---|---|---|---|
| 1 | `declared` | reads the rule's **own vendor ATT&CK tag** — no inference at all | 39 rows, **71.8%** |
| 2 | `ioc_alias` | matches malware/tool names in the title against MITRE's alias table | 8 rows, 37.5% |
| 3 | `supervised_classifier` | TF-IDF + LinearSVC, trained live on the labelled corpora | 36 rows, **66.7%** |
| 4 | `knn_corpus` | nearest-neighbour retrieval over 32,048 labelled rule texts | best source 46.7% |
| 5 | `llm` (Layer D) | only fires below 0.5 confidence, and blends rather than overrides | **off by default** |

**The point to land — and it's the same point as everything else today:**

> *The most accurate source is the one that barely runs. `declared` is right
> 71.8% of the time and only gets 39 of 397 rows, because most Suricata rules
> carry no vendor tag. The headroom isn't a better model — it's more labelled
> coverage.*

**Two layers we removed, if they ask what's missing** (both on the diagram,
greyed):

- `bridge_table` — 34.8%, structurally capped, removed
- `embedding` — **4.5%**, compared rule text against MITRE *description prose*.
  Replacing it with retrieval against labelled *rule text* took the same job to
  ~36%. Same data, different register. (This is also Toby's data point.)

> **If asked "are those percentages one run?" — no.** The first three are
> effort 9 (397 scoreable), the kNN figure is effort 19 (361). Each box on the
> diagram is labelled with its own run, and no coherent single-run table across
> all five exists yet — it needs one validation pass recording per-source
> accuracy, which is cheap and not yet done.

### Now the NER work — first say where it sits

**It is not a sixth stage.** Point back at the diagram: NER doesn't answer
anything. It **rewrites the signature text** that stages 3 and 4 both read,
through the one normalisation function the corpus and the query both pass
through. So it's a single switch over the whole matching system, not a filter
on one source.

**Then show what it actually does** — this is the part that answers the ask
directly, so use a real example:

```
before   ET WEB_SPECIFIC_APPS AlstraSoft AskMe que_id Parameter
         SELECT FROM SQL Injection Attempt

         NER tags "AlstraSoft" as a company  (confidence 0.96)

drop     ET WEB_SPECIFIC_APPS AskMe que_id Parameter SELECT FROM
         SQL Injection Attempt                      ← artefact deleted
marker   ET WEB_SPECIFIC_APPS <company> AskMe que_id Parameter ...
                                                    ← artefact replaced by its type
```

**SAY:** *"Low-level artefact" means the vendor name, product, IP, port —
detail specific to one rule rather than to the behaviour. The idea is that two
SQL-injection rules for different products should look alike once you remove
the product name. We only touch rare ones: `SQL` appears in 12% of the corpus
and survives; `ASA 5500 Series` appears in 0.0% and gets replaced.*

### Then the result

**SHOW:** in `mapping.html`, scroll to the bottom. The card is headed
**"Entity-normalisation arms"** — second from the end, between *Regime E* and
*Oracle condition*.

It has **two tables, 3 rows then 12** — the split matters, so point at them in
that order.

**First, say what the two columns are** — otherwise the numbers are noise:

> *We hand-labelled 500 IDS signatures with their correct ATT&CK technique;
> 361 of them are unambiguous enough to score against. **Micro** is how many of
> those 361 the mapper gets right — 39.1% is 141 of 361. **Macro** averages the
> accuracy per technique instead, across the 51 distinct techniques in the set,
> so a rare technique counts as much as a common one.*
>
> *The gap between them is the interesting part. `T1190` alone is 27% of the
> rows, so micro is flattered by getting the common cases right. Macro is the
> number that says whether it works across the long tail — and it's the one we
> care about, because the long tail is where the technique diversity lives.*

**The top table of 3 is your request**, run on the current stack:

| arm | micro (of 361) | macro (51 techniques) |
|---|---:|---:|
| `intersection` + typed + replace 0.01 + **drop** | 39.1% — 141/361 (−1.1) | 28.3% (−0.4) |
| `intersection` + typed + replace 0.01 + **marker** | 38.5% (−1.7) | 26.2% (−2.5) |
| `gliner_only` + typed + replace 0.01 + marker | 35.7% (−4.5) | 20.3% (−8.4) |

*(the bracketed figure is the change against the no-tagging baseline of
40.2% micro / 28.7% macro — every one is negative)*

**What differs between those three.** Only two things vary, and they're two
separate decisions:

*Which spans count as an entity* — there are **two detectors**, the neural NER
model and a dictionary lookup (gazetteer):
- `intersection` — keep only spans **both** detectors agree on. High precision,
  low recall.
- `gliner_only` — keep the **neural model's spans alone**. Fires on ~42% of
  rows, so far more aggressive.

> ⚠️ **`gliner_only` is a legacy name** — it means "model-only", and the model
> is now SecureModernBERT, not GLiNER. Say *"model-only"* out loud; the label
> on screen will otherwise sound like we're still using the old model.

*What happens to those spans* — `drop` deletes them, `marker` replaces them
with a type label like `<company>`.

So the three rows are two controlled comparisons:

| compare | holds constant | varies | result |
|---|---|---|---|
| row 1 vs 2 | same spans (`intersection`) | drop vs marker | **drop wins** +0.6 micro, +2.1 macro |
| row 2 vs 3 | same treatment (`marker`) | intersection vs model-only | **intersection wins** +2.8 micro, +5.9 macro |

**SAY:** *Two lessons. Being conservative about what counts as an entity
matters more than what you do with it. And deleting beats labelling — the
`<company>` token gets injected into ~40% of documents, so it carries almost no
information itself while diluting every real feature's weight. The type
information isn't paying for its own cost.*

**SAY:** *These three are exactly what you asked for — SecureModernBERT, typed
markers, replacing the low-level artefacts. Best is 39.1% against a 40.2%
baseline. **Every one is negative.** The best sits inside the noise band, so
the honest reading is "no better than not tagging".*

**The 12 below are the earlier exploration** — two NER models, five merge
rules, three replacement styles, a threshold sweep. **SAY:** *none of those
beats its baseline either. Fifteen configurations, no winner.*

> **Why two tables and not one ranking:** we improved the underlying corpus
> midway through, which moved the no-tagging baseline from 36.6% to 40.2%. The
> top three were scored against the new baseline, the twelve against the old.
> Ranking them together would compare arms against different references — so
> the deltas in each table are against *its own* baseline only.

> There's a 16th row at the bottom marked **"measured on a different eval
> set"** — that's the LLM layer, not an entity configuration, and it's on 80
> rows rather than 361. Don't let its 62.5% get read as a win; it's a modal-
> collapse artifact.

**Two things that make this a finding rather than an empty null:**

1. **An earlier verdict of ours is overturned.** We first measured this idea at
   16–18% macro against a 22% baseline and wrote it up as *falsified*. On the
   current stack the same idea scores 26–28% against 28.7%. Most of that
   original damage was **the weak NER model and a generic `<ENTITY>` marker,
   not the replacement idea itself**. "Decisively negative" becomes "no better
   than not tagging" — a materially different claim, and we've corrected it in
   writing.
2. **There's a mechanism, and it explains the whole thing.** The rare tokens
   NER finds are exactly the ones carrying the technique signal — rare means
   high IDF means discriminative. Strip them and rules stop looking distinct,
   including rules that mean different things. Deleting the artefact outright
   beats substituting a type label for it, which tells us the *type*
   information isn't adding anything either.

**Tie it back:** *this is the same coverage story as the cascade — the binding
constraint is how many rules carry usable labels, and no amount of rewriting
the text we already have gets around that.*

---

## 20–22 min · Item 2 — NLP similarity

Toby's. **Confirm with him beforehand.**

**Offer him one data point we own:** retrieving against labelled *rule text*
instead of MITRE *description prose* took top-1 from **4.5% → ~36%**. That is
the short-sentence vs long-paragraph register mismatch, measured in our own
pipeline rather than cited.

---

## 22–30 min · Disclose, then ask

**Don't let this get squeezed — it's the part that shapes the paper.**

**Raise before being asked:**

1. **Mapping accuracy is 40.2% micro / 28.7% macro, not "high"** — that's 145
   of 361 hand-labelled signatures mapped to the right technique, and 28.7%
   averaged per technique across the 51 in the set. The abstract promises high
   accuracy and can't keep it. A careful human reader reaches ~87% on the same
   task.
2. **The ET-metadata validation in our own proposal (§III-B2) has never been
   run.** Better from us than remembered by them.
3. **"IDS-agnostic" is untested** — everything is Suricata.

**Ask for:**

1. **Should the paper be centred on the severity dependency?** It reframes
   Objective 2 from an accuracy claim to a characterised ceiling, and promotes
   what the proposal treated as a five-line config detail into a primary
   contribution.
2. **Sign-off on retracting** *"maintaining high mapping accuracy"*, and on
   qualifying *"MITRE annotation will produce more coherent graphs"* (true only
   under `aif-aligned`).
3. **ET validation or a second IDS source?** Break plus run-up to week 9 is
   enough for one properly, not both.

---

## Rehearse these two

**"So which tiering is correct?"**
> *ATT&CK publishes none. We measured three and characterised the trade-off.*

Do not invent an answer. The honest one is the more interesting one — and it
leads straight into the trade-off result: the tier table buys coverage and
noise-sensitivity together, so it's a tunable dial rather than a guess.

**"Why is mapping accuracy only 40%?"**

Split the 51 techniques by how much training data each has — **head** is the 3
with plenty, **mid** 21, **tail** 27 with almost none. Then:

> *We added 223 hand-labelled examples. Mid accuracy moved +7.3 points, tail
> +8.6 — and **head didn't move at all**. The three well-covered techniques
> were already saturated, so more data can't help them; the starved ones can
> still be moved. That's the whole diagnosis: the binding constraint is
> coverage, not how we represent the text. A careful human reader only reaches
> ~87% on this task anyway.*

That answer is why item 1 came out negative, so it's worth being fluent in.

---

# Appendix — only if pressed

**Scale of the evaluation.** 540 cells: four arms × three datasets, the full
baseline matrix (61 cells per CPTC set, the documented reduced 13-cell matrix
on ccdc), 14 h 44 m, every cell clean. Each arm carries the same three
artifacts as `baseline/` from the same renderers.

**Why graph count isn't the headline.** `aif-aligned` reaches more victims than
AIF on all three datasets (+13.9%, +58.3%, +172.3%) but graph count flips sign
on cptc-2018 (−41%). Graph count = coverage × objective granularity, and
granularity is a property of the taxonomy. **Never quote graph count without
victim count.**

**The tier table as a dial.** Phantom-graph generation under noise scales with
high-severity share — same lever, same direction as coverage. A deployment
weighting analyst trust over recall has a principled reason to tier
conservatively; one weighting coverage has a principled reason not to.

**What's still unmeasured.** ccdc noise injection (none in the baseline either,
by an earlier documented decision); inter-rater agreement on the 530-signature
label set, currently single-annotator; two effort-23 falsifications that still
rest on single-dataset reasoning.

**Terms you may use without thinking — define them if you do.**

| term | say this |
|---|---|
| **objective** | a high-severity state; reaching one ends an attack graph |
| **victim** | a destination host alerts were raised against; SAGE builds graphs per victim |
| **cell** | one pipeline run under one configuration; the matrix is 540 of them |
| **Jaccard** | overlap between the noisy graph set and the clean one, 0–1 |
| **micro / macro** | micro = accuracy over all rows, so common classes dominate; macro = mean accuracy per technique, so a rare technique counts as much as a common one |
| **head / mid / tail** | classes split by how much training data they have — head is the 3 saturated ones, tail the 27 starved ones |
| **effort N** | our own numbering of experiments on this branch, in `STATUS.md` |
| **regime** | an evaluation frame — its own eval set, denominator and scoring rules. Numbers from different regimes are **not** comparable |
| **drop / marker** | replace-mode variants: delete the rare entity outright, vs substitute a type sentinel for it |

**Full detail:** `REPORT.md` §8a.7–8a.11, `STATUS.md` efforts 24–26.
