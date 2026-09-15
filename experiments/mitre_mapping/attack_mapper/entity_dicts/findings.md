# Step 1: deterministic entity dictionaries — built and measured

> **The consolidated reference for this work is [`../../REPORT.md`](../../REPORT.md).**
> This file remains the detailed record for effort 13, Step 1; read the report first.

Step 1 of `../../entity_normalisation_plan.md`. Harvest three public
redistributable dictionaries into a typed gazetteer, and measure coverage on
the 397 scoreable eval rows **before** integrating anything.

**Nothing is integrated.** `normalize.py` is untouched; no pipeline behaviour
has changed. This is a measurement, and the plan's §5 requires it before
Step 2.

**Not gated by Step 0.** Coverage counting is not accuracy evaluation, so the
`reviewer_verdict` correction is irrelevant here and these numbers are
uncontaminated by it.

## Sources

| source | raw entries | accepted | licence |
|---|---:|---:|---|
| MISP galaxy `tool.json` | 620 values | 763 | CC0 1.0 |
| IANA service-names-port-numbers | 7,329 names | 7,236 | public registry |
| `tiiuae/cpedict` (distilled NVD CPE) | 63,577 products / 37,453 vendors | 87,088 | Apache-2.0 |
| **gazetteer total** | | **94,786** | |

`build_dicts.py` fetches and caches under `./sources/` (gitignored, re-fetch
with `--refetch`). Output is `../data/entity_gazetteer.csv` (`name,type,source`).

Matching policy — minimum length, letter-leading form, generic-word stoplist,
per-source trust tiers — is recorded in the plan's §3.4 along with the
collision rates that motivated it. It was decided *before* this was built.

## Result 1: coverage

| configuration | rows matched | share of 397 |
|---|---:|---:|
| all three sources | 288 | **72.5%** |
| IANA + MISP only (CPE dropped) | 135 | **34.0%** |

By entity type (all sources): product 207 (52.1%), service 132 (33.2%),
vendor 56 (14.1%), tool 4 (1.0%).

## Result 2: precision — the number that matters

Coverage alone would be misleading, which is why the plan required a
hand-checked sample. 30 matches drawn at random (seed 11),
`coverage_sample.csv`, verdicts assigned by inspection:

**16/30 correct = 53% precision.**

Split by source, and the gap is the whole story:

| source | sample matches | correct | precision |
|---|---:|---:|---:|
| IANA | 13 | 10 | **77%** |
| cpedict | 17 | 6 | **35%** |
| MISP galaxy | 0 | — | — |

True positives look like: `powershell`, `apache`, `snmp`, `microsoft`, `http`,
`fortios`, `ntp`, `mysql`, `rsync`, `openvas`, `nmap`, `tftp`, `openvpn`,
`upnp`, `stratum`.

False positives are almost all CPE listing an ordinary word as a product:
`create`, `agent`, `community`, `configuration`, `modified`, `command`,
`engine`, `proxy`, `traversal`, `trojan`, `quad`, `retrieve`, `domain`,
`shadow`.

Compounding problems in the same rows:

- **`ET SCAN Nessus User Agent`** matched `agent` (false) alongside `Nessus`
  (correct, typed `service` via IANA).
- **`ET SCAN Modified Sipvicious User-Agent Detected`** matched `modified`
  (false) and missed `Sipvicious` (real).

Also missed: `SolarWinds`, `BIG-IP`, `ZynOS`. So the dictionaries are
simultaneously over- and under-matching on the same titles.

## Result 3: corpus frequency does NOT fix it

The obvious automatic filter — reject entries that appear in too many corpus
rules, on the theory that common words are generic — was tested against the 30
hand-labelled matches. It **fails**, and the failure is informative.

Document frequency over the 31,825 training rules (never the eval set;
tuning a filter on eval false positives would be fitting to the test set):

```
 49.99%  domain        FALSE POSITIVE   <- most frequent token of all
 12.22%  http          REAL             <- any cut killing `domain` kills this
  2.10%  command       FALSE POSITIVE
  1.06%  powershell    REAL
  0.03%  trojan        FALSE POSITIVE
  0.02%  nmap          REAL             <- same frequency band
  0.00%  retrieve      FALSE POSITIVE
  0.00%  openvas       REAL             <- both zero
```

| threshold | TPs kept | FPs killed | precision |
|---:|---:|---:|---:|
| 0.1% | 11/15 | 7/14 | 61.1% |
| 0.5% | 12/15 | 2/14 | 50.0% |
| 2.0% | 14/15 | 2/14 | 53.8% |

Best achievable is 61% precision at the cost of 4 of 15 true positives. The
distributions interleave because **the false positives are mostly rare words**
that CPE happens to list as products (`retrieve`, `quad`, `trojan`). Rarity
does not imply entity-hood.

This is the load-bearing conclusion: the discriminator is not frequency and
not dictionary membership. It is **context** — and context is exactly what
Step 2's NER supplies. Step 1 therefore establishes the baseline Step 2 has to
beat (53% precision at 72.5% coverage), and evidence for why a model is needed
rather than a bigger list.

## Result 4: MISP galaxy contributed almost nothing

4 rows out of 397 (1.0%). Its `tool.json` cluster is malware-family-oriented
(`Zeus`, `Tinba`, `Duqu`) and does not carry the scanning/offensive tooling
that ET signature titles actually name (`Nmap`, `Nessus`, `Sipvicious`,
`Havij`, `Masscan`). It was the cleanest source by collision probing — zero
generic-word collisions — and it is nearly useless here anyway. Cleanliness
and usefulness are independent properties.

## Known limitations

- **CPE `part` field is lost.** `tiiuae/cpedict` distils NVD CPE to
  vendor/product pairs and drops CPE 2.3's `part` (`a`/`o`/`h`), so
  application, OS and hardware cannot be distinguished and everything is typed
  `product`. The full NVD dictionary retains it if that matters later.
- **The generic-word stoplist is hand-written** and demonstrably incomplete —
  it did not catch `command`, `trojan`, `create`, `agent`, `configuration`,
  `engine`, `proxy`. Extending it by inspecting eval false positives would be
  fitting to the test set and was deliberately not done.
- **30-match sample.** Precision figures carry the uncertainty of that size;
  the 77%-vs-35% source gap is large enough to be directional, the absolute
  numbers are not tight.

## What this means for the decision

Three configurations, none obviously best:

| configuration | coverage | precision | character |
|---|---:|---:|---|
| all sources | 72.5% | ~53% | high recall, half the matches wrong |
| IANA + MISP | 34.0% | ~77% | conservative, misses most products |
| IANA only | 33.2% | ~77% | MISP adds 4 rows |

Adding CPE buys 38.5 points of coverage at 35% precision. Whether that is worth
it depends on how the augmented token is consumed downstream — a wrong
`<PRODUCT>` tag on `command` is a noise feature added to every rule containing
the word "command", which on the §3.1 augmentation design does not destroy the
original token but does dilute.

## Revision: the source split does not survive concrete inspection

An earlier draft of this file recommended a "service-only" configuration on the
strength of the 77%-vs-35% precision gap. Rendering real titles under each
configuration (per the §3.1 augmentation design) contradicts that:

```
ET SCAN Nessus User Agent
  ALL      : nessus <SERVICE>  user agent <PRODUCT>     <- 1 right, 1 wrong
  SERVICE  : nessus <SERVICE>  user agent               <- clean win

ET EXPLOIT FortiOS SSL VPN - Information Disclosure (CVE-2018-13379)
  ALL      : fortios <PRODUCT> ssl vpn ...              <- exactly the wanted tag
  SERVICE  : fortios ssl vpn ...                        <- loses it entirely

ET WEB_SERVER Coldfusion cfcexplorer Directory Traversal
  ALL      : coldfusion <PRODUCT> ... directory <PRODUCT> traversal <SERVICE>
  SERVICE  : coldfusion ... directory traversal <SERVICE>
             ^ keeps the WRONG tag, drops the right one -- strictly worse here
```

Good and bad matches are **mixed within both sources**, not separated by them.
Service-only discards correct product tags (`fortios`, `coldfusion`,
`microsoft`, `apache`, `powershell` — precisely the 24.9% product class this
work targeted) while retaining wrong service tags (`traversal`, `quad`,
`domain`). The average precision gap is real; it is not a usable slicing rule.

**Revised conclusion: no purely dictionary-based configuration is good enough
to integrate standalone.** The discriminator is whether a token denotes an
entity *in this title*, and nothing available in Step 1 can see that.

This matches the standard practice found in the Step 2 research: a gazetteer
belongs as **features into an NER model**, not as a competing predictor. So the
gazetteer is kept as a built artifact and carried into Step 2 as a
feature/candidate source, rather than being wired into `normalize.py` on its
own. Two integration measurement cycles are saved by not deciding between two
mediocre configurations.

`normalize.py` remains untouched.
