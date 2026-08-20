"""
Per-symbol perplexity of a learned S-PDFA against a set of episode traces.

No perplexity implementation exists in this fork or in `tudelft-cda-lab/SAGE`
upstream, so the definitions here are written from scratch and every choice is
recorded in the emitted record rather than left implicit.

**Where the probabilities come from.** The task spec treated this as an open
question, with a trace-MLE fallback in case FlexFringe did not export counts. It
does. Each node of `*.ff.final.json` carries:

    "data": {"trans_counts": {"vulnD|mysql": "7", ...},
             "total_paths": 39, "total_final": 0}

Verified against the baseline artifacts: `sum(trans_counts) == total_paths`
holds for all 524 main-model nodes and all 2310 sink-model nodes, with zero
exceptions, and `total_final` is counted separately. So `total_paths` counts
traces that *continue* out of a state and `total_final` those that *stop* there,
and the generative distribution at a state normalises over

    N(state) = total_paths + total_final

with `total_final` giving the end-of-trace probability directly. That answers the
spec's question of whether the final-state event can be scored: it can, natively,
and it is (see SCORES_END_OF_TRACE).

`model_learning.load_model` discards all of this -- it keeps only
`source -> name -> target` -- so this module parses the JSON itself.

**Main vs sinks model.** `model_learning.traverse` resolves a symbol in the main
model where possible and otherwise falls back to the sinks model, so a scored
step can land on a state resolved by either. Verified against the baseline
artifacts: of the 456 node IDs present in both files, all 456 have identical
`trans_counts`, so the two share one ID space and a main-first merge is sound.
The resolving model is still tracked per step and reported, because that
equivalence is an observed property of these artifacts, not a guarantee.
"""
import json
import math
import random
import re
from collections import defaultdict

# The end-of-trace event is scored as an outcome alongside the alphabet symbols.
SCORES_END_OF_TRACE = True

DEFAULT_ALPHA = 0.1
DEFAULT_SPLIT_SEED = 42
DEFAULT_TEST_FRACTION = 0.2

FORMULA = ('PP = exp( -(1/N) * sum_i log P(outcome_i | state_i) ), N = total scored outcomes. '
           'Outcomes at a state are the alphabet symbols plus an explicit END event, so '
           'N counts one END per trace in addition to every symbol.')

PROB_FORMULA = ('P(sym|state)  = (trans_counts[sym] + alpha) / (N_state + alpha * n_outcomes) ; '
                'P(END|state)  = (total_final   + alpha) / (N_state + alpha * n_outcomes) ; '
                'N_state = total_paths + total_final ; n_outcomes = |alphabet| + 1')

# What happens when traversal cannot resolve a symbol at all (`traverse` yields
# state '-1'). Skipping such events would quietly flatter the model, so they are
# scored against a maximum-entropy uniform over the outcome space and counted.
UNRESOLVED_POLICY = ('uniform_over_outcomes: an unresolvable step (traverse state -1) is scored '
                     'as 1/n_outcomes rather than skipped, and counted in unresolved_events')

# Held-out traces contain `mcat|mserv` symbols absent from the training alphabet
# entirely, which add-alpha over the training alphabet alone does not cover.
OOV_POLICY = ('union_alphabet: n_outcomes spans the union of the training and scored alphabets '
              'plus END, so an unseen symbol receives alpha / (N_state + alpha * n_outcomes) '
              'rather than zero. Counted in oov_events.')


def _read_model_json(path):
    """
    Reads a FlexFringe model file, applying the same repairs `model_learning`
        applies (unescaped newlines in labels, duplicated commas).

    @param path: the path to a `.ff.final.json` or `.ff.finalsinks.json` file
    @return: the parsed model dict
    """
    with open(path, 'r', encoding='utf-8') as handle:
        data = handle.read()
    data = re.sub(r'\"label\" : \"([^\n|]*)\n([^\n]*)\"', r'"label" : "\1 \2"', data)
    data = data.replace('\n', '').replace(',,', ',')
    data = re.sub(',+', ',', data)
    return json.loads(data)


class Automaton:
    """
    A scored S-PDFA: the transition function plus the per-state outcome counts
        that `model_learning.load_model` throws away.
    """

    def __init__(self, main_path, sinks_path):
        """
        @param main_path: the path to `<traces>.ff.final.json`
        @param sinks_path: the path to `<traces>.ff.finalsinks.json`
        """
        main, sinks = _read_model_json(main_path), _read_model_json(sinks_path)

        self.transitions = {'main': defaultdict(dict), 'sinks': defaultdict(dict)}
        for label, model in (('main', main), ('sinks', sinks)):
            for edge in model['edges']:
                self.transitions[label][str(edge['source'])][edge['name']] = str(edge['target'])

        # Main-first merge; see the module docstring for why this is safe here.
        self.counts, self.totals = {}, {}
        for model in (sinks, main):
            for node in model['nodes']:
                data = node.get('data') or {}
                trans = {sym: int(count) for sym, count in (data.get('trans_counts') or {}).items()}
                final = int(data.get('total_final') or 0)
                paths = int(data.get('total_paths') or 0)
                self.counts[str(node['id'])] = trans
                self.totals[str(node['id'])] = {'n': paths + final, 'final': final}

        self.alphabet = set(main.get('alphabet') or []) | set(sinks.get('alphabet') or [])
        for state_counts in self.counts.values():
            self.alphabet.update(state_counts)

    def step(self, state, symbol):
        """
        Resolves one transition, mirroring `model_learning.traverse`: the main
            model first, then the sinks model, then unresolvable.

        @param state: the current state ID
        @param symbol: the `mcat|mserv` symbol to consume
        @return: (next_state, resolving_model) where resolving_model is
            'main', 'sinks' or None
        """
        if symbol in self.transitions['main'].get(state, {}):
            return self.transitions['main'][state][symbol], 'main'
        if symbol in self.transitions['sinks'].get(state, {}):
            return self.transitions['sinks'][state][symbol], 'sinks'
        return '-1', None


def read_traces(path):
    """
    Reads a FlexFringe trace file into lists of symbols.

    The file's first line is a `<num_traces> <alphabet_size>` header; each later
    line is `<label> <length> <sym> <sym> ...`. Symbols are already reversed by
    `model_learning.generate_traces` (that reversal is what makes the model an
    S-PDFA) and are left in file order here, so the model is scored on exactly
    the sequences it was learned from.

    @param path: the path to `<experiment>.txt`
    @return: a list of traces, each a list of symbol strings
    """
    with open(path, 'r', encoding='utf-8') as handle:
        lines = [ln for ln in handle.read().splitlines() if ln.strip()]
    traces = []
    for line in lines[1:]:  # Skip the header
        parts = line.split()
        traces.append(parts[2:])  # Drop the label and the length field
    return traces


def score(automaton, traces, alpha=DEFAULT_ALPHA, extra_alphabet=None):
    """
    Computes per-symbol perplexity of an automaton over a set of traces.

    Every trace scores: smoothing guarantees a finite probability for every
    outcome, so no trace can produce an infinity and none are silently dropped.

    @param automaton: an `Automaton`
    @param traces: a list of traces, each a list of symbols
    @param alpha: the add-alpha smoothing constant
    @param extra_alphabet: symbols to include in the outcome space beyond the
        model's own -- used for held-out scoring, where the test set may contain
        symbols the training set never had (see OOV_POLICY)
    @return: a dict with the perplexity, its inputs, and the diagnostic counts
    """
    alphabet = set(automaton.alphabet) | set(extra_alphabet or ())
    n_outcomes = len(alphabet) + 1  # +1 for the explicit END outcome
    uniform_logp = -math.log(n_outcomes)

    total_logp, n_scored = 0.0, 0
    unresolved, oov, resolved_by = 0, 0, {'main': 0, 'sinks': 0}

    for trace in traces:
        state = '0'
        for symbol in trace:
            sym = symbol.split(':')[0]  # Mirrors traverse's multivariate handling
            if state == '-1':
                # Already off the model; no state distribution to score against.
                total_logp += uniform_logp
                n_scored += 1
                unresolved += 1
                continue
            if sym not in alphabet:
                oov += 1
            totals = automaton.totals.get(state, {'n': 0, 'final': 0})
            count = automaton.counts.get(state, {}).get(sym, 0)
            denominator = totals['n'] + alpha * n_outcomes
            total_logp += math.log((count + alpha) / denominator)
            n_scored += 1

            state, resolver = automaton.step(state, sym)
            if resolver:
                resolved_by[resolver] += 1

        # Score the end-of-trace event against the final state.
        if state == '-1':
            total_logp += uniform_logp
            unresolved += 1
        else:
            totals = automaton.totals.get(state, {'n': 0, 'final': 0})
            denominator = totals['n'] + alpha * n_outcomes
            total_logp += math.log((totals['final'] + alpha) / denominator)
        n_scored += 1

    perplexity = math.exp(-total_logp / n_scored) if n_scored else None
    return {
        'perplexity': perplexity,
        'mean_log_prob': (total_logp / n_scored) if n_scored else None,
        'n_traces': len(traces),
        'n_scored_outcomes': n_scored,
        'n_symbols': n_scored - len(traces),  # One END per trace
        'alpha': alpha,
        'alphabet_size': len(alphabet),
        'n_outcomes': n_outcomes,
        'unresolved_events': unresolved,
        # Surfaced as a fraction because it governs how much the reported figure
        # rests on UNRESOLVED_POLICY rather than on the model. On training traces
        # this is ~0 and perplexity is a property of the automaton; on held-out
        # traces it can approach half of all scored outcomes, at which point the
        # figure is substantially a statement about the uniform fallback and must
        # not be read as a like-for-like comparison against the training number.
        'unresolved_fraction': (unresolved / n_scored) if n_scored else None,
        'oov_events': oov,
        'resolved_by_model': resolved_by,
        'scores_end_of_trace': SCORES_END_OF_TRACE,
        'prob_source': 'flexfringe_counts',
        'formula': FORMULA,
        'prob_formula': PROB_FORMULA,
        'unresolved_policy': UNRESOLVED_POLICY,
        'oov_policy': OOV_POLICY,
    }


def counts_from_traces(automaton, traces):
    """
    Re-derives the per-state outcome counts by maximum likelihood, by traversing
        traces through the model and tallying `(state, symbol)` occurrences.

    The spec required this as a fallback for FlexFringe not exporting counts. It
    does export them, so this now serves as an independent cross-check: run it
    over the same traces the model was learned from and the tallies should
    reproduce `trans_counts` (see `tests.py`). A divergence means the traversal
    here has drifted from `model_learning.traverse`.

    @param automaton: an `Automaton`
    @param traces: the traces the model was learned from
    @return: (counts, totals) in the same shape as `Automaton.counts`/`.totals`
    """
    counts = defaultdict(lambda: defaultdict(int))
    finals = defaultdict(int)
    for trace in traces:
        state = '0'
        for symbol in trace:
            sym = symbol.split(':')[0]
            if state == '-1':
                break
            counts[state][sym] += 1
            state, _ = automaton.step(state, sym)
        if state != '-1':
            finals[state] += 1

    totals = {}
    for state in set(counts) | set(finals):
        totals[state] = {'n': sum(counts[state].values()) + finals[state],
                         'final': finals[state]}
    return {s: dict(c) for s, c in counts.items()}, totals


def split_traces(traces, test_fraction=DEFAULT_TEST_FRACTION, seed=DEFAULT_SPLIT_SEED):
    """
    Splits traces into train and test sets at the trace level.

    Splitting must happen before FlexFringe is invoked -- held-out perplexity
    needs a model that has never seen the test traces, which means a separate
    FlexFringe run and therefore a separate model, not a re-scoring of the
    training model.

    @param traces: the full list of traces
    @param test_fraction: the proportion held out
    @param seed: the pinned RNG seed, recorded in the output
    @return: (train, test)
    """
    shuffled = list(traces)
    random.Random(seed).shuffle(shuffled)
    n_test = int(round(len(shuffled) * test_fraction))
    return shuffled[n_test:], shuffled[:n_test]


def write_traces(traces, path):
    """
    Writes traces back out in FlexFringe's input format, so a held-out training
        split can be fed to FlexFringe as-is.

    @param traces: a list of traces, each a list of symbols
    @param path: the file to write
    """
    alphabet = {sym for trace in traces for sym in trace}
    with open(path, 'w', encoding='utf-8') as handle:
        handle.write('{} {}\n'.format(len(traces), len(alphabet)))
        for trace in traces:
            handle.write('1 {} {}\n'.format(len(trace), ' '.join(trace)))
