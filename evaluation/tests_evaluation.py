"""
Unit tests for the pure layer of the evaluation package.

Run with:  python evaluation/tests_evaluation.py

These cover the functions that turn artifacts into numbers, on fixtures small
enough to verify by hand. They deliberately do not run SAGE: the point is that a
metric definition can be checked without a pipeline run, so a wrong number is
caught before it is baked into a recorded baseline.
"""
import datetime
import json
import math
import os
import random
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from evaluation import (alerts, collect, compare, dot_metrics,  # noqa: E402
                        perplexity, perturbation, runner, schema)


# A graph whose counts are obvious by inspection, using the dialect SAGE emits:
# node names containing literal newlines, a self-loop, and a parallel edge.
FIXTURE_DOT = '''digraph FIXTURE {
rankdir="BT";
 graph [ nodesep="0.1", ranksep="0.02"]
 node [ fontname=Arial, fontsize=24, penwidth=3];
"Victim: 10.0.0.1
DATA EXFILTRATION
http" [shape=doubleoctagon, style=filled, fillcolor=salmon];
{ rank = max; "Victim: 10.0.0.1
DATA EXFILTRATION
http"}
"A
svc" -> "B
svc" [ label="start_next: 04/11/17, 13:08:47
gap: 1sec"][ fontcolor="magenta" color=magenta]
"B
svc" -> "C
svc" [ color=blue]
"A
svc" -> "B
svc" [ color=blue]
"A
svc" -> "A
svc" [ color=blue]
"C
svc" -> "Victim: 10.0.0.1
DATA EXFILTRATION
http"
"A
svc" [style=filled, fillcolor= yellow]
"A
svc" [tooltip="zebra sig\\napple sig"]
}
'''


class TestDotParsing(unittest.TestCase):
    """The .dot reader, on a fixture whose counts are known by inspection."""

    def setUp(self):
        self.metrics = dot_metrics.graph_metrics(FIXTURE_DOT, name='fixture')

    def test_node_names_with_newlines_are_not_split(self):
        nodes, _ = dot_metrics.parse_dot(FIXTURE_DOT)
        self.assertIn('A\nsvc', nodes)
        self.assertNotIn('svc', nodes)  # The tail half of a split name

    def test_attribute_values_are_not_counted_as_nodes(self):
        nodes, _ = dot_metrics.parse_dot(FIXTURE_DOT)
        # "BT" (rankdir), "0.1" (nodesep) and the label/tooltip text are values.
        for value in ('BT', '0.1', 'magenta', 'zebra sig\\napple sig'):
            self.assertNotIn(value, nodes)

    def test_node_and_edge_counts(self):
        # Nodes: A, B, C, Victim  -> 4
        self.assertEqual(self.metrics['nodes'], 4)
        # Edges: A->B, B->C, A->B (parallel), A->A (self), C->Victim -> 5
        self.assertEqual(self.metrics['edges_total'], 5)
        self.assertEqual(self.metrics['edges_simple'], 4)       # parallel collapsed
        self.assertEqual(self.metrics['edges_simple_no_loops'], 3)
        self.assertEqual(self.metrics['self_loops'], 1)
        self.assertEqual(self.metrics['parallel_edges'], 1)

    def test_longest_path_ignores_self_loop(self):
        # A -> B -> C -> Victim is 3 edges; the self-loop cannot extend it.
        self.assertEqual(self.metrics['longest_path_edges'], 3)
        self.assertEqual(self.metrics['longest_path_method'], 'exact_dfs')

    def test_derived_metrics_match_their_formulas(self):
        self.assertAlmostEqual(self.metrics['branching_factor'], 5 / 4)
        self.assertAlmostEqual(self.metrics['simplicity'], 4 / 5)
        self.assertAlmostEqual(self.metrics['path_linearity'], 3 / 5)
        # Density excludes self-loops and collapses parallels: 3 / (4*3)
        self.assertAlmostEqual(self.metrics['density'], 3 / 12)

    def test_density_cannot_exceed_one(self):
        self.assertLessEqual(self.metrics['density'], 1.0)
        self.assertLessEqual(self.metrics['reachability_density'], 1.0)

    def test_reachability_density_counts_indirect_routes(self):
        # Fixture: A -> B -> C -> Victim, plus a self-loop on A.
        # Reachable ordered pairs: A reaches B, C, Victim (3); B reaches C,
        # Victim (2); C reaches Victim (1); Victim reaches nothing (0) = 6.
        # Denominator is 4*3 = 12, so 0.5. Edge density is only 3/12 = 0.25,
        # because it counts the three direct edges and ignores the routes.
        self.assertAlmostEqual(self.metrics['reachability_density'], 6 / 12)
        self.assertAlmostEqual(self.metrics['density'], 3 / 12)
        self.assertGreater(self.metrics['reachability_density'], self.metrics['density'])

    def test_reachability_density_ignores_self_loops(self):
        # A node reaching itself via its own loop is not a traversal.
        nodes, edges = {'A', 'B'}, {('A', 'B'), ('A', 'A'), ('B', 'B')}
        self.assertAlmostEqual(dot_metrics._reachability_density(nodes, edges), 0.5)

    def test_reachability_density_endpoints(self):
        # A fully connected pair in both directions: every ordered pair reachable.
        self.assertAlmostEqual(
            dot_metrics._reachability_density({'A', 'B'}, {('A', 'B'), ('B', 'A')}), 1.0)
        # No edges at all: nothing is reachable.
        self.assertAlmostEqual(dot_metrics._reachability_density({'A', 'B'}, set()), 0.0)
        # Undefined below two nodes, rather than dividing by zero.
        self.assertIsNone(dot_metrics._reachability_density({'A'}, set()))

    def test_reachability_density_is_less_size_confounded_than_edge_density(self):
        # The reason reachability density is the headline: a linear chain has the
        # same shape at any size, but edge density collapses as it grows while
        # reachability density stays put. Chains of 4 and 12 nodes:
        results = {}
        for size in (4, 12):
            nodes = {'n{}'.format(i) for i in range(size)}
            edges = {('n{}'.format(i), 'n{}'.format(i + 1)) for i in range(size - 1)}
            results[size] = (
                len(edges) / (size * (size - 1)),
                dot_metrics._reachability_density(nodes, edges))

        edge_drop = results[4][0] / results[12][0]
        reach_drop = results[4][1] / results[12][1]
        self.assertGreater(edge_drop, 2.5)    # edge density collapses with size
        self.assertLess(reach_drop, 1.3)      # reachability density barely moves

    def test_ag_filename_identity(self):
        victim, objective = dot_metrics.parse_ag_filename(
            'exp-2017.txt-attack-graph-for-victim-10.0.0.100-DATADELIVERYwsman.dot')
        self.assertEqual(victim, '10.0.0.100')
        self.assertEqual(objective, 'DATADELIVERYwsman')


class TestToyPerplexity(unittest.TestCase):
    """
    Perplexity against an automaton small enough to compute by hand.

    Two states, alphabet {a, b}. State 0 emits a x3, b x1, and never ends
    (total_final 0, total_paths 4). State 1 emits nothing and always ends
    (total_final 3, total_paths 0).
    """

    def setUp(self):
        self.directory = tempfile.mkdtemp()
        model = {
            'alphabet': ['a', 'b'],
            'nodes': [
                {'id': 0, 'isred': 1, 'isblue': 0, 'issink': 0,
                 'data': {'trans_counts': {'a': '3', 'b': '1'},
                          'total_paths': 4, 'total_final': 0}},
                {'id': 1, 'isred': 1, 'isblue': 0, 'issink': 0,
                 'data': {'trans_counts': {}, 'total_paths': 0, 'total_final': 3}},
            ],
            'edges': [{'source': '0', 'target': '1', 'name': 'a'},
                      {'source': '0', 'target': '1', 'name': 'b'}],
        }
        self.main = os.path.join(self.directory, 'toy.ff.final.json')
        self.sinks = os.path.join(self.directory, 'toy.ff.finalsinks.json')
        for path in (self.main, self.sinks):
            with open(path, 'w', encoding='utf-8') as handle:
                json.dump(model if path == self.main
                          else {'alphabet': [], 'nodes': [], 'edges': []}, handle)
        self.automaton = perplexity.Automaton(self.main, self.sinks)

    def test_hand_computed_perplexity(self):
        # Trace ['a']: score P(a | state 0), then P(END | state 1).
        # n_outcomes = |{a,b}| + 1 = 3; alpha = 0.1.
        # P(a|0)   = (3 + 0.1) / (4 + 0.1*3) = 3.1 / 4.3
        # P(END|1) = (3 + 0.1) / (3 + 0.1*3) = 3.1 / 3.3
        # PP = exp( -(log(3.1/4.3) + log(3.1/3.3)) / 2 )
        expected = math.exp(-(math.log(3.1 / 4.3) + math.log(3.1 / 3.3)) / 2)
        result = perplexity.score(self.automaton, [['a']], alpha=0.1)
        self.assertAlmostEqual(result['perplexity'], expected, places=10)
        self.assertEqual(result['n_scored_outcomes'], 2)  # one symbol + one END
        self.assertEqual(result['n_symbols'], 1)

    def test_end_of_trace_is_scored(self):
        # One trace of one symbol scores two outcomes, the second being END.
        result = perplexity.score(self.automaton, [['a']])
        self.assertTrue(result['scores_end_of_trace'])
        self.assertEqual(result['n_scored_outcomes'] - result['n_symbols'], 1)

    def test_unseen_symbol_scores_finitely_and_is_counted(self):
        # 'zzz' is outside the alphabet; smoothing must keep it finite, and the
        # union-alphabet policy must widen the outcome space rather than assign 0.
        result = perplexity.score(self.automaton, [['zzz']], extra_alphabet={'zzz'})
        self.assertTrue(math.isfinite(result['perplexity']))
        self.assertEqual(result['oov_events'], 0)  # in the union alphabet, so not OOV
        self.assertEqual(result['n_outcomes'], 4)  # a, b, zzz, END

        # Without widening, the same symbol is genuinely out of vocabulary.
        strict = perplexity.score(self.automaton, [['zzz']])
        self.assertEqual(strict['oov_events'], 1)
        self.assertTrue(math.isfinite(strict['perplexity']))

    def test_every_trace_scores(self):
        # No trace may be silently dropped, however badly it fits.
        traces = [['a'], ['b'], ['a', 'b', 'a'], ['zzz', 'zzz']]
        result = perplexity.score(self.automaton, traces)
        self.assertEqual(result['n_traces'], 4)
        self.assertTrue(math.isfinite(result['perplexity']))

    def test_split_is_seeded_and_disjoint(self):
        traces = [[str(i)] for i in range(100)]
        train_a, test_a = perplexity.split_traces(traces, seed=42)
        train_b, test_b = perplexity.split_traces(traces, seed=42)
        self.assertEqual(test_a, test_b)               # reproducible
        self.assertEqual(len(test_a), 20)              # 20% held out
        self.assertEqual(len(train_a) + len(test_a), 100)
        as_tuples = {tuple(t) for t in train_a}
        self.assertFalse(as_tuples & {tuple(t) for t in test_a})  # disjoint


class TestAlertCounting(unittest.TestCase):
    """Alert counting across all three wrapper formats."""

    def _write(self, records):
        handle = tempfile.NamedTemporaryFile('w', suffix='.json', delete=False,
                                             encoding='utf-8')
        json.dump(records, handle)
        handle.close()
        return handle.name

    @staticmethod
    def _suricata(src='10.0.0.1', dst='10.0.0.2', category='Attempted Admin',
                  event_type='alert'):
        return {'timestamp': '2017-11-04T12:48:35.198583+0000',
                'event_type': event_type, 'src_ip': src, 'dest_ip': dst,
                'alert': {'signature': 'TEST SIG', 'category': category}}

    def test_cptc_2017_result_raw_wrapper(self):
        path = self._write([{'preview': False, 'offset': 1,
                             'result': {'_raw': json.dumps(self._suricata())}}])
        self.assertEqual(alerts.count_file(path, 'cptc')['raw_alerts'], 1)

    def test_cptc_2018_top_level_raw_wrapper(self):
        path = self._write([{'_bkt': 'ids~21', '_raw': json.dumps(self._suricata())}])
        self.assertEqual(alerts.count_file(path, 'cptc')['raw_alerts'], 1)

    def test_ccdc_plain_format(self):
        path = self._write([self._suricata()])
        self.assertEqual(alerts.count_file(path, 'other')['raw_alerts'], 1)

    def test_naive_key_counting_would_have_failed(self):
        # Guards the specific bug the wrapper handling exists to prevent: the
        # Suricata fields are inside a JSON *string*, so they are invisible to a
        # reader that does not unwrap.
        path = self._write([{'result': {'_raw': json.dumps(self._suricata())}}])
        with open(path, encoding='utf-8') as handle:
            raw = json.load(handle)
        self.assertNotIn('event_type', raw[0])
        self.assertEqual(alerts.count_file(path, 'cptc')['raw_alerts'], 1)

    def test_dataset_filters(self):
        records = [self._suricata(),
                   self._suricata(dst=alerts.CPTC_BAD_IP),
                   self._suricata(category=alerts.DROPPED_CATEGORY),
                   self._suricata(event_type='flow')]
        path = self._write(records)

        cptc = alerts.count_file(path, 'cptc')
        self.assertEqual(cptc['raw_records'], 4)
        self.assertEqual(cptc['raw_alerts'], 1)
        self.assertEqual(cptc['dropped_bad_ip'], 1)
        self.assertEqual(cptc['dropped_category'], 1)
        self.assertEqual(cptc['dropped_non_alert'], 1)

        # The bad-IP filter is CPTC-only, so 'other' keeps that record.
        self.assertEqual(alerts.count_file(path, 'other')['raw_alerts'], 2)

    def test_compression_ratios(self):
        ratios = alerts.compression_ratios(raw_records=1200, raw_alerts=1000,
                                           post_dedup_alerts=800, n_attack_graphs=10,
                                           total_ag_nodes=200, unique_ag_nodes=50)
        self.assertAlmostEqual(ratios['raw_records_per_ag'], 120.0)
        self.assertAlmostEqual(ratios['raw_alerts_per_ag'], 100.0)
        self.assertAlmostEqual(ratios['post_dedup_alerts_per_ag'], 80.0)
        self.assertAlmostEqual(ratios['raw_alerts_per_ag_node'], 5.0)
        self.assertAlmostEqual(ratios['raw_alerts_per_unique_ag_node'], 20.0)

    def test_primary_ratio_follows_the_paper_convention(self):
        # The paper's own CCDC-2018 count (1,052,281) equals the raw_records count,
        # not the post-filter alert count, so the primary numerator is raw_records.
        # If this flips, every recorded compression figure changes meaning.
        self.assertEqual(alerts.PRIMARY_COMPRESSION, 'raw_records_per_ag')
        ratios = alerts.compression_ratios(1200, 1000, 800, 10, 200, 50)
        self.assertEqual(ratios['primary'], 'raw_records_per_ag')
        self.assertIn('1,052,281', ratios['formulas'][ratios['primary']])

    def test_compression_ratio_survives_zero_denominator(self):
        ratios = alerts.compression_ratios(1200, 1000, None, 0, 0, 0)
        self.assertIsNone(ratios['raw_records_per_ag'])
        self.assertIsNone(ratios['raw_alerts_per_ag'])
        self.assertIsNone(ratios['post_dedup_alerts_per_ag'])


class TestDistortion(unittest.TestCase):
    """Jaccard, deltas, elasticity, and the tooltip normalisation."""

    def test_jaccard(self):
        self.assertEqual(compare.jaccard({1, 2, 3}, {1, 2, 3}), 1.0)
        self.assertEqual(compare.jaccard({1, 2}, {3, 4}), 0.0)
        self.assertAlmostEqual(compare.jaccard({1, 2, 3}, {2, 3, 4}), 2 / 4)
        self.assertEqual(compare.jaccard(set(), set()), 1.0)  # defined, not undefined

    def test_metric_deltas(self):
        deltas = compare.metric_deltas({'nodes': 100, 'edges': 50, 'label': 'x'},
                                       {'nodes': 110, 'edges': 50, 'label': 'y'})
        self.assertAlmostEqual(deltas['nodes']['absolute'], 10)
        self.assertAlmostEqual(deltas['nodes']['relative'], 0.1)
        self.assertAlmostEqual(deltas['edges']['absolute'], 0)
        self.assertNotIn('label', deltas)  # non-numeric fields are skipped

    def test_elasticity(self):
        self.assertAlmostEqual(compare.elasticity(0.2, 0.5), 0.4)
        self.assertIsNone(compare.elasticity(0.2, 0))

    def test_tooltip_normalisation_neutralises_set_ordering(self):
        # The same graph with its tooltip signatures in a different order: the
        # difference baseline-v1's unsorted set join produces between runs.
        one = '"N" [tooltip="alpha\\nbeta\\ngamma"]\n'
        two = '"N" [tooltip="gamma\\nalpha\\nbeta"]\n'
        self.assertNotEqual(one, two)
        self.assertEqual(compare.normalise_dot(one), compare.normalise_dot(two))

    def test_normalisation_still_detects_real_differences(self):
        # Normalising must not flatten an actual change in the signature set.
        one = '"N" [tooltip="alpha\\nbeta"]\n'
        two = '"N" [tooltip="alpha\\ndelta"]\n'
        self.assertNotEqual(compare.normalise_dot(one), compare.normalise_dot(two))

        # ...nor a genuine structural difference.
        self.assertNotEqual(compare.normalise_dot('"A" -> "B"\n'),
                            compare.normalise_dot('"A" -> "C"\n'))


class TestRunner(unittest.TestCase):
    """The runner's pure logic: argv construction and stage attribution."""

    def test_keep_files_is_always_passed(self):
        # Without it the .dot graphs and model JSONs are deleted, and every
        # structural metric is derived from them.
        argv = runner.build_argv('alerts/cptc-2017', 'exp', 'cptc')
        self.assertIn('--keep-files', argv)

    def test_experiment_name_with_separator_is_rejected(self):
        # plotting.py writes 'data_histogram-' + experiment_name, so a separator
        # here makes the run die on a missing directory partway through.
        for bad in ('runs/exp', 'runs' + os.sep + 'exp'):
            with self.assertRaises(ValueError):
                runner.build_argv('alerts/cptc-2017', bad, 'cptc')

    def test_optional_parameters_are_omitted_when_none(self):
        argv = runner.build_argv('alerts/x', 'exp', 'cptc')
        self.assertNotIn('-t', argv)
        self.assertNotIn('-w', argv)
        argv = runner.build_argv('alerts/x', 'exp', 'cptc', filter_window=2.0,
                                 aggregation_window=200, timerange=(0, 5))
        self.assertEqual(argv[argv.index('-t') + 1], '2.0')
        self.assertEqual(argv[argv.index('-w') + 1], '200')
        self.assertEqual(argv[argv.index('--timerange') + 1:][:2], ['0', '5'])

    def test_stage_rollup_absorbs_sub_banners(self):
        # SAGE prints '------ TEAMS ------' between stage banners; the work of
        # 'Converting to episodes' happens after it, so naive attribution gives
        # that stage 0.00s and misattributes its time to the sub-banner.
        raw = [{'stage': 'Reading alerts', 'started': 1.0},
               {'stage': 'Converting to episodes', 'started': 3.0},
               {'stage': 'TEAMS', 'started': 3.0},
               {'stage': 'Making alert-driven AGs', 'started': 9.0},
               {'stage': 'FIN', 'started': 20.0}]
        rolled = runner._roll_up_stages(raw, total_seconds=21.0)

        self.assertEqual([s['stage'] for s in rolled],
                         ['Reading alerts', 'Converting to episodes',
                          'Making alert-driven AGs'])
        by_stage = {s['stage']: s['seconds'] for s in rolled}
        self.assertAlmostEqual(by_stage['Converting to episodes'], 6.0)  # not 0.0
        self.assertAlmostEqual(by_stage['Reading alerts'], 2.0)
        self.assertAlmostEqual(by_stage['Making alert-driven AGs'], 12.0)

    def test_stage_rollup_handles_no_banners(self):
        self.assertEqual(runner._roll_up_stages([], total_seconds=5.0), [])

    def test_incomplete_cell_is_not_treated_as_done(self):
        directory = tempfile.mkdtemp()
        self.assertFalse(runner.cell_is_complete(directory))  # no marker

        marker = os.path.join(directory, 'cell.json')
        with open(marker, 'w', encoding='utf-8') as handle:
            json.dump({'exit_code': 1}, handle)
        self.assertFalse(runner.cell_is_complete(directory))  # failed run

        with open(marker, 'w', encoding='utf-8') as handle:
            json.dump({'exit_code': 0}, handle)
        self.assertTrue(runner.cell_is_complete(directory))

        with open(marker, 'w', encoding='utf-8') as handle:
            handle.write('{ truncated')
        self.assertFalse(runner.cell_is_complete(directory))  # corrupt marker

    def test_cached_cell_from_a_different_config_is_not_reused(self):
        # Resuming on the cell name alone let a check against a PERTURBED alert
        # corpus poison the reference cell, so a later run silently reported the
        # perturbed run's numbers as its own baseline. The stored spec must match.
        directory = tempfile.mkdtemp()
        clean = {'name': 'cptc-2017-reference', 'dataset_path': '/alerts/cptc-2017',
                 'dataset_flag': 'cptc', 't': 1.0, 'w': 150}
        perturbed = dict(clean, dataset_path='/eval-runs/bad/alerts/cptc-2017')

        with open(os.path.join(directory, 'cell.json'), 'w', encoding='utf-8') as handle:
            json.dump({'exit_code': 0, 'cell': perturbed}, handle)

        self.assertFalse(runner.cell_is_complete(directory, expected_cell=clean))
        self.assertTrue(runner.cell_is_complete(directory, expected_cell=perturbed))
        # Without a spec to check against, the old name-only behaviour stands.
        self.assertTrue(runner.cell_is_complete(directory))

    def test_differing_parameters_also_invalidate_a_cached_cell(self):
        directory = tempfile.mkdtemp()
        base = {'name': 'x', 'dataset_path': '/a', 'dataset_flag': 'cptc',
                't': 1.0, 'w': 150}
        with open(os.path.join(directory, 'cell.json'), 'w', encoding='utf-8') as handle:
            json.dump({'exit_code': 0, 'cell': base}, handle)
        self.assertFalse(runner.cell_is_complete(directory,
                                                 expected_cell=dict(base, w=200)))
        self.assertFalse(runner.cell_is_complete(directory,
                                                 expected_cell=dict(base, t=2.0)))


def _record_with(aggregate=None, perplexity_training=None, timing=None, totals=None):
    """
    Builds a minimal record for the regression-check tests.

    @param aggregate: the attack graph aggregate section
    @param perplexity_training: a training perplexity value
    @param timing: the timing section
    @param totals: the alert totals section
    @return: a record dict
    """
    record = schema.new_record('test-dataset', 'abc1234', {}, {})
    record['reference'] = {
        'attack_graphs': {'aggregate': aggregate or {}},
        'alerts': {'totals': totals or {}},
        'perplexity': {'training': {'perplexity': perplexity_training}},
        'timing': timing or {},
    }
    return record


class TestRegressionCheck(unittest.TestCase):
    """The --check logic: what counts as a regression and what does not."""

    def test_identical_records_pass(self):
        record = _record_with({'n_attack_graphs': 104, 'total_nodes': 1885},
                              perplexity_training=13.478)
        result = schema.check_regression(record, record)
        self.assertTrue(result['passed'])
        self.assertEqual(result['failures'], [])
        self.assertEqual(result['n_compared'], 3)

    def test_structural_change_fails(self):
        # The check must fail on a perturbed run -- otherwise the snapshot is a
        # document, not a reference.
        baseline = _record_with({'n_attack_graphs': 104, 'total_nodes': 1885})
        candidate = _record_with({'n_attack_graphs': 103, 'total_nodes': 1885})
        result = schema.check_regression(baseline, candidate)
        self.assertFalse(result['passed'])
        self.assertIn('n_attack_graphs', result['failures'])
        self.assertNotIn('total_nodes', result['failures'])

    def test_single_node_change_fails(self):
        # Structural tolerances are exact, so even one node must trip the check.
        baseline = _record_with({'total_nodes': 1885})
        candidate = _record_with({'total_nodes': 1886})
        self.assertFalse(schema.check_regression(baseline, candidate)['passed'])

    def test_runtime_drift_is_reported_but_never_fatal(self):
        # Runtime is hardware-dependent; failing on it would make the check fail
        # on a different machine for reasons unrelated to a regression.
        baseline = _record_with(timing={'wall_clock_seconds': 57.0})
        candidate = _record_with(timing={'wall_clock_seconds': 400.0})
        result = schema.check_regression(baseline, candidate)
        self.assertTrue(result['passed'])
        finding = next(f for f in result['findings']
                       if f['metric'] == 'wall_clock_seconds')
        self.assertEqual(finding['status'], 'informational')
        self.assertAlmostEqual(finding['relative'], (400.0 - 57.0) / 57.0)

    def test_float_noise_within_tolerance_passes(self):
        baseline = _record_with(perplexity_training=13.478000000)
        candidate = _record_with(perplexity_training=13.478000001)
        self.assertTrue(schema.check_regression(baseline, candidate)['passed'])

    def test_real_perplexity_shift_fails(self):
        baseline = _record_with(perplexity_training=13.478)
        candidate = _record_with(perplexity_training=13.52)
        self.assertFalse(schema.check_regression(baseline, candidate)['passed'])

    def test_missing_metric_fails(self):
        baseline = _record_with({'n_attack_graphs': 104})
        candidate = _record_with({})
        result = schema.check_regression(baseline, candidate)
        self.assertFalse(result['passed'])
        self.assertEqual(next(f['status'] for f in result['findings']
                              if f['metric'] == 'n_attack_graphs'), 'missing')

    def test_schema_version_mismatch_is_flagged(self):
        baseline = _record_with({'n_attack_graphs': 104})
        baseline['schema_version'] = 999
        result = schema.check_regression(baseline, _record_with({'n_attack_graphs': 104}))
        self.assertIn('schema_warning', result)

    def test_summarise_reports_spread(self):
        summary = schema.summarise([10, 12, 14, 11, 13])
        self.assertEqual(summary['n'], 5)
        self.assertEqual((summary['min'], summary['median'], summary['max']), (10, 12, 14))
        self.assertAlmostEqual(summary['mean'], 12.0)
        self.assertGreater(summary['stdev'], 0)

    def test_summarise_of_identical_repeats_has_zero_spread(self):
        # What a deterministic pipeline should look like across repeats.
        summary = schema.summarise([13.478] * 5)
        self.assertEqual(summary['stdev'], 0.0)
        self.assertEqual(summary['min'], summary['max'])

    def test_round_trip_through_disk(self):
        record = _record_with({'n_attack_graphs': 104})
        path = os.path.join(tempfile.mkdtemp(), 'metrics-test.json')
        schema.save(record, path)
        self.assertTrue(schema.check_regression(schema.load(path), record)['passed'])


class TestPerturbation(unittest.TestCase):
    """Noise injection: seeding, rates, and wrapper preservation."""

    @staticmethod
    def _records(n=100, wrapper='plain'):
        made = []
        for i in range(n):
            stamp = '2017-11-04T12:{:02d}:{:02d}.000000+0000'.format(i // 60, i % 60)
            inner = {
                'timestamp': stamp,
                'event_type': 'alert', 'src_ip': '10.0.0.1',
                'dest_ip': '10.0.0.2', 'src_port': 100 + i, 'dest_port': 80,
                'alert': {'signature': 'SIG {}'.format(i % 5),
                          'category': 'Attempted Admin'},
            }
            if wrapper == 'result_raw':
                made.append({'preview': False, 'result': {'_raw': json.dumps(inner)}})
            elif wrapper == 'top_raw':
                made.append({'_bkt': 'x', '_raw': json.dumps(inner)})
            else:
                made.append(inner)
        return made

    def test_injection_preserves_each_wrapper_shape(self):
        # A synthetic alert in the wrong wrapper is silently skipped by SAGE's
        # parser, which would make a robustness run inject nothing at all.
        for wrapper in ('plain', 'result_raw', 'top_raw'):
            records = self._records(wrapper=wrapper)
            perturbed, injected = perturbation.inject_false_positives(
                records, 0.10, random.Random(1))
            self.assertEqual(injected, 10, wrapper)
            for record in perturbed:
                inner = perturbation._unwrap(record)
                self.assertEqual(inner['event_type'], 'alert', wrapper)
                self.assertIn('signature', inner['alert'], wrapper)

    def test_rates_are_honoured(self):
        records = self._records(200)
        for rate in (0.01, 0.05, 0.10, 0.20):
            _, injected = perturbation.inject_false_positives(
                records, rate, random.Random(1))
            self.assertEqual(injected, int(round(200 * rate)))
            kept, dropped = perturbation.drop_alerts(records, rate, random.Random(1))
            self.assertEqual(dropped, int(round(200 * rate)))
            self.assertEqual(len(kept), 200 - dropped)

    def test_same_seed_reproduces_same_perturbation(self):
        records = self._records()
        first, _ = perturbation.drop_alerts(records, 0.2, random.Random(7))
        second, _ = perturbation.drop_alerts(records, 0.2, random.Random(7))
        third, _ = perturbation.drop_alerts(records, 0.2, random.Random(8))
        self.assertEqual(first, second)
        self.assertNotEqual(first, third)

    def test_injected_alerts_stay_inside_the_capture_window(self):
        records = self._records()
        earliest, latest = perturbation._timestamps(
            [perturbation._unwrap(r) for r in records])
        perturbed, _ = perturbation.inject_false_positives(
            records, 0.5, random.Random(3))
        for record in perturbed:
            when = datetime.datetime.strptime(
                perturbation._unwrap(record)['timestamp'], perturbation._TIMESTAMP_FORMAT)
            self.assertGreaterEqual(when, earliest)
            self.assertLessEqual(when, latest)

    def test_duplicates_repeat_existing_alerts_only(self):
        records = self._records()
        perturbed, added = perturbation.duplicate_subsequences(
            records, 0.2, random.Random(5))
        self.assertEqual(len(perturbed), len(records) + added)
        original = [json.dumps(r, sort_keys=True) for r in records]
        for record in perturbed:
            self.assertIn(json.dumps(record, sort_keys=True), original)

    def test_unknown_family_is_rejected(self):
        with self.assertRaises(ValueError):
            perturbation.perturb_dataset('.', tempfile.mkdtemp(), 'nonsense', 0.1, 1)

    def test_sweep_excludes_each_dataset_own_baseline(self):
        # CPTC-2018's baseline is -t 2.0 -w 200, not SAGE's defaults, so its
        # sweep must exclude those values rather than the global defaults.
        cells = perturbation.sweep_grid('cptc-2018')
        swept_t = {c['value'] for c in cells if c['parameter'] == 't'}
        swept_w = {c['value'] for c in cells if c['parameter'] == 'w'}
        self.assertNotIn(2.0, swept_t)
        self.assertNotIn(200, swept_w)
        self.assertIn(1.0, swept_t)     # the default IS swept for 2018
        self.assertIn(150, swept_w)

        cells_2017 = perturbation.sweep_grid('cptc-2017')
        self.assertNotIn(1.0, {c['value'] for c in cells_2017 if c['parameter'] == 't'})

    def test_sweep_holds_the_other_parameter_at_baseline(self):
        for cell in perturbation.sweep_grid('cptc-2018'):
            if cell['parameter'] == 't':
                self.assertEqual(cell['w'], 200)
            else:
                self.assertEqual(cell['t'], 2.0)

    def test_perturbation_grid_size(self):
        grid = perturbation.perturbation_grid()
        self.assertEqual(len(grid), 4 * 4 * 3)  # families x rates x seeds
        self.assertEqual(len({(c['family'], c['rate'], c['seed']) for c in grid}), 48)


class TestExactMatch(unittest.TestCase):
    """Comparing artifacts across repeat runs."""

    def _run(self, experiment, bodies):
        """Builds a fake completed cell with an AG directory."""
        directory = os.path.join(tempfile.mkdtemp(), experiment + 'AGs')
        os.makedirs(directory)
        for objective, body in bodies.items():
            name = '{}.txt-attack-graph-for-victim-10.0.0.1-{}.dot'.format(
                experiment, objective)
            with open(os.path.join(directory, name), 'w', encoding='utf-8') as handle:
                handle.write(body)
        return {'name': experiment, 'artifacts': {'ag_directory': directory}}

    def test_differing_experiment_names_still_compare(self):
        # Every artifact filename embeds its own experiment name, so two runs
        # never share a filename. Matching on the raw name reported all 104
        # graphs as "missing in some repeat" and a 0.0 match rate -- reading as
        # total non-determinism when the graphs were in fact byte-identical.
        graphs = {'DATAEXFIL': '"A" -> "B"\n', 'NETWORKDOS': '"C" -> "D"\n'}
        runs = [self._run('exp-repeat-0', graphs), self._run('exp-repeat-1', graphs)]

        verdict = collect.exact_match_across_repeats(runs)
        self.assertEqual(verdict['n_ag_dot_files'], 2)          # not 4
        self.assertEqual(verdict['ag_dot_missing_in_some_repeat'], 0)
        self.assertEqual(verdict['ag_dot_match_rate_raw'], 1.0)

    def test_real_difference_is_still_detected(self):
        # The keying fix must not make everything look identical.
        runs = [self._run('exp-repeat-0', {'DATAEXFIL': '"A" -> "B"\n'}),
                self._run('exp-repeat-1', {'DATAEXFIL': '"A" -> "Z"\n'})]
        verdict = collect.exact_match_across_repeats(runs)
        self.assertEqual(verdict['ag_dot_match_rate_raw'], 0.0)

    def test_graph_present_in_only_one_run_is_counted_missing(self):
        runs = [self._run('exp-repeat-0', {'DATAEXFIL': 'x\n', 'EXTRA': 'y\n'}),
                self._run('exp-repeat-1', {'DATAEXFIL': 'x\n'})]
        verdict = collect.exact_match_across_repeats(runs)
        self.assertEqual(verdict['ag_dot_missing_in_some_repeat'], 1)
        self.assertEqual(verdict['ag_dot_identical_raw'], 1)


class TestLogScraping(unittest.TestCase):
    """Recovering SAGE's own alert counts from stdout."""

    def _cell_with_log(self, text):
        directory = tempfile.mkdtemp()
        with open(os.path.join(directory, 'stdout.log'), 'w', encoding='utf-8') as handle:
            handle.write(text)
        return {'artifacts': {'.txt': os.path.join(directory, 'exp.txt')}}

    def test_counts_are_summed_across_team_files(self):
        # SAGE prints these once per team file, not once per run. Taking the
        # first match yields only the first team's count -- 4183 instead of the
        # real 43299 on the CPTC-2017 baseline.
        cell = self._cell_with_log(
            '------ Reading alerts ------\n'
            'Reading # alerts:  4274\n'
            'Filtered # alerts (remaining): 4183\n'
            'Reading # alerts:  5105\n'
            'Filtered # alerts (remaining): 4949\n'
            'Reading # alerts:  2923\n'
            'Filtered # alerts (remaining): 2904\n')
        counts = collect.alert_counts_from_log(cell)
        self.assertEqual(counts['sage_read'], 4274 + 5105 + 2923)
        self.assertEqual(counts['post_dedup'], 4183 + 4949 + 2904)
        self.assertEqual(len(counts['per_file_read']), 3)
        self.assertNotEqual(counts['post_dedup'], 4183)  # the bug this guards

    def test_missing_log_yields_nulls_not_guesses(self):
        counts = collect.alert_counts_from_log({'artifacts': {}})
        self.assertIsNone(counts['sage_read'])
        self.assertIsNone(counts['post_dedup'])

    def test_unrelated_numbers_are_not_scraped(self):
        cell = self._cell_with_log('# episode traces: 1102\n'
                                   'Total medium-severity states: 42\n')
        counts = collect.alert_counts_from_log(cell)
        self.assertIsNone(counts['sage_read'])
        self.assertIsNone(counts['post_dedup'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
