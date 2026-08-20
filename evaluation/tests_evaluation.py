"""
Unit tests for the pure layer of the evaluation package.

Run with:  python evaluation/tests_evaluation.py

These cover the functions that turn artifacts into numbers, on fixtures small
enough to verify by hand. They deliberately do not run SAGE: the point is that a
metric definition can be checked without a pipeline run, so a wrong number is
caught before it is baked into a recorded baseline.
"""
import json
import math
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from evaluation import alerts, compare, dot_metrics, perplexity, runner  # noqa: E402


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


if __name__ == '__main__':
    unittest.main(verbosity=2)
