"""
Counts raw alerts per dataset and derives the alert compression ratios.

**Three wrapper formats, not two.** The task spec said CPTC-2017 was plain
Suricata JSON and only CPTC-2018 was Splunk-wrapped. Both are wrapped, in
different shapes, and CCDC is the plain one:

    cptc-2017  [{"preview":..., "result": {"_raw": "<suricata json string>"}}]
    cptc-2018  [{"_bkt":..., "_raw": "<suricata json string>"}]
    ccdc       [{"timestamp":..., "event_type":"alert", ...}]

`_unwrap` handles all three in the same order `alert_loading._parse` does, so a
naive key count -- which returns zero on the wrapped formats -- cannot happen.

Counts are reported at three stages, because "raw alerts" is ambiguous and the
compression ratio is sensitive to which one is meant:

    raw_records      every JSON object in the files, including non-alert events
    raw_alerts       records with event_type == 'alert', after the same dataset
                     filters `_parse` applies (CPTC bad IP, Not Suspicious Traffic)
    post_dedup_alerts  after the `-t` duplicate-filter window
"""
import glob
import json
import os

# Mirrors alert_loading.CPTC_BAD_IP and the category filter in `_parse`.
CPTC_BAD_IP = '169.254.169.254'
DROPPED_CATEGORY = 'Not Suspicious Traffic'

COMPRESSION_FORMULAS = {
    'raw_records_per_ag':
        'raw_records / n_attack_graphs  (PRIMARY -- the paper defines compression as '
        '"number of raw alerts divided by number of generated attack graphs", and its own '
        'dataset counts pin "raw alerts" to every record in the file: it cites CCDC-2018 as '
        '1,052,281, which is exactly the raw_records count here, whereas the post-filter '
        'alert count is 1,033,067. See RAW_ALERT_CONVENTION.)',
    'raw_alerts_per_ag':
        'raw_alerts / n_attack_graphs  (the same ratio over alerts SAGE actually ingests, '
        'i.e. after the event_type and dataset filters. Diverges sharply from the primary on '
        'CPTC-2018, where the bad-IP filter drops ~69% of records.)',
    'post_dedup_alerts_per_ag': 'post_dedup_alerts / n_attack_graphs',
    'raw_alerts_per_ag_node': 'raw_alerts / total_ag_nodes  (nodes summed across graphs)',
    'raw_alerts_per_unique_ag_node': 'raw_alerts / unique_ag_nodes  (node union across graphs)',
}

# Reconciliation of the paper's dataset counts against this counter, which is what
# fixes the primary ratio's numerator. Recorded because the choice is load-bearing
# and non-obvious, and the two CPTC figures do NOT reconcile exactly:
#
#   dataset     paper       raw_records  raw_alerts   delta vs paper
#   CCDC-2018   1,052,281    1,052,281    1,033,067   0        (exact)
#   CPTC-2018     330,270      331,554      101,571   +1,284   (0.4%)
#   CPTC-2017      43,611       47,876       47,876   +4,265   (10 teams vs 9)
#
# CPTC-2017 reconciles once NationalTeam1 is excluded: 47,876 - 4,274 = 43,602,
# within 9 of the paper's 43,611. That confirms the paper's figure is the pre-fix
# 9-team number inherited from Nadeem et al., and is NOT comparable to a corrected
# 10-team run. The residual CPTC gaps (9 and 1,284) are unexplained and are
# reported rather than reconciled away.
RAW_ALERT_CONVENTION = (
    'raw_records: every JSON object in the dataset files. Matches the paper convention, '
    'confirmed exactly against its CCDC-2018 count of 1,052,281.')

PRIMARY_COMPRESSION = 'raw_records_per_ag'


def _unwrap(record):
    """
    Extracts the Suricata alert from whichever wrapper a dataset uses.

    @param record: one JSON object from an alert file
    @return: the inner Suricata record
    """
    if 'result' in record and '_raw' in record['result']:
        return json.loads(record['result']['_raw'])       # cptc-2017
    if '_raw' in record:
        return json.loads(record['_raw'])                  # cptc-2018
    return record                                          # ccdc


def count_file(path, dataset_name):
    """
    Counts records and alerts in a single alert file.

    @param path: the path to a `.json` alert file
    @param dataset_name: 'cptc' or 'other', matching SAGE's --dataset flag
    @return: a dict with raw_records, raw_alerts and the per-reason drop counts
    """
    with open(path, 'r', encoding='utf-8-sig') as handle:
        data = json.load(handle)

    counts = {'raw_records': len(data), 'raw_alerts': 0,
              'dropped_non_alert': 0, 'dropped_bad_ip': 0, 'dropped_category': 0}

    for record in data:
        raw = _unwrap(record)
        if raw.get('event_type') != 'alert':
            counts['dropped_non_alert'] += 1
            continue
        category = raw['alert']['category']
        if dataset_name == 'cptc' and CPTC_BAD_IP in (raw['src_ip'], raw['dest_ip']):
            counts['dropped_bad_ip'] += 1
            continue
        if category == DROPPED_CATEGORY:
            counts['dropped_category'] += 1
            continue
        counts['raw_alerts'] += 1
    return counts


def count_directory(path, dataset_name):
    """
    Counts alerts across a dataset directory, matching SAGE's own file selection.

    SAGE selects files with `glob.glob(path + "/*.json")`, so a file not ending in
    exactly `.json` is silently skipped -- the bug that once excluded
    NationalTeam1 and produced a 9-team CPTC-2017 corpus. The same glob is used
    here so the count reflects what SAGE actually reads, and the per-file
    breakdown makes an unexpectedly absent team visible.

    @param path: the dataset directory
    @param dataset_name: 'cptc' or 'other'
    @return: a dict with the totals, the per-file breakdown and the file list
    """
    files = sorted(glob.glob(os.path.join(path, '*.json')))
    per_file, totals = {}, {'raw_records': 0, 'raw_alerts': 0,
                            'dropped_non_alert': 0, 'dropped_bad_ip': 0,
                            'dropped_category': 0}
    for file_path in files:
        counts = count_file(file_path, dataset_name)
        per_file[os.path.basename(file_path)] = counts
        for key, value in counts.items():
            totals[key] += value

    return {
        'directory': path,
        'dataset_name': dataset_name,
        'n_files': len(files),
        'files': [os.path.basename(f) for f in files],
        'totals': totals,
        'per_file': per_file,
    }


def compression_ratios(raw_records, raw_alerts, post_dedup_alerts, n_attack_graphs,
                       total_ag_nodes, unique_ag_nodes):
    """
    Derives every variant of the alert compression ratio.

    The paper specifies the numerator only as "raw alerts", so all five variants
    are recorded and one is marked primary rather than an interpretation being
    chosen silently. The primary numerator is `raw_records`, matching the
    convention the paper's own dataset counts imply (see RAW_ALERT_CONVENTION).

    @param raw_records: every JSON object in the dataset files
    @param raw_alerts: records surviving the event_type and dataset filters
    @param post_dedup_alerts: alerts after the `-t` duplicate window, or None if
        the run's stdout did not report it
    @param n_attack_graphs: distinct (victim, objective) graphs, NOT file count
    @param total_ag_nodes: nodes summed across graphs
    @param unique_ag_nodes: the node union across graphs
    @return: a dict of ratios, their formulas, and which is primary
    """
    def ratio(numerator, denominator):
        if not denominator or numerator is None:
            return None
        return numerator / denominator

    return {
        'raw_records_per_ag': ratio(raw_records, n_attack_graphs),
        'raw_alerts_per_ag': ratio(raw_alerts, n_attack_graphs),
        'post_dedup_alerts_per_ag': ratio(post_dedup_alerts, n_attack_graphs),
        'raw_alerts_per_ag_node': ratio(raw_alerts, total_ag_nodes),
        'raw_alerts_per_unique_ag_node': ratio(raw_alerts, unique_ag_nodes),
        'primary': PRIMARY_COMPRESSION,
        'raw_alert_convention': RAW_ALERT_CONVENTION,
        'formulas': COMPRESSION_FORMULAS,
        'inputs': {
            'raw_records': raw_records,
            'raw_alerts': raw_alerts,
            'post_dedup_alerts': post_dedup_alerts,
            'n_attack_graphs': n_attack_graphs,
            'total_ag_nodes': total_ag_nodes,
            'unique_ag_nodes': unique_ag_nodes,
        },
    }
