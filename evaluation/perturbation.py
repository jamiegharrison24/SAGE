"""
Noise injection and the parameter sweep grid.

Perturbations are applied to the **raw alert files**, before SAGE reads them, so
the whole chain is exercised -- deduplication, episode aggregation, S-PDFA
learning and graph construction all see the corrupted input. Perturbing a later
intermediate would measure the robustness of a fragment of the pipeline rather
than of the pipeline.

That means a perturbed file has to remain readable by SAGE, which is why
`_rewrap` exists: each dataset carries its alerts inside a different wrapper
(see `alerts._unwrap`), and a synthetic alert written in the wrong shape is
silently skipped rather than injected, quietly turning a robustness run into a
no-op.

Three perturbation families, each with a rate and a recorded seed:

    false_positives   synthetic alerts drawn from the observed signature
                      distribution, at random times in the capture window
    duplicates        randomly chosen contiguous subsequences, repeated
    missing_alerts    a random fraction of alerts dropped
    missing_episodes  contiguous time-blocks dropped per attacker-victim pair

The last two are both the paper's "missing attack steps", split because they are
not equally damaging: scattered losses often leave an episode's shape intact,
while losing a contiguous block can remove an attack step altogether. They are
reported under separate labels rather than averaged.
"""
import copy
import json
import os
import random
from datetime import datetime, timedelta

FAMILIES = ['false_positives', 'duplicates', 'missing_alerts', 'missing_episodes']
DEFAULT_RATES = [0.01, 0.05, 0.10, 0.20]
DEFAULT_SEEDS = [1, 2, 3]

# Sweep grids, one parameter at a time around each dataset's own defaults.
DEFAULT_T_SWEEP = [0.5, 1.0, 2.0, 5.0]
DEFAULT_W_SWEEP = [50, 100, 150, 200, 300]

# SAGE's own defaults, and the documented per-dataset baseline commands. Sweeps
# are relative to these, since CPTC-2018's baseline is not SAGE's default.
DATASET_DEFAULTS = {
    'cptc-2017': {'t': 1.0, 'w': 150, 'dataset_flag': 'cptc'},
    'cptc-2018': {'t': 2.0, 'w': 200, 'dataset_flag': 'cptc'},
    'ccdc': {'t': 1.0, 'w': 150, 'dataset_flag': 'other'},
}

_TIMESTAMP_FORMAT = '%Y-%m-%dT%H:%M:%S.%f%z'


def _unwrap(record):
    """
    Extracts the inner Suricata record from whichever wrapper a dataset uses.

    @param record: one JSON object from an alert file
    @return: the inner Suricata record
    """
    if 'result' in record and '_raw' in record['result']:
        return json.loads(record['result']['_raw'])
    if '_raw' in record:
        return json.loads(record['_raw'])
    return record


def _rewrap(record, inner):
    """
    Puts a modified Suricata record back into the wrapper it came from.

    A synthetic alert written in the wrong shape is skipped by SAGE's parser
    rather than rejected, so getting this wrong silently produces a robustness
    run that injected nothing.

    @param record: the original wrapper object
    @param inner: the modified inner Suricata record
    @return: a new wrapper object carrying `inner`
    """
    wrapper = copy.deepcopy(record)
    if 'result' in wrapper and '_raw' in wrapper['result']:
        wrapper['result']['_raw'] = json.dumps(inner)
    elif '_raw' in wrapper:
        wrapper['_raw'] = json.dumps(inner)
    else:
        return inner
    return wrapper


def _timestamps(inners):
    """
    Parses the capture window from a list of inner records.

    @param inners: the inner Suricata records
    @return: (earliest, latest) as datetimes, or (None, None)
    """
    stamps = []
    for inner in inners:
        try:
            stamps.append(datetime.strptime(inner['timestamp'], _TIMESTAMP_FORMAT))
        except (KeyError, ValueError):
            continue
    return (min(stamps), max(stamps)) if stamps else (None, None)


def inject_false_positives(records, rate, rng):
    """
    Adds synthetic alerts drawn from the observed signature distribution.

    Sampling from the observed distribution (rather than inventing signatures)
    keeps the injected alerts plausible: they map to real attack stages via the
    same lookup the genuine alerts use, so they enter the model as noise rather
    than being discarded as unknown.

    @param records: the wrapper objects from one file
    @param rate: the proportion of the original count to add
    @param rng: a seeded `random.Random`
    @return: (perturbed_records, n_injected)
    """
    if not records:
        return list(records), 0
    inners = [_unwrap(r) for r in records]
    alerts = [(r, i) for r, i in zip(records, inners) if i.get('event_type') == 'alert']
    if not alerts:
        return list(records), 0

    earliest, latest = _timestamps([i for _, i in alerts])
    span = (latest - earliest).total_seconds() if earliest and latest else 0

    signatures = [(i['alert']['signature'], i['alert']['category']) for _, i in alerts]
    endpoints = [(i['src_ip'], i['dest_ip'],
                  i.get('src_port'), i.get('dest_port')) for _, i in alerts]

    n_inject = int(round(len(alerts) * rate))
    injected = []
    for _ in range(n_inject):
        template_record, template_inner = alerts[rng.randrange(len(alerts))]
        synthetic = copy.deepcopy(template_inner)
        signature, category = signatures[rng.randrange(len(signatures))]
        src, dst, src_port, dst_port = endpoints[rng.randrange(len(endpoints))]
        synthetic['alert'] = dict(synthetic.get('alert', {}))
        synthetic['alert']['signature'] = signature
        synthetic['alert']['category'] = category
        synthetic['src_ip'], synthetic['dest_ip'] = src, dst
        if src_port is not None:
            synthetic['src_port'] = src_port
        if dst_port is not None:
            synthetic['dest_port'] = dst_port
        if earliest:
            when = earliest + timedelta(seconds=rng.uniform(0, span))
            synthetic['timestamp'] = when.strftime(_TIMESTAMP_FORMAT)
        injected.append(_rewrap(template_record, synthetic))

    return list(records) + injected, len(injected)


def duplicate_subsequences(records, rate, rng, max_run=10):
    """
    Duplicates randomly chosen contiguous runs of alerts.

    Contiguous runs rather than scattered singles, because the failure mode being
    modelled is an IDS re-reporting a burst -- which is also precisely what SAGE's
    `-t` duplicate filter is meant to absorb, making this the family that tests it.

    @param records: the wrapper objects from one file
    @param rate: the proportion of the original count to add as duplicates
    @param rng: a seeded `random.Random`
    @param max_run: the longest run duplicated in one go
    @return: (perturbed_records, n_duplicated)
    """
    if not records:
        return list(records), 0
    target = int(round(len(records) * rate))
    result, added = list(records), 0
    while added < target:
        run = min(rng.randint(1, max_run), target - added)
        start = rng.randrange(len(records))
        chunk = records[start:start + run]
        if not chunk:
            continue
        insert_at = rng.randrange(len(result) + 1)
        result[insert_at:insert_at] = copy.deepcopy(chunk)
        added += len(chunk)
    return result, added


def drop_alerts(records, rate, rng):
    """
    Drops a uniformly random fraction of alerts.

    @param records: the wrapper objects from one file
    @param rate: the proportion to remove
    @param rng: a seeded `random.Random`
    @return: (perturbed_records, n_dropped)
    """
    if not records:
        return list(records), 0
    n_drop = int(round(len(records) * rate))
    doomed = set(rng.sample(range(len(records)), min(n_drop, len(records))))
    return [r for i, r in enumerate(records) if i not in doomed], len(doomed)


def drop_episodes(records, rate, rng, block_seconds=150):
    """
    Drops contiguous time-blocks of alerts per attacker-victim pair.

    Approximates losing whole attack steps rather than scattered alerts: blocks
    are cut per (src_ip, dest_ip) over `block_seconds`, matching the default
    episode aggregation window, so a dropped block plausibly removes an episode
    rather than merely thinning one.

    @param records: the wrapper objects from one file
    @param rate: the proportion of alerts to remove
    @param rng: a seeded `random.Random`
    @param block_seconds: the block width, matching SAGE's `-w` default
    @return: (perturbed_records, n_dropped)
    """
    if not records:
        return list(records), 0

    blocks = {}
    for index, record in enumerate(records):
        inner = _unwrap(record)
        if inner.get('event_type') != 'alert':
            continue
        try:
            when = datetime.strptime(inner['timestamp'], _TIMESTAMP_FORMAT)
        except (KeyError, ValueError):
            continue
        key = (inner.get('src_ip'), inner.get('dest_ip'),
               int(when.timestamp() // block_seconds))
        blocks.setdefault(key, []).append(index)

    if not blocks:
        return list(records), 0

    target = int(round(len(records) * rate))
    keys = list(blocks)
    rng.shuffle(keys)

    doomed, dropped = set(), 0
    for key in keys:
        if dropped >= target:
            break
        doomed.update(blocks[key])
        dropped += len(blocks[key])

    return [r for i, r in enumerate(records) if i not in doomed], len(doomed)


_APPLY = {
    'false_positives': inject_false_positives,
    'duplicates': duplicate_subsequences,
    'missing_alerts': drop_alerts,
    'missing_episodes': drop_episodes,
}


def perturb_dataset(source_directory, destination_directory, family, rate, seed):
    """
    Writes a perturbed copy of a dataset directory.

    The copy keeps each file's original name and wrapper shape, so SAGE reads it
    exactly as it reads the original -- only the alerts differ.

    @param source_directory: the original alerts directory
    @param destination_directory: where to write the perturbed copy
    @param family: one of FAMILIES
    @param rate: the perturbation rate
    @param seed: the RNG seed, recorded in the returned manifest
    @return: a manifest describing exactly what was changed
    @raise ValueError: if the family is unknown
    """
    if family not in _APPLY:
        raise ValueError('Unknown perturbation family {!r}; expected one of {}'
                         .format(family, FAMILIES))

    import glob
    os.makedirs(destination_directory, exist_ok=True)
    rng = random.Random(seed)
    manifest = {'family': family, 'rate': rate, 'seed': seed,
                'source': os.path.abspath(source_directory),
                'destination': os.path.abspath(destination_directory),
                'per_file': {}, 'n_changed': 0, 'n_original': 0}

    for path in sorted(glob.glob(os.path.join(source_directory, '*.json'))):
        with open(path, 'r', encoding='utf-8-sig') as handle:
            records = json.load(handle)
        perturbed, changed = _APPLY[family](records, rate, rng)

        target = os.path.join(destination_directory, os.path.basename(path))
        with open(target, 'w', encoding='utf-8') as handle:
            json.dump(perturbed, handle)

        manifest['per_file'][os.path.basename(path)] = {
            'original': len(records), 'perturbed': len(perturbed), 'changed': changed}
        manifest['n_changed'] += changed
        manifest['n_original'] += len(records)

    manifest['effective_rate'] = (manifest['n_changed'] / manifest['n_original']
                                  if manifest['n_original'] else 0.0)
    return manifest


def perturbation_grid(families=None, rates=None, seeds=None):
    """
    Enumerates the noise-injection run matrix.

    @param families: which families to include, defaulting to all of FAMILIES
    @param rates: the rates, defaulting to DEFAULT_RATES
    @param seeds: the seeds, defaulting to DEFAULT_SEEDS
    @return: a list of cell specifications
    """
    families = families if families is not None else FAMILIES
    rates = rates if rates is not None else DEFAULT_RATES
    seeds = seeds if seeds is not None else DEFAULT_SEEDS
    return [{'family': family, 'rate': rate, 'seed': seed}
            for family in families for rate in rates for seed in seeds]


def sweep_grid(dataset, t_values=None, w_values=None):
    """
    Enumerates the one-at-a-time parameter sweep around a dataset's own defaults.

    CPTC-2018's documented baseline is `-t 2.0 -w 200`, not SAGE's defaults, so
    sweeping around a single global default would measure the wrong neighbourhood
    for it. The dataset's own baseline value is excluded from its sweep, since
    that cell is the reference run.

    @param dataset: a key of DATASET_DEFAULTS
    @param t_values: the `-t` values, defaulting to DEFAULT_T_SWEEP
    @param w_values: the `-w` values, defaulting to DEFAULT_W_SWEEP
    @return: a list of cell specifications
    @raise KeyError: if the dataset has no recorded defaults
    """
    defaults = DATASET_DEFAULTS[dataset]
    t_values = t_values if t_values is not None else DEFAULT_T_SWEEP
    w_values = w_values if w_values is not None else DEFAULT_W_SWEEP

    cells = []
    for value in t_values:
        if value != defaults['t']:
            cells.append({'parameter': 't', 'value': value,
                          't': value, 'w': defaults['w'],
                          'baseline_value': defaults['t']})
    for value in w_values:
        if value != defaults['w']:
            cells.append({'parameter': 'w', 'value': value,
                          't': defaults['t'], 'w': value,
                          'baseline_value': defaults['w']})
    return cells
