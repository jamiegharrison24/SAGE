"""
Builds and executes the run matrix, and captures everything needed to reproduce it.

Every cell shells out to `python sage.py ... --keep-files` and derives its metrics
from the artifacts and the timestamped stdout. Nothing here imports the pipeline:
`baseline-v1` exposes no importable pipeline, so an import-based harness could not
measure the baseline at all.

Four traps this module exists to handle, all of which silently corrupt a baseline
rather than failing loudly:

**The IANA download.** `load_iana_mapping` fetches a CSV from iana.org at runtime
and derives `mserv` labels from it, so if IANA republishes mid-matrix the attack
graphs shift for reasons unrelated to the code, splitting the run matrix into two
incomparable halves. At `baseline-v1` the fetch has no timeout and no retry, so a
slow IANA also hangs the run indefinitely. We snapshot the CSV once and serve the
pinned copy via a generated `sitecustomize.py` on PYTHONPATH -- which Python
imports automatically at interpreter start -- so the baseline tree is never
patched. Every cell asserts the CSV digest, so a drift cannot go unnoticed.

**Artifact placement.** `plotting.py` writes `'data_histogram-' + experiment_name`,
so an experiment name containing a path separator makes the run fail on a missing
directory (or an invalid filename on Windows). Experiment names must therefore be
bare, artifacts land in the worktree root, and we harvest them out afterwards.

**Worktree cleanliness.** `flexfringe.log` is a *tracked* file that FlexFringe
rewrites on every invocation, so each cell dirties the baseline worktree. We
restore it after every cell and assert cleanliness per cell rather than once at
the end, so the offending cell is identifiable.

**Hash seed.** `PYTHONHASHSEED` is pinned, because at `baseline-v1` the AG tooltip
join is unsorted over a set and Python randomises string hashing per process.
"""
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone

IANA_CSV_URL = 'https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.csv'

# Emitted by SAGE at each pipeline stage; timestamping these recovers per-stage
# runtime without modifying sage.py.
_BANNER = re.compile(r'^-+ (?P<stage>.+?) -+$')

# SAGE emits sub-banners in the same '------ X ------' shape as its stage banners
# ('TEAMS', 'Sub-sequences', 'FIN'), which makes naive attribution wrong: the work
# of 'Converting to episodes' lands under the 'TEAMS' banner that follows it, and
# the stage itself reads 0.00s. These are the real stage boundaries; time between
# one and the next is attributed to it regardless of sub-banners in between.
_CANONICAL_STAGES = [
    'Downloading the IANA port-service mapping',
    'Reading alerts',
    'Converting to episodes',
    'Converting to episode sequences',
    'Breaking into sub-sequences and generating traces',
    'Learning S-PDFA',
    '!! Special: Fixing syntax error in main model and sink files',
    'Loading and traversing S-PDFA',
    'Encoding traces into state sequences',
    'Making alert-driven AGs',
]


def _roll_up_stages(raw_stages, total_seconds):
    """
    Attributes elapsed time to canonical pipeline stages, absorbing sub-banners.

    @param raw_stages: every banner seen, in order, with its start offset
    @param total_seconds: the run's wall-clock time, to close the final stage
    @return: a list of canonical stage timings
    """
    boundaries = [s for s in raw_stages if s['stage'] in _CANONICAL_STAGES]
    rolled = []
    for index, stage in enumerate(boundaries):
        end = (boundaries[index + 1]['started'] if index + 1 < len(boundaries)
               else total_seconds)
        rolled.append({'stage': stage['stage'],
                       'started': stage['started'],
                       'ended': round(end, 3),
                       'seconds': round(end - stage['started'], 3)})
    return rolled


# Written into the worktree root by a run, keyed on the experiment name.
_ARTIFACT_SUFFIXES = ['.txt', '.txt.png',
                      '.txt.ff.final.json', '.txt.ff.final.dot',
                      '.txt.ff.finalsinks.json', '.txt.ff.finalsinks.dot',
                      '.txt.ff.init.json', '.txt.ff.init.dot',
                      '.txt.ff.initsinks.json', '.txt.ff.initsinks.dot']

# Tracked files a run modifies in place, restored after every cell.
_TRACKED_SIDE_EFFECTS = ['flexfringe.log']

_COMPLETED_MARKER = 'cell.json'


def snapshot_iana(destination):
    """
    Downloads the IANA port-service CSV once and pins it for the whole matrix.

    @param destination: where to write the pinned CSV
    @return: a dict with the path, SHA-256 and byte size
    @raise RuntimeError: if the download fails
    """
    import requests
    if not os.path.exists(destination):
        response = requests.get(IANA_CSV_URL, timeout=60)
        if not response.ok:
            raise RuntimeError('Could not download the IANA CSV to pin it: HTTP {}'
                               .format(response.status_code))
        os.makedirs(os.path.dirname(os.path.abspath(destination)), exist_ok=True)
        with open(destination, 'wb') as handle:
            handle.write(response.content)
    with open(destination, 'rb') as handle:
        payload = handle.read()
    return {'path': os.path.abspath(destination),
            'sha256': hashlib.sha256(payload).hexdigest(),
            'bytes': len(payload),
            'url': IANA_CSV_URL,
            'pinned_at': datetime.now(timezone.utc).isoformat()}


_SITECUSTOMIZE = '''\
"""
Generated by evaluation.runner -- do not edit.

Serves the pinned IANA CSV instead of fetching it live, so that every cell of a
run matrix sees byte-identical port-service data. Python imports sitecustomize
automatically at interpreter start, which lets this apply to the SAGE process
without modifying the baseline tree.
"""
import requests

_PINNED = {csv_path!r}
_URL = {url!r}
_real_get = requests.get


class _PinnedResponse:
    ok = True
    status_code = 200

    def __init__(self, payload):
        self.content = payload


def _get(url, *args, **kwargs):
    if url == _URL:
        with open(_PINNED, 'rb') as handle:
            return _PinnedResponse(handle.read())
    return _real_get(url, *args, **kwargs)


requests.get = _get
'''


def write_iana_shim(directory, csv_path):
    """
    Writes the `sitecustomize.py` that serves the pinned IANA CSV.

    @param directory: the directory to put on PYTHONPATH
    @param csv_path: the absolute path to the pinned CSV
    @return: the directory, for use as a PYTHONPATH entry
    """
    os.makedirs(directory, exist_ok=True)
    with open(os.path.join(directory, 'sitecustomize.py'), 'w', encoding='utf-8') as handle:
        handle.write(_SITECUSTOMIZE.format(csv_path=os.path.abspath(csv_path), url=IANA_CSV_URL))
    return os.path.abspath(directory)


def _command_output(command):
    """
    Runs a command and returns its first line of output, or None if unavailable.

    stderr is merged into stdout because several version probes report there
    rather than on stdout -- `dot -V` is the one that matters here, and silently
    returning None for the Graphviz version would leave a hole in the
    fingerprint that only shows up when a run is no longer reproducible.

    @param command: the argv list
    @return: the stripped first line, or None
    """
    try:
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                universal_newlines=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return None
    lines = [ln.strip() for ln in (result.stdout or '').splitlines() if ln.strip()]
    return lines[0] if lines else None


def _file_digest(path):
    """
    Hashes a file, tolerating its absence.

    @param path: the file to hash
    @return: the hex SHA-256, or None
    """
    if not os.path.exists(path):
        return None
    with open(path, 'rb') as handle:
        return hashlib.sha256(handle.read()).hexdigest()


def environment_fingerprint(worktree):
    """
    Captures the hardware and toolchain a run was made on.

    Runtimes are only comparable within one fingerprint, so it is recorded per
    run rather than once per document.

    @param worktree: the SAGE tree being measured, for the FlexFringe digest
    @return: a dict describing the machine and toolchain
    """
    fingerprint = {
        'captured_at': datetime.now(timezone.utc).isoformat(),
        'os': platform.platform(),
        'system': platform.system(),
        'machine': platform.machine(),
        'processor': platform.processor() or None,
        'cpu_count': os.cpu_count(),
        'python_version': sys.version.split()[0],
        'python_implementation': platform.python_implementation(),
        'graphviz_version': _command_output(['dot', '-V']),
        'flexfringe_sha256': _file_digest(os.path.join(worktree, 'FlexFringe', 'flexfringe')),
        'flexfringe_ini_sha256': _file_digest(
            os.path.join(worktree, 'FlexFringe', 'ini', 'spdfa-config.ini')),
    }

    # FlexFringe is a Linux binary; on Windows it runs through WSL, so the glibc
    # that actually matters is WSL's, not the host's.
    if platform.system() == 'Windows':
        fingerprint['wsl_kernel'] = _command_output(['wsl', '-d', 'Ubuntu', 'uname', '-r'])
        fingerprint['glibc_version'] = _command_output(['wsl', '-d', 'Ubuntu', 'ldd', '--version'])
        fingerprint['runs_flexfringe_via'] = 'wsl -d Ubuntu'
    else:
        fingerprint['kernel'] = _command_output(['uname', '-r'])
        fingerprint['glibc_version'] = _command_output(['ldd', '--version'])
        fingerprint['runs_flexfringe_via'] = 'native'

    try:
        import psutil  # Optional; absent from requirements.txt by design
        fingerprint['total_ram_bytes'] = psutil.virtual_memory().total
    except ImportError:
        fingerprint['total_ram_bytes'] = None
        fingerprint['total_ram_note'] = 'psutil not installed; not added to requirements.txt'

    return fingerprint


def git_commit(worktree):
    """
    Records exactly which commit a run measured.

    @param worktree: the tree being measured
    @return: a dict with the resolved SHA and whether the tree was dirty
    """
    sha = _command_output(['git', '-C', worktree, 'rev-parse', 'HEAD'])
    status = subprocess.run(['git', '-C', worktree, 'status', '--porcelain'],
                            stdout=subprocess.PIPE, universal_newlines=True)
    tracked = [ln for ln in (status.stdout or '').splitlines() if not ln.startswith('??')]
    return {'commit': sha, 'dirty_tracked_files': tracked, 'clean': not tracked}


def assert_worktree_clean(worktree, context):
    """
    Fails loudly if a run left tracked modifications behind.

    Checked per cell rather than once at the end, so the offending cell is
    identifiable instead of merely knowing that something, somewhere, dirtied
    the baseline.

    @param worktree: the tree being measured
    @param context: a label for the error message
    @raise RuntimeError: if tracked files are modified
    """
    state = git_commit(worktree)
    if not state['clean']:
        raise RuntimeError('Baseline worktree has tracked modifications after {}: {}. '
                           'The baseline tree must never be modified.'
                           .format(context, state['dirty_tracked_files']))


def restore_tracked_side_effects(worktree):
    """
    Restores tracked files a run rewrites in place.

    `flexfringe.log` is committed to the repo and FlexFringe overwrites it on
    every invocation, so without this every cell leaves the worktree dirty.

    @param worktree: the tree being measured
    @return: the list of files restored
    """
    restored = []
    for filename in _TRACKED_SIDE_EFFECTS:
        if os.path.exists(os.path.join(worktree, filename)):
            subprocess.run(['git', '-C', worktree, 'checkout', '--', filename],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            restored.append(filename)
    return restored


def build_argv(dataset_path, experiment_name, dataset_flag, filter_window=None,
               aggregation_window=None, timerange=None):
    """
    Builds the SAGE command line for one cell.

    `--keep-files` is always passed: the `.dot` attack graphs and the model JSONs
    are deleted without it, and every structural metric is derived from them.

    @param dataset_path: the alerts directory
    @param experiment_name: a bare name (no path separators -- see module docstring)
    @param dataset_flag: 'cptc' or 'other'
    @param filter_window: the `-t` value, or None for SAGE's default
    @param aggregation_window: the `-w` value, or None for SAGE's default
    @param timerange: an optional (start_hour, end_hour) pair
    @return: the argv list
    @raise ValueError: if the experiment name contains a path separator
    """
    if os.sep in experiment_name or '/' in experiment_name:
        raise ValueError(
            'experiment_name must be a bare name, got {!r}. plotting.py writes '
            "'data_histogram-' + experiment_name, so a separator here makes the run fail "
            'on a missing directory.'.format(experiment_name))

    argv = [sys.executable, 'sage.py', dataset_path, experiment_name,
            '--dataset', dataset_flag, '--keep-files']
    if filter_window is not None:
        argv += ['-t', str(filter_window)]
    if aggregation_window is not None:
        argv += ['-w', str(aggregation_window)]
    if timerange is not None:
        argv += ['--timerange', str(timerange[0]), str(timerange[1])]
    return argv


def run_sage(argv, worktree, shim_directory=None, env_overrides=None):
    """
    Executes one SAGE run, timestamping its stdout to recover per-stage runtime.

    @param argv: the command line from `build_argv`
    @param worktree: the tree to run in; must be the SAGE root, since FlexFringe is
        resolved as the relative path 'FlexFringe/flexfringe'
    @param shim_directory: the PYTHONPATH entry holding the pinned-IANA sitecustomize
    @param env_overrides: extra environment variables
    @return: a dict with the exit code, wall-clock time, per-stage timings and the log
    """
    environment = dict(os.environ)
    environment['PYTHONHASHSEED'] = '0'      # See module docstring
    environment['PYTHONUNBUFFERED'] = '1'    # So stage banners arrive as they happen
    if shim_directory:
        existing = environment.get('PYTHONPATH')
        environment['PYTHONPATH'] = (shim_directory + os.pathsep + existing
                                     if existing else shim_directory)
    environment.update(env_overrides or {})

    started = time.time()
    process = subprocess.Popen(argv, cwd=worktree, env=environment, stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT, universal_newlines=True, bufsize=1)

    log, stages, current = [], [], None
    for line in process.stdout:
        now = time.time()
        log.append({'t': round(now - started, 3), 'line': line.rstrip('\n')})
        banner = _BANNER.match(line.strip())
        if banner:
            if current:
                current['ended'] = round(now - started, 3)
                current['seconds'] = round(current['ended'] - current['started'], 3)
                stages.append(current)
            current = {'stage': banner.group('stage').strip(),
                       'started': round(now - started, 3)}
    process.wait()
    finished = time.time()
    if current:
        current['ended'] = round(finished - started, 3)
        current['seconds'] = round(current['ended'] - current['started'], 3)
        stages.append(current)

    total = round(finished - started, 3)
    return {
        'argv': argv,
        'exit_code': process.returncode,
        'wall_clock_seconds': total,
        'stages': _roll_up_stages(stages, total),
        'raw_banners': stages,
        'log': log,
        'pythonhashseed': '0',
    }


def harvest(worktree, experiment_name, destination):
    """
    Moves a run's artifacts out of the worktree into the cell's output directory.

    Artifacts must be produced in the worktree root (see module docstring), so
    moving them out is what keeps the baseline tree clean and stops the next cell
    from reading a previous cell's leftovers.

    @param worktree: the tree the run was made in
    @param experiment_name: the bare experiment name used for the run
    @param destination: the cell's output directory
    @return: a dict of artifact name -> harvested path
    @raise FileNotFoundError: if the trace file or AG directory is missing, which
        means the run did not complete
    """
    os.makedirs(destination, exist_ok=True)
    harvested = {}

    for suffix in _ARTIFACT_SUFFIXES:
        source = os.path.join(worktree, experiment_name + suffix)
        if os.path.exists(source):
            target = os.path.join(destination, experiment_name + suffix)
            shutil.move(source, target)
            harvested[suffix] = target

    histogram = os.path.join(worktree, 'data_histogram-' + experiment_name + '.png')
    if os.path.exists(histogram):
        target = os.path.join(destination, os.path.basename(histogram))
        shutil.move(histogram, target)
        harvested['histogram'] = target

    ag_source = os.path.join(worktree, experiment_name + 'AGs')
    if os.path.isdir(ag_source):
        target = os.path.join(destination, experiment_name + 'AGs')
        if os.path.isdir(target):
            shutil.rmtree(target)
        shutil.move(ag_source, target)
        harvested['ag_directory'] = target

    if '.txt' not in harvested:
        raise FileNotFoundError(
            'Run produced no trace file ({}.txt) in {}. The run did not complete.'
            .format(experiment_name, worktree))
    if 'ag_directory' not in harvested:
        raise FileNotFoundError(
            'Run produced no {}AGs directory in {}. Was --keep-files passed?'
            .format(experiment_name, worktree))

    return harvested


def cell_is_complete(output_directory, expected_cell=None):
    """
    Reports whether a cell already finished *with the requested configuration*.

    Resuming on the name alone is not safe. Two different configurations can map
    to the same cell name -- a `check` run against a perturbed alert corpus and a
    `run` reference cell both being '<dataset>-reference', for instance -- and the
    second then silently reuses the first's artifacts and reports another run's
    numbers as its own. So the stored spec is compared against the requested one
    and a mismatch counts as incomplete.

    @param output_directory: the cell's output directory
    @param expected_cell: the cell spec being requested; when given, a stored cell
        whose spec differs is treated as not complete
    @return: True only if a successful cell with a matching spec is present
    """
    marker = os.path.join(output_directory, _COMPLETED_MARKER)
    if not os.path.exists(marker):
        return False
    try:
        with open(marker, encoding='utf-8') as handle:
            stored = json.load(handle)
    except (ValueError, OSError):
        return False
    if stored.get('exit_code') != 0:
        return False
    if expected_cell is not None and stored.get('cell') != expected_cell:
        return False
    return True


def execute_cell(cell, worktree, output_root, iana, shim_directory, force=False):
    """
    Runs one matrix cell end to end: execute, harvest, restore, verify, record.

    @param cell: a dict with 'name', 'dataset_path', 'dataset_flag' and optionally
        't', 'w', 'timerange'
    @param worktree: the SAGE tree to measure
    @param output_root: the directory holding all cells
    @param iana: the pinned-CSV record from `snapshot_iana`
    @param shim_directory: the PYTHONPATH entry from `write_iana_shim`
    @param force: re-run even if the cell is already complete
    @return: the cell record
    @raise RuntimeError: if the pinned CSV changed, or the worktree was dirtied
    """
    output_directory = os.path.join(output_root, cell['name'])
    if not force and cell_is_complete(output_directory, expected_cell=cell):
        with open(os.path.join(output_directory, _COMPLETED_MARKER), encoding='utf-8') as handle:
            record = json.load(handle)
        record['skipped'] = 'already complete'
        return record

    # A mid-matrix change to the pinned CSV would silently split the run matrix
    # into two incomparable halves, so it is re-checked on every cell.
    current = _file_digest(iana['path'])
    if current != iana['sha256']:
        raise RuntimeError('The pinned IANA CSV changed mid-matrix ({} -> {}). Every cell '
                           'must see identical port-service data.'
                           .format(iana['sha256'], current))

    assert_worktree_clean(worktree, 'before cell {}'.format(cell['name']))
    measured_commit = git_commit(worktree)['commit']

    argv = build_argv(cell['dataset_path'], cell['name'], cell['dataset_flag'],
                      filter_window=cell.get('t'), aggregation_window=cell.get('w'),
                      timerange=cell.get('timerange'))
    result = run_sage(argv, worktree, shim_directory)

    record = {
        'name': cell['name'],
        'cell': cell,
        'exit_code': result['exit_code'],
        'wall_clock_seconds': result['wall_clock_seconds'],
        'stages': result['stages'],
        'raw_banners': result['raw_banners'],
        'pythonhashseed': result['pythonhashseed'],
        'argv': result['argv'],
        'worktree': os.path.abspath(worktree),
        # The commit measured. Cleanliness is recorded separately below, after
        # restoration -- capturing it here would report every cell as dirty,
        # since the run has just rewritten the tracked flexfringe.log.
        'measured_commit': measured_commit,
        'iana': iana,
        'finished_at': datetime.now(timezone.utc).isoformat(),
    }

    try:
        if result['exit_code'] == 0:
            record['artifacts'] = harvest(worktree, cell['name'], output_directory)
    finally:
        # Always restore and re-check, even when the run failed: a failed run can
        # still have rewritten flexfringe.log.
        record['restored_tracked_files'] = restore_tracked_side_effects(worktree)
        assert_worktree_clean(worktree, 'after cell {}'.format(cell['name']))
        record['worktree_clean_after_cell'] = True  # assert_worktree_clean would have raised

    os.makedirs(output_directory, exist_ok=True)
    with open(os.path.join(output_directory, 'stdout.log'), 'w', encoding='utf-8') as handle:
        for entry in result['log']:
            handle.write('[{:>9.3f}] {}\n'.format(entry['t'], entry['line']))
    with open(os.path.join(output_directory, _COMPLETED_MARKER), 'w', encoding='utf-8') as handle:
        json.dump(record, handle, indent=2)

    return record
