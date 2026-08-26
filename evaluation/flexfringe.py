"""
Invokes the FlexFringe binary directly, for held-out perplexity.

Held-out scoring needs a model that has never seen the test traces, which means
splitting at the trace level *before* learning and therefore a second FlexFringe
run producing a second model. `sage.py` offers no way to do that -- it always
learns from the traces it just generated -- so this module drives the binary
itself, replicating exactly the flags `model_learning.flexfringe` passes
(`--ini`, `--symbol_count=2`, `--state_count=4`) and the trailing-comma repair
`fix_flexfringe_output` applies afterwards.

Replicating rather than importing is deliberate: `model_learning` lives in the
tree being measured, and importing from it would couple the harness to a
particular commit's module layout -- the exact coupling this package exists to
avoid.
"""
import os
import platform
import re
import subprocess

DEFAULT_INI = 'FlexFringe/ini/spdfa-config.ini'
DEFAULT_SYMBOL_COUNT = '2'
DEFAULT_STATE_COUNT = '4'


def _win_to_wsl_path(path):
    """
    Converts a Windows path to its WSL equivalent.

    Mirrors `model_learning._win_to_wsl_path`: FlexFringe is a Linux ELF binary,
    so on Windows it runs under WSL and every path handed to it must be
    translated.

    @param path: a Windows path
    @return: the /mnt/<drive>/... equivalent
    """
    path = os.path.abspath(path)
    drive, rest = os.path.splitdrive(path)
    return '/mnt/' + drive[0].lower() + rest.replace('\\', '/')


def run(trace_path, worktree, ini=DEFAULT_INI, symbol_count=DEFAULT_SYMBOL_COUNT,
        state_count=DEFAULT_STATE_COUNT):
    """
    Learns an S-PDFA from a trace file.

    @param trace_path: the FlexFringe-format trace file to learn from
    @param worktree: the SAGE tree holding the FlexFringe binary and its ini
    @param ini: the config path, relative to the worktree
    @param symbol_count: FlexFringe's --symbol_count
    @param state_count: FlexFringe's --state_count
    @return: a dict with the argv, exit code and the produced model paths
    @raise RuntimeError: if FlexFringe produced no main model
    """
    ini_path = os.path.join(worktree, ini)
    binary = os.path.join(worktree, 'FlexFringe', 'flexfringe')

    if platform.system() == 'Windows':
        argv = ['wsl', '-d', 'Ubuntu', _win_to_wsl_path(binary),
                '--ini=' + _win_to_wsl_path(ini_path),
                '--symbol_count=' + symbol_count,
                '--state_count=' + state_count,
                _win_to_wsl_path(trace_path)]
    else:
        argv = [binary, '--ini=' + ini_path,
                '--symbol_count=' + symbol_count,
                '--state_count=' + state_count,
                trace_path]

    # Run with cwd in the scratch directory, not the worktree: FlexFringe writes
    # flexfringe.log into its working directory, and that file is *tracked* in the
    # SAGE repo, so running from the worktree dirties the baseline tree on every
    # invocation. Every path handed to the binary is absolute, so cwd is free.
    result = subprocess.run(argv, cwd=os.path.dirname(os.path.abspath(trace_path)),
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            universal_newlines=True)

    main_model = trace_path + '.ff.final.json'
    sinks_model = trace_path + '.ff.finalsinks.json'
    for path in (sinks_model, main_model):
        if os.path.exists(path):
            fix_trailing_commas(path)

    if not os.path.exists(main_model):
        raise RuntimeError(
            'FlexFringe produced no model for {} (exit {}). Output:\n{}'
            .format(trace_path, result.returncode, (result.stdout or '')[-2000:]))

    return {'argv': argv, 'exit_code': result.returncode, 'stdout': result.stdout,
            'main_model': main_model, 'sinks_model': sinks_model}


def fix_trailing_commas(json_file):
    """
    Strips the spurious trailing commas FlexFringe can emit before a closing `]}`.

    Replicates `model_learning._fix_json_trailing_commas`; without it the model
    files are not valid JSON and cannot be loaded at all.

    @param json_file: the model file to repair in place
    """
    with open(json_file, 'r', encoding='utf-8') as handle:
        data = handle.read()
    stripped = re.sub(r'[\s+]', '', data)
    extra = re.search(r'(}(,+)]}$)', stripped)
    if extra is not None:
        count = extra.group(0).count(',')
        with open(json_file, 'w', encoding='utf-8') as handle:
            handle.write(''.join(data.rsplit(',', count)))
