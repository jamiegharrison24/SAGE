"""
SAGE CLI: Intrusion Alert-driven Attack Graph Extractor.

Thin command-line wrapper over `pipeline.run_pipeline()`. All pipeline logic
lives in `pipeline.py` and the stage modules it orchestrates
(`alert_loading.py`, `episode_sequence_generation.py`, `model_learning.py`,
`ag_generation.py`) -- import `pipeline` directly to reuse the pipeline
without going through this CLI.
"""
import argparse
import os
import platform
import shutil

if platform.system() == 'Windows' and shutil.which('dot') is None:
    _graphviz_bin = r'C:\Program Files\Graphviz\bin'
    if os.path.isdir(_graphviz_bin):
        os.environ['PATH'] = _graphviz_bin + os.pathsep + os.environ.get('PATH', '')

from pipeline import PipelineConfig, run_pipeline


def parse_args():
    parser = argparse.ArgumentParser(description='SAGE: Intrusion Alert-Driven Attack Graph Extractor.')
    parser.add_argument('path_to_json_files', type=str, help='Directory containing intrusion alerts in json format. sample-input.json provides an example of the accepted file format')
    parser.add_argument('experiment_name', type=str, help='Custom name for all artefacts')
    parser.add_argument('-t', type=float, required=False, default=1.0, help='Time window in which duplicate alerts are discarded (default: 1.0 sec)')
    parser.add_argument('-w', type=int, required=False, default=150, help='Aggregate alerts occuring in this window as one episode (default: 150 sec)')
    parser.add_argument('--timerange', type=int, nargs=2, required=False, default=[0, 100], metavar=('STARTRANGE', 'ENDRANGE'), help='Filtering alerts. Only parsing from and to the specified hours, relative to the start of the alert capture (default: (0, 100))')
    parser.add_argument('--dataset', required=False, type=str, choices=['cptc', 'other'], default='other', help='The name of the dataset with the alerts (default: other)')
    parser.add_argument('--keep-files', action='store_true', help='Do not delete the dot files after the program ends')
    return parser.parse_args()


def main():
    args = parse_args()

    config = PipelineConfig(
        path_to_json_files=args.path_to_json_files,
        experiment_name=args.experiment_name,
        dataset_name=args.dataset,
        alert_filtering_window=args.t,
        alert_aggr_window=args.w,
        start_hour=args.timerange[0],
        end_hour=args.timerange[1],
        delete_files=not args.keep_files,
    )

    run_pipeline(config)

    print('\n------- FIN -------')


if __name__ == '__main__':
    main()
