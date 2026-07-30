import argparse
import glob
import os
import platform
import re
import shutil
import subprocess

if platform.system() == 'Windows' and shutil.which('dot') is None:
    _graphviz_bin = r'C:\Program Files\Graphviz\bin'
    if os.path.isdir(_graphviz_bin):
        os.environ['PATH'] = _graphviz_bin + os.pathsep + os.environ.get('PATH', '')

from ag_generation import make_attack_graphs
from alert_loading import load_iana_mapping, load_data, group_alerts_per_team
from episode_sequence_generation import aggregate_into_episodes, host_episode_sequences, break_into_subbehaviors
from model_learning import generate_traces, flexfringe, load_model, encode_sequences
from plotting import plot_histogram


SAVE_AG = True


# ----- MAIN ------
parser = argparse.ArgumentParser(description='SAGE: Intrusion Alert-Driven Attack Graph Extractor.')
parser.add_argument('path_to_json_files', type=str, help='Directory containing intrusion alerts in json format. sample-input.json provides an example of the accepted file format')
parser.add_argument('experiment_name', type=str, help='Custom name for all artefacts')
parser.add_argument('-t', type=float, required=False, default=1.0, help='Time window in which duplicate alerts are discarded (default: 1.0 sec)')
parser.add_argument('-w', type=int, required=False, default=150, help='Aggregate alerts occuring in this window as one episode (default: 150 sec)')
parser.add_argument('--timerange', type=int, nargs=2, required=False, default=[0, 100], metavar=('STARTRANGE', 'ENDRANGE'), help='Filtering alerts. Only parsing from and to the specified hours, relative to the start of the alert capture (default: (0, 100))')
parser.add_argument('--dataset', required=False, type=str, choices=['cptc', 'other'], default='other', help='The name of the dataset with the alerts (default: other)')
parser.add_argument('--keep-files', action='store_true', help='Do not delete the dot files after the program ends')
args = parser.parse_args()

path_to_json_files = args.path_to_json_files
experiment_name = args.experiment_name
alert_filtering_window = args.t
alert_aggr_window = args.w
start_hour, end_hour = args.timerange
dataset_name = args.dataset
delete_files = not args.keep_files

path_to_ini = "FlexFringe/ini/spdfa-config.ini"

path_to_traces = experiment_name + '.txt'
ag_directory = experiment_name + 'AGs'

print('------ Downloading the IANA port-service mapping ------')
port_services = load_iana_mapping()

print('------ Reading alerts ------')
team_alerts, team_labels, team_start_times = load_data(
    path_to_json_files, alert_filtering_window, start_hour, end_hour, dataset_name)
plot_histogram(team_alerts, team_labels, experiment_name)
team_data = group_alerts_per_team(team_alerts, port_services, dataset_name)

print('------ Converting to episodes ------')
team_episodes, _ = aggregate_into_episodes(team_data, team_start_times, step=alert_aggr_window)

print('\n------ Converting to episode sequences ------')
host_data = host_episode_sequences(team_episodes)

print('------ Breaking into sub-sequences and generating traces ------')
episode_subsequences = break_into_subbehaviors(host_data)
episode_traces = generate_traces(episode_subsequences, path_to_traces)


print('------ Learning S-PDFA ------')
flexfringe(path_to_traces, ini=path_to_ini, symbol_count="2", state_count="4")

subprocess.run(["dot", "-Tpng", path_to_traces + ".ff.final.dot", "-o", path_to_traces + ".png"])

print('------ !! Special: Fixing syntax error in main model and sink files ------')
print('--- Sinks')
with open(path_to_traces + ".ff.finalsinks.json", 'r') as file:
    filedata = file.read()
stripped = re.sub(r'[\s+]', '', filedata)
extra_commas = re.search(r'(}(,+)]}$)', stripped)
if extra_commas is not None:
    comma_count = (extra_commas.group(0)).count(',')
    print(extra_commas.group(0), comma_count)
    filedata = ''.join(filedata.rsplit(',', comma_count))
    with open(path_to_traces + ".ff.finalsinks.json", 'w') as file:
        file.write(filedata)

print('--- Main')
with open(path_to_traces + ".ff.final.json", 'r') as file:
    filedata = file.read()
stripped = re.sub(r'[\s+]', '', filedata)
extra_commas = re.search(r'(}(,+)]}$)', stripped)
if extra_commas is not None:
    comma_count = (extra_commas.group(0)).count(',')
    print(extra_commas.group(0), comma_count)
    filedata = ''.join(filedata.rsplit(',', comma_count))
    with open(path_to_traces + ".ff.final.json", 'w') as file:
        file.write(filedata)

print('------ Loading and traversing S-PDFA ------')
main_model = load_model(path_to_traces + ".ff.final.json")
sinks_model = load_model(path_to_traces + ".ff.finalsinks.json")

print('------ Encoding traces into state sequences ------')
state_sequences, severe_sinks = encode_sequences(main_model, sinks_model, episode_subsequences)

# print('------ Clustering state groups ------')
# state_groups = plot_state_groups(state_sequences, path_to_traces)

print('------ Making alert-driven AGs ------')
make_attack_graphs(state_sequences, severe_sinks, path_to_traces, ag_directory, SAVE_AG)

if delete_files:
    print('Deleting extra files')
    for suffix in [".ff.final.dot", ".ff.final.json", ".ff.finalsinks.json", ".ff.finalsinks.dot",
                   ".ff.init.dot", ".ff.init.json", ".ff.initsinks.dot", ".ff.initsinks.json"]:
        try:
            os.remove(path_to_traces + suffix)
        except FileNotFoundError:
            pass
    for dot_file in glob.glob(ag_directory + "/*.dot"):
        try:
            os.remove(dot_file)
        except FileNotFoundError:
            pass

print('\n------- FIN -------')
# ----- END MAIN ------
