"""
Orchestrates the full SAGE pipeline: alerts -> episodes -> S-PDFA -> attack graphs.

This is the single reusable entry point for code that wants to run (or reuse
parts of) SAGE without going through the CLI in sage.py, e.g. Contribution A
(MITRE mapping, which consumes the `signatures` package and the per-episode
`mcat` values already flowing through this pipeline) and Contribution C
(a reusable evaluation module, which consumes `PipelineResult.state_sequences`
and `PipelineResult.severe_sinks`, the same inputs `ag_generation.make_attack_graphs`
uses).

Call `run_pipeline()` with a `PipelineConfig` to run the full pipeline; each
stage function (`load_alerts`, `build_episode_subsequences`, `learn_model`,
`generate_attack_graphs`) is also exported separately so callers can run a
subset of the pipeline (e.g. stop after model learning) or substitute their
own inputs at a given stage.
"""
import glob
import os
import subprocess
from dataclasses import dataclass, field
from typing import Any, Dict, List, Tuple

from ag_generation import make_attack_graphs
from alert_loading import load_iana_mapping, load_data, group_alerts_per_team
from episode_sequence_generation import aggregate_into_episodes, host_episode_sequences, break_into_subbehaviors
from model_learning import generate_traces, flexfringe, fix_flexfringe_output, load_model, encode_sequences
from plotting import plot_histogram


SAVE_AG = True


@dataclass
class PipelineConfig:
    """
    Explicit inputs for a full pipeline run, equivalent to sage.py's CLI arguments.
    """
    path_to_json_files: str
    experiment_name: str
    dataset_name: str = 'other'
    alert_filtering_window: float = 1.0
    alert_aggr_window: int = 150
    start_hour: int = 0
    end_hour: int = 100
    path_to_ini: str = "FlexFringe/ini/spdfa-config.ini"
    delete_files: bool = True
    save_ag: bool = SAVE_AG

    @property
    def path_to_traces(self):
        return self.experiment_name + '.txt'

    @property
    def ag_directory(self):
        return self.experiment_name + 'AGs'


@dataclass
class PipelineResult:
    """
    Explicit outputs of a full pipeline run.
    """
    port_services: Dict[int, Dict[str, str]]
    team_data: Dict[int, Any]
    team_episodes: Dict[Any, Any]
    episode_subsequences: Dict[str, List[Tuple]]
    main_model: Dict[str, Dict[str, str]]
    sinks_model: Dict[str, Dict[str, str]]
    state_sequences: Dict[str, List[Tuple]]
    severe_sinks: set
    path_to_traces: str
    ag_directory: str
    extra: Dict[str, Any] = field(default_factory=dict)


# Stage 1-3: load and group raw alerts
def load_alerts(config):
    """
    Loads the IANA port mapping and the raw alerts, and groups them per attacker-victim pair.

    @param config: a PipelineConfig
    @return: (port_services, team_alerts, team_labels, team_start_times, team_data)
    """
    print('------ Downloading the IANA port-service mapping ------')
    port_services = load_iana_mapping()

    print('------ Reading alerts ------')
    team_alerts, team_labels, team_start_times = load_data(
        config.path_to_json_files, config.alert_filtering_window, config.start_hour, config.end_hour,
        config.dataset_name)
    plot_histogram(team_alerts, team_labels, config.experiment_name)
    team_data = group_alerts_per_team(team_alerts, port_services, config.dataset_name)

    return port_services, team_alerts, team_labels, team_start_times, team_data


# Stage 4-5: turn grouped alerts into episode subsequences and write FlexFringe traces
def build_episode_subsequences(team_data, team_start_times, config):
    """
    Aggregates alerts into episodes, reorganises per host, and cuts into subsequences.

    @param team_data: alerts grouped by team and by (src_ip, dst_ip), from `load_alerts`
    @param team_start_times: the first alert timestamp per team, from `load_alerts`
    @param config: a PipelineConfig
    @return: (team_episodes, episode_subsequences)
    """
    print('------ Converting to episodes ------')
    team_episodes, _ = aggregate_into_episodes(team_data, team_start_times, step=config.alert_aggr_window)

    print('\n------ Converting to episode sequences ------')
    host_data = host_episode_sequences(team_episodes)

    print('------ Breaking into sub-sequences and generating traces ------')
    episode_subsequences = break_into_subbehaviors(host_data)

    return team_episodes, episode_subsequences


# Stage 6-8: learn the S-PDFA and traverse it to encode state sequences
def learn_model(episode_subsequences, config):
    """
    Generates FlexFringe traces, learns the S-PDFA, and encodes the traces into state sequences.
        Cleanly separable from attack graph generation: callers that only need the model or the
        state sequences (e.g. Contribution C's evaluation module) can stop here.

    @param episode_subsequences: the episode subsequences per attacker-victim pair, from `build_episode_subsequences`
    @param config: a PipelineConfig
    @return: (main_model, sinks_model, state_sequences, severe_sinks)
    """
    generate_traces(episode_subsequences, config.path_to_traces)

    print('------ Learning S-PDFA ------')
    flexfringe(config.path_to_traces, ini=config.path_to_ini, symbol_count="2", state_count="4")

    subprocess.run(["dot", "-Tpng", config.path_to_traces + ".ff.final.dot", "-o", config.path_to_traces + ".png"])

    print('------ !! Special: Fixing syntax error in main model and sink files ------')
    fix_flexfringe_output(config.path_to_traces)

    print('------ Loading and traversing S-PDFA ------')
    main_model = load_model(config.path_to_traces + ".ff.final.json")
    sinks_model = load_model(config.path_to_traces + ".ff.finalsinks.json")

    print('------ Encoding traces into state sequences ------')
    state_sequences, severe_sinks = encode_sequences(main_model, sinks_model, episode_subsequences)

    return main_model, sinks_model, state_sequences, severe_sinks


# Stage 9: render attack graphs from the state sequences
def generate_attack_graphs(state_sequences, severe_sinks, config):
    """
    Renders the attack graphs (.dot/.png/.svg) for each victim x high-severity objective.

    @param state_sequences: the state sequences per attacker-victim pair, from `learn_model`
    @param severe_sinks: the medium/high-severity sink states, from `learn_model`
    @param config: a PipelineConfig
    """
    print('------ Making alert-driven AGs ------')
    make_attack_graphs(state_sequences, severe_sinks, config.path_to_traces, config.ag_directory, config.save_ag)


def cleanup_intermediate_files(config):
    """
    Deletes FlexFringe's intermediate model/dot files and the AG directory's .dot files,
        keeping only the rendered .png/.svg attack graphs. Mirrors sage.py's `--keep-files` CLI flag.

    @param config: a PipelineConfig
    """
    print('Deleting extra files')
    for suffix in [".ff.final.dot", ".ff.final.json", ".ff.finalsinks.json", ".ff.finalsinks.dot",
                   ".ff.init.dot", ".ff.init.json", ".ff.initsinks.dot", ".ff.initsinks.json"]:
        try:
            os.remove(config.path_to_traces + suffix)
        except FileNotFoundError:
            pass
    for dot_file in glob.glob(config.ag_directory + "/*.dot"):
        try:
            os.remove(dot_file)
        except FileNotFoundError:
            pass


def run_pipeline(config):
    """
    Runs the full SAGE pipeline: alerts -> episodes -> S-PDFA -> attack graphs.

    @param config: a PipelineConfig
    @return: a PipelineResult with the outputs of every stage
    """
    port_services, team_alerts, team_labels, team_start_times, team_data = load_alerts(config)

    team_episodes, episode_subsequences = build_episode_subsequences(team_data, team_start_times, config)

    main_model, sinks_model, state_sequences, severe_sinks = learn_model(episode_subsequences, config)

    generate_attack_graphs(state_sequences, severe_sinks, config)

    if config.delete_files:
        cleanup_intermediate_files(config)

    return PipelineResult(
        port_services=port_services,
        team_data=team_data,
        team_episodes=team_episodes,
        episode_subsequences=episode_subsequences,
        main_model=main_model,
        sinks_model=sinks_model,
        state_sequences=state_sequences,
        severe_sinks=severe_sinks,
        path_to_traces=config.path_to_traces,
        ag_directory=config.ag_directory,
        extra={'team_alerts': team_alerts, 'team_labels': team_labels, 'team_start_times': team_start_times},
    )
