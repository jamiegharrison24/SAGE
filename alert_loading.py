"""
Stage 1-3 of the SAGE pipeline: loading raw Suricata alerts and grouping them
per attacker-victim pair.

Entry points:
    load_iana_mapping()   -- Step 0: download the IANA port-service mapping
    load_data()            -- Step 1: read, parse and de-duplicate alerts per team
    group_alerts_per_team() -- Step 3: group alerts by (attacker, victim) pair

All functions here are dataset-parameterised (`dataset_name` is passed
explicitly, not read from a module-level global) so they can be called
directly by other tooling (e.g. Contribution A's MITRE mapping) without
depending on sage.py's CLI state.
"""
import csv
import datetime
import glob
import json
import os
import sys

import requests

from plotting import plot_alert_filtering
from signatures.attack_stages import MicroAttackStage
from signatures.mappings import micro_inv
from signatures.alert_signatures import usual_mapping, unknown_mapping, ccdc_combined, attack_stage_mapping
from signatures import taxonomy


IANA_CSV_FILE = "https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.csv"
IANA_NUM_RETRIES = 5
IANA_TIMEOUT = 30  # Seconds to wait for the IANA download before giving up on an attempt
CPTC_BAD_IP = '169.254.169.254'


def _get_attack_stage_mapping(signature):
    """
    Infers the attack stage based on the alert signature.

    @param signature: the signature of the alert
    @return: the inferred attack stage
    """
    return taxonomy.signature_to_code(signature, _aif_attack_stage_mapping)


def _aif_attack_stage_mapping(signature):
    """The original AIF lookup, unchanged.

    Kept as its own function so `taxonomy.signature_to_code` can call it in
    AIF mode without importing this module (which would be a cycle), and so
    the AIF path stays byte-identical to what it was -- the ATT&CK comparison
    is only meaningful if the baseline arm is untouched.
    """
    result = MicroAttackStage.NON_MALICIOUS
    if signature in usual_mapping.keys():
        result = usual_mapping[signature]
    elif signature in unknown_mapping.keys():
        result = unknown_mapping[signature]
    elif signature in ccdc_combined.keys():
        result = ccdc_combined[signature]
    else:
        for k, v in attack_stage_mapping.items():
            if signature in v:
                result = k
                break
    return micro_inv[str(result)]


# Step 0: Download the IANA port-service mapping
def load_iana_mapping():
    """
    Downloads the IANA port-service mapping. In case of a failure or a timeout, retries IANA_NUM_RETRIES times.

    @return: a dictionary that maps a port to the corresponding service based on the IANA mapping
    """
    # Perform the first request and in case of a failure retry the specified number of times
    for attempt in range(IANA_NUM_RETRIES + 1):
        try:
            response = requests.get(IANA_CSV_FILE, timeout=IANA_TIMEOUT)
            succeeded = response.ok
        except requests.exceptions.RequestException:  # Covers the timeout promised by the docstring
            succeeded = False
        if succeeded:
            content = response.content.decode("utf-8")
            break
        elif attempt < IANA_NUM_RETRIES:
            print('Could not download IANA ports. Retrying...')
        else:
            raise RuntimeError('Cannot download IANA ports')
    table = csv.reader(content.splitlines())

    # Drop headers (service name, port, protocol, description, ...)
    next(table)

    # Note that ports might have holes
    ports = {}
    for row in table:
        # Drop missing port number, Unassigned and Reserved ports
        if row[1] and 'Unassigned' not in row[3]:  # and 'Reserved' not in row[3]:

            # Split range in single ports
            if '-' in row[1]:
                low_port, high_port = map(int, row[1].split('-'))
            else:
                low_port = high_port = int(row[1])

            for port in range(low_port, high_port + 1):
                ports[port] = {
                    "name": row[0] if row[0] else "unknown",
                    "description": row[3] if row[3] else "---",
                }
    return ports


def _readfile(fname):
    """
    Reads the file with the alerts.

    @param fname: the name of the file with the alerts
    @return: the unparsed alerts
    """
    with open(fname, 'r', encoding='utf-8-sig') as f:
        unparsed_data = json.load(f)

    unparsed_data = unparsed_data[::-1]  # Reverse the list, for chronological order
    return unparsed_data


# Step 1.1: Parse the input alerts
def _parse(unparsed_data, dataset_name):
    """
    Parses the alerts and converts them into the specific format:
        (diff_dt, src_ip, src_port, dst_ip, dst_port, sig, cat, host, dt, mcat).

    @param unparsed_data: the unparsed alerts
    @param dataset_name: the name of the dataset (e.g. 'cptc' or 'other'), used to filter out mistaken alerts
    @return: parsed alerts, sorted by the start time
    """
    parsed_data = []

    prev = -1
    for d in unparsed_data:
        if 'result' in d and '_raw' in d['result']:
            raw = json.loads(d['result']['_raw'])
        elif '_raw' in d:
            raw = json.loads(d['_raw'])
        else:
            raw = d

        # Filter out non-alert events
        if raw['event_type'] != 'alert':
            continue

        # Get the host name
        if 'host' in raw:
            host = raw['host']
        elif 'host' in d:
            host = d['host'][3:]
        else:
            host = 'dummy'

        # Get the timestamp
        # Convert the timestamp to a datetime object
        # Calculate the difference between the current and previous timestamp
        dt = datetime.datetime.strptime(raw['timestamp'], '%Y-%m-%dT%H:%M:%S.%f%z')  # 2018-11-03T23:16:09.148520+0000
        diff_dt = 0.0 if prev == -1 else round((dt - prev).total_seconds(), 2)
        prev = dt

        sig = raw['alert']['signature']
        cat = raw['alert']['category']

        src_ip = raw['src_ip']
        src_port = None if 'src_port' not in raw.keys() else raw['src_port']
        dst_ip = raw['dest_ip']
        dst_port = None if 'dest_port' not in raw.keys() else raw['dest_port']

        # Filter out mistaken alerts / uninteresting alerts
        if (dataset_name == 'cptc' and CPTC_BAD_IP in (src_ip, dst_ip)) or cat == 'Not Suspicious Traffic':
            continue

        mcat = _get_attack_stage_mapping(sig)
        parsed_data.append((diff_dt, src_ip, src_port, dst_ip, dst_port, sig, cat, host, dt, mcat))

    print('Reading # alerts: ', len(parsed_data))
    parsed_data = sorted(parsed_data, key=lambda al: al[8])  # Sort alerts into ascending order
    return parsed_data


# Step 1.2: Remove duplicate alerts (defined by the alert_filtering_window parameter)
def _remove_duplicates(unfiltered_alerts, plot=False, gap=1.0):
    """
    Removes the duplicate alerts, i.e. all alerts with identical attributes that occur within a gap (=1.0),
        keeping only the first occurrence, as defined in the paper.

    @param unfiltered_alerts: the parsed alerts that have not yet been filtered
    @param plot: whether to plot the alert frequencies per Micro Attack Stage before and after filtering
    @param gap: the filtering gap, i.e. alert filtering window (parameter `t` in the paper, default 1.0 sec)
    @return: the alerts without duplicates
    """
    filtered_alerts = [unfiltered_alerts[x] for x in range(1, len(unfiltered_alerts))
                       if unfiltered_alerts[x][9] != MicroAttackStage.NON_MALICIOUS.value  # Skip non-malicious alerts
                       and not (unfiltered_alerts[x][0] <= gap  # Diff from previous alert is less than gap sec
                                and unfiltered_alerts[x][1] == unfiltered_alerts[x - 1][1]  # Same srcIP
                                and unfiltered_alerts[x][3] == unfiltered_alerts[x - 1][3]  # Same destIP
                                and unfiltered_alerts[x][5] == unfiltered_alerts[x - 1][5]  # Same suricata signature
                                and unfiltered_alerts[x][2] == unfiltered_alerts[x - 1][2]  # Same srcPort
                                and unfiltered_alerts[x][4] == unfiltered_alerts[x - 1][4])]  # Same destPort
    if plot:
        plot_alert_filtering(unfiltered_alerts, filtered_alerts)

    print('Filtered # alerts (remaining):', len(filtered_alerts))
    return filtered_alerts


# Step 1: Read the input alerts
def load_data(path_to_alerts, filtering_window, start, end, dataset_name):
    """
    Reads the input alerts, parses them, removes duplicates, and groups them per attacker team.

    @param path_to_alerts: the path to the directory with the alerts
    @param filtering_window: filtering window (aka gap, aka t, default: 1.0)
    @param start: the start hour to limit alerts based on the user preferences (default: 0)
    @param end: the end hour to limit alerts based on the user preferences (default: 100)
    @param dataset_name: the name of the dataset (e.g. 'cptc' or 'other')
    @return: parsed and filtered alerts grouped by team, team labels and the first timestamp for each team
    """
    _team_alerts = []
    _team_labels = []
    _team_start_times = []  # Record the first alert just to get the real elapsed time (if the user filters (s,e) range)
    files = glob.glob(path_to_alerts + "/*.json")
    print('About to read json files...')
    if len(files) < 1:
        print('No alert files found.')
        sys.exit()
    for f in files:
        name = os.path.basename(f)[:-5]
        print(name)

        parsed_alerts = _parse(_readfile(f), dataset_name)
        parsed_alerts = _remove_duplicates(parsed_alerts, gap=filtering_window)

        # A team can be left with no alerts at all (e.g. all non-malicious, or all duplicates), in which case
        # there is no first alert to anchor the time range to. Skip the team entirely so that the three
        # per-team lists stay aligned with each other.
        if not parsed_alerts:
            print('No alerts left after filtering, skipping', name)
            continue

        _team_labels.append(name)

        # EXP: Limit alerts by timing is better than limiting volume because each team is on a different scale.
        # 50% alerts for one team end at a diff time than for others
        end_time_limit = 3600 * end       # Which hour to end at?
        start_time_limit = 3600 * start   # Which hour to start from?

        first_ts = parsed_alerts[0][8]
        _team_start_times.append(first_ts)

        filtered_alerts = [x for x in parsed_alerts if (((x[8] - first_ts).total_seconds() <= end_time_limit)
                                                        and ((x[8] - first_ts).total_seconds() >= start_time_limit))]
        _team_alerts.append(filtered_alerts)

    return _team_alerts, _team_labels, _team_start_times


def group_alerts_per_team(alerts, port_mapping, dataset_name):
    """
    Reorganises the alerts per team, for each attacker and victim pair.

    @param alerts: the parsed and filtered alerts, grouped by team
    @param port_mapping: the IANA port-service mapping
    @param dataset_name: the name of the dataset (e.g. 'cptc' or 'other')
    @return: alerts grouped by team and by (src_ip, dst_ip)
    """
    _team_data = dict()
    for tid, team in enumerate(alerts):
        host_alerts = dict()  # (attacker, victim) -> alerts

        for alert in team:
            # Alert format: (diff_dt, src_ip, src_port, dst_ip, dst_port, sig, cat, host, ts, mcat)
            src_ip, dst_ip, signature, ts, mcat = alert[1], alert[3], alert[5], alert[8], alert[9]
            dst_port = alert[4] if alert[4] is not None else 65000

            # Say 'unknown' if the port cannot be resolved
            if dst_port not in port_mapping.keys() or port_mapping[dst_port] == 'unknown':
                dst_port = 'unknown'
            else:
                dst_port = port_mapping[dst_port]['name']

            # For the CPTC dataset, attacker IPs (src_ip) start with '10.0.254', but this prefix might also be in dst_ip
            # TODO: for the future, we might want to address internal paths
            if dataset_name == 'cptc' and not src_ip.startswith('10.0.254') and not dst_ip.startswith('10.0.254'):
                continue
            # Swap src_ip and dst_ip, so that the prefix '10.0.254' is in src_ip
            if dataset_name == 'cptc' and dst_ip.startswith('10.0.254'):
                src_ip, dst_ip = dst_ip, src_ip

            if (src_ip, dst_ip) not in host_alerts.keys() and (dst_ip, src_ip) not in host_alerts.keys():
                host_alerts[(src_ip, dst_ip)] = []

            if (src_ip, dst_ip) in host_alerts.keys():  # TODO: remove the redundant host names
                host_alerts[(src_ip, dst_ip)].append((dst_ip, mcat, ts, dst_port, signature))
            else:
                host_alerts[(dst_ip, src_ip)].append((src_ip, mcat, ts, dst_port, signature))

        _team_data[tid] = host_alerts.items()
    return _team_data
