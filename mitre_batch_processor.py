"""Build a deterministic Suricata SID-to-MITRE table and map alert batches."""
import argparse
import csv
import json
import re
from pathlib import Path

UNKNOWN = "Unknown"
TECHNIQUE_DICTIONARY_FILE = Path(__file__).with_name("mitre_technique_dictionary.json")
TACTICS = (
    "Reconnaissance", "Resource Development", "Initial Access", "Execution",
    "Persistence", "Privilege Escalation", "Defense Evasion", "Impair Defenses",
    "Credential Access", "Discovery", "Lateral Movement", "Collection",
    "Command and Control", "Exfiltration", "Impact",
)

# Ordered from specific to general so a precise behavior wins deterministically.
SIGNATURE_RULES = (
    (re.compile(r"eternalblue|ms17-010", re.I), ("T1210", UNKNOWN, "Lateral Movement", "Exploitation of Remote Services")),
    (re.compile(r"scheduled job|scheduled task", re.I), ("T1053.005", "Scheduled Task/Job: Scheduled Task", "Persistence", "Remote or local scheduled task activity")),
    (re.compile(r"powershell", re.I), ("T1059.001", "Command and Scripting Interpreter: PowerShell", "Execution", "PowerShell activity detected")),
    (re.compile(r"cmd\.exe|/bin/sh|bash shell|shell command|command injection|wscript\.shell", re.I), ("T1059", "Command and Scripting Interpreter", "Execution", "Shell or command interpreter activity detected")),
    (re.compile(r"webshell|web shell", re.I), ("T1505.003", "Server Software Component: Web Shell", "Persistence", "Web shell access or delivery detected")),
    (re.compile(r"sql injection|sqli|sqlmap", re.I), ("T1190", UNKNOWN, "Initial Access", "SQL injection or SQL injection tooling detected")),
    (re.compile(r"cve-|exploit|rce|remote code execution|overflow|shellshock", re.I), ("T1190", UNKNOWN, "Initial Access", "Exploit attempt detected")),
    (re.compile(r"brute.?force|login failures|hydra", re.I), ("T1110", UNKNOWN, "Credential Access", "Credential guessing or brute-force activity detected")),
    (re.compile(r"cleartext|unencrypted.*password|password.*unencrypted|passwd=|pass=|pwd=", re.I), ("T1552.001", "Unsecured Credentials: Credentials In Files", "Credential Access", "Credentials observed in an unsecured form")),
    (re.compile(r"file download|executable.*transfer|executable.*download|payload.*download|\.exe|\.dll|\.ps1", re.I), ("T1105", "Ingress Tool Transfer", "Command and Control", "Executable or payload transfer detected")),
    (re.compile(r"port scan|scan|nmap|nessus|masscan|dirbuster|nikto|openvas|scanner|probe", re.I), ("T1046", "Network Service Scanning", "Discovery", "Network or service scanning detected")),
    (re.compile(r"dns query|dns lookup|dns response|\.onion|\bc2\b|cnc|checkin", re.I), ("T1071.004", "Application Layer Protocol: DNS", "Command and Control", "DNS-based or beaconing communication detected")),
    (re.compile(r"tor", re.I), ("T1090.003", "Proxy: Multi-hop Proxy", "Command and Control", "Tor relay or exit traffic detected")),
)


def load_technique_dictionary(path=TECHNIQUE_DICTIONARY_FILE):
    with Path(path).open(encoding="utf-8") as handle:
        data = json.load(handle)
    return {entry["technique_id"]: entry for entry in data["techniques"]}


def _dictionary_match(text, techniques):
    normalized = re.sub(r"[^a-z0-9]+", " ", text.lower()).strip()
    for technique_id in sorted(techniques):
        entry = techniques[technique_id]
        for keyword in entry["detection_keywords"]:
            if keyword and (" " in keyword and keyword in normalized):
                return entry
    return None

CATEGORY_TACTICS = (
    (re.compile(r"privilege gain|user privilege|administrator", re.I), "Privilege Escalation"),
    (re.compile(r"information leak|information disclosure|suspicious filename", re.I), "Discovery"),
    (re.compile(r"web application attack|potentially bad traffic|exploit", re.I), "Initial Access"),
    (re.compile(r"denial of service|dos|resource", re.I), "Impact"),
    (re.compile(r"trojan|malware|network.*trojan|command", re.I), "Command and Control"),
)


def _raw_alert(item):
    if isinstance(item, dict) and isinstance(item.get("result"), dict) and "_raw" in item["result"]:
        return json.loads(item["result"]["_raw"])
    if isinstance(item, dict) and "_raw" in item:
        return json.loads(item["_raw"])
    return item


def _alert_fields(item):
    raw = _raw_alert(item)
    nested = raw.get("alert", {}) if isinstance(raw, dict) else {}
    return {
        "sid": nested.get("signature_id", raw.get("signature_id")),
        "signature": nested.get("signature", raw.get("signature", "")),
        "classtype": nested.get("classtype", raw.get("classtype", "")),
        "category": nested.get("category", raw.get("category", "")),
        "metadata": nested.get("metadata", raw.get("metadata", {})),
        "references": nested.get("references", raw.get("references", [])),
    }


def _metadata_text(metadata, references):
    values = []
    if isinstance(metadata, dict):
        values.extend(str(value) for value in metadata.values())
    elif isinstance(metadata, list):
        values.extend(str(value) for value in metadata)
    elif metadata:
        values.append(str(metadata))
    if isinstance(references, list):
        values.extend(str(value) for value in references)
    elif references:
        values.append(str(references))
    return " ".join(values)


def _normalise_metadata(metadata, signature):
    if isinstance(metadata, dict):
        result = dict(metadata)
    elif metadata:
        result = {"value": metadata}
    else:
        result = {}
    cves = sorted(set(re.findall(r"CVE-\d{4}-\d{4,7}", signature, re.I)))
    if cves:
        result["cves"] = cves
    return result


def classify(signature, category="", metadata=None, references=None):
    text = " ".join(filter(None, (signature, _metadata_text(metadata or {}, references or []))))
    technique_id_match = re.search(r"\bT\d{4}\b", text, re.I)
    techniques = load_technique_dictionary() if TECHNIQUE_DICTIONARY_FILE.exists() else {}
    if technique_id_match and technique_id_match.group(0).upper() in techniques:
        entry = techniques[technique_id_match.group(0).upper()]
        return {"mitre_technique": entry["technique_id"], "mitre_subtechnique": UNKNOWN, "tactic": entry["tactic"], "behaviour_summary": entry["short_description"], "confidence": "high"}
    for pattern, result in SIGNATURE_RULES:
        if pattern.search(text):
            technique, subtechnique, tactic, summary = result
            return {"mitre_technique": technique, "mitre_subtechnique": subtechnique, "tactic": tactic, "behaviour_summary": summary, "confidence": "high" if metadata or signature else "medium"}
    entry = _dictionary_match(text, techniques)
    if entry:
        return {"mitre_technique": entry["technique_id"], "mitre_subtechnique": UNKNOWN, "tactic": entry["tactic"], "behaviour_summary": entry["short_description"], "confidence": "medium"}
    for pattern, tactic in CATEGORY_TACTICS:
        if pattern.search(category):
            return {"mitre_technique": UNKNOWN, "mitre_subtechnique": UNKNOWN, "tactic": tactic, "behaviour_summary": "Category indicates suspicious activity; technique is undetermined", "confidence": "Low"}
    return {"mitre_technique": UNKNOWN, "mitre_subtechnique": UNKNOWN, "tactic": UNKNOWN, "behaviour_summary": "No deterministic MITRE technique match", "confidence": "Low"}


def build_technique_dictionary(path):
    sections = [[] for _ in TACTICS]
    section_index = 0
    saw_entry = False
    for line in Path(path).read_text(encoding="utf-8-sig").splitlines():
        stripped = line.strip()
        if not stripped:
            if saw_entry and section_index < len(TACTICS) - 1:
                section_index += 1
                saw_entry = False
            continue
        match = re.match(r"^(T\d{4})\s+(.+)$", stripped)
        if match:
            sections[section_index].append((match.group(1), match.group(2)))
            saw_entry = True
    entries = {}
    for index, section in enumerate(sections):
        for technique_id, name in section:
            if technique_id in entries:
                continue
            keywords = [re.sub(r"[^a-z0-9]+", " ", name.lower()).strip()]
            entries[technique_id] = {"technique_id": technique_id, "technique_name": name, "tactic": TACTICS[index], "short_description": "Activity associated with " + name, "detection_keywords": list(dict.fromkeys(keywords))}
    return {"schema_version": 1, "source": str(path), "techniques": [entries[key] for key in sorted(entries)]}


def _iter_alert_items(path):
    suffix = path.suffix.lower()
    if suffix == ".jsonl":
        with path.open(encoding="utf-8-sig") as handle:
            for line in handle:
                if line.strip():
                    yield json.loads(line)
    elif suffix == ".csv":
        with path.open(newline="", encoding="utf-8-sig") as handle:
            yield from csv.DictReader(handle)
    else:
        with path.open(encoding="utf-8-sig") as handle:
            data = json.load(handle)
        yield from (data if isinstance(data, list) else [data])


def build_mapping(input_root):
    root = Path(input_root)
    rows = {}
    rule_files = sorted(path for path in root.rglob("*") if path.is_file() and path.suffix.lower() in {".rules", ".rule"})
    alert_files = sorted(path for path in root.rglob("*.json") if "mitre_mapping.json" not in path.name)
    for path in alert_files:
        try:
            items = _iter_alert_items(path)
            for item in items:
                fields = _alert_fields(item)
                sid = fields["sid"]
                if sid is None:
                    continue
                sid = str(sid)
                classification = classify(fields["signature"], fields["category"], fields["metadata"], fields["references"])
                rows[sid] = {"sid": sid, "signature": fields["signature"], "classtype": fields["classtype"], "category": fields["category"], "metadata": _normalise_metadata(fields["metadata"], fields["signature"]), "references": fields["references"], **classification}
        except (OSError, ValueError, json.JSONDecodeError):
            continue
    # Rule parsing is intentionally limited to standard msg/sid/classtype/references fields.
    for path in rule_files:
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            if not line.lstrip().startswith("alert "):
                continue
            sid_match = re.search(r"\bsid\s*:\s*(\d+)", line)
            msg_match = re.search(r'\bmsg\s*:\s*"([^"]*)"', line)
            if not sid_match:
                continue
            sid = sid_match.group(1)
            signature = msg_match.group(1) if msg_match else ""
            category_match = re.search(r"\bclasstype\s*:\s*([^;\s]+)", line)
            category = category_match.group(1) if category_match else ""
            metadata_match = re.search(r"\bmetadata\s*:\s*([^;]+)", line)
            references = re.findall(r"\breference\s*:\s*([^;]+)", line)
            metadata = {"values": [value.strip() for value in metadata_match.group(1).split(",")]} if metadata_match else {}
            rows.setdefault(sid, {"sid": sid, "signature": signature, "classtype": category, "category": category, "metadata": _normalise_metadata(metadata, signature), "references": references, **classify(signature, category, metadata, references)})
    return {"schema_version": 1, "source": "repository alert JSON and Suricata rule files", "entries": [rows[sid] for sid in sorted(rows, key=lambda value: int(value) if value.isdigit() else value)]}


def load_mapping(path):
    with Path(path).open(encoding="utf-8") as handle:
        data = json.load(handle)
    return {str(entry["sid"]): entry for entry in data.get("entries", data if isinstance(data, list) else [])}


def process_alerts(input_path, mapping_path, output_path, limit=None):
    mapping = load_mapping(mapping_path)
    output = []
    unknown_output = []
    for index, item in enumerate(_iter_alert_items(Path(input_path))):
        if limit is not None and index >= limit:
            break
        fields = _alert_fields(item)
        sid = None if fields["sid"] in (None, "") else str(fields["sid"])
        result = mapping.get(sid) if sid else None
        if result is None:
            result = {"sid": sid or UNKNOWN, "signature": fields["signature"], "category": fields["category"], **classify(fields["signature"], fields["category"], fields["metadata"], fields["references"])}
        action = "Investigate and contain" if result["mitre_technique"] != UNKNOWN else "Review alert context and signature definition"
        mapped_alert = {"sid": result["sid"], "signature": fields["signature"] or result.get("signature", ""), "mitre_technique": result["mitre_technique"], "mitre_subtechnique": result["mitre_subtechnique"], "tactic": result["tactic"], "behaviour_summary": result["behaviour_summary"], "recommended_action": action, "confidence": result["confidence"]}
        output.append(mapped_alert)
        if result["mitre_technique"] == UNKNOWN:
            unknown_output.append(mapped_alert)

    def write_output(path, records):
        with path.open("w", encoding="utf-8", newline="") as handle:
            if path.suffix.lower() == ".jsonl":
                for record in records:
                    handle.write(json.dumps(record, sort_keys=True) + "\n")
            elif path.suffix.lower() == ".csv":
                writer = csv.DictWriter(handle, fieldnames=list(records[0]) if records else ["sid"])
                writer.writeheader()
                writer.writerows(records)
            else:
                json.dump(records, handle, indent=2)
                handle.write("\n")

    output_path = Path(output_path)
    write_output(output_path, output)
    unknown_path = output_path.with_name(output_path.stem + "_UnKMappings" + output_path.suffix)
    write_output(unknown_path, unknown_output)


def main():
    parser = argparse.ArgumentParser(description="Build a SID-to-MITRE mapping or process Suricata alerts.")
    subparsers = parser.add_subparsers(dest="command", required=True)
    build = subparsers.add_parser("build-mapping")
    build.add_argument("input_root", type=Path)
    build.add_argument("output", type=Path)
    techniques = subparsers.add_parser("build-techniques")
    techniques.add_argument("input", type=Path)
    techniques.add_argument("output", type=Path)
    process = subparsers.add_parser("process")
    process.add_argument("input", type=Path)
    process.add_argument("mapping", type=Path)
    process.add_argument("output", type=Path)
    process.add_argument("--limit", type=int, default=None, help="process only the first N alerts")
    args = parser.parse_args()
    if args.command == "build-mapping":
        with args.output.open("w", encoding="utf-8") as handle:
            json.dump(build_mapping(args.input_root), handle, indent=2)
    elif args.command == "build-techniques":
        with args.output.open("w", encoding="utf-8") as handle:
            json.dump(build_technique_dictionary(args.input), handle, indent=2)
    else:
        process_alerts(args.input, args.mapping, args.output, limit=args.limit)


if __name__ == "__main__":
    main()
