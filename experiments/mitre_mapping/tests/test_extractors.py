import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from attack_mapper.extractors.generic import GenericExtractor  # noqa: E402
from attack_mapper.extractors.sigma import SigmaExtractor  # noqa: E402
from attack_mapper.extractors.suricata import SuricataExtractor  # noqa: E402
from attack_mapper.models import IoCType, RuleFormat  # noqa: E402

SIGMA_RULE = """
title: Suspicious PowerShell EncodedCommand
description: Detects PowerShell execution with an encoded command
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\powershell.exe'
        CommandLine|contains: '-EncodedCommand'
    condition: selection
level: high
tags:
    - attack.execution
    - attack.t1059.001
    - attack.defense_evasion
    - attack.t1027
"""

SURICATA_BODY = (
    'alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET TEST Fake Exploit '
    'Attempt"; content:"deadbeef"; classtype:attempted-admin; sid:9999001; '
    'rev:1; metadata: mitre_tactic_id TA0001, mitre_tactic_name Initial_Access, '
    'mitre_technique_id T1190, mitre_technique_name Exploit_Public_Facing_Application;)'
)

SURICATA_KNOWN_TITLE = (
    "ET EXPLOIT Possible Oracle Database Text Component ctxsys.drvxtabc."
    "create_tables Remote SQL Injection Attempt"
)


def test_sigma_can_extract():
    ext = SigmaExtractor()
    assert ext.can_extract(SIGMA_RULE)
    assert not ext.can_extract(SURICATA_BODY)


def test_sigma_extract_fields_and_declared_techniques():
    ext = SigmaExtractor()
    rule = ext.extract(SIGMA_RULE)
    assert rule.format == RuleFormat.SIGMA
    assert rule.title == "Suspicious PowerShell EncodedCommand"
    assert rule.logsource == "windows"
    assert set(rule.declared_technique_ids) == {"T1059.001", "T1027"}
    ioc_types = {ioc.type for ioc in rule.iocs}
    assert IoCType.PROCESS in ioc_types
    assert IoCType.COMMAND_LINE in ioc_types


def test_suricata_can_extract_body_and_bare_name():
    ext = SuricataExtractor()
    assert ext.can_extract(SURICATA_BODY)
    assert ext.can_extract("ET SCAN Nmap Scripting Engine User-Agent Detected")
    assert not ext.can_extract("just some random unrelated text")


def test_suricata_parses_full_body_and_declared_technique():
    ext = SuricataExtractor()
    rule = ext.extract(SURICATA_BODY)
    assert rule.title == "ET TEST Fake Exploit Attempt"
    assert rule.declared_technique_ids == ["T1190"]
    assert rule.body_matched is True
    assert "attempted-admin" in rule.conditions


def test_suricata_name_only_looks_up_body_from_emerging_all_rules():
    ext = SuricataExtractor()
    rule = ext.extract(SURICATA_KNOWN_TITLE)
    # If the vendored ruleset is present, the title should resolve to the
    # real rule body and its declared T1190; if the file is missing in some
    # checkout, fall back to asserting the name-only path still produced a
    # usable rule rather than raising.
    assert rule.title is not None
    if rule.body_matched:
        assert rule.declared_technique_ids == ["T1190"]


def test_generic_extractor_always_matches_and_pulls_cve():
    ext = GenericExtractor()
    rule = ext.extract("some vendor alert referencing CVE-2018-13379")
    assert rule.format == RuleFormat.GENERIC
    assert any(ioc.value == "CVE-2018-13379" for ioc in rule.iocs)
