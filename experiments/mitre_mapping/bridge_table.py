"""
The 36-row MicroAttackStage -> MITRE ATT&CK bridge table from
B4_mitre_replacement_design.md section 2, transcribed verbatim (including its
confidence flags). This table must be authored independently of ATTACK-BERT
(it is -- it's hand-drafted in the design doc) so scoring against it is not
circular.

kind:
  "technique"  -- one or more real ATT&CK technique IDs (exact or a range)
  "tactic"     -- a tactic ID (TA0xxx), not a technique -- SAGE's own taxonomy
                  mixes granularities here (see design doc note under the table)
  "none"       -- sentinel / no-mapping / reject class

Sub-technique ranges (e.g. "T1566.001-T1566.003") are stored as a tuple
(start, end) under "range" and resolved against the live technique corpus in
validate_bridge.py -- do not hand-expand them here.
"""
from signatures.attack_stages import MicroAttackStage

# confidence markers from the design doc, kept as-is for the report
OK = "high"          # (was checkmark in the doc)
AMBIG = "ambiguous"   # (was warning-sign)
TACTIC = "tactic"     # (was diamond -- tactic-level, not technique-level)
NONE_ = "none"        # sentinel / no mapping / reject class
NEEDS_REVIEW = "needs_review"

BRIDGE_TABLE = {
    MicroAttackStage.INIT: {
        "kind": "none", "ids": [], "confidence": NONE_,
        "note": "sentinel value, not a real attack stage",
    },
    MicroAttackStage.TARGET_IDEN: {
        "kind": "technique", "ids": ["T1590"], "confidence": AMBIG,
        "note": "Gather Victim Network Information",
    },
    MicroAttackStage.SURFING: {
        "kind": "technique", "ids": ["T1595"], "confidence": AMBIG,
        "note": "Active Scanning",
    },
    MicroAttackStage.SOCIAL_ENGINEERING: {
        "kind": "technique", "ids": ["T1566"], "confidence": OK,
        "note": "Phishing",
    },
    MicroAttackStage.HOST_DISC: {
        "kind": "technique", "ids": ["T1018"], "confidence": OK,
        "note": "Remote System Discovery",
    },
    MicroAttackStage.SERVICE_DISC: {
        "kind": "technique", "ids": ["T1046"], "confidence": OK,
        "note": "Network Service Discovery",
    },
    MicroAttackStage.VULN_DISC: {
        "kind": "technique", "ids": ["T1595.002"], "confidence": OK,
        "note": "Active Scanning: Vulnerability Scanning",
    },
    MicroAttackStage.INFO_DISC: {
        "kind": "technique", "ids": ["T1592", "T1590"], "confidence": AMBIG,
        "note": "Gather Victim Host/Network Information -- context-dependent",
    },
    MicroAttackStage.USER_PRIV_ESC: {
        "kind": "technique", "ids": ["T1068"], "confidence": AMBIG,
        "note": "Exploitation for Privilege Escalation",
    },
    MicroAttackStage.ROOT_PRIV_ESC: {
        "kind": "technique", "ids": ["T1068"], "confidence": AMBIG,
        "note": "same as USER_PRIV_ESC -- SAGE splits user/root, ATT&CK doesn't",
    },
    MicroAttackStage.NETWORK_SNIFFING: {
        "kind": "technique", "ids": ["T1040"], "confidence": OK,
        "note": "Network Sniffing",
    },
    MicroAttackStage.BRUTE_FORCE_CREDS: {
        "kind": "technique", "ids": ["T1110"], "confidence": OK,
        "note": "Brute Force",
    },
    MicroAttackStage.ACCT_MANIP: {
        "kind": "technique", "ids": ["T1098"], "confidence": OK,
        "note": "Account Manipulation",
    },
    MicroAttackStage.TRUSTED_ORG_EXP: {
        "kind": "technique", "ids": ["T1199"], "confidence": OK,
        "note": "Trusted Relationship",
    },
    MicroAttackStage.PUBLIC_APP_EXP: {
        "kind": "technique", "ids": ["T1190"], "confidence": OK,
        "note": "Exploit Public-Facing Application",
    },
    MicroAttackStage.REMOTE_SERVICE_EXP: {
        "kind": "technique", "ids": ["T1210"], "confidence": OK,
        "note": "Exploitation of Remote Services",
    },
    MicroAttackStage.SPEARPHISHING: {
        "kind": "technique", "range": ("T1566.001", "T1566.003"), "ids": [], "confidence": OK,
        "note": "Spearphishing sub-techniques",
    },
    MicroAttackStage.SERVICE_SPECIFIC: {
        "kind": "none", "ids": [], "confidence": NEEDS_REVIEW,
        "note": "no clean match -- catch-all",
    },
    MicroAttackStage.DEFENSE_EVASION: {
        "kind": "tactic", "ids": ["TA0005"], "confidence": TACTIC,
        "note": "Defense Evasion (tactic, not a technique)",
    },
    MicroAttackStage.COMMAND_AND_CONTROL: {
        "kind": "tactic", "ids": ["TA0011"], "confidence": TACTIC,
        "note": "Command and Control (tactic)",
    },
    MicroAttackStage.LATERAL_MOVEMENT: {
        "kind": "tactic", "ids": ["TA0008"], "confidence": TACTIC,
        "note": "Lateral Movement (tactic)",
    },
    MicroAttackStage.ARBITRARY_CODE_EXE: {
        "kind": "technique", "ids": ["T1203"], "confidence": AMBIG,
        "note": "Exploitation for Client Execution (alt: T1059)",
    },
    MicroAttackStage.PRIV_ESC: {
        "kind": "tactic", "ids": ["TA0004"], "confidence": TACTIC,
        "note": "Privilege Escalation (tactic -- generic fallback bucket)",
    },
    MicroAttackStage.END_POINT_DOS: {
        "kind": "technique", "ids": ["T1499"], "confidence": OK,
        "note": "Endpoint Denial of Service",
    },
    MicroAttackStage.NETWORK_DOS: {
        "kind": "technique", "ids": ["T1498"], "confidence": OK,
        "note": "Network Denial of Service",
    },
    MicroAttackStage.SERVICE_STOP: {
        "kind": "technique", "ids": ["T1489"], "confidence": OK,
        "note": "Service Stop",
    },
    MicroAttackStage.RESOURCE_HIJACKING: {
        "kind": "technique", "ids": ["T1496"], "confidence": OK,
        "note": "Resource Hijacking",
    },
    MicroAttackStage.DATA_DESTRUCTION: {
        "kind": "technique", "ids": ["T1485"], "confidence": OK,
        "note": "Data Destruction",
    },
    MicroAttackStage.CONTENT_WIPE: {
        "kind": "technique", "ids": ["T1561"], "confidence": AMBIG,
        "note": "Disk Wipe -- overlaps with Data Destruction",
    },
    MicroAttackStage.DATA_ENCRYPTION: {
        "kind": "technique", "ids": ["T1486"], "confidence": OK,
        "note": "Data Encrypted for Impact",
    },
    MicroAttackStage.DEFACEMENT: {
        "kind": "technique", "ids": ["T1491"], "confidence": OK,
        "note": "Defacement",
    },
    MicroAttackStage.DATA_MANIPULATION: {
        "kind": "technique", "ids": ["T1565"], "confidence": OK,
        "note": "Data Manipulation",
    },
    MicroAttackStage.DATA_EXFILTRATION: {
        "kind": "technique", "ids": ["T1041"], "confidence": AMBIG,
        "note": "Exfiltration Over C2 Channel (alt: tactic-level TA0010)",
    },
    MicroAttackStage.DATA_DELIVERY: {
        "kind": "technique", "ids": ["T1105"], "confidence": AMBIG,
        "note": "Ingress Tool Transfer -- ambiguous, could be Initial Access delivery",
    },
    MicroAttackStage.PHISHING: {
        "kind": "technique", "ids": ["T1566"], "confidence": OK,
        "note": "redundant with SOCIAL_ENGINEERING/SPEARPHISHING",
    },
    MicroAttackStage.NON_MALICIOUS: {
        "kind": "none", "ids": [], "confidence": NONE_,
        "note": "no MITRE equivalent -- not an attack; reject class",
    },
}

# sanity: every MicroAttackStage member must appear exactly once
assert set(BRIDGE_TABLE.keys()) == set(MicroAttackStage), (
    set(MicroAttackStage) - set(BRIDGE_TABLE.keys()),
    set(BRIDGE_TABLE.keys()) - set(MicroAttackStage),
)
