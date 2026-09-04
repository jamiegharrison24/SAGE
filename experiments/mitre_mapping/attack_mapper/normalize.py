"""
Canonicalization for IDS signature/rule text before it hits any tier.
Strip vendor prefixes, split concatenated tokens, placeholder out
CVEs/IPs/hex/version numbers, expand a small abbreviation table.

Own copy inside this package (originally ../archive/tiered_approach/normalize.py)
so this package has no imports reaching outside its own tree -- see ../STATUS.md.
"""
import re

VENDOR_PREFIXES = [
    "ETPRO", "ET ", "GPL ", "MALWARE-CNC", "SERVER-", "BROWSER-", "FILE-",
    "POLICY-", "INDICATOR-", "OS-", "PROTOCOL-", "APP-DETECT", "EXPLOIT-KIT",
]

ABBREVIATIONS = {
    "ps": "powershell",
    "uac": "user account control",
    "xss": "cross site scripting",
    "sqli": "sql injection",
    "rce": "remote code execution",
    "lfi": "local file inclusion",
    "rfi": "remote file inclusion",
    "dos": "denial of service",
    "c2": "command and control",
    "cnc": "command and control",
    "priv": "privilege",
    "esc": "escalation",
    "auth": "authentication",
    "recon": "reconnaissance",
    "vuln": "vulnerability",
}

_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
_IP_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
_HEX_RE = re.compile(r"\b(?:0x)?[0-9a-fA-F]{6,}\b")
_VERSION_RE = re.compile(r"\bv?\d+(?:\.\d+){1,3}\b")
_CAMEL_RE = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
_NON_ALNUM_RE = re.compile(r"[._/\\-]+")
_WS_RE = re.compile(r"\s+")


def strip_vendor_prefix(text):
    for prefix in VENDOR_PREFIXES:
        if text.upper().startswith(prefix.upper()):
            return text[len(prefix):].strip(" -_")
    return text


def split_concatenated(text):
    text = _CAMEL_RE.sub(" ", text)
    text = _NON_ALNUM_RE.sub(" ", text)
    return text


def placeholder_entities(text):
    text = _CVE_RE.sub(" <CVE> ", text)
    text = _IP_RE.sub(" <IP> ", text)
    text = _HEX_RE.sub(" <HEX> ", text)
    text = _VERSION_RE.sub(" <VERSION> ", text)
    return text


def expand_abbreviations(tokens):
    out = []
    for tok in tokens:
        low = tok.lower()
        out.append(ABBREVIATIONS.get(low, tok))
    return out


def canonicalize(text):
    """Full pipeline: vendor-prefix strip -> entity placeholders -> split
    concatenation -> lowercase -> abbreviation expansion -> collapse whitespace."""
    text = strip_vendor_prefix(text)
    text = placeholder_entities(text)
    text = split_concatenated(text)
    text = text.lower()
    tokens = text.split()
    tokens = expand_abbreviations(tokens)
    text = " ".join(tokens)
    text = _WS_RE.sub(" ", text).strip()
    return text


if __name__ == "__main__":
    samples = [
        "ET WEB_SERVER /etc/shadow Detected in URI",
        "ETPRO WEB_SERVER SQLMap Scan Tool User Agent",
        "ET EXPLOIT FortiOS SSL VPN - Information Disclosure (CVE-2018-13379)",
        "Win32/Trojan.Downloader.Gen",
        "BROWSER-CHROME Apple Safari/Google Chrome Webkit memory corruption attempt",
    ]
    for s in samples:
        print(s, "->", canonicalize(s))
