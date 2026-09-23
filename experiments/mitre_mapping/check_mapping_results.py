"""
Verifies `mapping_results.json` against REPORT.md section 11.

The regime tables are transcribed rather than measured -- those runs cannot be
reproduced, because the eval sets and scoring rules changed under them. A
transcription is a second copy of the truth, and second copies drift: correct a
figure in the report and the dashboard keeps showing the old one, with nothing
to say which is right.

So every number in the JSON is checked to still appear in the report's section
11, and the check is cheap enough to run whenever either file changes.

Exits non-zero on the first mismatch, naming it.

Usage:
    python experiments/mitre_mapping/check_mapping_results.py
"""

import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))


def section_11(report_path):
    """The text of REPORT.md's appendix, which is what the JSON copies."""
    with open(report_path, 'r', encoding='utf-8') as handle:
        text = handle.read()
    start = text.find('## 11. Appendix')
    end = text.find('## 12. Glossary', start + 1)
    if start < 0:
        raise SystemExit('REPORT.md has no section 11 to check against')
    return text[start:end if end > 0 else len(text)]


def figures_in(regime):
    """Every numeric figure the JSON claims for one regime, with a label."""
    found = []
    for row in regime['rows']:
        for index, value in enumerate(row[2:], start=2):
            if isinstance(value, float):
                found.append(('regime %s / %s / %s'
                              % (regime['id'], row[1], regime['columns'][index]),
                              value))
    for row in (regime.get('buckets') or {}).get('rows', []):
        for value in row[1:]:
            if isinstance(value, float):
                found.append(('regime %s buckets / %s' % (regime['id'], row[0]),
                              value))
    return found


def main():
    with open(os.path.join(HERE, 'mapping_results.json'),
              'r', encoding='utf-8') as handle:
        results = json.load(handle)
    text = section_11(os.path.join(HERE, 'REPORT.md'))
    # Percentages as the report writes them, e.g. "40.2%" or "43.9% head".
    present = set(re.findall(r'([0-9]+\.[0-9]+)%', text))

    missing, checked = [], 0
    for regime in results['regimes']:
        for label, value in figures_in(regime):
            checked += 1
            if '{:.1f}'.format(value) not in present:
                missing.append((label, value))

    print('checked %d figures against REPORT.md section 11' % checked)
    if missing:
        print('MISMATCH -- these are in mapping_results.json but not in the report:')
        for label, value in missing:
            print('   %-62s %.1f%%' % (label, value))
        print('\nOne of the two is stale. The report is the source of truth;')
        print('correct the JSON to match it, or correct both together.')
        return 1
    print('OK -- every transcribed figure still appears in the report')
    return 0


if __name__ == '__main__':
    sys.exit(main())
