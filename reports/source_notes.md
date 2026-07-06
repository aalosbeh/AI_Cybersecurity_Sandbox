# Source and Reproducibility Notes

Generated: 2026-07-02T22:43:38.212455+00:00

## Data sources

- CISA Known Exploited Vulnerabilities catalog JSON: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
- FIRST EPSS current scores CSV: https://epss.empiricalsecurity.com/epss_scores-current.csv.gz
- NIST Cybersecurity Framework 2.0 overview: https://www.nist.gov/cyberframework
- MITRE ATT&CK Enterprise matrix: https://attack.mitre.org/
- Source transcript: /Users/anasalsobeh/.codex/attachments/eabacbc5-16a3-4df7-bc3c-940a2ff3e12c/pasted-text.txt

## Dataset snapshot

- CISA KEV catalog version: 2026.07.01
- CISA KEV released: 2026-07-01T19:00:06.9016Z
- CISA KEV rows observed: 1,631
- EPSS model version: v2026.06.15
- EPSS score date: 2026-07-02T12:00:26Z
- EPSS rows observed: 345,190
- KEV rows with EPSS match: 1,631 (100.0%)

## Processing

The script joins CISA KEV to EPSS by CVE identifier, computes EPSS-threshold capture and miss rates, ransomware-flag capture and miss rates, top vendor/product/CWE counts, KEV year counts, and CISA due-window distributions.

No UVU, vendor-customer, student, or production security telemetry is used. The paper intentionally models a privacy-preserving classroom environment where public vulnerability intelligence is combined with synthetic asset and identity context.

## Visual note

The available local Python runtime includes pandas and numpy but not matplotlib or seaborn. The report therefore uses tables as the evidence surface and does not claim Seaborn-template chart compliance.
