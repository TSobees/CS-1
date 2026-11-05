# DNS Packet Analysis

[![Project checks](https://github.com/TSobees/CS-1/actions/workflows/checks.yml/badge.svg)](https://github.com/TSobees/CS-1/actions/workflows/checks.yml)

Analyze an existing packet capture using a portable command-line tool. It counts
DNS queries and responses, summarizes queried names and response codes, and can
write a separate filtered capture. It never captures live traffic or sends packets.

## Quick start

Python 3.12 or 3.13:

```sh
python -m venv .venv
# Activate .venv, then:
python -m pip install -r requirements.txt
python -m dns_analysis
python -m dns_analysis data/dns.cap --output-dir outputs/lab --write-filtered
```

The default input is resolved relative to the package, not a personal filesystem path.
Reports go to `outputs/dns_summary.json`, or the selected output folder. Filtering is
optional and does not change the input. Offline reading does not require root,
administrator privileges or a Kali VM. Scapy must support the input capture's link type.

## Structure

```text
dns_analysis/           Streaming parser and CLI
scripts/                Friendly script launcher and original-path compatibility launcher
data/                   Existing capture evidence, retained without modification
report/                 Historical learning report
tests/                  Generated example packets, overwrite protection and bundled input
outputs/                Generated summaries and optional filtered capture, ignored by Git
```

The two existing files `data/dns.cap` and `data/filtered_dns.pcap` have identical
contents in the original repository. Their names do not prove a filtering step was
performed. Generate a new optional filtered output to reproduce the tool's behavior.

## Interpretation and evidence

Read the [original report](report/DNS_Packet_Capture_Analysis_Report_Entry_1.md)
as historical learning notes. Failed resolutions and repeated queries alone do not
identify malicious domains or establish unauthorized activity. Filtering a capture
does not itself implement access control or demonstrate NIST compliance. Public
capture contents remain visible; review any future capture before publishing it.

## Tests

```sh
python -m unittest discover -s tests -v
```

Tests create local fictional packets without transmitting them. Reference:
[Scapy usage documentation](https://scapy.readthedocs.io/en/stable/usage.html).
MIT license. Author: Sobanjo Oluwatosin. AI assisted the portable parser, tests,
evidence clarification and documentation in this revision.
