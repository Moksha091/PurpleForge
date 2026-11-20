# PurpleForge

**Detection engineering and SOC automation lab**  
[Repository](https://github.com/Moksha091/PurpleForge) · MIT License

PurpleForge is a security engineering project for authoring, testing, and operationalizing detections as code. It combines Sigma rules, a Wazuh/OpenSearch SIEM, a positive-and-benign test corpus, and supporting SOAR/DFIR workflows in a containerized lab.

## Project highlights

- Built a PySigma pipeline to compile and map Sigma detections to OpenSearch queries.
- Created a detection test harness that checks positive events trigger rules and benign events do not.
- Added GitHub Actions workflow stages for rule linting and detection tests.
- Developed scripts and workflow assets for OpenSearch monitor deployment, threat-intelligence enrichment, risk scoring, and incident-response handoff.
- Connected the detection workflow to MITRE ATT&CK coverage reporting and DFIR investigation tooling.

## Validation and reported results

The local detection test run validated **30 rules, with 30/30 passing** their true-positive and true-negative checks. The repository's 14-day lab metrics report records the following comparison:

| Metric | Untuned baseline | Tuned pipeline |
| --- | ---: | ---: |
| Alert precision | 4.08% | 96.77% |
| False positives per day | 97.28 | 0.14 |
| ATT&CK techniques detected | — | 5 of 26 (19.23%) |

These are project-reported lab results, not independently audited or production measurements. **Live monitor deployment is not yet validated end-to-end**: the latest deployment attempt created 0 of 30 monitors and returned API errors. Detection-test success should not be read as proof of successful production deployment.

## Architecture and tools

```text
Sigma rules → PySigma/OpenSearch pipeline → TP/TN test gate
                                               ↓
Wazuh telemetry → OpenSearch alerting → Shuffle SOAR workflow
                                               ↓
                                enrichment / response / DFIR
```

**Core technologies:** Python, Sigma, PySigma, Wazuh, OpenSearch, Docker Compose, GitHub Actions, Shuffle SOAR, MITRE ATT&CK, Velociraptor, and Volatility.

## Run the detection checks

Use the full [project README](README.md) for lab setup and configuration. With the required dependencies and OpenSearch service configured:

```bash
python tools/seed_test_logs.py
python tools/test_runner.py
```

The test runner recreates its `test-tp` and `test-tn` OpenSearch indices. Run it only against a lab instance where those test indices can be replaced.

## Project links

- [Full setup and architecture guide](README.md)
- [Detection rules](rules/)
- [CI workflow](.github/workflows/ci-cd.yml)
- [Metrics report](metrics_report.md)
- [Troubleshooting and handover notes](docs/HANDOVER_TROUBLESHOOTING.md)
