# PurpleForge: Project Deep Dive

**Purpose:** explain the project’s design, implementation, current evidence, and limitations in enough detail to discuss it accurately in a technical interview or handoff.

**Evidence snapshot:** repository and local lab state checked on 2026-11-20. Runtime status can change; distinguish the checked-in design from what has actually been exercised.

## 1. The short explanation

PurpleForge is a defensive security lab and Detection-as-Code (DaC) project. It stores Windows detections as Sigma rules, compiles them for OpenSearch, checks each rule against a matching positive fixture and a benign event corpus, and provides assets for alerting, enrichment, response, and forensics.

The project has three different levels of evidence that should not be conflated:

1. **Rule-level test:** a local run passed all 30 Sigma rules against the project’s positive and benign fixtures.
2. **Reported benchmark:** repository metrics files contain illustrative lab numbers, but their inputs and reported values conflict; they are not independently audited production measurements.
3. **End-to-end integration:** live monitor deployment was attempted and did **not** complete successfully. The last recorded attempt deployed 0 of 30 monitors.

### A 30-second project pitch

> I built PurpleForge as a Detection-as-Code lab around Wazuh and OpenSearch. It contains 30 Sigma rules across eight ATT&CK tactics, a PySigma pipeline to map Windows event fields, and a test runner that requires each rule to match its positive fixture while excluding a shared benign baseline. The repository also contains CI, SOAR, active-response, ATT&CK Navigator, and DFIR assets. The local rule fixture suite passed 30/30 in the last recorded run; I’m careful to distinguish that from production coverage, because live monitor deployment still needs integration work.

## 2. System architecture

```text
                  Detection engineering
  Sigma rules ──> PySigma/OpenSearch pipeline ──> TP/TN rule tests
       │                                               │
       └──────────────> ATT&CK layer generator         └──> GitHub Actions

  DC01 / WS01 (optional LIN01)
       │ Windows/Linux telemetry from Wazuh agents
       ▼
  Wazuh Manager ──> Filebeat ──> Wazuh Indexer / OpenSearch
                                      ├── wazuh-alerts-* (rule alerts)
                                      ├── wazuh-archives-* (raw events)
                                      └── monitoring/statistics indices
                                               │
                                    OpenSearch Alerting
                                               │
                       Shuffle SOAR workflow assets
                       ├── normalize alert
                       ├── enrich observables
                       ├── calculate risk / request approval
                       ├── response and case actions
                       └── IRIS / MISP workflow actions
                                               │
                            Velociraptor / Volatility DFIR assets
```

The diagram describes the intended flow. The repository contains assets for most stages, but the complete chain has not been verified end-to-end.

### Telemetry and index roles

- **Wazuh Manager** receives and normalizes endpoint events from Wazuh agents.
- **Filebeat** ships Wazuh alerts and, when archive collection is enabled, raw JSON telemetry to the Indexer.
- **Wazuh Indexer** is the secured OpenSearch-compatible storage and query service.
- **`wazuh-alerts-*`** is for events that Wazuh rules promote to alerts.
- **`wazuh-archives-*`** is intended for raw archived events. PurpleForge’s monitor deployer targets this pattern.
- **Monitoring/statistics indices** support Wazuh’s status and statistics features; they are not substitutes for alert or archive data.

An index template can exist before any matching index has documents. Similarly, a rule test passing against generated events does not prove that a live endpoint event will be collected, mapped, alerted, or responded to.

## 3. Lab and infrastructure

### Endpoint lab

- [`scripts/hyperv/build_hyperv_diet_vms.ps1`](../scripts/hyperv/build_hyperv_diet_vms.ps1) creates an isolated Hyper-V internal switch/NAT and lightweight VM shells for **DC01** and **WS01**. It does not install Windows; operating-system media and installation are still required.
- [`scripts/lab_setup/setup_dc01.ps1`](../scripts/lab_setup/setup_dc01.ps1) promotes DC01 to the sample Active Directory forest, creates simulated directory users/service accounts, and enables audit categories used by the detections.
- [`scripts/lab_setup/setup_ws01.ps1`](../scripts/lab_setup/setup_ws01.ps1) enables PowerShell logging, installs Sysmon and the Wazuh agent, and configures event-channel collection.
- [`scripts/lab_setup/setup_lin01_cowrie_auditd.sh`](../scripts/lab_setup/setup_lin01_cowrie_auditd.sh) is an optional Linux sensor setup for Cowrie and auditd. LIN01 is not created by the Hyper-V builder.
- [`scripts/emulation/benign_activity_generator.ps1`](../scripts/emulation/benign_activity_generator.ps1) provides background administrative activity for benign-event testing.
- [`scripts/emulation/run_atomic_killchain.ps1`](../scripts/emulation/run_atomic_killchain.ps1) has 30 emulation entries spanning 26 unique ATT&CK technique IDs. It can change real endpoint state; use only in a dedicated, snapshotted lab with authorization. It is not a harmless unit-test runner.

The scripts contain lab-only account and network assumptions. Change sample credentials and addresses before using the lab outside an isolated environment. The active-response script also uses a fixed management Tailscale address; it must match the actual lab before isolation is enabled.

### Container stack

[`docker/docker-compose.yml`](../docker/docker-compose.yml) defines a private Compose network and named volumes. The principal profiles are:

| Profile | Main services |
| --- | --- |
| `siem` | Wazuh Indexer, Manager, Dashboard |
| `soar` | Shuffle database/backend/frontend; IRIS services are also assigned to this profile |
| `dfir` | DFIR-IRIS and Velociraptor |

Compose profile selection matters: starting `siem` does not start every SOAR/DFIR service. The README’s optional SOAR/DFIR steps add those profiles after the SIEM stack.

Notable image versions in the Compose file include Wazuh 4.7.2, OpenSearch 2.11.0 for Shuffle’s database, and DFIR-IRIS 2.4.29. Shuffle and Velociraptor images use mutable tags, so their exact build can change over time. MISP appears as a workflow action, but there is no MISP service in this Compose file. The Compose header mentions Orborus, but no Orborus service is defined.

### Developer environment and ports

The [Dev Container definition](../.devcontainer/devcontainer.json) uses Python 3.11 on Debian Bookworm, Docker-in-Docker, Tailscale, and installs `requirements.txt` after creation. Its forwarded ports are:

| Host port | Service/use | Public exposure guidance |
| --- | --- | --- |
| `443` | Wazuh Dashboard (container port 5601) | Only UI port needed for the Wazuh screen; keep private unless public access is intentional and demo credentials have been changed |
| `3443` | Shuffle frontend | Optional UI; public only if external users need it |
| `8080` | DFIR-IRIS web UI (container port 8000) | Optional UI; public only if needed |
| `9200` | Wazuh Indexer API | Keep private |
| `55000` | Wazuh Manager API | Keep private |
| `1514/udp`, `1515/tcp` | Wazuh agent traffic/enrollment | Keep private or expose only to the intended agent network |
| `3001` | Shuffle backend/API | Keep private |
| `8000`, `8889` | Velociraptor services | Keep private unless specifically required |

`forwardPorts` forwards ports into Codespaces; it does not itself make them public. Codespaces visibility is controlled in the Ports panel. The repo’s current Dev Container file does not set a public visibility override.

## 4. Detection engineering

### Sigma rule inventory

There are **30 Sigma YAML rules**, each with a `custom.tp_file` reference and ATT&CK technique/tactic metadata. They are grouped as:

| ATT&CK tactic | Rule count |
| --- | ---: |
| Command and control | 3 |
| Credential access | 5 |
| Defense evasion | 5 |
| Execution | 4 |
| Impact | 2 |
| Lateral movement | 4 |
| Persistence | 4 |
| Privilege escalation | 3 |
| **Total** | **30** |

The rules cover 26 unique technique IDs; some techniques have multiple detections. Five additional YARA-L files are in [`rules/yara-l/`](../rules/yara-l/). Those are Chronicle-oriented assets and are not compiled or tested by the current Sigma test runner or CI lint job.

### How a Sigma rule is structured

A typical rule includes:

- `title`, stable `id`, status, description, author, and severity `level`.
- ATT&CK tags, `logsource`, and `detection` selections.
- One or more `filter_*` selections to exclude known benign cases.
- A `condition` that combines positive selections and filters.
- A `custom` block with `mitre_technique`, `mitre_tactic`, `tp_file`, and tuning notes.

For example, the LSASS-access rule selects Sysmon process-access events against `lsass.exe` with suspicious access masks, then filters known system/Defender activity. The shadow-copy rule selects deletion behavior and excludes known backup parents. These are detection predicates, not proof that the same telemetry is enabled or present in every environment.

### PySigma field mapping

[`pipelines/wazuh_opensearch.yml`](../pipelines/wazuh_opensearch.yml) translates Sigma field names into the Wazuh JSON event schema. Examples include:

| Sigma field | Wazuh event path |
| --- | --- |
| `EventID` | `data.win.system.eventID` |
| `Image` | `data.win.eventdata.image` |
| `CommandLine` | `data.win.eventdata.commandLine` |
| `TargetImage` | `data.win.eventdata.targetImage` |
| `QueryName` | `data.win.eventdata.queryName` |

The pipeline also adds event-channel conditions for Windows/Sysmon log sources. This lets a Sigma rule express portable detection intent while the backend pipeline handles the local field and log-source representation.

### Test corpus generation

[`tools/seed_test_logs.py`](../tools/seed_test_logs.py) has a generator keyed by rule filename:

- It creates one Wazuh-shaped positive event for each mapped Sigma rule and writes it to the rule’s `custom.tp_file`.
- It creates 30 benign Windows events in [`tests/tn/benign_baseline.json`](../tests/tn/benign_baseline.json), including administrative, monitoring, browser, backup, installer, and development activity.
- Events use a current UTC timestamp and randomly generated IDs. Re-running the generator overwrites tracked fixtures and produces noisy diffs even when the event semantics are unchanged.

These are synthetic fixtures. A generated TP proves the rule matches the fixture the project authored; it is not an independent sample from production telemetry.

### Test runner behavior

[`tools/test_runner.py`](../tools/test_runner.py):

1. Connects to the configured OpenSearch endpoint.
2. Deletes and recreates the `test-tp` and `test-tn` indices.
3. Applies a one-shard, zero-replica mapping with strings normalized as lowercase keywords.
4. Loads the shared benign baseline and one TP event per rule.
5. Invokes `sigma convert` with the OpenSearch Lucene target and PurpleForge pipeline.
6. Runs the compiled query against the TP and TN indices.
7. Passes a rule when `TP hits >= 1` and `TN hits == 0`; compilation, empty query, or search failures fail the rule.

**Safety note:** the runner deletes and recreates `test-tp` and `test-tn`. Do not point it at an environment where those indices contain data to preserve.

**Last recorded local result:** 30/30 Sigma rules passed this fixture-level gate. This is a 100% pass rate for the test cases supplied to the runner, not 100% ATT&CK coverage, real-world precision, or end-to-end validation.

## 5. CI/CD and generated artifacts

The GitHub Actions workflow is [`.github/workflows/ci-cd.yml`](../.github/workflows/ci-cd.yml).

It defines four jobs:

1. **Lint:** runs `yamllint` over Sigma rules and the pipeline.
2. **Detection tests:** starts a single-node OpenSearch service, seeds fixtures, and runs the TP/TN runner.
3. **Generate artifacts:** generates the ATT&CK Navigator layer and uploads it as an Actions artifact.
4. **Deploy monitors:** on a push to `main`, uses production secrets to deploy monitors. The job has `continue-on-error: true`, so a deployment failure does not necessarily fail the overall workflow.

The workflow’s path filters include rules, pipelines, tests, tools, and workflow files. Documentation-only changes do not trigger those filtered push/PR runs. The test job disables OpenSearch security for its ephemeral service and includes lab test credentials; those are not production credentials.

### ATT&CK Navigator output

[`tools/generate_navigator.py`](../tools/generate_navigator.py) extracts technique/tactic metadata from Sigma YAML and writes [`attack_navigator_layer.json`](../attack_navigator_layer.json). The current output has 26 unique technique entries, each scored 100 and colored green.

Important caveat: the generator derives entries from rule metadata; it does **not** read CI results, query live detections, or check which techniques actually fired. Treat it as a rule-mapping inventory, not evidence of 100% operational detection coverage. The root README badge claiming 100% ATT&CK coverage is inconsistent with the metrics files.

## 6. OpenSearch monitor deployment

[`tools/deploy_opensearch_monitors.py`](../tools/deploy_opensearch_monitors.py) is intended to:

- Compile each Sigma rule.
- Create or reuse an OpenSearch Alerting webhook destination.
- Create or update one query-level monitor per Sigma rule.
- Search `wazuh-archives-*` on a one-minute schedule.
- Send a notification to Shuffle when a query has hits.

The current implementation has important gaps:

- The destination builder hardcodes its HTTPS scheme, port, and webhook path rather than fully deriving them from the configured URL.
- Destination creation catches errors and can return a placeholder ID; this can lead to later monitor failures instead of stopping at the first configuration error.
- Query payloads have not yet been validated against the target Alerting API version.
- The production deploy job is non-blocking in Actions.

**Observed deployment result:** the last direct run connected to OpenSearch but created **0 of 30 monitors**. Destination creation returned HTTP 405 and monitor creation returned HTTP 400 for the query payload. The later Dashboard/Filebeat connectivity fixes do not establish that monitor deployment is fixed; this deployer needs a focused API-payload and destination integration test.

## 7. SOAR and risk scoring

[`soar/shuffle_workflow_export.json`](../soar/shuffle_workflow_export.json) is a Shuffle workflow export with one OpenSearch alert trigger and nine action nodes:

1. Normalize telemetry.
2. Query VirusTotal.
3. Check AbuseIPDB.
4. Query Shodan.
5. Calculate a weighted risk score.
6. Request analyst approval.
7. Execute active response.
8. Create a DFIR-IRIS case.
9. Add a MISP event.

The export is a workflow asset, not proof that every remote integration, webhook, credential, or action was deployed and exercised.

### Threat-intelligence enrichment

[`soar/enrichment_shodan_gotham.py`](../soar/enrichment_shodan_gotham.py) supports VirusTotal, AbuseIPDB, and Shodan API keys through environment variables. Without keys, it returns deterministic mock results so the workflow can be demonstrated without live API access. Live mode should not be claimed unless valid credentials and successful provider responses are verified.

The code uses VirusTotal’s file lookup path for the supplied observable, including when that observable is an IP; review this before relying on IP reputation results. Provider errors can also result in fallback error-shaped payloads with zero counts.

### Risk scoring model

[`soar/risk_score_calculator.py`](../soar/risk_score_calculator.py) computes:

```text
base severity
+ VirusTotal malicious detections × 5 (cap 40)
+ AbuseIPDB confidence × 0.3 (cap 30)
+ Shodan port weights (cap 25)
```

The final score is clamped to 0–100. Severity/action bands are:

| Score | Classification | Intended response |
| ---: | --- | --- |
| 85–100 | Critical | Immediate isolation and triage |
| 65–84.9 | High | Analyst approval before isolation |
| 45–64.9 | Medium | Enrich and log a ticket |
| Below 45 | Low | Informational monitoring |

This is a deterministic heuristic, not a calibrated probability. Missing lifecycle timestamps default to the current time, and the code clamps negative MTTD/MTTR to zero. Benchmark outputs therefore require trustworthy event timestamps and real enrichment inputs to be meaningful.

## 8. Active response and DFIR

### Host isolation

[`docker/wazuh_config/custom_active_response_isolate.cmd`](../docker/wazuh_config/custom_active_response_isolate.cmd) defines `add` and `delete` actions. The add path changes Windows Firewall policy to block general inbound/outbound traffic while allowing the configured SECOPS address and loopback. The delete path removes those rules and restores a default firewall policy.

This can disconnect a host if the allowlisted management address is wrong or unreachable. Validate the recovery path and the exact lab address on a disposable VM snapshot before enabling it. The script’s fixed address is an assumption, not automatically discovered configuration.

### Collection and investigation

- [`dfir/velociraptor_hunt_spec.yaml`](../dfir/velociraptor_hunt_spec.yaml) describes a hunt for lab endpoints and collection of selected KAPE, process, network, and memory artifacts.
- [`dfir/volatility3_triage.sh`](../dfir/volatility3_triage.sh) runs common Volatility plugins for process lists, process trees, command lines, suspicious memory regions, and network connections. If Volatility is unavailable, the script emits **simulated mock output**; such output must never be presented as actual forensic findings.
- [`dfir/IR_Report_Template.md`](../dfir/IR_Report_Template.md) is a filled example/template with a simulated incident narrative and sample timestamps. It is not independently verified case evidence.
- The Compose file defines IRIS and Velociraptor services. In the last local `docker compose ps` snapshot, IRIS services were up; no Velociraptor container was listed as running.

The root README refers to `scripts/emulation/ransomware_simulator_safe.py`, but that file is absent from the current repository tree. Do not cite or run that referenced simulator until the implementation or documentation reference is corrected.

## 9. Metrics: what the numbers mean

The current metrics sources are [`emulation_log.csv`](../emulation_log.csv), [`soar_metrics.json`](../soar_metrics.json), [`metrics_summary.json`](../metrics_summary.json), and [`metrics_report.md`](../metrics_report.md).

### Values recorded in the repository

- The checked-in emulation manifest has 30 rows, 26 unique technique IDs, and status values marked `SUCCESS`; its event timestamps are from 2024.
- The detailed SOAR telemetry contains five fixed example events and marks five unique techniques as detected.
- `metrics_summary.json` therefore reports 5/26 techniques, or **19.23%** coverage.
- The benchmark inputs report 1,420 baseline alerts (58 TP, 1,362 FP) versus 62 tuned alerts (60 TP, 2 FP). The corresponding reported precision is about 4.08% versus 96.77%, and FP/day is 97.28 versus 0.14.

These values are stored sample/benchmark data. The files do not establish that the 14-day measurements were collected from a production deployment or independently audited.

### Inconsistencies to know

- `metrics_summary.json` and `metrics_report.md` calculate v2 MTTD/MTTR from the five detailed events as **35.2s / 59.8s**.
- The aggregate fields in `soar_metrics.json` and the root README say **38.4s / 86.2s**.
- The sample IR report uses yet another example: **38s / 64s**.
- The root README badge says 100% ATT&CK coverage, while the metrics summary says 19.23% (5/26).
- `generate_navigator.py` marks all metadata-mapped techniques as score 100 without verifying live detections.
- `calculate_metrics.py` can generate sample inputs when files are absent and has fallback coverage values when no detections are present. Its output can therefore look authoritative even when it is using fallback/sample data.

**Interview-safe language:** quote 30/30 only as the last local fixture-test result. If discussing metrics, explicitly label them as repository-reported illustrative lab benchmarks and use the 19.23% coverage figure from the current summary. Do not claim 100% production coverage, a measured MTTR, or 30 live monitors.

## 10. Configuration and operational troubleshooting

### Credentials and secrets

- Compose reads `docker/.env` when present; `docker/.env.example` is a template, not an automatically loaded secrets file.
- The Dashboard’s Wazuh API password configures the Dashboard connection; it does not provision or reset the corresponding Manager-side API user.
- The stock Manager image’s lab API account and the example Dashboard credentials are aligned in the current template. If changing the Dashboard password, change the Manager-side API user too.
- Example credentials, account setup scripts, and lab network addresses are not production secrets/configuration. Replace them before any non-lab deployment or public exposure.
- The Shuffle API key in the template is now a placeholder. If a previously committed token was valid, rotate it at the provider; replacing the repository value does not revoke the old token.

### Dashboard API URL

The Wazuh Dashboard stores API `url` and `port` separately. Compose now sets `WAZUH_API_URL` to the manager host only (`https://wazuh.manager`) and the Dashboard supplies port 55000 separately. Including `:55000` in both places can prevent the Wazuh app from connecting.

The latest local checks confirmed:

- The Dashboard’s generated Wazuh config has the host-only URL and separate port.
- The API authentication request from the Dashboard container returned HTTP 200.
- A browser-side health-check screenshot was not captured after this final correction; refresh the Wazuh app and re-run its check to confirm the UI state.

### Filebeat TLS and archive indices

The manager’s Filebeat output uses the internal Compose service name `wazuh.indexer`. The lab Indexer certificate is not mounted as a trusted CA in the Manager, so [`enable_archives.sh`](../docker/wazuh_config/enable_archives.sh) sets `ssl.verification_mode: none` while enabling raw archives.

This was a lab connectivity workaround on the private Docker network, not a production TLS pattern. A real deployment should mount/trust the Indexer CA and validate the certificate instead of disabling verification.

After the fix, the last local check found the `wazuh` template covering both `wazuh-alerts-4.x-*` and `wazuh-archives-4.x-*`, and an archive index had been created. An alerts index may not exist until an alert is actually generated.

### Public Codespaces ports

For the Wazuh browser UI, port 443 is the relevant port. IRIS 8080 and Shuffle 3443 are optional browser interfaces. Keep Indexer/API and agent ports private unless a specific trusted network path requires them. Public Codespaces ports can be reachable by anyone with the forwarded URL; change lab credentials before making an admin UI public.

## 11. Safe validation workflow

For an authorized local lab, the Python-side checks can be run with:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
docker compose -f docker/docker-compose.yml --profile siem up -d
python tools/seed_test_logs.py
python tools/test_runner.py
python tools/generate_navigator.py
```

Configure `docker/.env` from the example before starting services if the defaults are not appropriate. On Windows, activate the virtual environment with its Windows activation script instead of `source`.

The sequence does the following:

1. Install the Python dependencies from `requirements.txt`.
2. Start the SIEM profile and verify the Wazuh Manager, Indexer, and Dashboard are healthy.
3. Generate or refresh fixtures with `tools/seed_test_logs.py` (expect changed timestamps/IDs in tracked JSON).
4. Run `tools/test_runner.py` only against a lab Indexer because it deletes its two test indices.
5. Generate the ATT&CK layer with `tools/generate_navigator.py`, understanding that it is metadata-derived.
6. Use `tools/calculate_metrics.py` only after confirming the provenance and consistency of both input files.
7. Treat `tools/deploy_opensearch_monitors.py` as unverified until destination creation and monitor creation pass against the actual target Alerting API.

The endpoint emulation script changes system state and can perform sensitive behaviors. Do not run it on a production endpoint, a personal workstation, or a network you do not own/control. Use isolated VM snapshots and an approved scope.

## 12. Current known gaps and sensible next work

1. **Make monitor deployment pass end-to-end.** Fix the destination request and validate the Alerting monitor payload with the exact OpenSearch/Wazuh version. Replace placeholder fallbacks with explicit failures and add a test that asserts the monitor exists.
2. **Make CI deployment status meaningful.** Avoid masking deployment failures; distinguish non-production test deployment from production deployment and make required status checks reflect the result.
3. **Correct evidence and marketing claims.** Align README badges, metrics reports, and Navigator output with one validated source of truth. Label synthetic benchmarks clearly.
4. **Make fixture generation deterministic.** Use stable timestamps/IDs or keep generated runtime data out of tracked fixtures.
5. **Improve integration tests.** Cover field mappings, malformed/empty rule output, API payload shapes, webhook destination configuration, and missing templates.
6. **Harden configuration.** Replace demo defaults, rotate any exposed credentials, avoid public admin endpoints, and use CA validation for internal TLS.
7. **Resolve documentation drift.** The README references a simulator that is not present; its MISP/Orborus descriptions also exceed what the current Compose file defines.
8. **Separate sample from observed metrics.** Store provenance, collection window, raw input references, and calculation version with any benchmark used in a résumé.

## 13. Technical Q&A

### Why use Sigma?

Sigma keeps the detection intent in a backend-neutral YAML format. The custom PySigma pipeline maps generic Windows fields and log sources to the Wazuh event schema, then the OpenSearch backend compiles the rule for the target query engine.

### What does 30/30 mean?

It means each of the 30 Sigma rules matched its authored positive fixture and had zero hits in the shared benign baseline during the last local run. It does not mean every technique is detected in production or that the monitor deployment succeeded.

### Why have a benign corpus?

Positive-only tests reward broad, noisy rules. The shared TN corpus exercises environment-specific filters for common administrative, monitoring, backup, browser, and installer behavior. It is a useful gate but not a representative sample of every organization’s normal activity.

### How many detections versus techniques?

There are 30 Sigma rules, five YARA-L rules, and 26 unique ATT&CK technique IDs in the current Sigma/manifest inventories. Several rules map to the same technique. Five detected techniques in the metrics file is a separate sample telemetry count.

### What is the strongest verified result?

The strongest directly exercised detection result in the current history is the local **30/30 fixture test**. The latest local service checks also confirmed API authentication and Filebeat archive/template creation. Live monitor deployment remains unverified and the last attempt failed.

### Is this production-ready?

No. It is a portfolio/security lab with useful engineering assets. It still has demo credentials, relaxed internal TLS verification, non-deterministic fixtures, sample metrics, a non-blocking deploy job, and an unverified monitor deployer.

### What does the risk score represent?

A bounded heuristic score combining configured rule severity and mock/live threat-intelligence inputs. It is a prioritization aid, not a calibrated probability or proof of maliciousness. The thresholds map to intended handling paths, including analyst approval for high-severity isolation.

### Why are raw archives useful?

Wazuh alerts contain events that matched Wazuh rules. Archives preserve raw telemetry so OpenSearch monitors can query events even when the base Wazuh rule did not promote them to an alert. Archive collection increases storage and privacy impact and should be scoped intentionally.

### Why can the Dashboard show an API error when the API itself works?

The Wazuh app’s API host and port are separate config fields. A malformed host/port combination or mismatched Manager-side user can break the app even if the API listener is reachable. Check the generated `wazuh.yml`, host/port fields, API credentials, and logs from the Dashboard container.

### What are the main risks of active response?

Isolation can sever management access if the allowlisted SECOPS IP is wrong, while endpoint emulation can make real system changes. Validate both only in disposable, isolated VMs with snapshots and a recovery path.

## 14. Repository map

| Path | Responsibility |
| --- | --- |
| [`rules/`](../rules/) | 30 Sigma rules and five separate YARA-L rules |
| [`pipelines/wazuh_opensearch.yml`](../pipelines/wazuh_opensearch.yml) | Sigma-to-Wazuh field and log-source mappings |
| [`tests/tp/`](../tests/tp/) | One authored positive event per Sigma rule |
| [`tests/tn/benign_baseline.json`](../tests/tn/benign_baseline.json) | Shared benign event corpus |
| [`tools/seed_test_logs.py`](../tools/seed_test_logs.py) | Generates/refreshes test events |
| [`tools/test_runner.py`](../tools/test_runner.py) | Compiles rules and asserts TP/TN query behavior |
| [`tools/deploy_opensearch_monitors.py`](../tools/deploy_opensearch_monitors.py) | Intended live OpenSearch Alerting deployer; currently unverified |
| [`tools/generate_navigator.py`](../tools/generate_navigator.py) | Generates ATT&CK Navigator metadata layer |
| [`tools/calculate_metrics.py`](../tools/calculate_metrics.py) | Computes metrics from CSV/JSON inputs |
| [`soar/`](../soar/) | Shuffle export, enrichment, and risk-scoring code |
| [`dfir/`](../dfir/) | Velociraptor hunt, Volatility triage, and report template |
| [`docker/`](../docker/) | Compose stack, environment template, archive setup, active response |
| [`.github/workflows/`](../.github/workflows/) | Rule lint, fixture tests, artifacts, and monitor deployment workflow |
| [`README.md`](../README.md) | Main setup and architecture guide; contains claims that should be reconciled with this evidence |
| [`RESUME_PROJECT_README.md`](../RESUME_PROJECT_README.md) | Concise portfolio-oriented summary |

## 15. Recent repository work

Recent changes on `main` include:

- `3d6d79a` — aligned demo service configuration.
- `448baa3` — aligned OpenSearch client credential fallbacks and updated the handover/testing data; a subsequent local run passed 30/30 fixture tests but did not deploy monitors.
- `783b106` — added the resume-focused project README.
- `201df5a` — aligned the Wazuh Dashboard API account example, corrected Filebeat’s internal Indexer connection/archive setup, and replaced the Shuffle template key with a placeholder.
- `3d8707d` — corrected the Dashboard API host so its URL and port are configured separately.
- Earlier commits updated the Dev Container base to Debian Bookworm and set the repository license to MIT.

These changes improved local connectivity, but they do not change the recorded 0/30 live monitor deployment result. The branch and service state should be rechecked before using this guide as a current operational runbook.
