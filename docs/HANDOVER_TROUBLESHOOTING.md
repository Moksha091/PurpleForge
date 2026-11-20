# PurpleForge Lab Environment: Architecture & Troubleshooting Handover

This document outlines the architecture, current deployment status, and critical troubleshooting steps for the **PurpleForge Detection-as-Code and Automated Purple Team** pipeline environment. It serves as a technical handover reference for engineers or AI agents working with this repository.

---

## 1. System Architecture & Component Overview

PurpleForge is built as a modular, containerized security lab combining SIEM, SOAR, and DFIR capabilities. The primary components running in the environment include:

- **OpenSearch:** Acts as the central log indexing and alerting engine. The default Docker Compose profile runs the secured Wazuh Indexer over HTTPS; CI uses a standalone OpenSearch service with security disabled over HTTP.
  - **Port:** `9200`. The detection tools default to `https://localhost:9200` with the Compose development credentials. Override with `OPENSEARCH_URL`, `OPENSEARCH_USER`, and `OPENSEARCH_PASS`, or their `INDEXER_USERNAME` and `INDEXER_PASSWORD` equivalents.
- **Wazuh Manager & Dashboard (`purpleforge-manager`, `purpleforge-dashboard`):** Collects endpoint logs, system events, and archives.
  - **Ports:** `1514` (Agent registration/events), `1515` (Auth), `55000` (REST API), Dashboard on `443` (mapped to `5601`).
- **Shuffle SOAR (`purpleforge-shuffle-frontend`, `purpleforge-shuffle-backend`, `purpleforge-shuffle-db`):** Automated incident response and playbook execution engine.
  - **Ports:** Frontend UI on `3443` (mapped to container port `80`), Backend API/Webhooks on `3001` (mapped to container port `5001`).
- **DFIR-IRIS (`purpleforge-iris-web`, `purpleforge-iris-worker`, `purpleforge-iris-db`, `purpleforge-iris-rabbitmq`):** Incident response management platform, background worker, and supporting services.
  - **Port:** Web UI on `http://localhost:8080` (mapped to the app's HTTP port `8000`).

---

## 2. Current Environment Status & Progress

- **OpenSearch Health:** Verified and running with a green cluster status (`/_cluster/health`).
- **Alerting Framework:** The OpenSearch Alerting plugin is active, and internal system indices (`.opendistro-alerting-config`) are bootstrapped via test monitor creation.
- **Detection Rules:** 30 Sigma rules across 8 MITRE ATT&CK tactics are compiled via pySigma and verified in CI/CD with 100% precision (`TP >= 1`, `TN == 0`).
- **Networking & Port Visibility:** All primary developer ports (`3443`, `3001`, `9200`) must be configured as **Public** in GitHub Codespaces to allow external webhook delivery and browser access.

---

## 3. Known Issues & Troubleshooting Playbook

### Issue A: Shuffle UI Stuck on "Waiting for the Shuffle database"
- **Root Cause:** The OpenSearch-backed database container (`purpleforge-shuffle-db`) is terminated by the host Linux kernel's OOM (Out-Of-Memory) Killer because Java memory allocation exceeds available RAM during startup.
- **Resolution Steps:**
  1. Check memory availability:
     ```bash
     free -h
     ```
  2. Restrict the Java heap size and adjust memory limits for the Shuffle database container in `docker-compose.yml`:
     ```yaml
     shuffle-database:
       environment:
         - "discovery.type=single-node"
         - "DISABLE_SECURITY_PLUGIN=true"
         - "OPENSEARCH_JAVA_OPTS=-Xms512m -Xmx512m"
       mem_limit: 1024m
     ```
  3. Fix volume permissions and restart the database stack:
     ```bash
     mkdir -p docker/shuffle-database
     sudo chown -R 1000:1000 docker/shuffle-database
     sudo swapoff -a
     docker restart purpleforge-shuffle-db
     ```

### Issue B: OpenSearch Alerting Missing System Indices (404 Not Found)
- **Root Cause:** OpenSearch Alerting creates `.opendistro-alerting-config` lazily upon first monitor creation.
- **Resolution:** If deployment scripts fail with `Configured indices are not found: [.opendistro-alerting-config]`, bootstrap the alerting index by posting a bootstrap monitor via API:
  ```bash
  curl -k -u "${OPENSEARCH_USER:-${INDEXER_USERNAME:-admin}}:${OPENSEARCH_PASS:-${INDEXER_PASSWORD:-SecretAdmin123!}}" \
    -X POST "https://localhost:9200/_plugins/_alerting/monitors" \
    -H "Content-Type: application/json" \
    -d '{
      "name": "Init-Monitor",
      "type": "monitor",
      "enabled": true,
      "schedule": { "period": { "interval": 1, "unit": "MINUTES" } },
      "inputs": [{
        "search": {
          "indices": ["wazuh-archives-*"],
          "query": { "size": 0, "query": { "match_all": {} } }
        }
      }],
      "triggers": []
    }'
  ```

---

## 4. Quick Verification Commands

Run these checks to validate the pipeline:

```bash
# 1. Verify OpenSearch Cluster Health (default secured Compose profile)
curl -k -u "${OPENSEARCH_USER:-${INDEXER_USERNAME:-admin}}:${OPENSEARCH_PASS:-${INDEXER_PASSWORD:-SecretAdmin123!}}" \
  https://localhost:9200/_cluster/health?pretty

# 2. Check Container Status & Resource Usage
docker ps
docker stats --no-stream

# 3. Seed Test Logs & Run Detection Test Suite
python3 tools/seed_test_logs.py
python3 tools/test_runner.py
```
