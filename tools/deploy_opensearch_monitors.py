#!/usr/bin/env python3
"""
deploy_opensearch_monitors.py — PurpleForge Monitor Deployment

Connects to the production Wazuh OpenSearch cluster and deploys Sigma rules
as OpenSearch Alerting Monitors targeting wazuh-archives-* on a 1-minute schedule,
linked to the Shuffle SOAR webhook destination.
"""

import json
import os
import sys
import glob
import subprocess
import uuid
import yaml

try:
    from opensearchpy import OpenSearch
except ImportError:
    print("[!] Missing dependency. Run: pip install opensearch-py")
    sys.exit(1)


PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RULES_DIR = os.path.join(PROJECT_ROOT, "rules")
PIPELINE_PATH = os.path.join(PROJECT_ROOT, "pipelines", "wazuh_opensearch.yml")

OPENSEARCH_URL = os.environ.get("OPENSEARCH_URL", "https://localhost:9200")
OPENSEARCH_USER = os.environ.get("OPENSEARCH_USER", "admin")
OPENSEARCH_PASS = os.environ.get("OPENSEARCH_PASS", "admin")
SHUFFLE_WEBHOOK_URL = os.environ.get("SHUFFLE_WEBHOOK_URL", "https://shuffle.corp.purpleforge.local:3443/api/v1/hooks/webhook_placeholder")

TARGET_INDEX = "wazuh-archives-*"
MONITOR_SCHEDULE_INTERVAL = 1
MONITOR_SCHEDULE_UNIT = "MINUTES"


def get_client():
    """Create OpenSearch client."""
    parsed = OPENSEARCH_URL.replace("https://", "").replace("http://", "")
    host_port = parsed.split(":")
    host = host_port[0]
    port = int(host_port[1]) if len(host_port) > 1 else 9200
    use_ssl = OPENSEARCH_URL.startswith("https")

    return OpenSearch(
        hosts=[{"host": host, "port": port}],
        http_auth=(OPENSEARCH_USER, OPENSEARCH_PASS) if OPENSEARCH_USER else None,
        use_ssl=use_ssl,
        verify_certs=False,
        ssl_show_warn=False,
        timeout=30,
    )


def compile_sigma_rule(rule_path):
    """Compile Sigma rule to OpenSearch DSL query."""
    try:
        result = subprocess.run(
            [
                sys.executable, "-m", "sigma", "convert",
                "-t", "opensearch",
                "-p", PIPELINE_PATH,
                "-f", "json",
                "--without-pipeline",
                rule_path,
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode == 0:
            return json.loads(result.stdout.strip()), None
        return None, result.stderr.strip()
    except Exception as e:
        return None, str(e)


def create_destination(client, name="Shuffle SOAR Webhook"):
    """Create or retrieve the Shuffle webhook destination."""
    # Check existing destinations
    try:
        resp = client.transport.perform_request(
            "GET", "/_plugins/_alerting/destinations"
        )
        destinations = resp.get("destinations", [])
        for dest in destinations:
            if dest.get("name") == name:
                print(f"  [*] Reusing existing destination: {dest['id']}")
                return dest["id"]
    except Exception:
        pass

    # Create new destination
    dest_body = {
        "name": name,
        "type": "custom_webhook",
        "custom_webhook": {
            "scheme": "HTTPS",
            "host": SHUFFLE_WEBHOOK_URL.split("//")[1].split(":")[0] if "//" in SHUFFLE_WEBHOOK_URL else "localhost",
            "port": 3443,
            "path": "/api/v1/hooks/webhook_purpleforge",
            "header_params": {
                "Content-Type": "application/json"
            },
        }
    }
    try:
        resp = client.transport.perform_request(
            "POST", "/_plugins/_alerting/destinations",
            body=dest_body
        )
        dest_id = resp.get("_id", str(uuid.uuid4()))
        print(f"  [+] Created destination: {dest_id}")
        return dest_id
    except Exception as e:
        print(f"  [!] Warning: Could not create destination: {e}")
        return "placeholder-destination-id"


def build_monitor_payload(rule_data, query_dsl, destination_id):
    """Build an OpenSearch Alerting Monitor JSON payload."""
    title = rule_data.get("title", "Unnamed Rule")
    description = rule_data.get("description", "")
    level = rule_data.get("level", "medium")
    custom = rule_data.get("custom", {})
    technique = custom.get("mitre_technique", "N/A")
    tactic = custom.get("mitre_tactic", "N/A")

    severity_map = {"low": "4", "medium": "3", "high": "2", "critical": "1"}
    severity = severity_map.get(level, "3")

    monitor = {
        "type": "monitor",
        "name": f"PF-{technique}: {title}",
        "monitor_type": "query_level_monitor",
        "enabled": True,
        "schedule": {
            "period": {
                "interval": MONITOR_SCHEDULE_INTERVAL,
                "unit": MONITOR_SCHEDULE_UNIT
            }
        },
        "inputs": [
            {
                "search": {
                    "indices": [TARGET_INDEX],
                    "query": query_dsl if isinstance(query_dsl, dict) else {"query_string": {"query": query_dsl}}
                }
            }
        ],
        "triggers": [
            {
                "query_level_trigger": {
                    "name": f"Trigger: {title}",
                    "severity": severity,
                    "condition": {
                        "script": {
                            "source": "ctx.results[0].hits.total.value > 0",
                            "lang": "painless"
                        }
                    },
                    "actions": [
                        {
                            "name": f"Notify Shuffle SOAR - {technique}",
                            "destination_id": destination_id,
                            "message_template": {
                                "source": json.dumps({
                                    "monitor_name": "{{ctx.monitor.name}}",
                                    "trigger_name": "{{ctx.trigger.name}}",
                                    "severity": severity,
                                    "mitre_technique": technique,
                                    "mitre_tactic": tactic,
                                    "rule_level": level,
                                    "period_start": "{{ctx.periodStart}}",
                                    "period_end": "{{ctx.periodEnd}}",
                                    "total_hits": "{{ctx.results.0.hits.total.value}}",
                                    "description": str(description)[:500]
                                }, indent=2)
                            },
                            "throttle_enabled": True,
                            "throttle": {
                                "value": 5,
                                "unit": "MINUTES"
                            }
                        }
                    ]
                }
            }
        ]
    }
    return monitor


def discover_rules():
    """Find all Sigma rules excluding yara-l/."""
    pattern = os.path.join(RULES_DIR, "**", "*.yml")
    rules = []
    for path in glob.glob(pattern, recursive=True):
        if "yara-l" not in path.replace("\\", "/"):
            rules.append(path)
    return sorted(rules)


def main():
    print("=" * 70)
    print("PurpleForge — OpenSearch Monitor Deployment")
    print("=" * 70)

    print(f"\n[*] Connecting to OpenSearch at {OPENSEARCH_URL}...")
    try:
        client = get_client()
        info = client.info()
        print(f"  [+] Connected to OpenSearch {info.get('version', {}).get('number', 'unknown')}")
    except Exception as e:
        print(f"  [!] Failed to connect: {e}")
        sys.exit(1)

    # Create/get webhook destination
    print("\n[*] Configuring Shuffle SOAR webhook destination...")
    destination_id = create_destination(client)

    # Process rules
    rules = discover_rules()
    print(f"\n[*] Deploying {len(rules)} monitors...\n")

    deployed = 0
    errors = 0

    for rule_path in rules:
        rule_filename = os.path.basename(rule_path)

        with open(rule_path, "r", encoding="utf-8") as f:
            rule_data = yaml.safe_load(f)

        # Compile to OpenSearch query
        query_dsl, compile_error = compile_sigma_rule(rule_path)
        if compile_error:
            print(f"  [-] SKIP {rule_filename}: {compile_error[:60]}")
            errors += 1
            continue

        # Build and deploy monitor
        monitor_payload = build_monitor_payload(rule_data, query_dsl, destination_id)

        try:
            # Check for existing monitor with same name
            monitor_name = monitor_payload["name"]
            search_resp = client.transport.perform_request(
                "GET", "/_plugins/_alerting/monitors/_search",
                body={"query": {"term": {"monitor.name.keyword": monitor_name}}}
            )
            existing = search_resp.get("hits", {}).get("hits", [])

            if existing:
                monitor_id = existing[0]["_id"]
                client.transport.perform_request(
                    "PUT", f"/_plugins/_alerting/monitors/{monitor_id}",
                    body=monitor_payload
                )
                print(f"  [~] Updated: {monitor_name}")
            else:
                client.transport.perform_request(
                    "POST", "/_plugins/_alerting/monitors",
                    body=monitor_payload
                )
                print(f"  [+] Created: {monitor_name}")
            deployed += 1
        except Exception as e:
            print(f"  [-] ERROR deploying {rule_filename}: {e}")
            errors += 1

    print(f"\n{'=' * 70}")
    print(f"Deployment Summary:")
    print(f"  Monitors deployed:  {deployed}")
    print(f"  Errors:             {errors}")
    print(f"  Target index:       {TARGET_INDEX}")
    print(f"  Schedule:           Every {MONITOR_SCHEDULE_INTERVAL} {MONITOR_SCHEDULE_UNIT}")
    print(f"  Webhook:            {SHUFFLE_WEBHOOK_URL[:60]}...")
    print(f"{'=' * 70}")

    if errors > 0 and deployed == 0:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
