#!/usr/bin/env python3
"""
test_runner.py — PurpleForge Detection Test Runner

Connects to OpenSearch (localhost:9200), indexes TP and TN test logs,
compiles each Sigma rule via pySigma, executes queries, and asserts
TP >= 1 and TN == 0 for every rule. Outputs a formatted ASCII table.
"""

import json
import os
import sys
import glob
import subprocess
import time
import yaml

try:
    from opensearchpy import OpenSearch
    from tabulate import tabulate
except ImportError:
    print("[!] Missing dependencies. Run: pip install opensearch-py tabulate")
    sys.exit(1)


PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RULES_DIR = os.path.join(PROJECT_ROOT, "rules")
TESTS_TP_DIR = os.path.join(PROJECT_ROOT, "tests", "tp")
TESTS_TN_DIR = os.path.join(PROJECT_ROOT, "tests", "tn")
PIPELINE_PATH = os.path.join(PROJECT_ROOT, "pipelines", "wazuh_opensearch.yml")

OPENSEARCH_URL = os.environ.get("OPENSEARCH_URL", "https://localhost:9200")
OPENSEARCH_USER = os.environ.get("OPENSEARCH_USER", "admin")
OPENSEARCH_PASS = os.environ.get("OPENSEARCH_PASS", "admin")

INDEX_TP = "test-tp"
INDEX_TN = "test-tn"


def get_client():
    """Create OpenSearch client with proper SSL/auth configuration."""
    parsed = OPENSEARCH_URL.replace("https://", "").replace("http://", "")
    host_port = parsed.split(":")
    host = host_port[0]
    port = int(host_port[1]) if len(host_port) > 1 else 9200
    use_ssl = OPENSEARCH_URL.startswith("https")

    client = OpenSearch(
        hosts=[{"host": host, "port": port}],
        http_auth=(OPENSEARCH_USER, OPENSEARCH_PASS) if OPENSEARCH_USER else None,
        use_ssl=use_ssl,
        verify_certs=False,
        ssl_show_warn=False,
        timeout=30,
    )
    return client


def cleanup_indices(client):
    """Delete test indices if they exist."""
    for idx in [INDEX_TP, INDEX_TN]:
        if client.indices.exists(index=idx):
            client.indices.delete(index=idx)
            print(f"  [*] Deleted existing index: {idx}")


def index_document(client, index, doc, doc_id=None):
    """Index a single document into OpenSearch."""
    client.index(index=index, body=doc, id=doc_id, refresh="wait_for")


def index_tn_baseline(client):
    """Index all benign baseline events into test-tn index."""
    tn_path = os.path.join(TESTS_TN_DIR, "benign_baseline.json")
    if not os.path.exists(tn_path):
        print(f"  [!] TN baseline not found: {tn_path}")
        return 0

    with open(tn_path, "r", encoding="utf-8") as f:
        events = json.load(f)

    if isinstance(events, list):
        for i, event in enumerate(events):
            index_document(client, INDEX_TN, event, doc_id=f"tn-{i}")
        return len(events)
    else:
        index_document(client, INDEX_TN, events, doc_id="tn-0")
        return 1


def compile_sigma_rule(rule_path):
    """Compile a Sigma rule to OpenSearch Lucene query using sigma-cli."""
    try:
        result = subprocess.run(
            [
                sys.executable, "-m", "sigma", "convert",
                "-t", "opensearch",
                "-p", PIPELINE_PATH,
                "--without-pipeline",
                rule_path,
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode == 0:
            return result.stdout.strip(), None
        else:
            return None, result.stderr.strip()
    except FileNotFoundError:
        # Fallback: try sigma CLI directly
        try:
            result = subprocess.run(
                ["sigma", "convert", "-t", "opensearch",
                 "-p", PIPELINE_PATH, "--without-pipeline", rule_path],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0:
                return result.stdout.strip(), None
            return None, result.stderr.strip()
        except FileNotFoundError:
            return None, "sigma-cli not found in PATH"
    except subprocess.TimeoutExpired:
        return None, "Compilation timed out"


def search_index(client, index, query_string):
    """Execute a Lucene query string against an index and return hit count."""
    try:
        body = {
            "query": {
                "query_string": {
                    "query": query_string,
                    "default_operator": "AND"
                }
            }
        }
        result = client.search(index=index, body=body)
        return result["hits"]["total"]["value"]
    except Exception as e:
        return -1


def discover_rules():
    """Find all Sigma rule YAML files, excluding yara-l/."""
    pattern = os.path.join(RULES_DIR, "**", "*.yml")
    rules = []
    for path in glob.glob(pattern, recursive=True):
        if "yara-l" not in path.replace("\\", "/"):
            rules.append(path)
    return sorted(rules)


def main():
    print("=" * 80)
    print("PurpleForge — Detection Test Runner (test_runner.py)")
    print("=" * 80)

    # Connect to OpenSearch
    print(f"\n[*] Connecting to OpenSearch at {OPENSEARCH_URL}...")
    try:
        client = get_client()
        info = client.info()
        print(f"  [+] Connected to OpenSearch {info.get('version', {}).get('number', 'unknown')}")
    except Exception as e:
        print(f"  [!] Failed to connect to OpenSearch: {e}")
        print("  [!] Ensure OpenSearch is running on localhost:9200")
        sys.exit(1)

    # Cleanup and index TN baseline
    print("\n[*] Preparing test indices...")
    cleanup_indices(client)
    tn_count = index_tn_baseline(client)
    print(f"  [+] Indexed {tn_count} TN (benign) events")

    # Discover and test rules
    rules = discover_rules()
    print(f"\n[*] Testing {len(rules)} Sigma rules...\n")

    results = []
    failures = 0

    for rule_path in rules:
        rule_filename = os.path.basename(rule_path)
        tactic = os.path.basename(os.path.dirname(rule_path))

        # Load rule to get TP file path
        with open(rule_path, "r", encoding="utf-8") as f:
            rule_data = yaml.safe_load(f)

        custom = rule_data.get("custom", {})
        tp_file = custom.get("tp_file", "")
        rule_title = rule_data.get("title", rule_filename)
        technique = custom.get("mitre_technique", "N/A")

        # Index TP event
        tp_path = os.path.join(PROJECT_ROOT, tp_file.replace("/", os.sep)) if tp_file else None
        tp_indexed = False
        if tp_path and os.path.exists(tp_path):
            # Clean TP index for each rule test
            if client.indices.exists(index=INDEX_TP):
                client.indices.delete(index=INDEX_TP)
            with open(tp_path, "r", encoding="utf-8") as f:
                tp_event = json.load(f)
            index_document(client, INDEX_TP, tp_event, doc_id="tp-0")
            tp_indexed = True

        # Compile Sigma rule
        query, compile_error = compile_sigma_rule(rule_path)

        if compile_error:
            results.append([
                technique, rule_filename, "COMPILE_ERR", "-", "-", "FAIL",
                compile_error[:50]
            ])
            failures += 1
            continue

        if not query:
            results.append([
                technique, rule_filename, "NO_QUERY", "-", "-", "FAIL",
                "Empty query output"
            ])
            failures += 1
            continue

        # Execute query against TP and TN indices
        tp_hits = search_index(client, INDEX_TP, query) if tp_indexed else -1
        tn_hits = search_index(client, INDEX_TN, query)

        # Evaluate pass/fail
        tp_pass = tp_hits >= 1
        tn_pass = tn_hits == 0
        overall = "PASS" if (tp_pass and tn_pass) else "FAIL"

        if overall == "FAIL":
            failures += 1
            note = []
            if not tp_pass:
                note.append(f"TP={tp_hits}")
            if not tn_pass:
                note.append(f"TN={tn_hits}")
            note_str = ", ".join(note)
        else:
            note_str = ""

        results.append([
            technique, rule_filename[:40], query[:30] + "...", tp_hits, tn_hits,
            overall, note_str
        ])

    # Print results table
    print("\n" + "=" * 80)
    headers = ["Technique", "Rule", "Query (trunc)", "TP Hits", "TN Hits", "Result", "Notes"]
    print(tabulate(results, headers=headers, tablefmt="grid"))

    # Summary
    total = len(results)
    passed = total - failures
    print(f"\n{'=' * 80}")
    print(f"Results: {passed}/{total} rules passed  |  {failures} failures")
    print(f"{'=' * 80}")

    if failures > 0:
        print("\n[✗] DETECTION TESTS FAILED!")
        sys.exit(1)
    else:
        print("\n[✓] All detection tests passed!")
        sys.exit(0)


if __name__ == "__main__":
    main()
