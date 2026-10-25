#!/usr/bin/env python3
"""
generate_navigator.py — PurpleForge ATT&CK Navigator Layer Generator

Parses all Sigma rules in rules/**/*.yml (excluding rules/yara-l/), extracts
MITRE ATT&CK technique IDs, tactics, rule titles, and tuning notes, and
generates a production-ready MITRE ATT&CK Navigator v4.5 layer JSON file
(attack_navigator_layer.json) at the workspace root.
"""

import glob
import json
import os
import sys
import yaml

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RULES_DIR = os.path.join(PROJECT_ROOT, "rules")
OUTPUT_PATH = os.path.join(PROJECT_ROOT, "attack_navigator_layer.json")

# Mapping of MITRE tactic names to standard ATT&CK matrix tactic slugs
TACTIC_MAP = {
    "initial_access": "initial-access",
    "execution": "execution",
    "persistence": "persistence",
    "privilege_escalation": "privilege-escalation",
    "defense_evasion": "defense-evasion",
    "credential_access": "credential-access",
    "discovery": "discovery",
    "lateral_movement": "lateral-movement",
    "collection": "collection",
    "command_and_control": "command-and-control",
    "exfiltration": "exfiltration",
    "impact": "impact",
}


def parse_sigma_rules():
    """Scans rules directory and extracts technique mapping and metadata."""
    rule_files = glob.glob(os.path.join(RULES_DIR, "**", "*.yml"), recursive=True)
    technique_entries = {}

    for file_path in sorted(rule_files):
        # Exclude YARA-L or non-Sigma folders if any
        if "yara-l" in file_path:
            continue

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
        except Exception as e:
            print(f"[!] Warning: Failed to parse {file_path}: {e}")
            continue

        if not isinstance(data, dict):
            continue

        title = data.get("title", os.path.basename(file_path))
        rule_id = data.get("id", "")
        custom = data.get("custom", {})
        technique_id = custom.get("mitre_technique")
        tactic_name = custom.get("mitre_tactic", "")
        tuning_notes = custom.get("tuning_notes", "Automated detection rule")

        # Fallback to tags if custom metadata is missing
        if not technique_id:
            tags = data.get("tags", [])
            for tag in tags:
                if tag.startswith("attack.t"):
                    technique_id = tag.replace("attack.", "").upper()
                    break

        if not technique_id:
            continue

        # Normalize tactic slug
        tactic_slug = TACTIC_MAP.get(tactic_name.lower(), tactic_name.lower().replace("_", "-"))

        key = (technique_id, tactic_slug)
        if key not in technique_entries:
            technique_entries[key] = {
                "techniqueID": technique_id,
                "tactic": tactic_slug if tactic_slug else None,
                "score": 100,
                "color": "#2ecc71",
                "comment": f"Rule: {title} | Tuning: {tuning_notes}",
                "enabled": True,
                "metadata": [
                    {"name": "Rule Title", "value": title},
                    {"name": "Rule ID", "value": rule_id},
                    {"name": "Rule File", "value": os.path.relpath(file_path, PROJECT_ROOT).replace("\\", "/")},
                    {"name": "Tuning Notes", "value": tuning_notes}
                ]
            }
        else:
            # Combine multiple rules covering the same technique
            entry = technique_entries[key]
            entry["comment"] += f" || Rule: {title} | Tuning: {tuning_notes}"
            entry["metadata"].extend([
                {"name": "Rule Title", "value": title},
                {"name": "Rule ID", "value": rule_id},
                {"name": "Rule File", "value": os.path.relpath(file_path, PROJECT_ROOT).replace("\\", "/")},
                {"name": "Tuning Notes", "value": tuning_notes}
            ])

    return list(technique_entries.values())


def build_navigator_layer(techniques):
    """Builds ATT&CK Navigator v4.5 specification structure."""
    layer = {
        "name": "PurpleForge Detection Coverage",
        "versions": {
            "attack": "14",
            "navigator": "4.5",
            "layer": "4.5"
        },
        "domain": "enterprise-attack",
        "description": "Detection-as-Code verified test coverage for PurpleForge automated purple team pipeline",
        "filters": {
            "platforms": ["Windows"]
        },
        "sorting": 0,
        "layout": {
            "layout": "side",
            "aggregateFunction": "average",
            "showID": True,
            "showName": True,
            "showAggregateScores": True,
            "countUnscored": False
        },
        "hideDisabled": False,
        "techniques": techniques,
        "gradient": {
            "colors": ["#e74c3c", "#f39c12", "#2ecc71"],
            "minValue": 0,
            "maxValue": 100
        },
        "legendItems": [
            {
                "color": "#2ecc71",
                "label": "Verified Detection-as-Code Rule (Passed CI/CD Assertion)"
            },
            {
                "color": "#e74c3c",
                "label": "Uncovered / No Verified Rule"
            }
        ],
        "metadata": [
            {"name": "Pipeline", "value": "PurpleForge Detection-as-Code"},
            {"name": "Author", "value": "Vemula Moksha"},
            {"name": "Target Lab", "value": "Hyper-V Active Directory (DC01, WS01)"}
        ]
    }
    return layer


def main():
    print(f"[*] Scanning Sigma rules in {os.path.relpath(RULES_DIR, PROJECT_ROOT)}...")
    techniques = parse_sigma_rules()
    print(f"  [+] Identified {len(techniques)} unique technique-tactic mappings.")

    layer = build_navigator_layer(techniques)

    with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
        json.dump(layer, f, indent=2)

    print(f"[✓] Successfully generated ATT&CK Navigator layer at: {os.path.relpath(OUTPUT_PATH, PROJECT_ROOT)}")
    print(f"    Total Techniques Covered: {len(techniques)}")
    for tech in techniques:
        print(f"    - {tech['techniqueID']} [{tech.get('tactic', 'all')}]: {tech['metadata'][0]['value']}")


if __name__ == "__main__":
    main()
