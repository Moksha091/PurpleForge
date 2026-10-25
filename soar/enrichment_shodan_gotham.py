#!/usr/bin/env python3
"""
enrichment_shodan_gotham.py — PurpleForge Threat Intelligence Enrichment Node

Queries external Threat Intelligence APIs (VirusTotal v3, AbuseIPDB, and Shodan)
to enrich observables extracted from OpenSearch / Wazuh alerts.

Provides fallback mock data when API keys are not supplied so that automated
lab workflows and testing suites can execute deterministically without external dependencies.

Author: Vemula Moksha
Project: PurpleForge Detection-as-Code
"""

import argparse
import json
import os
import sys
import requests
from datetime import datetime, timezone

# Ensure UTF-8 output on Windows consoles
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

VT_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "")
ABUSEIPDB_API_KEY = os.environ.get("ABUSEIPDB_API_KEY", "")
SHODAN_API_KEY = os.environ.get("SHODAN_API_KEY", "")


def query_virustotal(target_hash_or_ip):
    """Queries VirusTotal v3 for file hash or IP reputation."""
    if not VT_API_KEY:
        # Return deterministic simulation payload
        return {
            "source": "VirusTotal_Mock",
            "malicious_count": 48 if len(target_hash_or_ip) == 32 or len(target_hash_or_ip) == 64 else 0,
            "suspicious_count": 2,
            "harmless_count": 14,
            "reputation": -35 if len(target_hash_or_ip) in (32, 64) else 0,
            "tags": ["trojan", "mimikatz", "ransomware"] if len(target_hash_or_ip) in (32, 64) else []
        }

    url = f"https://www.virustotal.com/api/v3/files/{target_hash_or_ip}"
    headers = {"x-apikey": VT_API_KEY}
    try:
        resp = requests.get(url, headers=headers, timeout=10)
        if resp.status_code == 200:
            stats = resp.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            return {
                "source": "VirusTotal_Live",
                "malicious_count": stats.get("malicious", 0),
                "suspicious_count": stats.get("suspicious", 0),
                "harmless_count": stats.get("harmless", 0),
                "reputation": resp.json().get("data", {}).get("attributes", {}).get("reputation", 0),
                "tags": resp.json().get("data", {}).get("attributes", {}).get("tags", [])
            }
    except Exception as e:
        print(f"[!] VT Query error: {e}", file=sys.stderr)

    return {"source": "VirusTotal_Error", "malicious_count": 0, "suspicious_count": 0, "harmless_count": 0}


def query_abuseipdb(ip_address):
    """Queries AbuseIPDB v2 for IP reputation confidence score."""
    if not ABUSEIPDB_API_KEY:
        # Return deterministic simulation payload
        is_suspicious = ip_address.startswith("198.51.") or ip_address.startswith("203.0.113.")
        return {
            "source": "AbuseIPDB_Mock",
            "ipAddress": ip_address,
            "abuseConfidenceScore": 88 if is_suspicious else 0,
            "totalReports": 34 if is_suspicious else 0,
            "isWhitelisted": False,
            "countryCode": "RU" if is_suspicious else "US"
        }

    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip_address, "maxAgeInDays": 90}
    try:
        resp = requests.get(url, headers=headers, params=params, timeout=10)
        if resp.status_code == 200:
            data = resp.json().get("data", {})
            return {
                "source": "AbuseIPDB_Live",
                "ipAddress": data.get("ipAddress", ip_address),
                "abuseConfidenceScore": data.get("abuseConfidenceScore", 0),
                "totalReports": data.get("totalReports", 0),
                "isWhitelisted": data.get("isWhitelisted", False),
                "countryCode": data.get("countryCode", "UNKNOWN")
            }
    except Exception as e:
        print(f"[!] AbuseIPDB error: {e}", file=sys.stderr)

    return {"source": "AbuseIPDB_Error", "ipAddress": ip_address, "abuseConfidenceScore": 0}


def query_shodan(ip_address):
    """Queries Shodan for host intelligence, open ports, and vulnerabilities."""
    if not SHODAN_API_KEY:
        # Return deterministic simulation payload
        is_c2 = ip_address.startswith("198.51.") or ip_address.startswith("203.0.113.")
        return {
            "source": "Shodan_Mock",
            "ip": ip_address,
            "ports": [4444, 8080, 8443] if is_c2 else [80, 443],
            "vulns": ["CVE-2023-38831", "CVE-2021-44228"] if is_c2 else [],
            "org": "Suspicious VPS Hosting Ltd" if is_c2 else "Cloudflare, Inc.",
            "os": "Linux 5.x"
        }

    url = f"https://api.shodan.io/shodan/host/{ip_address}?key={SHODAN_API_KEY}"
    try:
        resp = requests.get(url, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            return {
                "source": "Shodan_Live",
                "ip": ip_address,
                "ports": data.get("ports", []),
                "vulns": list(data.get("vulns", [])),
                "org": data.get("org", "Unknown"),
                "os": data.get("os", "Unknown")
            }
    except Exception as e:
        print(f"[!] Shodan error: {e}", file=sys.stderr)

    return {"source": "Shodan_Error", "ip": ip_address, "ports": [], "vulns": []}


def enrich_observable(ip=None, file_hash=None):
    """Coordinates enrichment across all sources and returns consolidated payload."""
    enrichment_result = {
        "enrichment_timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "observables": {
            "ip": ip,
            "hash": file_hash
        },
        "virustotal": query_virustotal(file_hash if file_hash else (ip if ip else "")),
        "abuseipdb": query_abuseipdb(ip) if ip else None,
        "shodan": query_shodan(ip) if ip else None
    }
    return enrichment_result


def main():
    parser = argparse.ArgumentParser(description="PurpleForge Threat Intelligence Enrichment Node")
    parser.add_argument("--ip", help="IP address to enrich")
    parser.add_argument("--hash", help="File hash (MD5, SHA1, SHA256) to enrich")
    args = parser.parse_args()

    target_ip = args.ip if args.ip else "198.51.100.45"
    target_hash = args.hash if args.hash else "44d88612fea8a8f36de82e1278abb02f"

    result = enrich_observable(ip=target_ip, file_hash=target_hash)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
