#!/usr/bin/env python3
"""
risk_score_calculator.py — PurpleForge SOAR Weighted Risk Score Engine

Calculates composite risk scores for incoming alerts enriched by Threat Intelligence:
  Risk_Score = Base_Rule_Score + (VT_Malicious * 5) + (AbuseIPDB_Confidence * 0.3) + (Shodan_Open_Ports_Weight)

Normalizes score between 0 and 100, assigns severity categories, and logs
lifecycle telemetry timestamps (event_time, alert_time, enrichment_time, approval_time, isolation_time)
to enable automated calculation of MTTD and MTTR.

Author: Vemula Moksha
Project: PurpleForge Detection-as-Code
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone

# Ensure UTF-8 output on Windows consoles
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

# Baseline severity weights
SEVERITY_BASE_SCORES = {
    "informational": 10.0,
    "low": 25.0,
    "medium": 50.0,
    "high": 75.0,
    "critical": 90.0
}

# Suspicious port weights for Shodan exposure
SUSPICIOUS_PORTS = {
    4444: 15.0,  # Metasploit default
    8080: 5.0,
    8443: 5.0,
    3389: 10.0,  # External RDP
    445: 20.0,   # External SMB
    22: 5.0,     # SSH
    5985: 10.0,  # WinRM HTTP
    5986: 10.0   # WinRM HTTPS
}


def parse_timestamp(ts_str):
    """Parses ISO timestamp string to datetime object."""
    if not ts_str:
        return None
    try:
        return datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
    except Exception:
        return None


def calculate_risk(base_level="high", vt_malicious=0, abuseipdb_confidence=0,
                   shodan_ports=None, event_time=None, alert_time=None,
                   enrichment_time=None, approval_time=None, isolation_time=None):
    """
    Computes composite risk score and lifecycle durations.
    """
    if shodan_ports is None:
        shodan_ports = []

    # 1. Base Score
    if isinstance(base_level, (int, float)):
        base_score = float(base_level)
    else:
        base_score = SEVERITY_BASE_SCORES.get(str(base_level).lower(), 50.0)

    # 2. VirusTotal weight: 5 points per malicious detection engine
    vt_weight = min(40.0, float(vt_malicious) * 5.0)

    # 3. AbuseIPDB weight: 0.3 * confidence score (0 to 100) -> max 30 points
    abuse_weight = min(30.0, float(abuseipdb_confidence) * 0.3)

    # 4. Shodan ports weight
    port_weight = 0.0
    for p in shodan_ports:
        port_weight += SUSPICIOUS_PORTS.get(int(p), 2.0)
    port_weight = min(25.0, port_weight)

    # Raw composite score
    raw_score = base_score + vt_weight + abuse_weight + port_weight
    final_score = min(100.0, max(0.0, round(raw_score, 1)))

    # Classification
    if final_score >= 85.0:
        severity_level = "CRITICAL"
        recommended_action = "IMMEDIATE_HOST_ISOLATION_AND_TRIAGE"
    elif final_score >= 65.0:
        severity_level = "HIGH"
        recommended_action = "ANALYST_APPROVAL_GATE_HOST_ISOLATION"
    elif final_score >= 45.0:
        severity_level = "MEDIUM"
        recommended_action = "ENRICH_AND_LOG_TICKET"
    else:
        severity_level = "LOW"
        recommended_action = "INFORMATIONAL_MONITORING"

    # Time metrics (MTTD, MTTR)
    now_utc = datetime.now(timezone.utc)
    t_event = parse_timestamp(event_time) or now_utc
    t_alert = parse_timestamp(alert_time) or now_utc
    t_enrich = parse_timestamp(enrichment_time) or now_utc
    t_approval = parse_timestamp(approval_time) or now_utc
    t_isolate = parse_timestamp(isolation_time) or now_utc

    mttd_seconds = max(0.0, round((t_alert - t_event).total_seconds(), 2))
    mttr_seconds = max(0.0, round((t_isolate - t_alert).total_seconds(), 2))

    return {
        "evaluation_timestamp_utc": now_utc.isoformat(),
        "final_score": final_score,
        "severity_level": severity_level,
        "recommended_action": recommended_action,
        "score_breakdown": {
            "base_score": base_score,
            "virustotal_weight": round(vt_weight, 1),
            "abuseipdb_weight": round(abuse_weight, 1),
            "shodan_port_weight": round(port_weight, 1)
        },
        "lifecycle_timestamps": {
            "event_time_utc": t_event.isoformat(),
            "alert_time_utc": t_alert.isoformat(),
            "enrichment_time_utc": t_enrich.isoformat(),
            "approval_time_utc": t_approval.isoformat(),
            "isolation_time_utc": t_isolate.isoformat()
        },
        "metrics_delta": {
            "mttd_seconds": mttd_seconds,
            "mttr_seconds": mttr_seconds
        }
    }


def main():
    parser = argparse.ArgumentParser(description="PurpleForge Weighted Risk Score Engine")
    parser.add_argument("--base-level", default="high", help="Rule severity level or numeric score")
    parser.add_argument("--vt-malicious", type=int, default=12, help="Number of VT engines marking observable malicious")
    parser.add_argument("--abuse-confidence", type=int, default=85, help="AbuseIPDB confidence percentage (0-100)")
    parser.add_argument("--shodan-ports", nargs="*", type=int, default=[4444, 8080], help="List of open ports")
    parser.add_argument("--event-time", default="2026-10-25T03:10:00Z", help="Event occurrence ISO timestamp")
    parser.add_argument("--alert-time", default="2026-10-25T03:10:38Z", help="Alert detection ISO timestamp")
    parser.add_argument("--isolation-time", default="2026-10-25T03:11:42Z", help="Host isolation ISO timestamp")
    args = parser.parse_args()

    result = calculate_risk(
        base_level=args.base_level,
        vt_malicious=args.vt_malicious,
        abuseipdb_confidence=args.abuse_confidence,
        shodan_ports=args.shodan_ports,
        event_time=args.event_time,
        alert_time=args.alert_time,
        isolation_time=args.isolation_time
    )

    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
