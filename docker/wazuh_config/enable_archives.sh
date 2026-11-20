#!/bin/bash
# ==============================================================================
# enable_archives.sh — PurpleForge Wazuh Archives Telemetry Activator
#
# Enables raw telemetry archival (<logall_json>yes</logall_json>) in ossec.conf
# and enables filebeat archive indexing to stream into wazuh-archives-*.
# This ensures all raw Windows, Sysmon, and network telemetry is accessible
# by OpenSearch monitors even if standard Wazuh rules do not trigger an alert.
# ==============================================================================

set -euo pipefail

OSSEC_CONF="/var/ossec/etc/ossec.conf"
FILEBEAT_CONF="/etc/filebeat/filebeat.yml"

echo "[*] PurpleForge: Activating raw archive telemetry on Wazuh Manager..."

# 1. Enable logall_json in ossec.conf
if [ -f "$OSSEC_CONF" ]; then
    echo "  [+] Configuring logall_json in ${OSSEC_CONF}..."
    if grep -q "<logall_json>" "$OSSEC_CONF"; then
        sed -i 's/<logall_json>.*<\/logall_json>/<logall_json>yes<\/logall_json>/g' "$OSSEC_CONF"
    else
        sed -i '/<ossec_config>/a \  <global>\n    <logall_json>yes</logall_json>\n  </global>' "$OSSEC_CONF"
    fi
    echo "  [✓] ossec.conf updated: logall_json=yes"
else
    echo "  [-] Warning: ${OSSEC_CONF} not found."
fi

# 2. Enable archives in Filebeat
if [ -f "$FILEBEAT_CONF" ]; then
    echo "  [+] Enabling archives module in ${FILEBEAT_CONF}..."
    if ! grep -Eq '^[[:space:]]*archives:[[:space:]]*$' "$FILEBEAT_CONF"; then
        echo "  [-] Error: archives section not found in ${FILEBEAT_CONF}." >&2
        exit 1
    fi
    sed -i '/^[[:space:]]*archives:[[:space:]]*$/,/^[^[:space:]]/ s/^\([[:space:]]*enabled:[[:space:]]*\)false/\1true/' "$FILEBEAT_CONF"
    echo "  [✓] Filebeat updated: archives=true"
else
    echo "  [-] Warning: ${FILEBEAT_CONF} not found."
fi

# This runs during container initialization, before the supervised services start.
# Restarting them here starts Filebeat twice and causes its data-path lock failure.
echo "[✓] PurpleForge: Archive settings applied; Wazuh and Filebeat will start with them."
