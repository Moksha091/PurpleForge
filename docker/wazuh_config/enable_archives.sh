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
    sed -i 's/archives:\s*false/archives: true/g' "$FILEBEAT_CONF"
    # Ensure archives section is enabled if commented
    sed -i 's/#archives:/archives:/g' "$FILEBEAT_CONF"
    sed -i 's/#\s*enabled:\s*false/  enabled: true/g' "$FILEBEAT_CONF"
    echo "  [✓] Filebeat updated: archives=true"
else
    echo "  [-] Warning: ${FILEBEAT_CONF} not found."
fi

# 3. Restart Filebeat and Wazuh Manager services
echo "[*] Restarting services to apply configuration changes..."
if command -v systemctl >/dev/null 2>&1; then
    systemctl restart wazuh-manager || /var/ossec/bin/wazuh-control restart
    systemctl restart filebeat || service filebeat restart
elif [ -f "/var/ossec/bin/wazuh-control" ]; then
    /var/ossec/bin/wazuh-control restart
    service filebeat restart || true
fi

echo "[✓] PurpleForge: Raw archive telemetry successfully activated (wazuh-archives-* active)!"
