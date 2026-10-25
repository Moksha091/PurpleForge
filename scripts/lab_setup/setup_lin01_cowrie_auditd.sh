#!/usr/bin/env bash
# ==============================================================================
# setup_lin01_cowrie_auditd.sh — PurpleForge Linux Honeypot & Telemetry Setup
#
# Configures LIN01 (Debian/Ubuntu) as an SSH honeypot (Cowrie) with auditd
# monitoring execution and lateral movement, shipping all telemetry via Wazuh Agent.
# ==============================================================================

set -euo pipefail

SECOPS_IP="${1:-100.64.0.10}"

echo "======================================================================"
echo "PurpleForge Linux Sensor & Cowrie Honeypot Setup (LIN01)"
echo "Targeting SECOPS Server: ${SECOPS_IP}"
echo "======================================================================"

# 1. Update package manager and install core dependencies
echo "[*] Installing auditd, python3-virtualenv, and git..."
apt-get update -qq
apt-get install -y -qq auditd audispd-plugins git python3-virtualenv python3-pip libssl-dev libffi-dev build-essential authbind

# 2. Configure auditd for process execution and sensitive file access
echo "[*] Configuring auditd rules..."
cat << 'EOF' > /etc/audit/rules.d/purpleforge.rules
# Delete all current rules
-D

# Buffer Size
-b 8192

# Failure Mode (1 = printk, 2 = panic)
-f 1

# Monitor execution of commands (64-bit and 32-bit execve)
-a always,exit -F arch=b64 -S execve -k purpleforge_exec
-a always,exit -F arch=b32 -S execve -k purpleforge_exec

# Monitor sensitive file access
-w /etc/passwd -p wa -k identity_tampering
-w /etc/shadow -p rwa -k credential_access
-w /etc/sudoers -p wa -k privesc_tampering
-w /root/.ssh/authorized_keys -p wa -k persistence_ssh
EOF

augenrules --load || systemctl restart auditd
echo "  [✓] auditd rules active."

# 3. Setup Cowrie SSH Honeypot
echo "[*] Setting up Cowrie SSH / Telnet honeypot..."
if ! id "cowrie" &>/dev/null; then
    adduser --disabled-password --gecos "" cowrie
fi

COWRIE_HOME="/home/cowrie/cowrie"
if [ ! -d "$COWRIE_HOME" ]; then
    echo "  [+] Cloning Cowrie repository..."
    su - cowrie -c "git clone https://github.com/cowrie/cowrie.git $COWRIE_HOME"
    su - cowrie -c "cd $COWRIE_HOME && virtualenv --python=python3 cowrie-env && . cowrie-env/bin/activate && pip install -q -r requirements.txt"
fi

# Move real SSH port to 2222 so Cowrie can bind to 22 (via authbind or iptables)
echo "  [+] Redirecting port 22 to Cowrie port 2222..."
sed -i 's/^#*Port .*/Port 22222/' /etc/ssh/sshd_config
systemctl restart ssh || systemctl restart sshd

# iptables redirect port 22 -> 2222 for Cowrie
iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222 || true

# 4. Install Wazuh Agent
echo "[*] Installing Wazuh Agent for Linux..."
if ! command -v /var/ossec/bin/wazuh-control >/dev/null 2>&1; then
    curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import
    chmod 644 /usr/share/keyrings/wazuh.gpg
    echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | tee -a /etc/apt/sources.list.d/wazuh.list
    apt-get update -qq
    WAZUH_MANAGER="${SECOPS_IP}" WAZUH_AGENT_NAME="LIN01" apt-get install -y -qq wazuh-agent
fi

# 5. Append Cowrie & Auditd log collection to ossec.conf
OSSEC_CONF="/var/ossec/etc/ossec.conf"
if [ -f "$OSSEC_CONF" ]; then
    echo "  [+] Adding Cowrie JSON and Audit log collection to ${OSSEC_CONF}..."
    if ! grep -q "cowrie.json" "$OSSEC_CONF"; then
        sed -i '/<\/ossec_config>/i \
  <localfile>\
    <location>/home/cowrie/cowrie/var/log/cowrie/cowrie.json</location>\
    <log_format>json</log_format>\
  </localfile>\
  <localfile>\
    <location>/var/log/audit/audit.log</location>\
    <log_format>audit</log_format>\
  </localfile>' "$OSSEC_CONF"
    fi
    /var/ossec/bin/wazuh-control restart
    echo "  [✓] Wazuh Agent restarted with Cowrie + auditd log ingestion."
fi

echo "======================================================================"
echo "[✓] LIN01 Honeypot and auditd sensor deployment completed!"
echo "======================================================================"
