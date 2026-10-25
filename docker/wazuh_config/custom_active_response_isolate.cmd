@echo off
:: ==============================================================================
:: custom_active_response_isolate.cmd — PurpleForge Automated Host Isolation
#
:: Deployed to: C:\Program Files (x86)\ossec-agent\active-response\bin\isolate-host.cmd
:: Invoked by Wazuh Active Response engine upon high-confidence alert detection
:: (e.g. Ransomware T1486 or LSASS Dumping T1003.001 approved by SOAR).
::
:: Action 'add'    : Isolates host via Windows Firewall, preserving connection ONLY
::                   to the SECOPS Tailscale IP (Wazuh Manager + Velociraptor).
:: Action 'delete' : Restores normal Windows Firewall policy and removes isolation rules.
:: ==============================================================================

setlocal enabledelayedexpansion

:: SECOPS Management Tailscale IP (Wazuh Manager, Velociraptor, SOAR)
set SECOPS_IP=100.64.0.10
set LOG_FILE=C:\Program Files (x86)\ossec-agent\active-response\active-responses.log

:: Read input arguments passed by Wazuh Active Response
:: Args typically: <action> <user> <ip> ...
set ACTION=%1

if "%ACTION%"=="" (
    set ACTION=add
)

echo [%date% %time%] PurpleForge Active Response invoked with action: %ACTION% >> "%LOG_FILE%"

if /i "%ACTION%"=="add" goto :ISOLATE_HOST
if /i "%ACTION%"=="delete" goto :RESTORE_HOST
goto :UNKNOWN_ACTION

:ISOLATE_HOST
echo [%date% %time%] [!] ALERT: Initiating emergency host isolation! >> "%LOG_FILE%"

:: 1. Add inbound rule allowing ONLY the SECOPS server
netsh advfirewall firewall add rule name="PurpleForge-SECOPS-Inbound" dir=in action=allow remoteip=%SECOPS_IP% protocol=any >nul 2>&1

:: 2. Add outbound rule allowing ONLY the SECOPS server
netsh advfirewall firewall add rule name="PurpleForge-SECOPS-Outbound" dir=out action=allow remoteip=%SECOPS_IP% protocol=any >nul 2>&1

:: 3. Add loopback rule for local system services
netsh advfirewall firewall add rule name="PurpleForge-Loopback-In" dir=in action=allow remoteip=127.0.0.1 protocol=any >nul 2>&1
netsh advfirewall firewall add rule name="PurpleForge-Loopback-Out" dir=out action=allow remoteip=127.0.0.1 protocol=any >nul 2>&1

:: 4. Block all other inbound and outbound traffic across all profiles
netsh advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound >nul 2>&1

echo [%date% %time%] [✓] Host isolated. Only SECOPS management IP (%SECOPS_IP%) allowed. >> "%LOG_FILE%"
exit /b 0

:RESTORE_HOST
echo [%date% %time%] [*] Restoring default network policy... >> "%LOG_FILE%"

:: 1. Delete custom isolation rules
netsh advfirewall firewall delete rule name="PurpleForge-SECOPS-Inbound" >nul 2>&1
netsh advfirewall firewall delete rule name="PurpleForge-SECOPS-Outbound" >nul 2>&1
netsh advfirewall firewall delete rule name="PurpleForge-Loopback-In" >nul 2>&1
netsh advfirewall firewall delete rule name="PurpleForge-Loopback-Out" >nul 2>&1

:: 2. Restore default firewall policy (Block inbound, Allow outbound)
netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound >nul 2>&1

echo [%date% %time%] [✓] Normal host connectivity restored. >> "%LOG_FILE%"
exit /b 0

:UNKNOWN_ACTION
echo [%date% %time%] [-] ERROR: Unknown action parameter '%ACTION%'. Valid options: add | delete >> "%LOG_FILE%"
exit /b 1
