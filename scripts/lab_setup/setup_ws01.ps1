<#
.SYNOPSIS
    setup_ws01.ps1 — PurpleForge Workstation (WS01) Target & Telemetry Setup
.DESCRIPTION
    Automates configuration of WS01 as the primary adversary emulation target:
      1. Disables unnecessary background bloat services (SysMain, WSearch) to preserve RAM.
      2. Enables PowerShell ScriptBlock Logging (EID 4104) and Transcription.
      3. Downloads and installs Microsoft Sysmon with Olaf Hartong's modular configuration.
      4. Installs and configures Wazuh Agent pointing to the SECOPS Tailscale IP.
      5. Configures Wazuh ossec.conf to ingest:
         - Microsoft-Windows-Sysmon/Operational
         - Microsoft-Windows-PowerShell/Operational
         - Security / System event channels
.NOTES
    Author: Vemula Moksha
    Target Host: WS01.corp.purpleforge.local
#>

[CmdletBinding()]
param(
    [string]$SecopsIP = "100.64.0.10",
    [string]$DomainName = "corp.purpleforge.local",
    [string]$SysmonConfigUrl = "https://raw.githubusercontent.com/olafhartong/sysmon-modular/master/sysmonconfig.xml",
    [string]$WazuhAgentInstallerUrl = "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.7.2-1.msi"
)

# Enforce Administrator privileges
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "[-] This script must be executed in an elevated session (Run as Administrator)."
    exit 1
}

Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "PurpleForge Workstation (WS01) Setup & Telemetry Pipeline" -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Cyan

# 1. Resource Optimization: Disable Resource-Heavy Services
Write-Host "`n[*] Disabling background bloat services (SysMain, WSearch)..." -ForegroundColor Yellow
$servicesToStop = @("SysMain", "WSearch")
foreach ($svc in $servicesToStop) {
    if (Get-Service -Name $svc -ErrorAction SilentlyContinue) {
        Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
        Set-Service -Name $svc -StartupType Disabled
        Write-Host "  [+] Disabled service: $svc" -ForegroundColor Green
    }
}

# 2. Enable PowerShell ScriptBlock Logging (Event ID 4104)
Write-Host "`n[*] Configuring PowerShell ScriptBlock Logging & Module Logging..." -ForegroundColor Yellow
$psPolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
if (-not (Test-Path $psPolicyPath)) { New-Item -Path $psPolicyPath -Force | Out-Null }
Set-ItemProperty -Path $psPolicyPath -Name "EnableScriptBlockLogging" -Value 1 -Type DWord -Force
Set-ItemProperty -Path $psPolicyPath -Name "EnableScriptBlockInvocationLogging" -Value 1 -Type DWord -Force

$psModPolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
if (-not (Test-Path $psModPolicyPath)) { New-Item -Path $psModPolicyPath -Force | Out-Null }
Set-ItemProperty -Path $psModPolicyPath -Name "EnableModuleLogging" -Value 1 -Type DWord -Force

Write-Host "  [+] PowerShell ScriptBlock Logging (4104) enabled." -ForegroundColor Green

# 3. Download and Install Sysmon
Write-Host "`n[*] Provisioning Microsoft Sysmon with modular configuration..." -ForegroundColor Yellow
$toolsDir = "C:\PurpleForge\Tools"
if (-not (Test-Path $toolsDir)) { New-Item -ItemType Directory -Path $toolsDir -Force | Out-Null }

$sysmonExe = Join-Path $toolsDir "Sysmon64.exe"
$sysmonConfig = Join-Path $toolsDir "sysmonconfig.xml"

# Download Sysmon binary if not present
if (-not (Test-Path $sysmonExe)) {
    $zipPath = Join-Path $toolsDir "Sysmon.zip"
    Write-Host "  [+] Downloading Sysmon from Microsoft Sysinternals..." -ForegroundColor Gray
    Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile $zipPath -UseBasicParsing
    Expand-Archive -Path $zipPath -DestinationPath $toolsDir -Force
    Remove-Item -Path $zipPath -Force -ErrorAction SilentlyContinue
}

# Download Olaf Hartong Sysmon config
Write-Host "  [+] Fetching Olaf Hartong's modular configuration..." -ForegroundColor Gray
try {
    Invoke-WebRequest -Uri $SysmonConfigUrl -OutFile $sysmonConfig -UseBasicParsing
} catch {
    Write-Host "  [-] Failed to download remote config, writing fallback modular XML..." -ForegroundColor Yellow
    @"
<Sysmon schemaversion="4.90">
  <EventFiltering>
    <RuleGroup name="process_creation" groupRelation="or">
      <ProcessCreate onmatch="exclude" />
    </RuleGroup>
    <RuleGroup name="file_creation" groupRelation="or">
      <FileCreate onmatch="exclude" />
    </RuleGroup>
    <RuleGroup name="process_access" groupRelation="or">
      <ProcessAccess onmatch="exclude" />
    </RuleGroup>
    <RuleGroup name="registry_events" groupRelation="or">
      <RegistryEvent onmatch="exclude" />
    </RuleGroup>
    <RuleGroup name="dns_queries" groupRelation="or">
      <DnsQuery onmatch="exclude" />
    </RuleGroup>
    <RuleGroup name="network_connect" groupRelation="or">
      <NetworkConnect onmatch="exclude" />
    </RuleGroup>
  </EventFiltering>
</Sysmon>
"@ | Out-File -FilePath $sysmonConfig -Encoding utf8
}

if (Test-Path $sysmonExe) {
    Write-Host "  [+] Installing Sysmon service..." -ForegroundColor Gray
    Start-Process -FilePath $sysmonExe -ArgumentList "-accepteula -i `"$sysmonConfig`"" -Wait -NoNewWindow
    Write-Host "  [✓] Sysmon service installed and active." -ForegroundColor Green
}

# 4. Install Wazuh Agent
Write-Host "`n[*] Configuring Wazuh Agent (targeting $SecopsIP)..." -ForegroundColor Yellow
$wazuhMsi = Join-Path $toolsDir "wazuh-agent.msi"
if (-not (Test-Path "C:\Program Files (x86)\ossec-agent\wazuh-agent.exe")) {
    if (-not (Test-Path $wazuhMsi)) {
        Write-Host "  [+] Downloading Wazuh Agent MSI..." -ForegroundColor Gray
        Invoke-WebRequest -Uri $WazuhAgentInstallerUrl -OutFile $wazuhMsi -UseBasicParsing
    }
    Write-Host "  [+] Installing Wazuh Agent MSI..." -ForegroundColor Gray
    $msiArgs = "/i `"$wazuhMsi`" /q WAZUH_MANAGER=`"$SecopsIP`" WAZUH_REGISTRATION_SERVER=`"$SecopsIP`" WAZUH_AGENT_NAME=`"WS01`""
    Start-Process -FilePath "msiexec.exe" -ArgumentList $msiArgs -Wait -NoNewWindow
    Write-Host "  [✓] Wazuh Agent installed." -ForegroundColor Green
}

# 5. Append Sysmon & PowerShell event channels to ossec.conf
$ossecConfPath = "C:\Program Files (x86)\ossec-agent\ossec.conf"
if (Test-Path $ossecConfPath) {
    Write-Host "  [+] Ensuring Sysmon & PowerShell channels exist in ossec.conf..." -ForegroundColor Gray
    $confContent = Get-Content $ossecConfPath -Raw
    
    $sysmonChannel = @"
  <localfile>
    <location>Microsoft-Windows-Sysmon/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>
  <localfile>
    <location>Microsoft-Windows-PowerShell/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>
"@

    if ($confContent -notmatch "Microsoft-Windows-Sysmon/Operational") {
        $updatedContent = $confContent -replace "</ossec_config>", "$sysmonChannel`n</ossec_config>"
        Set-Content -Path $ossecConfPath -Value $updatedContent -Encoding utf8
        Write-Host "  [✓] Event channels appended to ossec.conf." -ForegroundColor Green
    }

    # Restart Wazuh Agent service
    Restart-Service -Name "Wazuh" -Force -ErrorAction SilentlyContinue
    Write-Host "  [✓] Wazuh Agent service restarted." -ForegroundColor Green
}

Write-Host "`n[✓] WS01 endpoint setup and telemetry shipping complete!" -ForegroundColor Green
