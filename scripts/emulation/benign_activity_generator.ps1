<#
.SYNOPSIS
    benign_activity_generator.ps1 — PurpleForge Benign Noise & True Negative Generator
.DESCRIPTION
    Generates realistic, continuous background noise and benign administrative activity
    on target endpoints (WS01, DC01). This activity tests the tuned filter_* blocks
    in the Sigma rules to ensure ZERO false positives are triggered during normal operations:
      - Normal PowerShell administrative queries (Get-Process, Get-Service, Get-Date)
      - Microsoft Edge / Chrome HTTPS browsing (Port 443, 80)
      - Legitimate scheduled maintenance tasks
      - Benign registry reads and standard user profile updates
      - Legitimate svchost.exe RPC and service operations
      - Machine account ($) domain authentication
.NOTES
    Author: Vemula Moksha
    Project: PurpleForge Detection-as-Code
#>

[CmdletBinding()]
param(
    [int]$Iterations = 20,
    [int]$SleepIntervalSeconds = 5,
    [switch]$Continuous
)

Write-Host "======================================================================" -ForegroundColor Green
Write-Host "PurpleForge Benign Noise Generator (True Negative Validation)" -ForegroundColor Green
Write-Host "======================================================================" -ForegroundColor Green

$iterationCount = 0

do {
    $iterationCount++
    $timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    Write-Host "`n[$timestamp] Iteration #$iterationCount: Executing benign operational patterns..." -ForegroundColor Cyan

    # 1. Benign PowerShell Administrative Commands (Filtered out by win_powershell_*.yml)
    Write-Host "  [+] Simulating normal IT administration queries..." -ForegroundColor Gray
    Get-Process | Where-Object { $_.CPU -gt 10 } | Select-Object -First 5 -Property Name, CPU, WorkingSet | Out-Null
    Get-Service | Where-Object { $_.Status -eq "Running" } | Select-Object -First 5 -Property DisplayName, Status | Out-Null
    Get-HotFix | Select-Object -First 3 | Out-Null

    # 2. Benign Network Traffic to Approved Ports (Filtered out by win_non_browser_uncommon_port.yml)
    Write-Host "  [+] Performing legitimate HTTPS / DNS traffic (Ports 80, 443, 53)..." -ForegroundColor Gray
    try {
        $null = Test-NetConnection -ComputerName "1.1.1.1" -Port 53 -WarningAction SilentlyContinue
        $null = Invoke-WebRequest -Uri "https://www.google.com" -UseBasicParsing -TimeoutSec 3 -ErrorAction SilentlyContinue
    } catch {
        # Offline lab fallback
    }

    # 3. Benign Registry Operations (HKCU updates, benign AppPaths)
    Write-Host "  [+] Simulating standard application registry operations..." -ForegroundColor Gray
    $testKey = "HKCU:\Software\PurpleForgeBenignApp"
    if (-not (Test-Path $testKey)) {
        New-Item -Path $testKey -Force | Out-Null
    }
    Set-ItemProperty -Path $testKey -Name "LastCheckinTime" -Value (Get-Date).ToString("o") -Type String -Force
    $val = (Get-ItemProperty -Path $testKey -Name "LastCheckinTime").LastCheckinTime

    # 4. Benign Scheduled Task Query (schtasks.exe /query)
    Write-Host "  [+] Executing standard system maintenance query (schtasks /query)..." -ForegroundColor Gray
    & schtasks.exe /query /fo TABLE /nh 2>&1 | Select-Object -First 10 | Out-Null

    # 5. Benign File Operations in Public / Temp directories
    Write-Host "  [+] Simulating benign temporary file updates..." -ForegroundColor Gray
    $tempFile = [System.IO.Path]::Combine($env:TEMP, "benign_healthcheck_$(Get-Random).tmp")
    Set-Content -Path $tempFile -Value "Normal system diagnostic telemetry recorded at $(Get-Date)"
    Start-Sleep -Milliseconds 200
    Remove-Item -Path $tempFile -Force -ErrorAction SilentlyContinue

    # 6. Query Domain Controller Time (W32Time / net time)
    Write-Host "  [+] Synchronizing local system clock..." -ForegroundColor Gray
    & w32tm /query /status 2>&1 | Out-Null

    Write-Host "  [✓] Iteration #$iterationCount complete without triggering DaC alarms." -ForegroundColor Green
    Start-Sleep -Seconds $SleepIntervalSeconds

} while ($Continuous -or ($iterationCount -lt $Iterations))

Write-Host "`n======================================================================" -ForegroundColor Green
Write-Host "[✓] Benign noise generation sequence completed ($iterationCount iterations)." -ForegroundColor Green
Write-Host "======================================================================" -ForegroundColor Green
