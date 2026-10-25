<#
.SYNOPSIS
    build_hyperv_diet_vms.ps1 — PurpleForge Hyper-V Diet Target Lab Builder
.DESCRIPTION
    Automates the provisioning of lightweight Hyper-V virtual machines:
      - Virtual Switch: Internal switch 'PurpleForge-LAN' with NAT (10.10.10.0/24)
      - DC01: Windows Server Core / AD Domain Controller (1024MB Startup, Dynamic 768MB-2048MB)
      - WS01: Windows 10/11 Enterprise Target Workstation (3072MB RAM, 2 vCPUs)
    Optimized for resource-constrained development and testing hosts.
.NOTES
    Author: Vemula Moksha
    Project: PurpleForge Detection-as-Code
#>

[CmdletBinding()]
param(
    [string]$SwitchName = "PurpleForge-LAN",
    [string]$GatewayIP = "10.10.10.1",
    [string]$SubnetPrefix = "10.10.10.0/24",
    [string]$VMPath = "C:\Hyper-V\PurpleForge",
    [string]$VHDPath = "C:\Hyper-V\Virtual Hard Disks"
)

# Enforce Administrator privileges
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "[-] This script must be executed in an elevated PowerShell session (Run as Administrator)."
    exit 1
}

Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "PurpleForge Hyper-V Diet Lab Provisioner" -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Cyan

# 1. Create Internal Virtual Switch
Write-Host "`n[*] Configuring Hyper-V Internal Switch: $SwitchName..." -ForegroundColor Yellow
$existingSwitch = Get-VMSwitch -Name $SwitchName -ErrorAction SilentlyContinue
if (-not $existingSwitch) {
    New-VMSwitch -Name $SwitchName -SwitchType Internal -Notes "PurpleForge Isolated Lab Switch" | Out-Null
    Write-Host "  [+] Created internal virtual switch '$SwitchName'" -ForegroundColor Green
} else {
    Write-Host "  [~] Virtual switch '$SwitchName' already exists." -ForegroundColor Gray
}

# 2. Configure Host NAT Gateway on the virtual adapter
$vEthernet = Get-NetAdapter | Where-Object { $_.InterfaceDescription -like "*Hyper-V Virtual Ethernet Adapter*$SwitchName*" -or $_.Name -like "*$SwitchName*" }
if ($vEthernet) {
    $existingIP = Get-NetIPAddress -InterfaceIndex $vEthernet.ifIndex -IPAddress $GatewayIP -ErrorAction SilentlyContinue
    if (-not $existingIP) {
        New-NetIPAddress -IPAddress $GatewayIP -PrefixLength 24 -InterfaceIndex $vEthernet.ifIndex | Out-Null
        Write-Host "  [+] Bound gateway IP $GatewayIP/24 to interface $($vEthernet.Name)" -ForegroundColor Green
    }

    $existingNAT = Get-NetNat -Name "PurpleForge-NAT" -ErrorAction SilentlyContinue
    if (-not $existingNAT) {
        New-NetNat -Name "PurpleForge-NAT" -InternalIPInterfaceAddressPrefix $SubnetPrefix | Out-Null
        Write-Host "  [+] Configured WinNAT gateway for subnet $SubnetPrefix" -ForegroundColor Green
    }
}

# Ensure destination directories exist
if (-not (Test-Path $VMPath)) { New-Item -ItemType Directory -Path $VMPath -Force | Out-Null }
if (-not (Test-Path $VHDPath)) { New-Item -ItemType Directory -Path $VHDPath -Force | Out-Null }

# 3. Provision DC01 (Diet Domain Controller)
Write-Host "`n[*] Provisioning Virtual Machine: DC01 (Domain Controller)..." -ForegroundColor Yellow
$dc01 = Get-VM -Name "DC01" -ErrorAction SilentlyContinue
if (-not $dc01) {
    $dc01Vhd = Join-Path $VHDPath "DC01_OS.vhdx"
    if (-not (Test-Path $dc01Vhd)) {
        New-VHD -Path $dc01Vhd -SizeBytes 40GB -Dynamic | Out-Null
    }

    New-VM -Name "DC01" `
           -MemoryStartupBytes 1024MB `
           -Generation 2 `
           -VHDPath $dc01Vhd `
           -SwitchName $SwitchName `
           -Path $VMPath | Out-Null

    # Configure dynamic memory: 768MB to 2048MB
    Set-VM -Name "DC01" -ProcessorCount 2 -StaticMemory:$false
    Set-VMMemory -Name "DC01" `
                 -DynamicMemoryEnabled $true `
                 -MinimumBytes 768MB `
                 -StartupBytes 1024MB `
                 -MaximumBytes 2048MB `
                 -Buffer 20 `
                 -Priority 60

    # Disable automatic checkpoints to conserve disk
    Set-VM -Name "DC01" -AutomaticCheckpointsEnabled $false
    Write-Host "  [+] DC01 provisioned (Gen2, 1024MB dynamic memory, 40GB dynamic VHDX)" -ForegroundColor Green
} else {
    Write-Host "  [~] DC01 already exists." -ForegroundColor Gray
}

# 4. Provision WS01 (Workstation Target)
Write-Host "`n[*] Provisioning Virtual Machine: WS01 (Workstation)..." -ForegroundColor Yellow
$ws01 = Get-VM -Name "WS01" -ErrorAction SilentlyContinue
if (-not $ws01) {
    $ws01Vhd = Join-Path $VHDPath "WS01_OS.vhdx"
    if (-not (Test-Path $ws01Vhd)) {
        New-VHD -Path $ws01Vhd -SizeBytes 60GB -Dynamic | Out-Null
    }

    New-VM -Name "WS01" `
           -MemoryStartupBytes 3072MB `
           -Generation 2 `
           -VHDPath $ws01Vhd `
           -SwitchName $SwitchName `
           -Path $VMPath | Out-Null

    # Static 3072MB RAM, 2 vCPUs
    Set-VM -Name "WS01" -ProcessorCount 2
    Set-VMMemory -Name "WS01" -DynamicMemoryEnabled $false -StartupBytes 3072MB
    Set-VM -Name "WS01" -AutomaticCheckpointsEnabled $false
    Write-Host "  [+] WS01 provisioned (Gen2, 3072MB static RAM, 60GB dynamic VHDX)" -ForegroundColor Green
} else {
    Write-Host "  [~] WS01 already exists." -ForegroundColor Gray
}

Write-Host "`n[✓] PurpleForge Hyper-V Lab environment successfully configured!" -ForegroundColor Green
Write-Host "    Next steps: Attach Windows Server / Client ISOs and execute scripts/lab_setup/*.ps1 inside guests."
