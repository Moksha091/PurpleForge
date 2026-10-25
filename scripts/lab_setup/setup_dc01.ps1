<#
.SYNOPSIS
    setup_dc01.ps1 — PurpleForge Domain Controller (DC01) Automated Setup
.DESCRIPTION
    Configures DC01 as the Active Directory Domain Controller:
      1. Assigns static IP 10.10.10.10/24 with Gateway 10.10.10.1 and DNS 127.0.0.1.
      2. Installs AD-Domain-Services feature and forest corp.purpleforge.local.
      3. Creates 50 simulated domain user accounts for realistic directory size.
      4. Creates Kerberoastable service account 'svc_mssql' with SPN MSSQLSvc/DC01.corp.purpleforge.local:1433.
      5. Creates AS-REP Roastable service account 'svc_backup' with DoesNotRequirePreAuth enabled.
      6. Configures advanced Windows audit policies via auditpol to generate:
         - 4624/4625 (Logon/Logoff)
         - 4672 (Special privileges assigned)
         - 4688 (Process Creation with Command Line Logging)
         - 4768 (Kerberos TGT requests / AS-REP)
         - 4769 (Kerberos Service Ticket requests / Kerberoasting)
         - 5145 (Network Share Object Access)
         - 7045 (New Service Installed)
.NOTES
    Author: Vemula Moksha
    Target Host: DC01.corp.purpleforge.local
#>

[CmdletBinding()]
param(
    [string]$DomainName = "corp.purpleforge.local",
    [string]$NetbiosName = "CORP",
    [string]$StaticIP = "10.10.10.10",
    [string]$GatewayIP = "10.10.10.1",
    [int]$PrefixLength = 24,
    [SecureString]$SafeModePassword = (ConvertTo-SecureString "P@ssw0rdForge2026!" -AsPlainText -Force)
)

Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "PurpleForge Domain Controller (DC01) Setup" -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Cyan

# 1. Static Network Configuration
Write-Host "`n[*] Configuring static network settings ($StaticIP/24)..." -ForegroundColor Yellow
$adapter = Get-NetAdapter | Where-Object { $_.Status -eq "Up" } | Select-Object -First 1
if ($adapter) {
    Remove-NetIPAddress -InterfaceIndex $adapter.ifIndex -Confirm:$false -ErrorAction SilentlyContinue
    Remove-NetRoute -InterfaceIndex $adapter.ifIndex -Confirm:$false -ErrorAction SilentlyContinue
    New-NetIPAddress -InterfaceIndex $adapter.ifIndex -IPAddress $StaticIP -PrefixLength $PrefixLength -DefaultGateway $GatewayIP | Out-Null
    Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ServerAddresses @("127.0.0.1", $GatewayIP)
    Write-Host "  [+] Static IP $StaticIP configured on $($adapter.Name)" -ForegroundColor Green
}

# 2. Rename Computer to DC01 if needed
if ($env:COMPUTERNAME -ne "DC01") {
    Write-Host "`n[*] Renaming computer to DC01..." -ForegroundColor Yellow
    Rename-Computer -NewName "DC01" -Force
}

# 3. Install Active Directory Domain Services
Write-Host "`n[*] Checking AD-Domain-Services Windows Feature..." -ForegroundColor Yellow
$adFeature = Get-WindowsFeature -Name AD-Domain-Services
if (-not $adFeature.Installed) {
    Write-Host "  [+] Installing AD-Domain-Services and Management RSAT..." -ForegroundColor Yellow
    Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools | Out-Null
}

# 4. Check if Domain is already installed
$domainCheck = Get-WmiObject -Class Win32_ComputerSystem
if ($domainCheck.PartOfDomain -and (Get-CimInstance Win32_NTDomain -Filter "DnsForestName = '$DomainName'" -ErrorAction SilentlyContinue)) {
    Write-Host "  [~] Domain '$DomainName' already established." -ForegroundColor Green
} else {
    Write-Host "  [+] Deploying new AD Forest: $DomainName..." -ForegroundColor Yellow
    Import-Module ADDSDeployment
    Install-ADDSForest -DomainName $DomainName `
                      -DomainNetbiosName $NetbiosName `
                      -SafeModeAdministratorPassword $SafeModePassword `
                      -InstallDns:$true `
                      -Force:$true
    Write-Host "[!] Server will reboot to complete domain promotion." -ForegroundColor Magenta
    exit 0
}

# 5. Populate Active Directory Objects
Import-Module ActiveDirectory

$targetOU = "OU=Employees,DC=corp,DC=purpleforge,DC=local"
if (-not (Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$targetOU'" -ErrorAction SilentlyContinue)) {
    New-ADOrganizationalUnit -Name "Employees" -Path "DC=corp,DC=purpleforge,DC=local" | Out-Null
}

$serviceOU = "OU=ServiceAccounts,DC=corp,DC=purpleforge,DC=local"
if (-not (Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$serviceOU'" -ErrorAction SilentlyContinue)) {
    New-ADOrganizationalUnit -Name "ServiceAccounts" -Path "DC=corp,DC=purpleforge,DC=local" | Out-Null
}

Write-Host "`n[*] Generating 50 simulated domain users..." -ForegroundColor Yellow
$pass = ConvertTo-SecureString "PurpleCorp2026!#" -AsPlainText -Force
for ($i = 1; $i -le 50; $i++) {
    $sam = "user$($i.ToString('D2'))"
    if (-not (Get-ADUser -Filter "SamAccountName -eq '$sam'" -ErrorAction SilentlyContinue)) {
        New-ADUser -Name $sam `
                   -SamAccountName $sam `
                   -UserPrincipalName "$sam@$DomainName" `
                   -Path $targetOU `
                   -AccountPassword $pass `
                   -Enabled $true `
                   -PasswordNeverExpires $true | Out-Null
    }
}
Write-Host "  [+] 50 domain users populated in $targetOU" -ForegroundColor Green

# 6. Create Kerberoastable Service Account (svc_mssql)
Write-Host "`n[*] Configuring Kerberoastable service account: svc_mssql..." -ForegroundColor Yellow
$mssqlUser = Get-ADUser -Filter "SamAccountName -eq 'svc_mssql'" -ErrorAction SilentlyContinue
if (-not $mssqlUser) {
    New-ADUser -Name "svc_mssql" `
               -SamAccountName "svc_mssql" `
               -UserPrincipalName "svc_mssql@$DomainName" `
               -Path $serviceOU `
               -AccountPassword (ConvertTo-SecureString "MSSQL_Service_P@ss99!" -AsPlainText -Force) `
               -Enabled $true `
               -PasswordNeverExpires $true | Out-Null
    
    # Register Service Principal Name (SPN)
    setspn.exe -S "MSSQLSvc/DC01.corp.purpleforge.local:1433" "CORP\svc_mssql" | Out-Null
    Write-Host "  [+] Registered SPN: MSSQLSvc/DC01.corp.purpleforge.local:1433 for svc_mssql" -ForegroundColor Green
} else {
    Write-Host "  [~] svc_mssql already configured." -ForegroundColor Gray
}

# 7. Create AS-REP Roastable Account (svc_backup)
Write-Host "`n[*] Configuring AS-REP Roastable account: svc_backup..." -ForegroundColor Yellow
$backupUser = Get-ADUser -Filter "SamAccountName -eq 'svc_backup'" -ErrorAction SilentlyContinue
if (-not $backupUser) {
    New-ADUser -Name "svc_backup" `
               -SamAccountName "svc_backup" `
               -UserPrincipalName "svc_backup@$DomainName" `
               -Path $serviceOU `
               -AccountPassword (ConvertTo-SecureString "WeakBackupPass123" -AsPlainText -Force) `
               -Enabled $true `
               -PasswordNeverExpires $true | Out-Null
    
    # Disable Kerberos Pre-Authentication
    Set-ADAccountControl -Identity "svc_backup" -DoesNotRequirePreAuth $true
    Write-Host "  [+] Disabled Kerberos Pre-Authentication (DoesNotRequirePreAuth = True) on svc_backup" -ForegroundColor Green
} else {
    Set-ADAccountControl -Identity "svc_backup" -DoesNotRequirePreAuth $true
    Write-Host "  [~] svc_backup pre-auth disabled." -ForegroundColor Gray
}

# 8. Configure Advanced Audit Policy
Write-Host "`n[*] Enforcing Advanced Windows Security Auditing Policies via auditpol..." -ForegroundColor Yellow

$auditPolicies = @(
    @{ Subcategory = "Logon"; Success = "enable"; Failure = "enable" },             # 4624, 4625
    @{ Subcategory = "Special Logon"; Success = "enable"; Failure = "enable" },     # 4672
    @{ Subcategory = "Process Creation"; Success = "enable"; Failure = "disable" }, # 4688
    @{ Subcategory = "Kerberos Service Ticket Operations"; Success = "enable"; Failure = "enable" }, # 4769
    @{ Subcategory = "Kerberos Authentication Service"; Success = "enable"; Failure = "enable" },    # 4768
    @{ Subcategory = "File Share"; Success = "enable"; Failure = "enable" },        # 5145
    @{ Subcategory = "Audit Policy Change"; Success = "enable"; Failure = "enable" },
    @{ Subcategory = "User Account Management"; Success = "enable"; Failure = "enable" },
    @{ Subcategory = "Security State Change"; Success = "enable"; Failure = "enable" } # 1102, 4697/7045
)

foreach ($pol in $auditPolicies) {
    auditpol.exe /set /subcategory:"$($pol.Subcategory)" /success:$($pol.Success) /failure:$($pol.Failure) | Out-Null
    Write-Host "  [+] auditpol: $($pol.Subcategory) -> Success:$($pol.Success), Failure:$($pol.Failure)" -ForegroundColor Gray
}

# Enable Command Line Logging for Event 4688 in Registry
$auditRegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
if (-not (Test-Path $auditRegPath)) { New-Item -Path $auditRegPath -Force | Out-Null }
Set-ItemProperty -Path $auditRegPath -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1 -Type DWord -Force
Write-Host "  [+] Process Creation Command Line Logging enabled (4688 includes commandLine)" -ForegroundColor Green

Write-Host "`n[✓] DC01 setup and adversary target configuration complete!" -ForegroundColor Green
