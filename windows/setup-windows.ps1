<#
  Pilgrim detection lab - one-time preparation of the Windows 10 VM (Wazuh agent + Sysmon).
  Run in an elevated PowerShell from this folder:
      powershell -ExecutionPolicy Bypass -File .\setup-windows.ps1

  After a UC25 demo (files deleted from the share), put the synthetic files back with:
      powershell -ExecutionPolicy Bypass -File .\setup-windows.ps1 -SeedShareOnly

  What it does (configuration only - nothing here simulates an attack):
    1. Saves the current Sysmon configuration, then applies pilgrim-sysmon.xml
    2. Turns on the Windows audit categories the rules rely on
    3. Turns on PowerShell script block logging (event 4104)
    4. Creates C:\PilgrimShare with synthetic "passport scan" files (UC23 / UC25 lab data)
    5. Restarts the Wazuh agent so it picks up the shared configuration
#>
#Requires -RunAsAdministrator
param([switch]$SeedShareOnly)
$ErrorActionPreference = "Stop"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path

function Initialize-PilgrimShare {
  $scans = "C:\PilgrimShare\PassportScans"
  New-Item -ItemType Directory -Force -Path $scans | Out-Null
  1..40 | ForEach-Object {
    $f = Join-Path $scans ("passport_{0:D4}.pdf" -f $_)
    if (-not (Test-Path $f)) { Set-Content -Path $f -Value "Synthetic lab document $_ - not a real passport." }
  }
  Write-Host "    C:\PilgrimShare\PassportScans holds $((Get-ChildItem $scans -File).Count) synthetic files"
}

if ($SeedShareOnly) {
  Write-Host "Re-creating the synthetic files in C:\PilgrimShare"
  Initialize-PilgrimShare
  return
}

Write-Host "[1/5] Sysmon configuration"
$sysmon = @("$env:windir\Sysmon64.exe", "$env:windir\Sysmon.exe") | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $sysmon) { throw "Sysmon is not installed (no Sysmon64.exe in $env:windir)" }
$backup = Join-Path $here ("sysmon-config-backup-{0}.txt" -f (Get-Date -Format "yyyyMMdd-HHmmss"))
& $sysmon -c | Out-File -FilePath $backup -Encoding utf8
& $sysmon -accepteula -c (Join-Path $here "pilgrim-sysmon.xml")
if ($LASTEXITCODE -ne 0) { throw "Sysmon rejected the configuration (exit code $LASTEXITCODE). Previous config saved in $backup" }
Write-Host "    applied; previous configuration saved in $backup"

Write-Host "[2/5] Audit policy"
$subcategories = @(
  "Logon",                         # 4624 / 4625            UC16
  "User Account Management",       # 4720                   UC15
  "Security Group Management",     # 4728 / 4732            UC15
  "Other Object Access Events",    # 4698 scheduled task    UC14
  "Plug and Play Events",          # 6416 new device        UC23
  "Removable Storage"              # 4663 in Event Viewer (UC23 alerts use Sysmon file events)
)
foreach ($s in $subcategories) {
  auditpol /set /subcategory:"$s" /success:enable /failure:enable | Out-Null
  Write-Host "    $s"
}

Write-Host "[3/5] PowerShell script block logging"
$key = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
New-Item -Path $key -Force | Out-Null
Set-ItemProperty -Path $key -Name EnableScriptBlockLogging -Value 1 -Type DWord

Write-Host "[4/5] Lab share C:\PilgrimShare (synthetic documents)"
Initialize-PilgrimShare

Write-Host "[5/5] Restart the Wazuh agent"
Restart-Service -Name WazuhSvc
Write-Host ""
Write-Host "Done. Check Event Viewer > Applications and Services Logs > Microsoft > Windows > Sysmon > Operational for new events."
