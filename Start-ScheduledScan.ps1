#Requires -Version 5.1
<#
.SYNOPSIS
    Wrapper for Task Scheduler: reads scan settings from scan-config.json and a saved credential, then runs the scan.

.DESCRIPTION
    Save the credential once, logged in as the account the scheduled task will run as
    (Export-Clixml encrypts it with DPAPI, so only that account on this server can read it):

        Get-Credential CONTOSO\svc-vulnscan | Export-Clixml -Path .\scan-cred.xml

    Then point a scheduled task at this script (see README.md).
#>
param(
    [string]$ConfigPath = (Join-Path $PSScriptRoot 'scan-config.json')
)
$ErrorActionPreference = 'Stop'

$cfg = Get-Content $ConfigPath -Raw | ConvertFrom-Json
$params = @{ Target = @($cfg.Targets) }
if ($cfg.Exclude)         { $params.Exclude = @($cfg.Exclude) }
if ($cfg.Ports)           { $params.Ports = $cfg.Ports }
if ($cfg.Timing)          { $params.Timing = $cfg.Timing }
if ($cfg.NoPing)          { $params.NoPing = $true }
if ($cfg.UseSSL)          { $params.UseSSL = $true }
if ($cfg.OutputDirectory) { $params.OutputDirectory = $cfg.OutputDirectory }
if ($cfg.CredentialFile) {
    $credPath = $cfg.CredentialFile
    if (-not [System.IO.Path]::IsPathRooted($credPath)) { $credPath = Join-Path $PSScriptRoot $credPath }
    $params.Credential = Import-Clixml -Path $credPath
}

& (Join-Path $PSScriptRoot 'Invoke-VulnScan.ps1') @params
