#Requires -Version 5.1
<#
.SYNOPSIS
    Internal network vulnerability scanner for Windows Server. Produces an HTML report.

.DESCRIPTION
    1. Discovers hosts and services with Nmap (safe NSE scripts only, nothing is exploited).
    2. Flags risky services and configurations (SMBv1, SMB signing, legacy TLS, RDP without NLA, cleartext protocols, certificates).
    3. Matches detected product versions to CVEs using the NIST NVD API, flagging CISA Known Exploited Vulnerabilities.
    4. Optionally runs read-only authenticated checks on Windows hosts over WinRM (missing updates, Defender, firewall, SMB, RDP, WDigest, LLMNR, SCHANNEL, accounts).
    5. Writes a self-contained HTML report.

    Only scan networks you own or are authorized to test.

.EXAMPLE
    .\Invoke-VulnScan.ps1 -Target 10.10.0.0/24

.EXAMPLE
    $cred = Get-Credential CONTOSO\svc-vulnscan
    .\Invoke-VulnScan.ps1 -Target 10.10.0.0/24,10.20.5.0/24 -Exclude 10.10.0.1 -Credential $cred

.EXAMPLE
    # Re-run analysis and reporting on an existing Nmap XML file, without scanning
    .\Invoke-VulnScan.ps1 -NmapXml .\reports\20261017-1200\nmap.xml
#>
[CmdletBinding(DefaultParameterSetName = 'Scan')]
param(
    [Parameter(Mandatory, ParameterSetName = 'Scan')]
    [string[]]$Target,

    [Parameter(Mandatory, ParameterSetName = 'Import')]
    [string]$NmapXml,

    [Parameter(ParameterSetName = 'Scan')]
    [string[]]$Exclude,

    [Parameter(ParameterSetName = 'Scan')]
    [string]$Ports = 'top1000',

    [Parameter(ParameterSetName = 'Scan')]
    [ValidateSet('T2', 'T3', 'T4')]
    [string]$Timing = 'T3',

    [Parameter(ParameterSetName = 'Scan')]
    [switch]$NoPing,

    [pscredential]$Credential,
    [switch]$UseSSL,
    [string]$NvdApiKey = $env:NVD_API_KEY,
    [string]$OutputDirectory = (Join-Path $PSScriptRoot 'reports'),
    [int]$CveCacheDays = 7,
    [switch]$SkipCveLookup
)

$ErrorActionPreference = 'Stop'
foreach ($lib in @('Common', 'Discovery', 'CveLookup', 'NetworkChecks', 'WindowsChecks', 'Report')) {
    . (Join-Path (Join-Path $PSScriptRoot 'lib') "$lib.ps1")
}

$started = Get-Date
$runDir = Join-Path $OutputDirectory $started.ToString('yyyyMMdd-HHmm')
New-Item -ItemType Directory -Path $runDir -Force | Out-Null
$script:ScanLogPath = Join-Path $runDir 'scan.log'
$notes = @()

# 1. Discovery
if ($PSCmdlet.ParameterSetName -eq 'Scan') {
    $xmlPath = Join-Path $runDir 'nmap.xml'
    Write-ScanLog "Scanning $($Target -join ', ')"
    Invoke-NmapScan -Target $Target -Exclude $Exclude -Ports $Ports -Timing $Timing -NoPing:$NoPing -OutputXml $xmlPath
    $targetsLabel = $Target
} else {
    $xmlPath = (Resolve-Path $NmapXml).Path
    Write-ScanLog "Importing existing Nmap results from $xmlPath"
    $targetsLabel = @("imported: $(Split-Path $xmlPath -Leaf)")
}
$hosts = @(ConvertFrom-NmapXml -Path $xmlPath)
Write-ScanLog "$($hosts.Count) live hosts, $((@($hosts | ForEach-Object { $_.Ports })).Count) open ports"

# 2. Network findings
$findings = @(Get-NetworkFindings -Hosts $hosts)
Write-ScanLog "Network checks: $($findings.Count) findings"

# 3. CVE matching
if ($SkipCveLookup) {
    $notes += 'CVE lookup skipped (-SkipCveLookup).'
} else {
    if (-not $NvdApiKey) {
        Write-ScanLog 'No NVD API key: lookups are rate-limited to about 5 per 30 seconds. Get a free key at https://nvd.nist.gov/developers/request-an-api-key' -Level Warn
    }
    try {
        $cveFindings = @(Get-CveFindings -Hosts $hosts -ApiKey $NvdApiKey -CachePath (Join-Path $OutputDirectory 'cve-cache.json') -CacheDays $CveCacheDays)
        $findings += $cveFindings
        Write-ScanLog "CVE matching: $($cveFindings.Count) findings"
    } catch {
        $notes += "CVE lookup failed: $($_.Exception.Message)"
        Write-ScanLog "CVE lookup failed: $($_.Exception.Message)" -Level Error
    }
}

# 4. Authenticated Windows checks
if ($Credential) {
    try {
        $winFindings = @(Get-WindowsFindings -Hosts $hosts -Credential $Credential -UseSSL:$UseSSL)
        $findings += $winFindings
        $failed = @($winFindings | Where-Object Id -eq 'SCAN-WINRM-FAILED').Count
        if ($failed) { $notes += "Authenticated checks failed on $failed host(s); see their sections for the reason." }
        Write-ScanLog "Windows checks: $($winFindings.Count) findings"
    } catch {
        $notes += "Authenticated Windows checks failed: $($_.Exception.Message)"
        Write-ScanLog "Windows checks failed: $($_.Exception.Message)" -Level Error
    }
} else {
    $notes += 'Authenticated Windows checks not run (no -Credential). Missing patches and host settings are not covered.'
}

# 5. Report
$elapsed = (Get-Date) - $started
$scanInfo = @{
    Started  = $started.ToString('yyyy-MM-dd HH:mm')
    Duration = '{0:hh\:mm\:ss}' -f $elapsed
    Targets  = $targetsLabel
    Scanner  = $env:COMPUTERNAME
    Notes    = $notes
}
$reportPath = New-HtmlReport -Findings $findings -Hosts $hosts -ScanInfo $scanInfo -Path (Join-Path $runDir 'report.html')

$real = @($findings | Where-Object Category -ne 'Scan')
$summary = foreach ($s in @('Critical', 'High', 'Medium', 'Low')) { "$s $(@($real | Where-Object Severity -eq $s).Count)" }
Write-ScanLog "Done in $($scanInfo.Duration). $($summary -join ' | ')"
Write-ScanLog "Report: $reportPath"
