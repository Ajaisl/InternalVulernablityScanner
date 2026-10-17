# Offline test run: parses sample Nmap output, applies every rule, matches CVEs from a seeded cache,
# evaluates sample Windows host data, and builds a report. No network access needed.
#   pwsh -File .\tests\Test-VulnScan.ps1

$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
foreach ($lib in @('Common', 'Discovery', 'CveLookup', 'NetworkChecks', 'WindowsChecks', 'Report')) {
    . (Join-Path (Join-Path $root 'lib') "$lib.ps1")
}
$out = Join-Path $PSScriptRoot 'output'
if (Test-Path $out) { Remove-Item $out -Recurse -Force }
New-Item -ItemType Directory -Path $out | Out-Null

$script:failures = 0
function Assert {
    param([bool]$Condition, [string]$Message)
    if ($Condition) { Write-Host "  PASS  $Message" -ForegroundColor Green }
    else { Write-Host "  FAIL  $Message" -ForegroundColor Red; $script:failures++ }
}
function Has { param($Findings, $HostAddr, $Id) [bool](@($Findings | Where-Object { $_.HostAddress -eq $HostAddr -and $_.Id -eq $Id }).Count) }

Write-Host 'Parsing'
$hosts = @(ConvertFrom-NmapXml -Path (Join-Path $PSScriptRoot 'sample-nmap.xml'))
Assert ($hosts.Count -eq 3) 'three live hosts (down host ignored)'
Assert ((@($hosts | Where-Object Address -eq '10.10.0.25')[0].Ports.Count) -eq 3) 'intranet has 3 open ports'
Assert ($hosts[0].HostName -eq 'dc01.contoso.local') 'hostname parsed'

Write-Host 'CPE conversion'
Assert ((ConvertTo-Cpe23 'cpe:/a:apache:http_server:2.4.41') -eq 'cpe:2.3:a:apache:http_server:2.4.41:*:*:*:*:*:*:*') 'CPE 2.2 to 2.3'
Assert ($null -eq (ConvertTo-Cpe23 'cpe:/o:microsoft:windows')) 'CPE without version skipped'

Write-Host 'Network checks'
$net = @(Get-NetworkFindings -Hosts $hosts)
foreach ($pair in @(
    @('10.10.0.10', 'NET-SMB1'), @('10.10.0.10', 'NET-SMB-SIGNING'), @('10.10.0.10', 'NET-RDP-NONLA'),
    @('10.10.0.25', 'NET-TLS-LEGACY'), @('10.10.0.25', 'NET-CERT-EXPIRED'), @('10.10.0.25', 'NET-CERT-SELFSIGNED'),
    @('10.10.0.40', 'NET-FTP'), @('10.10.0.40', 'NET-FTP-ANON'), @('10.10.0.40', 'NET-TELNET'), @('10.10.0.40', 'NET-DB-MYSQL'))) {
    Assert (Has $net $pair[0] $pair[1]) "$($pair[1]) on $($pair[0])"
}
Assert (-not (Has $net '10.10.0.25' 'NET-TLS-WEAKCIPHER')) 'grade C cipher not flagged as weak'

Write-Host 'CVE matching (seeded cache, sample data)'
$apache = 'cpe:2.3:a:apache:http_server:2.4.41:*:*:*:*:*:*:*'
$ssh = 'cpe:2.3:a:openbsd:openssh:7.4:*:*:*:*:*:*:*'
$now = (Get-Date).ToString('o')
$cache = [ordered]@{
    $apache = @{ Fetched = $now; Cves = @(
        @{ Id = 'CVE-2021-40438'; Description = 'Crafted request uri-path can cause mod_proxy to forward the request to an origin server chosen by the remote user (SSRF).'; Score = 9.0; KnownExploited = $true; KevDueDate = '2021-12-15' },
        @{ Id = 'CVE-2021-44790'; Description = 'Buffer overflow in the mod_lua multipart parser (r:parsebody).'; Score = 9.8; KnownExploited = $false },
        @{ Id = 'CVE-2022-22720'; Description = 'HTTP request smuggling: connection not closed when discarding the request body fails.'; Score = 9.8; KnownExploited = $false }) }
    $ssh = @{ Fetched = $now; Cves = @(
        @{ Id = 'CVE-2023-38408'; Description = 'PKCS#11 feature in ssh-agent allows remote code execution via a forwarded agent socket.'; Score = 9.8; KnownExploited = $false },
        @{ Id = 'CVE-2018-15473'; Description = 'Username enumeration through malformed authentication requests.'; Score = 5.3; KnownExploited = $false }) }
    'cpe:2.3:a:mysql:mysql:5.7.33:*:*:*:*:*:*:*' = @{ Fetched = $now; Cves = @() }
    'cpe:2.3:a:vsftpd:vsftpd:3.0.3:*:*:*:*:*:*:*' = @{ Fetched = $now; Cves = @() }
}
$cachePath = Join-Path $out 'cve-cache.json'
$cache | ConvertTo-Json -Depth 6 | Set-Content $cachePath
$cveF = @(Get-CveFindings -Hosts $hosts -CachePath $cachePath)
Assert ($cveF.Count -eq 8) "8 CVE findings (3 Apache x 2 ports + 2 OpenSSH), got $($cveF.Count)"
Assert (@($cveF | Where-Object KnownExploited).Count -eq 2) 'KEV flag carried through'
Assert ((@($cveF | Where-Object Id -eq 'CVE-2021-44790')[0].Severity) -eq 'Critical') 'CVSS 9.8 mapped to Critical'

Write-Host 'Windows checks (sample host data)'
$win = [pscustomobject]@{
    ComputerName = 'DC01'; OSCaption = 'Microsoft Windows Server 2012 R2 Standard'; OSVersion = '6.3.9600'
    LastBoot = (Get-Date).AddDays(-95).ToString('o'); DomainRole = 5
    LastHotfix = 'KB5022899'; LastHotfixDate = (Get-Date).AddDays(-200).ToString('o')
    MissingUpdates = @(
        [pscustomobject]@{ Title = 'Security Monthly Quality Rollup for Windows Server 2012 R2'; KBs = 'KB5041828'; Severity = 'Critical'; Cves = '' },
        [pscustomobject]@{ Title = 'Servicing Stack Update for Windows Server 2012 R2'; KBs = 'KB5041588'; Severity = 'Important'; Cves = '' })
    WuaError = $null; RebootPending = $true
    SMB1Enabled = $true; SmbSigningRequired = $true; RdpEnabled = $true; RdpNla = $false
    FirewallProfiles = @([pscustomobject]@{ Name = 'Domain'; Enabled = $false }, [pscustomobject]@{ Name = 'Private'; Enabled = $true })
    DefenderPresent = $true; DefenderRealtime = $false; DefenderSigAge = 14
    WDigestEnabled = $true; LlmnrDisabled = $false
    Schannel = @{ 'SSL 3.0' = 'Disabled'; 'TLS 1.0' = 'Default'; 'TLS 1.1' = 'Enabled' }
    GuestEnabled = $false; LocalAdmins = @('CONTOSO\Domain Admins', 'DC01\Administrator')
    SpoolerRunning = $true; PSv2Installed = $true
}
$winF = @(ConvertTo-WindowsFindings -Data $win -HostAddress '10.10.0.10' -HostName 'dc01.contoso.local')
foreach ($id in @('WIN-OS-EOL', 'KB5041828', 'KB5041588', 'WIN-REBOOT-PENDING', 'WIN-SMB1', 'WIN-RDP-NLA', 'WIN-FW-DOMAIN',
                  'WIN-AV-REALTIME', 'WIN-AV-SIGS', 'WIN-WDIGEST', 'WIN-LLMNR', 'WIN-SCHANNEL-TLS1.0', 'WIN-SCHANNEL-TLS1.1',
                  'WIN-SPOOLER-DC', 'WIN-PSV2', 'WIN-UPTIME', 'WIN-LOCAL-ADMINS')) {
    Assert (Has $winF '10.10.0.10' $id) $id
}
Assert (-not (Has $winF '10.10.0.10' 'WIN-SMB-SIGNING')) 'SMB signing required -> no finding'
Assert (-not (Has $winF '10.10.0.10' 'WIN-SCHANNEL-SSL3.0')) 'SSL 3.0 disabled -> no finding'
Assert ((@($winF | Where-Object Id -eq 'KB5041828')[0].Severity) -eq 'Critical') 'MSRC Critical update mapped'

$win.MissingUpdates = $null; $win.WuaError = 'Access is denied (0x80070005)'
$fallback = @(ConvertTo-WindowsFindings -Data $win -HostAddress '10.10.0.10')
Assert (Has $fallback '10.10.0.10' 'WIN-PATCH-AGE') 'falls back to hotfix age when update search fails'

Write-Host 'Report'
$all = @($net + $cveF + $winF)
$scanInfo = @{ Started = (Get-Date).ToString('yyyy-MM-dd HH:mm'); Duration = '00:04:12'; Targets = @('10.10.0.0/24'); Scanner = 'VULNSCAN01'; Notes = @('Sample data for testing.') }
$report = New-HtmlReport -Findings $all -Hosts $hosts -ScanInfo $scanInfo -Path (Join-Path $out 'sample-report.html')
$html = Get-Content $report -Raw
Assert ($html -match 'CVE-2021-40438') 'report lists CVEs'
Assert ($html -match 'class="kev"') 'report marks KEV'
Assert ($html -notmatch '<script') 'report has no script tags (HTML-encoded)'

Write-Host 'End-to-end (import mode, cached CVEs)'
$run = Join-Path $out 'run'
New-Item -ItemType Directory $run | Out-Null
Copy-Item $cachePath (Join-Path $run 'cve-cache.json')
& (Join-Path $root 'Invoke-VulnScan.ps1') -NmapXml (Join-Path $PSScriptRoot 'sample-nmap.xml') -OutputDirectory $run | Out-Null
$e2e = Get-ChildItem $run -Recurse -Filter report.html | Select-Object -First 1
Assert ([bool]$e2e) 'main script produced report.html'

Write-Host ''
if ($script:failures) { Write-Host "$script:failures test(s) failed" -ForegroundColor Red; exit 1 }
Write-Host 'All tests passed' -ForegroundColor Green
