# CVE matching against the NIST NVD API 2.0, with a local cache.
# Docs: https://nvd.nist.gov/developers/vulnerabilities

$script:NvdEndpoint = 'https://services.nvd.nist.gov/rest/json/cves/2.0'

function ConvertTo-Cpe23 {
    # Nmap reports CPE 2.2 URIs (cpe:/a:apache:http_server:2.4.41).
    # Returns a CPE 2.3 match string, or $null when there is no version to match on.
    param([string]$Cpe)
    if (-not $Cpe -or -not $Cpe.StartsWith('cpe:/')) { return $null }
    $parts = $Cpe.Substring(5).Split(':')
    if ($parts.Count -lt 4) { return $null }
    $part, $vendor, $product, $version = $parts[0..3]
    if (-not $vendor -or -not $product -or -not $version) { return $null }
    $update = if ($parts.Count -ge 5 -and $parts[4]) { $parts[4] } else { '*' }
    return "cpe:2.3:${part}:${vendor}:${product}:${version}:${update}:*:*:*:*:*:*"
}

function Read-CveCache {
    param([string]$Path)
    if ($Path -and (Test-Path $Path)) {
        try {
            $raw = Get-Content $Path -Raw | ConvertFrom-Json
            $cache = @{}
            foreach ($p in $raw.PSObject.Properties) { $cache[$p.Name] = $p.Value }
            return $cache
        } catch {
            Write-ScanLog "CVE cache unreadable, starting fresh: $($_.Exception.Message)" -Level Warn
        }
    }
    return @{}
}

function Save-CveCache {
    param([hashtable]$Cache, [string]$Path)
    if (-not $Path) { return }
    $dir = Split-Path $Path -Parent
    if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $Cache | ConvertTo-Json -Depth 8 | Set-Content -Path $Path -Encoding UTF8
}

function ConvertFrom-NvdItem {
    param($Item)
    $cve = $Item.cve
    $desc = ($cve.descriptions | Where-Object { $_.lang -eq 'en' } | Select-Object -First 1).value
    $score = 0.0
    $vector = ''
    foreach ($key in @('cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2')) {
        $m = $cve.metrics.$key
        if ($m) {
            $primary = @($m) | Where-Object { $_.type -eq 'Primary' } | Select-Object -First 1
            if (-not $primary) { $primary = @($m)[0] }
            $score = [double]$primary.cvssData.baseScore
            $vector = [string]$primary.cvssData.vectorString
            break
        }
    }
    [pscustomobject]@{
        Id             = [string]$cve.id
        Description    = [string]$desc
        Score          = $score
        Vector         = $vector
        KnownExploited = [bool]$cve.cisaExploitAdd
        KevDueDate     = [string]$cve.cisaActionDue
        Published      = [string]$cve.published
    }
}

function Get-NvdCves {
    param(
        [Parameter(Mandatory)][string]$Cpe23,
        [string]$ApiKey,
        [hashtable]$Cache,
        [int]$CacheDays = 7
    )
    if ($Cache -and $Cache.ContainsKey($Cpe23)) {
        $entry = $Cache[$Cpe23]
        $age = (Get-Date) - [datetime]$entry.Fetched
        if ($age.TotalDays -lt $CacheDays) { return @($entry.Cves) }
    }

    $headers = @{}
    if ($ApiKey) { $headers['apiKey'] = $ApiKey }
    # NVD rate limits: 5 requests / 30 s without a key, 50 / 30 s with one.
    $delay = if ($ApiKey) { 0.7 } else { 6.5 }

    $results = @()
    $start = 0
    do {
        $uri = "$($script:NvdEndpoint)?virtualMatchString=$([uri]::EscapeDataString($Cpe23))&resultsPerPage=2000&startIndex=$start"
        $resp = $null
        for ($attempt = 1; $attempt -le 4 -and -not $resp; $attempt++) {
            Start-Sleep -Seconds $delay
            try {
                $resp = Invoke-RestMethod -Uri $uri -Headers $headers -Method Get -TimeoutSec 60 -ErrorAction Stop
            } catch {
                $code = $null
                if ($_.Exception.Response) { $code = [int]$_.Exception.Response.StatusCode }
                if ($code -eq 404) { return @() }
                Write-ScanLog "NVD request failed (attempt $attempt, HTTP $code): $($_.Exception.Message)" -Level Warn
                Start-Sleep -Seconds (10 * $attempt)
            }
        }
        if (-not $resp) { throw "NVD lookup failed for $Cpe23 after 4 attempts" }

        foreach ($v in @($resp.vulnerabilities)) {
            if ($v) { $results += ConvertFrom-NvdItem $v }
        }
        $start += [int]$resp.resultsPerPage
    } while ($start -lt [int]$resp.totalResults -and [int]$resp.resultsPerPage -gt 0)

    if ($Cache) {
        $Cache[$Cpe23] = [pscustomobject]@{ Fetched = (Get-Date).ToString('o'); Cves = $results }
    }
    return $results
}

function Get-CveFindings {
    param(
        [Parameter(Mandatory)][object[]]$Hosts,
        [string]$ApiKey,
        [string]$CachePath,
        [int]$CacheDays = 7
    )
    $cache = Read-CveCache -Path $CachePath
    $findings = @()

    # Collect unique CPEs first so each is queried once across the whole network.
    $cpeMap = @{}
    foreach ($h in $Hosts) {
        foreach ($p in $h.Ports) {
            foreach ($c in $p.Cpes) {
                $c23 = ConvertTo-Cpe23 $c
                if ($c23 -and -not $cpeMap.ContainsKey($c23)) { $cpeMap[$c23] = $null }
            }
        }
    }
    Write-ScanLog "Looking up CVEs for $($cpeMap.Count) unique product versions"

    foreach ($c23 in @($cpeMap.Keys)) {
        try {
            $cpeMap[$c23] = @(Get-NvdCves -Cpe23 $c23 -ApiKey $ApiKey -Cache $cache -CacheDays $CacheDays)
            Write-ScanLog "  $c23 -> $($cpeMap[$c23].Count) CVEs"
        } catch {
            Write-ScanLog "  $c23 -> lookup failed: $($_.Exception.Message)" -Level Warn
            $cpeMap[$c23] = @()
        }
    }
    Save-CveCache -Cache $cache -Path $CachePath

    foreach ($h in $Hosts) {
        foreach ($p in $h.Ports) {
            $seen = @{}
            foreach ($c in $p.Cpes) {
                $c23 = ConvertTo-Cpe23 $c
                if (-not $c23) { continue }
                foreach ($cve in @($cpeMap[$c23])) {
                    if (-not $cve -or $seen.ContainsKey($cve.Id)) { continue }
                    $seen[$cve.Id] = $true
                    $sev = Get-SeverityFromScore $cve.Score
                    if ($sev -eq 'Info') { $sev = 'Low' }
                    $evidence = "Version match: $(Get-ServiceLabel $p). Verify on the host - vendors often backport fixes without changing the version string."
                    if ($cve.KnownExploited) { $evidence += " Listed in CISA Known Exploited Vulnerabilities (due $($cve.KevDueDate))." }
                    $desc = $cve.Description
                    if ($desc.Length -gt 300) { $desc = $desc.Substring(0, 297) + '...' }
                    $findings += New-Finding -HostAddress $h.Address -HostName $h.HostName `
                        -Port "$($p.Port)/$($p.Protocol)" -Service (Get-ServiceLabel $p) `
                        -Category CVE -Id $cve.Id -Title $desc -Severity $sev -Score $cve.Score `
                        -Evidence $evidence `
                        -Remediation "Upgrade $($p.Product) to a version that fixes $($cve.Id), or apply the vendor patch." `
                        -References @("https://nvd.nist.gov/vuln/detail/$($cve.Id)") `
                        -KnownExploited $cve.KnownExploited
                }
            }
        }
    }
    return $findings
}
