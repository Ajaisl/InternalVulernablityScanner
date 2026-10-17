# Self-contained HTML report (no external files or internet needed to view it).

function ConvertTo-HtmlText {
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return '' }
    return [System.Net.WebUtility]::HtmlEncode([string]$Value)
}

function Get-SeverityBadge {
    param([string]$Severity)
    return "<span class=`"sev sev-$($Severity.ToLower())`">$Severity</span>"
}

function Get-FindingIdHtml {
    param($Finding)
    $id = ConvertTo-HtmlText $Finding.Id
    $ref = @($Finding.References) | Select-Object -First 1
    $html = if ($ref) { "<a href=`"$(ConvertTo-HtmlText $ref)`" target=`"_blank`" rel=`"noopener`">$id</a>" } else { $id }
    if ($Finding.KnownExploited) { $html += ' <span class="kev" title="CISA Known Exploited Vulnerability">KEV</span>' }
    return $html
}

function Get-FindingRowsHtml {
    param([object[]]$Findings, [switch]$IncludeHost)
    $sb = [System.Text.StringBuilder]::new()
    foreach ($f in $Findings) {
        [void]$sb.Append('<tr>')
        [void]$sb.Append("<td>$(Get-SeverityBadge $f.Severity)</td>")
        if ($IncludeHost) {
            $hn = if ($f.HostName) { "<div class=`"muted`">$(ConvertTo-HtmlText $f.HostName)</div>" } else { '' }
            [void]$sb.Append("<td><code>$(ConvertTo-HtmlText $f.HostAddress)</code>$hn</td>")
        }
        $score = if ($f.Score -gt 0) { '{0:N1}' -f $f.Score } else { '' }
        [void]$sb.Append("<td class=`"nowrap`">$(Get-FindingIdHtml $f)</td>")
        [void]$sb.Append("<td><strong>$(ConvertTo-HtmlText $f.Title)</strong><div class=`"muted`">$(ConvertTo-HtmlText $f.Evidence)</div></td>")
        [void]$sb.Append("<td class=`"nowrap`">$(ConvertTo-HtmlText $f.Port)</td>")
        [void]$sb.Append("<td class=`"num`">$score</td>")
        [void]$sb.Append("<td>$(ConvertTo-HtmlText $f.Remediation)</td>")
        [void]$sb.Append('</tr>')
    }
    return $sb.ToString()
}

function New-HtmlReport {
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Findings,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Hosts,
        [Parameter(Mandatory)][hashtable]$ScanInfo,
        [Parameter(Mandatory)][string]$Path
    )
    $sorted = @(Sort-Findings $Findings)
    $real = @($sorted | Where-Object { $_.Category -ne 'Scan' })
    $counts = [ordered]@{}
    foreach ($s in @('Critical', 'High', 'Medium', 'Low', 'Info')) {
        $counts[$s] = @($real | Where-Object Severity -eq $s).Count
    }
    $kevCount = @($real | Where-Object KnownExploited).Count

    $cards = ($counts.Keys | ForEach-Object {
        "<div class=`"card card-$($_.ToLower())`"><div class=`"card-num`">$($counts[$_])</div><div class=`"card-label`">$_</div></div>"
    }) -join ''
    $cards += "<div class=`"card card-kev`"><div class=`"card-num`">$kevCount</div><div class=`"card-label`">Known exploited</div></div>"

    $top = @($real | Where-Object { $_.KnownExploited -or $_.Severity -in @('Critical', 'High') } | Select-Object -First 20)
    $topHtml = if ($top) {
        "<table><thead><tr><th>Severity</th><th>Host</th><th>ID</th><th>Finding</th><th>Port</th><th class=`"num`">CVSS</th><th>Fix</th></tr></thead><tbody>$(Get-FindingRowsHtml $top -IncludeHost)</tbody></table>"
    } else { '<p class="ok">No critical or high findings.</p>' }

    # Host overview, riskiest first
    $hostRows = foreach ($h in $Hosts) {
        $hf = @($real | Where-Object HostAddress -eq $h.Address)
        $c = @{}
        foreach ($s in @('Critical', 'High', 'Medium', 'Low')) { $c[$s] = @($hf | Where-Object Severity -eq $s).Count }
        [pscustomobject]@{
            Host = $h; Findings = $hf; Counts = $c
            Risk = $c['Critical'] * 1000 + $c['High'] * 100 + $c['Medium'] * 10 + $c['Low']
        }
    }
    $hostRows = @($hostRows | Sort-Object Risk -Descending)

    $overview = [System.Text.StringBuilder]::new()
    foreach ($r in $hostRows) {
        $anchor = 'h-' + ($r.Host.Address -replace '[^0-9A-Za-z]', '-')
        [void]$overview.Append("<tr><td><a href=`"#$anchor`"><code>$(ConvertTo-HtmlText $r.Host.Address)</code></a></td><td>$(ConvertTo-HtmlText $r.Host.HostName)</td><td class=`"num`">$(@($r.Host.Ports).Count)</td>")
        foreach ($s in @('Critical', 'High', 'Medium', 'Low')) {
            $n = $r.Counts[$s]
            $cls = if ($n -gt 0) { "num cnt-$($s.ToLower())" } else { 'num zero' }
            [void]$overview.Append("<td class=`"$cls`">$n</td>")
        }
        [void]$overview.Append('</tr>')
    }

    $details = [System.Text.StringBuilder]::new()
    foreach ($r in $hostRows) {
        $h = $r.Host
        $anchor = 'h-' + ($h.Address -replace '[^0-9A-Za-z]', '-')
        $hostFindings = @(Sort-Findings @($sorted | Where-Object HostAddress -eq $h.Address))
        $open = if ($r.Risk -ge 100) { ' open' } else { '' }
        $title = ConvertTo-HtmlText $h.Address
        if ($h.HostName) { $title += " &middot; $(ConvertTo-HtmlText $h.HostName)" }
        $summary = ($r.Counts.Keys | Sort-Object { Get-SeverityRank $_ } | Where-Object { $r.Counts[$_] -gt 0 } |
            ForEach-Object { "$($r.Counts[$_]) $($_.ToLower())" }) -join ', '
        if (-not $summary) { $summary = 'no findings' }

        [void]$details.Append("<details id=`"$anchor`"$open><summary><span class=`"host-title`">$title</span><span class=`"muted`">$summary</span></summary>")
        $svc = (@($h.Ports) | ForEach-Object { "<li><code>$(ConvertTo-HtmlText (Get-ServiceLabel $_))</code></li>" }) -join ''
        if ($svc) { [void]$details.Append("<h4>Open services</h4><ul class=`"svc`">$svc</ul>") }
        if ($hostFindings) {
            [void]$details.Append("<h4>Findings</h4><table><thead><tr><th>Severity</th><th>ID</th><th>Finding</th><th>Port</th><th class=`"num`">CVSS</th><th>Fix</th></tr></thead><tbody>$(Get-FindingRowsHtml $hostFindings)</tbody></table>")
        }
        [void]$details.Append('</details>')
    }

    $notes = (@($ScanInfo.Notes) | Where-Object { $_ } | ForEach-Object { "<li>$(ConvertTo-HtmlText $_)</li>" }) -join ''
    if (-not $notes) { $notes = '<li>All scan stages completed.</li>' }

    $generated = (Get-Date).ToString('yyyy-MM-dd HH:mm')
    $html = @"
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Vulnerability Report - $(ConvertTo-HtmlText $ScanInfo.Started)</title>
<style>
:root { --bg:#f7f7f5; --panel:#fff; --ink:#1d1d1b; --muted:#6b6b66; --line:#e3e2dd; --accent:#2f5d8a;
  --crit:#a3001b; --high:#d0461b; --med:#c98a00; --low:#3a7d44; --info:#6b6b66; }
@media (prefers-color-scheme: dark) { :root { --bg:#161615; --panel:#20201e; --ink:#ecebe6; --muted:#a3a29c; --line:#34332f; --accent:#7fb0e0;
  --crit:#ff5c70; --high:#ff8a5c; --med:#f0c04a; --low:#78c487; --info:#a3a29c; } }
* { box-sizing:border-box; }
body { margin:0; background:var(--bg); color:var(--ink); font:14px/1.5 "Segoe UI", system-ui, sans-serif; }
main { max-width:1200px; margin:0 auto; padding:32px 16px 64px; }
h1 { font-size:26px; margin:0 0 4px; } h2 { font-size:18px; margin:36px 0 12px; } h4 { margin:16px 0 8px; font-size:13px; text-transform:uppercase; letter-spacing:.04em; color:var(--muted); }
.meta { color:var(--muted); margin:0 0 24px; }
.cards { display:grid; grid-template-columns:repeat(auto-fit, minmax(130px, 1fr)); gap:12px; }
.card { background:var(--panel); border:1px solid var(--line); border-left:5px solid var(--info); border-radius:8px; padding:12px 16px; }
.card-num { font-size:28px; font-weight:700; font-variant-numeric:tabular-nums; } .card-label { color:var(--muted); }
.card-critical { border-left-color:var(--crit); } .card-high { border-left-color:var(--high); } .card-medium { border-left-color:var(--med); }
.card-low { border-left-color:var(--low); } .card-kev { border-left-color:var(--ink); }
.panel { background:var(--panel); border:1px solid var(--line); border-radius:8px; overflow-x:auto; }
table { width:100%; border-collapse:collapse; } th, td { text-align:left; vertical-align:top; padding:8px 10px; border-bottom:1px solid var(--line); }
th { font-size:12px; color:var(--muted); font-weight:600; text-transform:uppercase; letter-spacing:.03em; }
tbody tr:last-child td { border-bottom:none; }
.num { text-align:right; font-variant-numeric:tabular-nums; } .nowrap { white-space:nowrap; } .zero { color:var(--line); }
.cnt-critical { color:var(--crit); font-weight:700; } .cnt-high { color:var(--high); font-weight:700; } .cnt-medium { color:var(--med); } .cnt-low { color:var(--low); }
.muted { color:var(--muted); font-size:12.5px; } code { font-family:Consolas, monospace; font-size:12.5px; }
a { color:var(--accent); }
.sev { display:inline-block; min-width:62px; text-align:center; padding:1px 8px; border-radius:10px; font-size:12px; font-weight:600; color:#fff; }
.sev-critical { background:var(--crit); } .sev-high { background:var(--high); } .sev-medium { background:var(--med); color:#1d1d1b; } .sev-low { background:var(--low); } .sev-info { background:var(--info); }
.kev { font-size:11px; font-weight:700; border:1px solid var(--crit); color:var(--crit); border-radius:4px; padding:0 4px; }
details { background:var(--panel); border:1px solid var(--line); border-radius:8px; margin:0 0 10px; padding:0 16px; }
summary { cursor:pointer; padding:12px 0; display:flex; gap:16px; align-items:baseline; flex-wrap:wrap; }
.host-title { font-weight:600; } details[open] { padding-bottom:12px; } details table { margin-bottom:8px; }
ul.svc { columns:2; margin:0; padding-left:18px; } .ok { color:var(--low); padding:12px 16px; margin:0; }
.notes { color:var(--muted); }
@media (max-width:700px) { ul.svc { columns:1; } }
@media print { details { break-inside:avoid; } details:not([open]) > *:not(summary) { display:block; } }
</style>
</head>
<body><main>
<h1>Internal Network Vulnerability Report</h1>
<p class="meta">Scan started $(ConvertTo-HtmlText $ScanInfo.Started) &middot; duration $(ConvertTo-HtmlText $ScanInfo.Duration) &middot; targets <code>$(ConvertTo-HtmlText ($ScanInfo.Targets -join ', '))</code> &middot; $(@($Hosts).Count) live hosts &middot; generated $generated on $(ConvertTo-HtmlText $ScanInfo.Scanner)</p>

<div class="cards">$cards</div>

<h2>Fix first</h2>
<p class="muted">Known exploited, critical and high findings, highest risk first (top 20).</p>
<div class="panel">$topHtml</div>

<h2>Hosts</h2>
<div class="panel"><table><thead><tr><th>Address</th><th>Name</th><th class="num">Open ports</th><th class="num">Critical</th><th class="num">High</th><th class="num">Medium</th><th class="num">Low</th></tr></thead><tbody>$($overview.ToString())</tbody></table></div>

<h2>Findings by host</h2>
$($details.ToString())

<h2>Scan notes</h2>
<ul class="notes">$notes
<li>CVE matches are based on detected product versions. Confirm on the host before patching; Linux distributions and appliances often backport fixes without changing the version.</li>
<li>Only scan networks you own or are authorized to test.</li></ul>
</main></body></html>
"@
    Set-Content -Path $Path -Value $html -Encoding UTF8
    return $Path
}
