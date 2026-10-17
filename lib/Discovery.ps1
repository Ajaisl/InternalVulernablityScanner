# Host and service discovery with Nmap, plus Nmap XML parsing.

# Only safe, non-exploiting NSE scripts: they read banners, protocol support and certificates.
$script:NmapScripts = @(
    'ssl-enum-ciphers', 'ssl-cert', 'smb-protocols', 'smb2-security-mode',
    'rdp-enum-encryption', 'ftp-anon', 'http-title'
)

function Find-Nmap {
    $cmd = Get-Command nmap -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    $candidates = @(
        "${env:ProgramFiles(x86)}\Nmap\nmap.exe",
        "$env:ProgramFiles\Nmap\nmap.exe"
    )
    foreach ($c in $candidates) {
        if ($c -and (Test-Path $c)) { return $c }
    }
    return $null
}

function Invoke-NmapScan {
    param(
        [Parameter(Mandatory)][string[]]$Target,
        [Parameter(Mandatory)][string]$OutputXml,
        [string[]]$Exclude,
        [string]$Ports = 'top1000',
        [string]$Timing = 'T3',
        [switch]$NoPing
    )
    $nmap = Find-Nmap
    if (-not $nmap) {
        throw 'Nmap not found. Install it from https://nmap.org/download.html (include Npcap) and try again.'
    }

    $nmapArgs = @('-sS', '-sV', '--version-intensity', '5', "-$Timing", '--open', '--reason')
    if ($Ports -eq 'top1000') { $nmapArgs += @('--top-ports', '1000') }
    else { $nmapArgs += @('-p', $Ports) }
    if ($NoPing) { $nmapArgs += '-Pn' }
    if ($Exclude) { $nmapArgs += @('--exclude', ($Exclude -join ',')) }
    $nmapArgs += @('--script', ($script:NmapScripts -join ','))
    $nmapArgs += @('-oX', $OutputXml)
    $nmapArgs += $Target

    Write-ScanLog "Running: nmap $($nmapArgs -join ' ')"
    & $nmap @args | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Nmap exited with code $LASTEXITCODE. Run the console as Administrator (raw SYN scans need it)."
    }
    if (-not (Test-Path $OutputXml)) { throw "Nmap did not produce $OutputXml" }
}

function Get-ScriptOutputs {
    param($Node)
    $map = @{}
    if ($null -eq $Node) { return $map }
    foreach ($s in @($Node.script)) {
        if ($s -and $s.id) { $map[$s.id] = [string]$s.output }
    }
    return $map
}

function ConvertFrom-NmapXml {
    param([Parameter(Mandatory)][string]$Path)

    [xml]$doc = Get-Content -Path $Path -Raw
    $hosts = @()
    foreach ($h in @($doc.nmaprun.host)) {
        if (-not $h -or $h.status.state -ne 'up') { continue }

        $ip = ($h.address | Where-Object { $_.addrtype -in @('ipv4', 'ipv6') } | Select-Object -First 1).addr
        $mac = ($h.address | Where-Object { $_.addrtype -eq 'mac' } | Select-Object -First 1)
        $name = ''
        if ($h.hostnames -and $h.hostnames.hostname) {
            $name = (@($h.hostnames.hostname) | Select-Object -First 1).name
        }

        $ports = @()
        if ($h.ports) {
            foreach ($p in @($h.ports.port)) {
                if (-not $p -or $p.state.state -ne 'open') { continue }
                $svc = $p.service
                $cpes = @()
                if ($svc -and $svc.cpe) { $cpes = @($svc.cpe | ForEach-Object { [string]$_ }) }
                $ports += [pscustomobject]@{
                    Port     = [int]$p.portid
                    Protocol = [string]$p.protocol
                    Service  = if ($svc) { [string]$svc.name } else { '' }
                    Product  = if ($svc) { [string]$svc.product } else { '' }
                    Version  = if ($svc) { [string]$svc.version } else { '' }
                    Extra    = if ($svc) { [string]$svc.extrainfo } else { '' }
                    Cpes     = $cpes
                    Scripts  = Get-ScriptOutputs $p
                }
            }
        }

        $hosts += [pscustomobject]@{
            Address     = [string]$ip
            HostName    = [string]$name
            Mac         = if ($mac) { [string]$mac.addr } else { '' }
            Vendor      = if ($mac) { [string]$mac.vendor } else { '' }
            Ports       = $ports
            HostScripts = Get-ScriptOutputs $h.hostscript
        }
    }
    return $hosts
}

function Get-ServiceLabel {
    param($PortInfo)
    $label = "$($PortInfo.Port)/$($PortInfo.Protocol) $($PortInfo.Service)"
    $ver = ("$($PortInfo.Product) $($PortInfo.Version)").Trim()
    if ($ver) { $label += " ($ver)" }
    return $label
}
