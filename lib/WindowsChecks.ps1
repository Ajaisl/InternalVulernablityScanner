# Authenticated checks on Windows hosts over WinRM (PowerShell remoting).
# Collection is read-only: it queries settings and update status, it changes nothing.

$script:WindowsCollector = {
    $r = [ordered]@{}
    $os = Get-CimInstance Win32_OperatingSystem
    $cs = Get-CimInstance Win32_ComputerSystem
    $r.ComputerName = $env:COMPUTERNAME
    $r.OSCaption    = $os.Caption
    $r.OSVersion    = $os.Version
    $r.LastBoot     = $os.LastBootUpTime.ToString('o')
    $r.DomainRole   = [int]$cs.DomainRole   # 4 or 5 = domain controller

    # Patching
    $hf = Get-HotFix -ErrorAction SilentlyContinue | Where-Object { $_.InstalledOn } |
        Sort-Object InstalledOn -Descending | Select-Object -First 1
    $r.LastHotfix     = if ($hf) { $hf.HotFixID } else { $null }
    $r.LastHotfixDate = if ($hf) { $hf.InstalledOn.ToString('o') } else { $null }
    $r.MissingUpdates = $null
    $r.WuaError       = $null
    try {
        $session  = New-Object -ComObject Microsoft.Update.Session
        $searcher = $session.CreateUpdateSearcher()
        $result   = $searcher.Search("IsInstalled=0 and Type='Software' and IsHidden=0")
        $list = @()
        foreach ($u in $result.Updates) {
            $list += [pscustomobject]@{
                Title    = $u.Title
                KBs      = (@($u.KBArticleIDs) | ForEach-Object { "KB$_" }) -join ', '
                Severity = [string]$u.MsrcSeverity
                Cves     = (@($u.CveIDs)) -join ', '
            }
        }
        $r.MissingUpdates = $list
    } catch {
        $r.WuaError = $_.Exception.Message
    }
    $r.RebootPending = Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'

    # SMB
    try {
        $smb = Get-SmbServerConfiguration -ErrorAction Stop
        $r.SMB1Enabled        = [bool]$smb.EnableSMB1Protocol
        $r.SmbSigningRequired = [bool]$smb.RequireSecuritySignature
    } catch { $r.SMB1Enabled = $null; $r.SmbSigningRequired = $null }

    # RDP
    $ts  = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -ErrorAction SilentlyContinue
    $rdp = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -ErrorAction SilentlyContinue
    $r.RdpEnabled = ($ts.fDenyTSConnections -eq 0)
    $r.RdpNla     = ($rdp.UserAuthentication -eq 1)

    # Firewall
    try {
        $r.FirewallProfiles = @(Get-NetFirewallProfile -ErrorAction Stop |
            ForEach-Object { [pscustomobject]@{ Name = $_.Name; Enabled = [bool]$_.Enabled } })
    } catch { $r.FirewallProfiles = $null }

    # Microsoft Defender
    try {
        $mp = Get-MpComputerStatus -ErrorAction Stop
        $r.DefenderPresent  = $true
        $r.DefenderRealtime = [bool]$mp.RealTimeProtectionEnabled
        $r.DefenderSigAge   = [int]$mp.AntivirusSignatureAge
    } catch { $r.DefenderPresent = $false }

    # Credential exposure settings
    $wd = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -ErrorAction SilentlyContinue
    $r.WDigestEnabled = ($wd.UseLogonCredential -eq 1)
    $ll = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -ErrorAction SilentlyContinue
    $r.LlmnrDisabled = ($ll.EnableMulticast -eq 0)

    # SCHANNEL legacy protocols (server side)
    $tls = @{}
    foreach ($proto in @('SSL 3.0', 'TLS 1.0', 'TLS 1.1')) {
        $key = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$proto\Server"
        $v = Get-ItemProperty $key -ErrorAction SilentlyContinue
        $tls[$proto] = if ($null -eq $v -or $null -eq $v.Enabled) { 'Default' } elseif ($v.Enabled -eq 0) { 'Disabled' } else { 'Enabled' }
    }
    $r.Schannel = $tls

    # Accounts
    try {
        $guest = Get-LocalUser -ErrorAction Stop | Where-Object { $_.SID.Value -like '*-501' }
        $r.GuestEnabled = [bool]$guest.Enabled
        $r.LocalAdmins = @(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop | ForEach-Object { $_.Name })
    } catch { $r.GuestEnabled = $null; $r.LocalAdmins = $null }

    # Attack surface
    $spooler = Get-Service -Name Spooler -ErrorAction SilentlyContinue
    $r.SpoolerRunning = ($spooler -and $spooler.Status -eq 'Running')
    $r.PSv2Installed = $false
    try {
        $f = Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -ErrorAction Stop
        $r.PSv2Installed = ($f.State -eq 'Enabled')
    } catch {
        try {
            $f = Get-WindowsFeature -Name PowerShell-V2 -ErrorAction Stop
            $r.PSv2Installed = [bool]$f.Installed
        } catch {}
    }

    [pscustomobject]$r
}

function ConvertTo-WindowsFindings {
    param(
        [Parameter(Mandatory)]$Data,
        [Parameter(Mandatory)][string]$HostAddress,
        [string]$HostName = '',
        [int]$PatchAgeDays = 45
    )
    $base = @{ HostAddress = $HostAddress; HostName = $HostName; Service = 'Windows (authenticated)' }
    $hp  = $base + @{ Category = 'Configuration' }
    $hpp = $base + @{ Category = 'Patching' }
    $f = @()

    # Unsupported operating systems
    if ($Data.OSCaption -match 'Server 2003|Server 2008|Server 2012|Windows XP|Windows Vista|Windows 7|Windows 8|Windows 10') {
        $f += New-Finding @hp -Id 'WIN-OS-EOL' -Title "Operating system past end of support: $($Data.OSCaption)" -Severity High `
            -Evidence "OS version $($Data.OSVersion). No security updates unless enrolled in Extended Security Updates." `
            -Remediation 'Upgrade to a supported Windows version, or confirm ESU enrollment and isolate the host.' `
            -References @('https://learn.microsoft.com/lifecycle/products/')
    }

    # Missing updates
    if ($null -ne $Data.MissingUpdates) {
        foreach ($u in @($Data.MissingUpdates)) {
            if (-not $u) { continue }
            $sev = switch ($u.Severity) { 'Critical' { 'Critical' } 'Important' { 'High' } 'Moderate' { 'Medium' } default { 'Low' } }
            $ev = "Not installed: $($u.KBs)."
            if ($u.Cves) { $ev += " Fixes: $($u.Cves)." }
            $f += New-Finding @hpp -Id ($(if ($u.KBs) { $u.KBs } else { 'WIN-UPDATE' })) `
                -Title "Missing update: $($u.Title)" -Severity $sev -Evidence $ev `
                -Remediation 'Install via Windows Update, WSUS or your patch management tool, then reboot if required.'
        }
    } else {
        $note = "Windows Update search unavailable remotely ($($Data.WuaError)); judged by last hotfix date instead."
        if ($Data.LastHotfixDate) {
            $age = [int]((Get-Date) - [datetime]$Data.LastHotfixDate).TotalDays
            if ($age -gt $PatchAgeDays) {
                $f += New-Finding @hpp -Id 'WIN-PATCH-AGE' -Title "No updates installed in $age days" -Severity High `
                    -Evidence "Last hotfix $($Data.LastHotfix) on $(([datetime]$Data.LastHotfixDate).ToString('yyyy-MM-dd')). $note" `
                    -Remediation 'Install the latest cumulative update. Check WSUS or patch tool assignment for this host.'
            }
        } else {
            $f += New-Finding @hpp -Id 'WIN-PATCH-UNKNOWN' -Title 'Patch status could not be determined' -Severity Info `
                -Evidence $note -Remediation 'Check patch status on the host directly.'
        }
    }
    if ($Data.RebootPending) {
        $f += New-Finding @hpp -Id 'WIN-REBOOT-PENDING' -Title 'Reboot pending to finish installing updates' -Severity Medium `
            -Evidence 'RebootRequired registry key present; installed updates are not active yet.' `
            -Remediation 'Reboot the host in the next maintenance window.'
    }

    if ($Data.SMB1Enabled -eq $true) {
        $f += New-Finding @hp -Id 'WIN-SMB1' -Title 'SMBv1 server protocol enabled' -Severity High `
            -Evidence 'Get-SmbServerConfiguration: EnableSMB1Protocol = True' `
            -Remediation 'Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force; remove the SMB1Protocol feature.'
    }
    if ($Data.SmbSigningRequired -eq $false) {
        $f += New-Finding @hp -Id 'WIN-SMB-SIGNING' -Title 'SMB signing not required' -Severity Medium `
            -Evidence 'Get-SmbServerConfiguration: RequireSecuritySignature = False' `
            -Remediation 'Enable "Microsoft network server: Digitally sign communications (always)" via GPO.'
    }
    if ($Data.RdpEnabled -and -not $Data.RdpNla) {
        $f += New-Finding @hp -Id 'WIN-RDP-NLA' -Title 'RDP enabled without Network Level Authentication' -Severity Medium `
            -Evidence 'RDP-Tcp UserAuthentication is not 1.' `
            -Remediation 'Require NLA for Remote Desktop via System Properties or GPO.'
    }
    foreach ($fw in @($Data.FirewallProfiles)) {
        if ($fw -and -not $fw.Enabled) {
            $f += New-Finding @hp -Id "WIN-FW-$($fw.Name.ToUpper())" -Title "Windows Firewall $($fw.Name) profile disabled" -Severity Medium `
                -Evidence "Get-NetFirewallProfile: $($fw.Name) Enabled = False" `
                -Remediation "Enable the $($fw.Name) firewall profile and allow only required inbound ports."
        }
    }
    if ($Data.DefenderPresent) {
        if (-not $Data.DefenderRealtime) {
            $f += New-Finding @hp -Id 'WIN-AV-REALTIME' -Title 'Microsoft Defender real-time protection off' -Severity High `
                -Evidence 'Get-MpComputerStatus: RealTimeProtectionEnabled = False' `
                -Remediation 'Turn on real-time protection, or confirm another EDR product is active and Defender is in passive mode.'
        }
        if ($Data.DefenderSigAge -gt 3) {
            $f += New-Finding @hp -Id 'WIN-AV-SIGS' -Title "Defender signatures $($Data.DefenderSigAge) days old" -Severity Medium `
                -Evidence "AntivirusSignatureAge = $($Data.DefenderSigAge)" `
                -Remediation 'Check Defender update source (WSUS, Windows Update or MECM) and force an update with Update-MpSignature.'
        }
    }
    if ($Data.WDigestEnabled) {
        $f += New-Finding @hp -Id 'WIN-WDIGEST' -Title 'WDigest stores cleartext passwords in memory' -Severity High `
            -Evidence 'WDigest UseLogonCredential = 1' `
            -Remediation 'Set HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential to 0.'
    }
    if (-not $Data.LlmnrDisabled) {
        $f += New-Finding @hp -Id 'WIN-LLMNR' -Title 'LLMNR not disabled by policy' -Severity Low `
            -Evidence 'DNSClient policy EnableMulticast is not 0; LLMNR poisoning can capture credentials.' `
            -Remediation 'GPO: Computer Configuration > Administrative Templates > Network > DNS Client > "Turn off multicast name resolution" = Enabled.'
    }
    foreach ($proto in @('SSL 3.0', 'TLS 1.0', 'TLS 1.1')) {
        $state = $Data.Schannel.$proto
        if ($state -eq 'Enabled' -or ($state -eq 'Default' -and $Data.OSCaption -notmatch 'Server 2025|Windows 11')) {
            $sev = if ($proto -eq 'SSL 3.0') { 'High' } else { 'Low' }
            $f += New-Finding @hp -Id "WIN-SCHANNEL-$($proto.Replace(' ', '').ToUpper())" -Title "$proto not disabled in SCHANNEL" -Severity $sev `
                -Evidence "SCHANNEL\Protocols\$proto\Server: $state (OS default may allow it)." `
                -Remediation "Set SCHANNEL\Protocols\$proto\Server Enabled = 0 and DisabledByDefault = 1, after confirming no clients depend on it."
        }
    }
    if ($Data.GuestEnabled -eq $true) {
        $f += New-Finding @hp -Id 'WIN-GUEST' -Title 'Local Guest account enabled' -Severity Medium `
            -Evidence 'Built-in Guest account (RID 501) is enabled.' -Remediation 'Disable the Guest account.'
    }
    if ($Data.LocalAdmins) {
        $admins = @($Data.LocalAdmins)
        $f += New-Finding @hp -Id 'WIN-LOCAL-ADMINS' -Title "Local Administrators group has $($admins.Count) members" `
            -Severity ($(if ($admins.Count -gt 5) { 'Low' } else { 'Info' })) `
            -Evidence ($admins -join '; ') `
            -Remediation 'Review membership; remove accounts that do not need admin rights. Use LAPS for the built-in admin password.'
    }
    if ($Data.SpoolerRunning -and $Data.DomainRole -ge 4) {
        $f += New-Finding @hp -Id 'WIN-SPOOLER-DC' -Title 'Print Spooler running on a domain controller' -Severity High `
            -Evidence 'Spooler service is running; DomainRole indicates a domain controller.' `
            -Remediation 'Stop and disable the Print Spooler service on domain controllers.' `
            -References @('https://learn.microsoft.com/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server')
    }
    if ($Data.PSv2Installed) {
        $f += New-Finding @hp -Id 'WIN-PSV2' -Title 'PowerShell 2.0 engine installed' -Severity Low `
            -Evidence 'PowerShell v2 bypasses script block logging and AMSI.' `
            -Remediation 'Remove the feature: Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root'
    }
    $uptime = [int]((Get-Date) - [datetime]$Data.LastBoot).TotalDays
    if ($uptime -gt 60) {
        $f += New-Finding @hp -Id 'WIN-UPTIME' -Title "Host not rebooted in $uptime days" -Severity Low `
            -Evidence "Last boot $(([datetime]$Data.LastBoot).ToString('yyyy-MM-dd'))." `
            -Remediation 'Long uptime usually means installed updates are not active; schedule a reboot.'
    }
    return $f
}

function Get-WindowsFindings {
    param(
        [Parameter(Mandatory)][object[]]$Hosts,
        [Parameter(Mandatory)][pscredential]$Credential,
        [switch]$UseSSL,
        [int]$ThrottleLimit = 16
    )
    $findings = @()
    $winPorts = if ($UseSSL) { @(5986) } else { @(5985) }
    $targets = @($Hosts | Where-Object { $_.Ports | Where-Object { $_.Port -in $winPorts } })
    if (-not $targets) {
        Write-ScanLog 'No hosts with WinRM open; skipping authenticated Windows checks.' -Level Warn
        return $findings
    }

    # Prefer DNS names: Kerberos authentication over WinRM needs them (IPs need TrustedHosts or HTTPS).
    $nameMap = @{}
    foreach ($t in $targets) {
        $n = if ($t.HostName) { $t.HostName } else { $t.Address }
        $nameMap[$n.ToLower()] = $t
    }
    Write-ScanLog "Running authenticated checks on $($nameMap.Count) Windows hosts"

    $icParams = @{
        ComputerName  = @($nameMap.Keys)
        Credential    = $Credential
        ScriptBlock   = $script:WindowsCollector
        ThrottleLimit = $ThrottleLimit
        ErrorAction   = 'SilentlyContinue'
        ErrorVariable = 'remoteErrors'
    }
    if ($UseSSL) { $icParams['UseSSL'] = $true }
    $results = @(Invoke-Command @icParams)

    $done = @{}
    foreach ($r in $results) {
        $key = ([string]$r.PSComputerName).ToLower()
        $h = $nameMap[$key]
        if (-not $h) { continue }
        $done[$key] = $true
        $findings += ConvertTo-WindowsFindings -Data $r -HostAddress $h.Address -HostName $h.HostName
    }
    foreach ($err in @($remoteErrors)) {
        $target = ([string]$err.TargetObject).ToLower()
        if (-not $target -and $err.OriginInfo) { $target = ([string]$err.OriginInfo.PSComputerName).ToLower() }
        $h = $nameMap[$target]
        if ($h -and -not $done.ContainsKey($target)) {
            $done[$target] = $true
            $findings += New-Finding -HostAddress $h.Address -HostName $h.HostName -Category Scan `
                -Id 'SCAN-WINRM-FAILED' -Title 'Authenticated Windows checks failed' -Severity Info `
                -Evidence ([string]$err.Exception.Message).Split("`n")[0] `
                -Remediation 'Check the account has local admin rights, WinRM is allowed from the scanner, and the name resolves (or add to TrustedHosts / use -UseSSL for IPs).'
        }
    }
    return $findings
}
