# Rule-based findings from Nmap service and NSE script results (no credentials needed).

$script:CleartextServices = @{
    'telnet'  = @{ Severity = 'High';   Title = 'Telnet service exposed (cleartext credentials)'; Fix = 'Disable Telnet and use SSH instead.' }
    'ftp'     = @{ Severity = 'Medium'; Title = 'FTP service exposed (cleartext credentials)';    Fix = 'Replace FTP with SFTP or FTPS, or restrict it to required hosts.' }
    'exec'    = @{ Severity = 'High';   Title = 'rexec service exposed';                          Fix = 'Disable r-services (rexec, rlogin, rsh); use SSH.' }
    'login'   = @{ Severity = 'High';   Title = 'rlogin service exposed';                         Fix = 'Disable r-services (rexec, rlogin, rsh); use SSH.' }
    'shell'   = @{ Severity = 'High';   Title = 'rsh service exposed';                            Fix = 'Disable r-services (rexec, rlogin, rsh); use SSH.' }
    'vnc'     = @{ Severity = 'Medium'; Title = 'VNC remote desktop exposed';                     Fix = 'Restrict VNC to a management network or VPN, require strong authentication, or replace it.' }
}

$script:DatabaseServices = @{
    'ms-sql-s'      = 'Microsoft SQL Server'
    'mysql'         = 'MySQL / MariaDB'
    'postgresql'    = 'PostgreSQL'
    'mongodb'       = 'MongoDB'
    'mongod'        = 'MongoDB'
    'redis'         = 'Redis'
    'elasticsearch' = 'Elasticsearch'
    'oracle-tns'    = 'Oracle Database'
}

function Get-NetworkFindings {
    param([Parameter(Mandatory)][object[]]$Hosts)
    $findings = @()

    foreach ($h in $Hosts) {
        $hp = @{ HostAddress = $h.Address; HostName = $h.HostName }

        foreach ($p in $h.Ports) {
            $port = "$($p.Port)/$($p.Protocol)"
            $label = Get-ServiceLabel $p
            $svc = $p.Service.ToLower()

            # Cleartext and legacy remote-access services
            if ($script:CleartextServices.ContainsKey($svc)) {
                $rule = $script:CleartextServices[$svc]
                $findings += New-Finding @hp -Port $port -Service $label -Category Exposure `
                    -Id "NET-$($svc.ToUpper())" -Title $rule.Title -Severity $rule.Severity `
                    -Evidence "Open port $port answering as $svc." -Remediation $rule.Fix
            }

            # Anonymous FTP
            if ($p.Scripts.ContainsKey('ftp-anon') -and $p.Scripts['ftp-anon'] -match 'Anonymous FTP login allowed') {
                $findings += New-Finding @hp -Port $port -Service $label -Category Configuration `
                    -Id 'NET-FTP-ANON' -Title 'Anonymous FTP login allowed' -Severity High `
                    -Evidence 'Nmap ftp-anon: anonymous login succeeded.' `
                    -Remediation 'Disable anonymous FTP access.'
            }

            # Databases reachable over the network
            if ($script:DatabaseServices.ContainsKey($svc)) {
                $findings += New-Finding @hp -Port $port -Service $label -Category Exposure `
                    -Id "NET-DB-$($svc.ToUpper())" -Title "$($script:DatabaseServices[$svc]) reachable over the network" `
                    -Severity Low -Evidence "Open port $port." `
                    -Remediation 'Allow database ports only from the application servers that need them (host firewall or network ACL).'
            }

            # TLS protocol and cipher weaknesses
            if ($p.Scripts.ContainsKey('ssl-enum-ciphers')) {
                $out = $p.Scripts['ssl-enum-ciphers']
                if ($out -match 'SSLv3:') {
                    $findings += New-Finding @hp -Port $port -Service $label -Category Configuration `
                        -Id 'NET-TLS-SSLV3' -Title 'SSLv3 enabled (POODLE)' -Severity High -Score 7.5 `
                        -Evidence 'Server accepts SSLv3 connections.' `
                        -Remediation 'Disable SSLv3; allow only TLS 1.2 and TLS 1.3.' `
                        -References @('https://nvd.nist.gov/vuln/detail/CVE-2014-3566')
                }
                $legacy = @()
                if ($out -match 'TLSv1\.0:') { $legacy += 'TLS 1.0' }
                if ($out -match 'TLSv1\.1:') { $legacy += 'TLS 1.1' }
                if ($legacy) {
                    $findings += New-Finding @hp -Port $port -Service $label -Category Configuration `
                        -Id 'NET-TLS-LEGACY' -Title "Deprecated TLS versions enabled: $($legacy -join ', ')" -Severity Medium `
                        -Evidence "Server accepts $($legacy -join ' and ')." `
                        -Remediation 'Disable TLS 1.0 and 1.1; allow only TLS 1.2 and TLS 1.3. On Windows, set SCHANNEL Protocols registry keys or use IIS Crypto.'
                }
                if ($out -match 'least strength:\s*([D-F])') {
                    $findings += New-Finding @hp -Port $port -Service $label -Category Configuration `
                        -Id 'NET-TLS-WEAKCIPHER' -Title "Weak TLS ciphers offered (grade $($Matches[1]))" -Severity Medium `
                        -Evidence "Nmap ssl-enum-ciphers rated the weakest offered cipher $($Matches[1])." `
                        -Remediation 'Remove RC4, 3DES, export and NULL ciphers; prefer AES-GCM and ChaCha20 suites.'
                }
            }

            # Certificate problems
            if ($p.Scripts.ContainsKey('ssl-cert')) {
                $out = $p.Scripts['ssl-cert']
                if ($out -match 'Not valid after:\s*(\d{4}-\d{2}-\d{2})') {
                    $expiry = [datetime]::ParseExact($Matches[1], 'yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture)
                    $days = [int]($expiry - (Get-Date)).TotalDays
                    if ($days -lt 0) {
                        $findings += New-Finding @hp -Port $port -Service $label -Category Configuration `
                            -Id 'NET-CERT-EXPIRED' -Title 'TLS certificate expired' -Severity Medium `
                            -Evidence "Certificate expired $($Matches[1]) ($([math]::Abs($days)) days ago)." `
                            -Remediation 'Renew and install a valid certificate.'
                    } elseif ($days -le 30) {
                        $findings += New-Finding @hp -Port $port -Service $label -Category Configuration `
                            -Id 'NET-CERT-EXPIRING' -Title 'TLS certificate expires within 30 days' -Severity Low `
                            -Evidence "Certificate expires $($Matches[1]) (in $days days)." `
                            -Remediation 'Renew the certificate before it expires.'
                    }
                }
                $subject = if ($out -match 'Subject:\s*(.+)') { $Matches[1].Trim() } else { '' }
                $issuer  = if ($out -match 'Issuer:\s*(.+)')  { $Matches[1].Trim() } else { '' }
                if ($subject -and $subject -eq $issuer) {
                    $findings += New-Finding @hp -Port $port -Service $label -Category Configuration `
                        -Id 'NET-CERT-SELFSIGNED' -Title 'Self-signed TLS certificate' -Severity Low `
                        -Evidence "Subject and issuer are the same: $subject" `
                        -Remediation 'Issue the certificate from your internal CA or a public CA so clients can validate it.'
                }
            }

            # RDP without Network Level Authentication
            if ($p.Scripts.ContainsKey('rdp-enum-encryption')) {
                $out = $p.Scripts['rdp-enum-encryption']
                if ($out -match 'Native RDP:\s*SUCCESS' -or $out -match '(?m)^\s*\|?\s*SSL:\s*SUCCESS') {
                    $findings += New-Finding @hp -Port $port -Service $label -Category Configuration `
                        -Id 'NET-RDP-NONLA' -Title 'RDP accepts connections without Network Level Authentication' -Severity Medium `
                        -Evidence 'Server negotiated a security layer other than CredSSP (NLA).' `
                        -Remediation 'Require NLA: System Properties > Remote > "Allow connections only from computers running Remote Desktop with Network Level Authentication", or GPO.'
                }
            }
        }

        # SMB host-level checks
        if ($h.HostScripts.ContainsKey('smb-protocols') -and $h.HostScripts['smb-protocols'] -match 'SMBv1|NT LM 0\.12') {
            $findings += New-Finding @hp -Port '445/tcp' -Service 'microsoft-ds' -Category Configuration `
                -Id 'NET-SMB1' -Title 'SMBv1 protocol enabled' -Severity High -Score 8.1 `
                -Evidence 'Server accepts the SMBv1 (NT LM 0.12) dialect.' `
                -Remediation 'Disable SMBv1: Set-SmbServerConfiguration -EnableSMB1Protocol $false, and remove the SMB1 feature.' `
                -References @('https://learn.microsoft.com/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3')
        }
        if ($h.HostScripts.ContainsKey('smb2-security-mode') -and $h.HostScripts['smb2-security-mode'] -match 'not required') {
            $findings += New-Finding @hp -Port '445/tcp' -Service 'microsoft-ds' -Category Configuration `
                -Id 'NET-SMB-SIGNING' -Title 'SMB signing not required' -Severity Medium `
                -Evidence 'Message signing is enabled but not required, which allows NTLM relay attacks.' `
                -Remediation 'Require SMB signing via GPO: "Microsoft network server: Digitally sign communications (always)".'
        }
    }
    return $findings
}
