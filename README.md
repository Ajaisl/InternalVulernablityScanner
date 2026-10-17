# VulnScan: internal network vulnerability scanner for Windows Server

PowerShell + Nmap scanner that finds vulnerabilities on your internal network and writes a self-contained HTML report.

**Only scan networks you own or are authorized to test.** Get written approval before scanning, and tell your network and security teams so the scan isn't mistaken for an attack.

## What it checks

| Stage | Needs credentials | What it finds |
| --- | --- | --- |
| Discovery (Nmap) | No | Live hosts, open ports, service product and version |
| Network checks | No | SMBv1, SMB signing not required, SSLv3 / TLS 1.0 / TLS 1.1, weak ciphers, expired or self-signed certificates, RDP without NLA, Telnet / FTP / anonymous FTP / r-services / VNC, databases reachable over the network |
| CVE matching (NVD API) | No | Known CVEs for detected product versions, with CVSS score and CISA Known Exploited (KEV) flag |
| Windows checks (WinRM) | Yes, local admin | Missing updates, pending reboot, unsupported OS, SMBv1, SMB signing, RDP NLA, firewall profiles, Defender real-time and signature age, WDigest, LLMNR, SCHANNEL legacy protocols, Guest account, local admins, Print Spooler on DCs, PowerShell 2.0 |

Nothing is exploited and nothing is changed. Nmap runs only safe NSE scripts (`ssl-enum-ciphers`, `ssl-cert`, `smb-protocols`, `smb2-security-mode`, `rdp-enum-encryption`, `ftp-anon`, `http-title`). Windows checks only read settings.

## Setup on the scanner server

1. **Windows Server 2016 or later**, Windows PowerShell 5.1 or PowerShell 7.
2. **Install Nmap** from https://nmap.org/download.html with Npcap (keep the default options). The scanner finds it in `C:\Program Files (x86)\Nmap` or on PATH.
3. **Copy this folder** to the server, for example `D:\VulnScan`, and unblock the files:
   ```powershell
   Get-ChildItem D:\VulnScan -Recurse | Unblock-File
   ```
4. **Get a free NVD API key** (https://nvd.nist.gov/developers/request-an-api-key) and store it as a machine environment variable. Without it, CVE lookups are rate-limited to about 5 per 30 seconds:
   ```powershell
   [Environment]::SetEnvironmentVariable('NVD_API_KEY', '<your key>', 'Machine')
   ```
   The server needs outbound HTTPS to `services.nvd.nist.gov`.
5. **For Windows checks:** create a dedicated account (e.g. `svc-vulnscan`) that is a local administrator on target servers (GPO Restricted Groups works well). WinRM must be enabled on targets (it is by default on Windows Server) and TCP 5985 allowed from the scanner.

## Run a scan

Open PowerShell **as Administrator** (Nmap SYN scans need it):

```powershell
cd D:\VulnScan

# Network checks + CVEs only
.\Invoke-VulnScan.ps1 -Target 10.10.0.0/24

# Add authenticated Windows checks, exclude the core switch
$cred = Get-Credential CONTOSO\svc-vulnscan
.\Invoke-VulnScan.ps1 -Target 10.10.0.0/24, 10.20.5.0/24 -Exclude 10.10.0.1 -Credential $cred

# Hosts that block ping, all ports, gentler timing
.\Invoke-VulnScan.ps1 -Target 10.30.0.0/24 -NoPing -Ports 1-65535 -Timing T2
```

Each run creates `reports\<yyyyMMdd-HHmm>\` containing:

- `report.html`: the report, open it in any browser
- `nmap.xml`: raw Nmap output
- `scan.log`: what the scan did

CVE results are cached in `reports\cve-cache.json` for 7 days (`-CveCacheDays`), so repeat scans are fast.

To rebuild a report from an earlier scan without scanning again:

```powershell
.\Invoke-VulnScan.ps1 -NmapXml .\reports\20261017-0200\nmap.xml -Credential $cred
```

### Parameters

| Parameter | Default | Purpose |
| --- | --- | --- |
| `-Target` | required | IPs, ranges or CIDRs, e.g. `10.0.0.0/24`, `10.0.1.10-50`, `srv01` |
| `-Exclude` | none | Hosts to skip (printers, fragile OT/medical devices, network gear) |
| `-Ports` | `top1000` | Nmap port list, e.g. `1-65535` or `22,80,443,445,3389` |
| `-Timing` | `T3` | `T2` gentler, `T4` faster |
| `-NoPing` | off | Treat all hosts as up (for hosts that block ICMP) |
| `-Credential` | none | Enables authenticated Windows checks |
| `-UseSSL` | off | WinRM over HTTPS (5986), needed when targeting by IP without TrustedHosts |
| `-NvdApiKey` | `$env:NVD_API_KEY` | NVD API key |
| `-SkipCveLookup` | off | Skip CVE matching (e.g. no internet access) |
| `-OutputDirectory` | `.\reports` | Where reports go |

## Schedule weekly scans

1. Copy `scan-config.example.json` to `scan-config.json` and edit targets.
2. Log in to the server **as the account the task will run as** and save the credential (DPAPI-encrypted, readable only by that account on that server):
   ```powershell
   Get-Credential CONTOSO\svc-vulnscan | Export-Clixml -Path D:\VulnScan\scan-cred.xml
   ```
3. Create the task (runs Sundays at 02:00, elevated):
   ```powershell
   $action  = New-ScheduledTaskAction -Execute 'powershell.exe' `
       -Argument '-NoProfile -ExecutionPolicy Bypass -File D:\VulnScan\Start-ScheduledScan.ps1'
   $trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Sunday -At 2am
   Register-ScheduledTask -TaskName 'Weekly Vulnerability Scan' -Action $action -Trigger $trigger `
       -User 'CONTOSO\svc-vulnscan' -Password (Read-Host 'Password') -RunLevel Highest
   ```

## Reading the report

- **Fix first** lists known-exploited (KEV), critical and high findings across the network, highest risk first.
- **Hosts** ranks hosts by risk; click one to jump to its findings.
- Each finding has evidence and a fix.

## Limitations

- **CVE matches are version-based.** Linux distributions and appliances often backport security fixes without changing the version string, which causes false positives. Confirm on the host before acting. Services where Nmap can't identify a version get no CVE matches (false negatives).
- **Missing updates:** Windows Update searches sometimes fail over remote sessions. The scanner then falls back to the last-installed hotfix date and notes this in the finding.
- **Not a replacement** for a full commercial scanner (Nessus, Qualys, Rapid7) or a penetration test. It covers common, high-impact issues well.
- **UDP is not scanned** (SNMP, TFTP). Add `-sU` in `lib\Discovery.ps1` if you need it; it is slow.

## Project layout

```
Invoke-VulnScan.ps1        Main entry point
Start-ScheduledScan.ps1    Wrapper for Task Scheduler (reads scan-config.json)
scan-config.example.json   Example settings
lib\Common.ps1             Finding objects, severity, logging
lib\Discovery.ps1          Nmap execution and XML parsing
lib\NetworkChecks.ps1      Unauthenticated configuration and exposure rules
lib\CveLookup.ps1          NVD API 2.0 matching and cache
lib\WindowsChecks.ps1      Authenticated WinRM checks
lib\Report.ps1             HTML report
tests\                     Sample data and test runner
```
