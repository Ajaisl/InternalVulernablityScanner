# Shared helpers: finding objects, severity handling, logging.

$script:SeverityOrder = @{ 'Critical' = 0; 'High' = 1; 'Medium' = 2; 'Low' = 3; 'Info' = 4 }

function Write-ScanLog {
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet('Info', 'Warn', 'Error')][string]$Level = 'Info'
    )
    $stamp = (Get-Date).ToString('HH:mm:ss')
    switch ($Level) {
        'Info'  { Write-Host "[$stamp] $Message" }
        'Warn'  { Write-Host "[$stamp] WARNING: $Message" -ForegroundColor Yellow }
        'Error' { Write-Host "[$stamp] ERROR: $Message" -ForegroundColor Red }
    }
    if ($script:ScanLogPath) {
        Add-Content -Path $script:ScanLogPath -Value "[$stamp] [$Level] $Message"
    }
}

function Get-SeverityFromScore {
    param([double]$Score)
    if ($Score -ge 9.0) { return 'Critical' }
    if ($Score -ge 7.0) { return 'High' }
    if ($Score -ge 4.0) { return 'Medium' }
    if ($Score -gt 0)   { return 'Low' }
    return 'Info'
}

function Get-SeverityRank {
    param([string]$Severity)
    if ($script:SeverityOrder.ContainsKey($Severity)) { return $script:SeverityOrder[$Severity] }
    return 5
}

function New-Finding {
    param(
        [Parameter(Mandatory)][string]$HostAddress,
        [string]$HostName = '',
        [string]$Port = '',
        [string]$Service = '',
        [Parameter(Mandatory)][ValidateSet('CVE', 'Configuration', 'Patching', 'Exposure', 'Scan')][string]$Category,
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][string]$Title,
        [Parameter(Mandatory)][ValidateSet('Critical', 'High', 'Medium', 'Low', 'Info')][string]$Severity,
        [double]$Score = 0,
        [string]$Evidence = '',
        [string]$Remediation = '',
        [string[]]$References = @(),
        [bool]$KnownExploited = $false
    )
    [pscustomobject]@{
        HostAddress    = $HostAddress
        HostName       = $HostName
        Port           = $Port
        Service        = $Service
        Category       = $Category
        Id             = $Id
        Title          = $Title
        Severity       = $Severity
        Score          = $Score
        Evidence       = $Evidence
        Remediation    = $Remediation
        References     = $References
        KnownExploited = $KnownExploited
    }
}

function Sort-Findings {
    param([object[]]$Findings)
    $Findings | Sort-Object -Property `
        @{ Expression = { if ($_.KnownExploited) { 0 } else { 1 } } },
        @{ Expression = { Get-SeverityRank $_.Severity } },
        @{ Expression = { $_.Score }; Descending = $true },
        @{ Expression = { $_.HostAddress } }
}
