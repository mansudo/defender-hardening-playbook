<#
.SYNOPSIS
    Full Microsoft Defender for Endpoint baseline audit.
    Checks CIS Benchmark settings, tamper protection, ASR rules, cloud protection,
    and outputs a summary report.

.PARAMETER OutputPath
    Directory to write audit results. Defaults to current directory.

.PARAMETER Level
    CIS Benchmark level: 1 (basic) or 2 (high security). Default: 1.

.EXAMPLE
    .\Invoke-DefenderAudit.ps1 -OutputPath "C:\Audit" -Level 1
#>
[CmdletBinding()]
param(
    [string]$OutputPath = ".",
    [ValidateSet(1,2)][int]$Level = 1
)

$results = @()
$timestamp = Get-Date -Format "yyyy-MM-dd_HHmm"

function Add-Result {
    param($Control, $Setting, $Expected, $Actual, $Status, $Notes = "")
    $results += [PSCustomObject]@{
        Control  = $Control
        Setting  = $Setting
        Expected = $Expected
        Actual   = $Actual
        Status   = $Status
        Notes    = $Notes
    }
}

Write-Host "`n[*] Microsoft Defender Baseline Audit — CIS Level $Level" -ForegroundColor Cyan
Write-Host "[*] Host: $env:COMPUTERNAME | $(Get-Date)`n"

# ── Defender Service State ─────────────────────────────────────────────
$mpStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue
if (-not $mpStatus) {
    Write-Warning "Could not retrieve MpComputerStatus. Ensure Defender is running and script is elevated."
    exit 1
}

# Real-time protection
$rtp = $mpStatus.RealTimeProtectionEnabled
Add-Result "18.10.42.10.2" "Real-Time Protection" $true $rtp `
    $(if ($rtp) { "PASS" } else { "FAIL" })

# Tamper protection
$tamper = $mpStatus.IsTamperProtected
Add-Result "Custom" "Tamper Protection" $true $tamper `
    $(if ($tamper) { "PASS" } else { "FAIL" }) `
    "Source: $($mpStatus.TamperProtectionSource)"

# Cloud protection
$cloud = $mpStatus.AntispywareEnabled
$mapsReporting = (Get-MpPreference).MAPSReporting
Add-Result "18.10.42.6" "Cloud Protection (MAPS)" 2 $mapsReporting `
    $(if ($mapsReporting -ge 2) { "PASS" } else { "FAIL" })

# Cloud block level
$cloudBlock = (Get-MpPreference).CloudBlockLevel
Add-Result "Custom" "Cloud Block Level" 2 $cloudBlock `
    $(if ($cloudBlock -ge 2) { "PASS" } else { "WARN" }) `
    "2=High, 6=HighPlus"

# Behavior monitoring
$behavMon = $mpStatus.BehaviorMonitorEnabled
Add-Result "18.10.42.13.1" "Behavior Monitoring" $true $behavMon `
    $(if ($behavMon) { "PASS" } else { "FAIL" })

# ── ASR Rules ──────────────────────────────────────────────────────────
$asrRules = (Get-MpPreference).AttackSurfaceReductionRules_Ids
$asrActions = (Get-MpPreference).AttackSurfaceReductionRules_Actions

$criticalASR = @(
    "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b0",  # LSASS credential theft
    "3b576869-a4ec-4529-8536-b80a7769e899",  # Office exec content
    "5beb7efe-fd9a-4556-801d-275e5ffc04cc",  # Obfuscated scripts
    "c1db55ab-c21a-4637-bb3f-a12568109d35"   # Ransomware protection
)

foreach ($guid in $criticalASR) {
    $idx = $asrRules.IndexOf($guid)
    $action = if ($idx -ge 0) { $asrActions[$idx] } else { "Not configured" }
    # 1 = Block, 2 = Audit, 6 = Warn
    $status = if ($action -eq 1) { "PASS" } elseif ($action -eq 2) { "AUDIT" } else { "FAIL" }
    Add-Result "18.10.42.6.1" "ASR: $($guid.Substring(0,8))..." 1 $action $status
}

# ── Output ─────────────────────────────────────────────────────────────
$pass  = ($results | Where-Object Status -eq "PASS").Count
$fail  = ($results | Where-Object Status -eq "FAIL").Count
$warn  = ($results | Where-Object { $_.Status -in "WARN","AUDIT" }).Count
$total = $results.Count

Write-Host "`n[*] Results: $pass/$total PASS | $fail FAIL | $warn WARN`n"
$results | Format-Table Control, Setting, Expected, Actual, Status, Notes -AutoSize

# Export CSV
$outFile = Join-Path $OutputPath "defender-audit-$timestamp.csv"
$results | Export-Csv -Path $outFile -NoTypeInformation
Write-Host "`n[*] Report saved: $outFile"
