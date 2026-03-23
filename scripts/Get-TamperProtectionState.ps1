<#
.SYNOPSIS
    Checks Microsoft Defender Tamper Protection state and management source.
#>
$status = Get-MpComputerStatus

[PSCustomObject]@{
    Host                  = $env:COMPUTERNAME
    TamperProtected       = $status.IsTamperProtected
    TamperProtectionSource = $status.TamperProtectionSource
    # Source values:
    #   "ATP"  = Managed via Microsoft Defender for Endpoint portal
    #   "MDM"  = Managed via Intune/MDM CSP
    #   "SHIELDED" = Managed via Security Center app
    #   "" = Not managed / local setting
    DefenderVersion       = $status.AMProductVersion
    SignatureVersion      = $status.AntivirusSignatureVersion
    LastUpdated           = $status.AntivirusSignatureLastUpdated
} | Format-List

# Registry verification (independent check)
$regPath = "HKLM:\SOFTWARE\Microsoft\Windows Defender\Features"
$regValue = (Get-ItemProperty -Path $regPath -Name "TamperProtection" -ErrorAction SilentlyContinue).TamperProtection
Write-Host "`nRegistry TamperProtection value: $regValue (5 = enabled, 4 = disabled)"
