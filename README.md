# defender-hardening-playbook

PowerShell scripts and configuration references for hardening Microsoft Defender for Endpoint in enterprise environments — based on CIS Benchmarks, NIST guidelines, and real-world validation across 500+ enterprise organizations.

This isn't a theoretical guide. Every script here has been run against production-class Windows environments and the output documented.

## What's In Here

| Directory | Contents |
|-----------|----------|
| [`/scripts`](/scripts) | PowerShell validation and remediation scripts |
| [`/cis-benchmarks`](/cis-benchmarks) | CIS Benchmark mappings for Defender settings |
| [`/intune-policies`](/intune-policies) | Exportable Intune configuration profiles |
| [`/gpo-templates`](/gpo-templates) | ADMX/ADML templates and GPO export references |
| [`/findings`](/findings) | Real-world validation findings and edge cases |

## Quick Start

```powershell
# Run the full Defender baseline audit
.\scripts\Invoke-DefenderAudit.ps1 -OutputPath ".\audit-results"

# Check tamper protection state
.\scripts\Get-TamperProtectionState.ps1

# Validate CIS L1 Defender settings
.\scripts\Test-CISDefenderBaseline.ps1 -Level 1
```

## CIS Benchmark Coverage

### CIS Microsoft Windows 11 Benchmark v3.0 — Defender Settings

| CIS Control | Setting | Recommended Value | Script |
|-------------|---------|-------------------|--------|
| 18.10.42.1 | Configure detection for potentially unwanted applications | Enabled: Block | `Test-CISDefenderBaseline.ps1` |
| 18.10.42.5 | Turn off Microsoft Defender AntiVirus | Disabled | `Test-CISDefenderBaseline.ps1` |
| 18.10.42.6.1 | Configure Attack Surface Reduction rules | Enabled | `Test-ASRRules.ps1` |
| 18.10.42.7.1 | Prevent users/apps from accessing dangerous websites | Enabled: Block | `Test-CISDefenderBaseline.ps1` |
| 18.10.42.10.1 | Scan all downloaded files and attachments | Enabled | `Test-CISDefenderBaseline.ps1` |
| 18.10.42.10.2 | Turn off real-time protection | Disabled | `Test-CISDefenderBaseline.ps1` |
| 18.10.42.13.1 | Turn on behavior monitoring | Enabled | `Test-CISDefenderBaseline.ps1` |

## Tamper Protection

Tamper Protection prevents local changes to Defender settings even with admin rights. Critical for enterprise deployments.

```powershell
# Check state via PowerShell
Get-MpComputerStatus | Select-Object IsTamperProtected, TamperProtectionSource

# Expected output on a hardened machine:
# IsTamperProtected : True
# TamperProtectionSource : ATP  (managed via Defender for Endpoint portal)
```

**Known issue:** Tamper Protection set to "on" via Intune CSP will show as `MDM` source, not `ATP`. Both are valid — `ATP` means MDE portal is managing it, `MDM` means Intune. Either blocks local tampering.

## Attack Surface Reduction Rules

ASR rules are one of the most effective preventive controls for ransomware and credential theft — and one of the most commonly misconfigured.

| Rule | GUID | Recommended Mode |
|------|------|-----------------|
| Block credential stealing from LSASS | 9e6c4e1f-7d60-472f-ba1a-a39ef669e4b0 | Block |
| Block Office apps from creating executable content | 3b576869-a4ec-4529-8536-b80a7769e899 | Block |
| Block execution of potentially obfuscated scripts | 5beb7efe-fd9a-4556-801d-275e5ffc04cc | Block |
| Block process creations from PSExec and WMI commands | d1e49aac-8f56-4280-b9ba-993a6d77406c | Audit first |
| Use advanced protection against ransomware | c1db55ab-c21a-4637-bb3f-a12568109d35 | Block |

```powershell
# Audit mode first — check what would be blocked before enforcing
Set-MpPreference -AttackSurfaceReductionRules_Ids 9e6c4e1f-7d60-472f-ba1a-a39ef669e4b0 `
                 -AttackSurfaceReductionRules_Actions AuditMode

# Review audit events
Get-WinEvent -LogName "Microsoft-Windows-Windows Defender/Operational" |
    Where-Object { $_.Id -eq 1121 -or $_.Id -eq 1122 } |
    Select-Object TimeCreated, Message |
    Format-List
```

## Cloud Protection

Cloud-delivered protection provides near-instant detection of new threats.

```powershell
# Enable cloud protection at highest block level
Set-MpPreference -MAPSReporting Advanced
Set-MpPreference -SubmitSamplesConsent SendAllSamples
Set-MpPreference -CloudBlockLevel High
Set-MpPreference -CloudExtendedTimeout 50
```

**Enterprise note:** `CloudBlockLevel = HighPlus` (value 6) triggers blocking on files with suspicious characteristics even without a definitive verdict — appropriate for high-security environments, may cause false positives in development environments.

## Intune Deployment

See [`/intune-policies`](/intune-policies) for ready-to-import Intune configuration profiles covering:
- Defender Antivirus baseline
- Attack Surface Reduction rules
- Endpoint Detection & Response onboarding
- Tamper Protection enforcement

## Findings & Edge Cases

See [`/findings`](/findings) for documented real-world behavior including:
- CSP/GPO conflicts on hybrid-joined devices
- Tamper Protection blocking legitimate admin scripts
- ASR rule false positives by software category
- Cloud protection timeout behavior on air-gapped segments

---

*Based on hands-on validation across enterprise environments. Contributions welcome.*

*Kofi Asirifi · [LinkedIn](https://linkedin.com/in/kofiasirifi)*
