# Finding: CSP/GPO Conflicts on Hybrid-Joined Devices

**Environment:** Windows 11, Hybrid AAD Join (AD + Intune enrolled)
**Severity:** Medium — causes policy drift and inconsistent compliance state

## Behavior

On hybrid-joined devices, certain MDM CSP settings applied via Intune conflict with
existing Group Policy Objects, producing unpredictable results:

1. **Policy not applied:** GPO wins silently — Intune reports compliant but setting isn't enforced
2. **Policy applied twice:** Both MDM and GPO enforce the same setting with different values
3. **MDM enrollment blocked:** Existing GPO prevents MDM enrollment for specific policy areas

## Affected Policy Areas

| Area | Behavior | Resolution |
|------|----------|------------|
| Windows Update | WSUS GPO blocks Intune WUfB | Remove WSUS GPO for MDM-targeted OUs |
| Firewall | Rules merge instead of replace | Use MDM-only or GPO-only for firewall |
| BitLocker | Silent encryption fails if GPO BitLocker exists | Migrate BitLocker to MDM CSP |
| Defender | Most CSPs win over GPO on hybrid joined | Verify via PolicyManager registry key |

## Diagnosis

```powershell
# Check which policy source is winning for a given setting
# Example: Check Defender real-time protection source
$mdmPath = "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Defender"
$gpPath  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"

Write-Host "MDM value:" (Get-ItemProperty $mdmPath -EA SilentlyContinue).AllowRealtimeMonitoring
Write-Host "GPO value:" (Get-ItemProperty $gpPath  -EA SilentlyContinue).DisableRealtimeMonitoring

# Check MDM enrollment diagnostic
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Enrollments" |
    Get-ItemProperty |
    Select-Object EnrollmentType, ProviderID, UPN
```

## Resolution

For new deployments: avoid hybrid join if full MDM management is the goal.
For existing hybrid environments:
1. Identify conflicting GPOs via `gpresult /h report.html`
2. Move conflicting settings to MDM CSP
3. Block GPO inheritance for MDM-targeted OUs where appropriate
4. Use MDM Diagnostic logs (`MDMDiagnosticsTool.exe -area DeviceEnrollment`) to confirm

## References
- [MDM and GPO coexistence](https://learn.microsoft.com/en-us/windows/client-management/mdm-overview)
- [WMI Bridge Provider](https://learn.microsoft.com/en-us/windows/client-management/using-powershell-scripting-with-the-wmi-bridge-provider)
