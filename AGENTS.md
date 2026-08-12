# AGENTS.md — defender-hardening-playbook

Instructions for AI agents (Claude, Codex, Copilot, etc.) working in this repository.

## What This Repo Is

PowerShell scripts and configuration references for hardening Microsoft Defender for Endpoint in enterprise environments, based on CIS Benchmarks, NIST guidelines, and real-world validation across 500+ enterprise organizations. Every script here has been run against production-class Windows environments, not just written against documentation.

## Repo Layout

| Path | Contents |
|---|---|
| `/scripts` | PowerShell validation and remediation scripts |
| `/cis-benchmarks` | CIS Benchmark mappings for Defender settings |
| `/intune-policies` | Exportable Intune configuration profiles |
| `/gpo-templates` | ADMX/ADML templates and GPO export references |
| `/findings` | Real-world validation findings and edge cases |

## Ground Rules for Agents

1. **Validate before remediate.** Every setting change should have a matching `Test-*` / `Get-*` read-only check before a `Set-*` / `Invoke-*` remediation script exists for it. Don't add a remediation script without a way to verify state first.
2. **Cite the source control.** Any new hardening rule must reference its origin (CIS Benchmark control ID, NIST guideline, or MSFT security baseline). Don't add settings on vibes — this repo's value is that everything traces back to a named standard.
3. **Document known issues, don't hide them.** If a setting behaves differently across Intune vs. GPO vs. local policy (see the Tamper Protection `ATP` vs `MDM` source example in the README), log it in `/findings` rather than silently picking one behavior to document.
4. **PowerShell style:** Use approved verbs (`Get-`, `Test-`, `Set-`, `Invoke-`), include `-WhatIf` support on anything that changes state, and comment-based help (`.SYNOPSIS`, `.DESCRIPTION`, `.EXAMPLE`) on every exported function.
5. **No destructive defaults.** Scripts that disable protections (real-time protection, tamper protection, ASR rules) for testing purposes must require an explicit `-Force` or `-Confirm:$false` flag — never silent by default.
6. **Enterprise scale in mind.** Assume scripts may run against 500+ endpoints via RMM/Intune/GPO push, not just one local machine. Avoid interactive prompts in remediation scripts; fail loudly and log instead.

## Testing Expectations

- New `Test-*` scripts should be runnable read-only with no side effects, and should output a pass/fail/not-applicable result per CIS control ID checked.
- If you can't validate a script against a real Windows/Defender environment, say so explicitly in the PR description rather than presenting it as field-tested.

## Out of Scope

- This repo is Defender-for-Endpoint specific. Don't fold in generic Windows hardening, third-party AV, or non-Microsoft EDR content — keep it focused.
- No cloud-only (Defender for Cloud Apps, Defender for Office) content here; this is endpoint/device-level only.
