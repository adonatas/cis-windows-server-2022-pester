# CIS Microsoft Windows Server 2022 Benchmark — Pester Tests (Domain Controller)

Data-driven [Pester v5](https://pester.dev) suite that audits a Windows Server 2022 **Domain Controller** against
**CIS Microsoft Windows Server 2022 Benchmark v5.0.0** (released 2026-02-20).

## Scope

| | Included | Excluded |
|---|---|---|
| **Role** | Domain Controller (L1-DC, L2-DC, NG-DC) | Member Server |
| **Policy area** | Computer Configuration + Section 19 (per-user) | — |
| **Profile** | Level 1, Level 2, Next-Generation | — |
| **Coverage** | **394** recommendations | "MS only" recs and 4 user-excluded controls |

Breakdown by rule type:

| Type | Count | How it's tested |
|---|---|---|
| Registry | 288 | Direct `Get-ItemProperty` against `HKLM:\` |
| Registry (paired/multi-location) | 8 | Many keys must all match |
| Registry (multi-value) | 1 | Hardened UNC Paths |
| Per-user (HKU) registry | 11 | Walks `HKEY_USERS\<SID>\…` for every loaded user hive |
| User Rights Assignment | 39 | `secedit /export` → `[Privilege Rights]` |
| Advanced Audit Policy | 34 | `auditpol /get /subcategory:{GUID}` |
| Account/Lockout Policy | 13 | `secedit /export` → `[System Access]` |

## Files

- `Invoke-CISAudit.ps1` — convenience wrapper. Runs the suite and exports a CSV report.
- `CIS-WS2022-DC.Tests.ps1` — the Pester test runner (no per-rec code; it loops over the JSON).
- `CIS-WS2022-DC-Rules.json` — the structured rule definitions auto-extracted from the CIS PDF.

## Quick start — CSV report

Run from an **elevated** PowerShell on the target DC:

```powershell
cd C:\path\to\cis-pester
.\Invoke-CISAudit.ps1
```

This writes `cis-audit-<HOSTNAME>-<yyyyMMdd-HHmm>.csv` to the current directory with columns:

| Column | Example |
|---|---|
| `date` | `2026-06-11 14:32:01` |
| `hostname` | `DC01` |
| `rule_id` | `2.3.4.1` |
| `compliance` | `pass`, `fail`, or `skip` |

Filter by tag:

```powershell
.\Invoke-CISAudit.ps1 -Tag L1-DC
.\Invoke-CISAudit.ps1 -Tag Registry -OutputCsv .\reg-only.csv
```

## Run

```powershell
# Install Pester v5 if needed
Install-Module Pester -MinimumVersion 5.0 -Force -SkipPublisherCheck

# Run everything (run on the DC, elevated PowerShell)
Invoke-Pester -Path .\CIS-WS2022-DC.Tests.ps1 -Output Detailed

# Run only Level 1
Invoke-Pester -Path .\CIS-WS2022-DC.Tests.ps1 -TagFilter L1-DC

# Run Level 2 + Next Gen
Invoke-Pester -Path .\CIS-WS2022-DC.Tests.ps1 -TagFilter L2-DC,NG-DC

# Run a single CIS section
Invoke-Pester -Path .\CIS-WS2022-DC.Tests.ps1 -TagFilter Section-17

# Run a single audit type
Invoke-Pester -Path .\CIS-WS2022-DC.Tests.ps1 -TagFilter AuditPol

# Emit NUnit XML for CI
Invoke-Pester -Path .\CIS-WS2022-DC.Tests.ps1 `
              -CI -Output Detailed `
              -OutputFile .\cis-results.xml -OutputFormat NUnitXml
```

## Tags

Every `It` is tagged with all three of:

- A **profile** — `L1-DC`, `L2-DC`, `NG-DC` (a rule that applies to multiple profiles is tagged once per profile via the joint `profile` field in JSON; use `-TagFilter` accordingly).
- A **section** — `Section-1`, `Section-2`, `Section-5`, `Section-9`, `Section-17`, `Section-18`.
- An **audit type** — `Registry`, `SecEdit`, `UserRights`, `AuditPol`.

## Caveats

1. **Run elevated, on the target DC.** Registry, secedit, and auditpol all require local admin.
2. **GPO vs. local registry.** Tests read effective registry — not whether the setting was applied via GPO vs. locally. Run `gpupdate /force` first if you want to verify a recently linked GPO.
3. **Account name comparison** for User Rights uses `*S-1-…` SIDs as exported by `secedit`. Tests accept both SID and friendly name forms, but the canonical comparison is SID-based. If your domain GPO injects friendly names (e.g. `BUILTIN\Administrators`), the test will normalise both sides.
4. **Account / Lockout / Password Policy** (`secedit_inf` rules) must be set in the **Default Domain Policy GPO** to take effect on domain users. The test reads the *effective* value via `secedit /export` on the DC.
5. **Hardened UNC Paths** (`18.6.14.1`) verifies that the two required REG_SZ entries each contain `RequireMutualAuthentication=1`, `RequireIntegrity=1`, `RequirePrivacy=1`. If you add additional flags or paths, the test will still pass as long as those three are present.
6. **Manual ("Configure ...") recommendations** for things like *Rename administrator account* (`2.3.1.3`) and *Rename guest account* (`2.3.1.4`) verify only that the name has been changed from the default — not what the new name is.

## How the rules were generated

`CIS-WS2022-DC-Rules.json` was produced by parsing the official CIS PDF and extracting:

- Recommendation number, title, profile applicability
- Registry path / value name / value type / expected value from the Audit and Remediation sections
- Privilege right constant + expected accounts (for User Rights)
- Subcategory GUID + expected setting (for auditpol)
- INF section/key (for Password, Lockout, and certain Security Options)

Re-running the extractor against a newer CIS PDF revision should regenerate the JSON with minimal manual touch-up.
