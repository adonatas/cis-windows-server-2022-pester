#Requires -Version 5.1
#Requires -Modules @{ ModuleName="Pester"; ModuleVersion="5.0.0" }
<#
    CIS Microsoft Windows Server 2022 Benchmark v5.0.0
    Data-driven Pester suite — Domain Controller, Computer Configuration only.
    Profiles included: Level 1 - DC, Level 2 - DC, Next Generation Windows Security - DC.
    User-configuration recommendations (section 19) are intentionally excluded.

    Usage:
        Invoke-Pester -Path .\CIS-WS2022-DC.Tests.ps1                       # run everything
        Invoke-Pester -Path .\CIS-WS2022-DC.Tests.ps1 -Tag L1-DC            # L1 only
        Invoke-Pester -Path .\CIS-WS2022-DC.Tests.ps1 -Tag L2-DC,NG-DC      # L2 + NG
        Invoke-Pester -Path .\CIS-WS2022-DC.Tests.ps1 -Tag Section-17       # one CIS section
        Invoke-Pester -Path .\CIS-WS2022-DC.Tests.ps1 -Output Detailed
#>

param(
    [string]$RulesPath = (Join-Path $PSScriptRoot 'CIS-WS2022-DC-Rules.json'),
    [string]$SeceditExportPath = (Join-Path $env:TEMP 'cis-secedit.inf')
)

BeforeDiscovery {
    if (-not (Test-Path $RulesPath)) {
        throw "Rules file not found: $RulesPath"
    }
    $script:Rules = Get-Content -Raw -LiteralPath $RulesPath | ConvertFrom-Json
}

BeforeAll {
    # ------------ Helper: registry value read ------------
    function Get-RegistryValueSafe {
        param([string]$Path, [string]$Name)
        try {
            $item = Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop
            return ,$item.$Name
        } catch {
            return $null
        }
    }

    # ------------ Helper: secedit export ------------
    function Initialize-SecEdit {
        param([string]$ExportPath)
        if (-not $script:SeceditCache) {
            $tmp = "$env:TEMP\cis-secedit-$([guid]::NewGuid()).inf"
            $null = & secedit.exe /export /cfg $tmp /quiet 2>&1
            if (-not (Test-Path $tmp)) {
                throw "secedit /export failed"
            }
            # secedit emits UTF-16 LE with BOM
            $raw = Get-Content -LiteralPath $tmp -Raw -Encoding Unicode
            Remove-Item $tmp -Force -ErrorAction SilentlyContinue
            $script:SeceditCache = $raw
        }
        $script:SeceditCache
    }

    function Get-SecEditValue {
        param([string]$Section, [string]$Key)
        $inf = Initialize-SecEdit
        $inSection = $false
        foreach ($line in $inf -split "`r?`n") {
            if ($line -match '^\s*\[(.+)\]\s*$') {
                $inSection = ($Matches[1].Trim() -eq $Section)
                continue
            }
            if ($inSection -and $line -match '^\s*([^=]+?)\s*=\s*(.+?)\s*$') {
                if ($Matches[1].Trim() -ieq $Key) {
                    return $Matches[2].Trim()
                }
            }
        }
        return $null
    }

    function Get-SecEditPrivilegeAccounts {
        param([string]$PrivilegeRight)
        $raw = Get-SecEditValue -Section 'Privilege Rights' -Key $PrivilegeRight
        if (-not $raw) { return @() }
        $list = $raw -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }
        # Normalise: convert "*S-1-5-..." → SID, raw account names left as-is
        ,$list
    }

    # ------------ Helper: auditpol ------------
    function Initialize-AuditPol {
        if (-not $script:AuditPolCache) {
            $out = & auditpol.exe /get /category:* 2>&1
            $map = @{}
            foreach ($line in $out) {
                # Format: "  Subcategory Name                  Setting"
                if ($line -match '^\s{2,}(\S.*?\S)\s{2,}(No Auditing|Success|Failure|Success and Failure)\s*$') {
                    $map[$Matches[1].Trim()] = $Matches[2].Trim()
                }
            }
            # Also fetch by GUID for reliability
            $script:AuditPolCache = $map
        }
        $script:AuditPolCache
    }

    function Get-AuditPolSettingByGuid {
        param([string]$Guid)
        $out = & auditpol.exe /get /subcategory:$Guid 2>&1
        foreach ($line in $out) {
            if ($line -match '^\s{2,}(\S.*?\S)\s{2,}(No Auditing|Success|Failure|Success and Failure)\s*$') {
                return $Matches[2].Trim()
            }
        }
        return $null
    }

    # ------------ Helper: comparison ------------
    function Test-IntCompare {
        param($Actual, $Op, $Expected, $ExtraNe)
        if ($null -eq $Actual) { return $false }
        $a = [int]$Actual
        $e = [int]$Expected
        $base = switch ($Op) {
            '>=' { $a -ge $e }
            '<=' { $a -le $e }
            '==' { $a -eq $e }
            default { $false }
        }
        if ($base -and $null -ne $ExtraNe) {
            return ($a -ne [int]$ExtraNe)
        }
        return $base
    }

    function Compare-RegistryValue {
        param($Actual, $Expected, $Op, $ValueType)
        if ($ValueType -in 'REG_DWORD','REG_QWORD') {
            return Test-IntCompare -Actual $Actual -Op $Op -Expected $Expected
        }
        if ($ValueType -eq 'REG_MULTI_SZ') {
            $expList = @()
            if ($Expected -is [string]) {
                $expList = $Expected -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }
            } elseif ($Expected -is [array]) {
                $expList = $Expected
            }
            $actList = @()
            if ($null -ne $Actual) {
                $actList = @($Actual) | ForEach-Object { "$_".Trim() } | Where-Object { $_ }
            }
            if ($expList.Count -eq 0 -and $actList.Count -eq 0) { return $true }
            if ($expList.Count -ne $actList.Count) { return $false }
            $sortedExp = $expList | Sort-Object
            $sortedAct = $actList | Sort-Object
            return -not (Compare-Object $sortedExp $sortedAct)
        }
        # REG_SZ / default: case-insensitive equality
        return ("$Actual".Trim() -ieq "$Expected".Trim())
    }
}

# -------------------- Discovery: build test data --------------------
Describe "CIS Microsoft Windows Server 2022 Benchmark v5.0.0 (Domain Controller, Computer Configuration)" {

    # --- Registry-backed recommendations ---
    Context "Registry-backed recommendations" {
        $regRules = $script:Rules | Where-Object { $_.type -eq 'registry' }
        It "<id> — <title>" -ForEach $regRules -Tag @('Registry', "<profile>", "Section-<section>") {
            param($id, $title, $key, $value_name, $value_type, $expected_value, $op)
            $actual = Get-RegistryValueSafe -Path $key -Name $value_name
            $result = Compare-RegistryValue -Actual $actual -Expected $expected_value -Op $op -ValueType $value_type
            $result | Should -BeTrue -Because "[$id] $key\$value_name should be $op $expected_value ($value_type); actual: '$actual'"
        }
    }

    # --- Multi-value registry (Hardened UNC Paths) ---
    Context "Multi-value registry recommendations" {
        $multi = $script:Rules | Where-Object { $_.type -eq 'registry_multi' }
        It "<id> — <title>" -ForEach $multi -Tag @('Registry', "<profile>", "Section-<section>") {
            param($id, $title, $key, $expected_values)
            $ok = $true
            $missing = @()
            $expected_values.PSObject.Properties | ForEach-Object {
                $valueName  = $_.Name
                $required   = $_.Value
                $actual     = Get-RegistryValueSafe -Path $key -Name $valueName
                if ($null -eq $actual) {
                    $ok = $false; $missing += "$valueName (value missing)"
                    return
                }
                foreach ($req in $required) {
                    if ($actual -notlike "*$req*") {
                        $ok = $false; $missing += "$valueName lacks '$req'"
                    }
                }
            }
            $ok | Should -BeTrue -Because "[$id] missing: $($missing -join '; ')"
        }
    }

    # --- secedit INF (Account Policies + a few Security Options) ---
    Context "secedit INF recommendations (Account Policy / System Access)" {
        $infRules = $script:Rules | Where-Object { $_.type -eq 'secedit_inf' }
        It "<id> — <title>" -ForEach $infRules -Tag @('SecEdit', "<profile>", "Section-<section>") {
            param($id, $title, $inf_section, $inf_key, $op, $value, $extra_ne, $default_value)
            $actual = Get-SecEditValue -Section $inf_section -Key $inf_key
            if ($op -eq 'configured_non_default') {
                # Rename admin/guest: must exist and not equal default name
                $actual | Should -Not -BeNullOrEmpty -Because "[$id] $inf_section\$inf_key not configured"
                $actual.Trim('"') | Should -Not -Be $default_value -Because "[$id] still using default name"
                return
            }
            $extraNeVal = $null
            if ($PSBoundParameters.ContainsKey('extra_ne')) { $extraNeVal = $extra_ne }
            (Test-IntCompare -Actual $actual -Op $op -Expected $value -ExtraNe $extraNeVal) | `
                Should -BeTrue -Because "[$id] $inf_section\$inf_key should be $op $value (extra_ne=$extraNeVal); actual: '$actual'"
        }
    }

    # --- User Rights Assignment ---
    Context "User Rights Assignment" {
        $urRules = $script:Rules | Where-Object { $_.type -eq 'user_rights' }
        It "<id> — <title>" -ForEach $urRules -Tag @('UserRights', "<profile>", "Section-<section>") {
            param($id, $title, $privilege_right, $expected_accounts, $expected_label, $op)
            $actual = Get-SecEditPrivilegeAccounts -PrivilegeRight $privilege_right
            $exp = @()
            if ($expected_accounts) { $exp = @($expected_accounts) }
            $actualNorm = $actual | ForEach-Object { $_.Trim() } | Sort-Object -Unique
            $expectedNorm = $exp | ForEach-Object { $_.Trim() } | Sort-Object -Unique

            if ($op -eq 'include') {
                $missing = @()
                foreach ($e in $expectedNorm) {
                    if ($actualNorm -notcontains $e) { $missing += $e }
                }
                $missing.Count | Should -Be 0 -Because "[$id] $privilege_right must include '$expected_label'; missing: $($missing -join ', '); actual: $($actualNorm -join ', ')"
            } else {
                if ($expectedNorm.Count -eq 0) {
                    $actualNorm.Count | Should -Be 0 -Because "[$id] $privilege_right should be granted to No One; actual: $($actualNorm -join ', ')"
                } else {
                    $diff = Compare-Object $expectedNorm $actualNorm
                    $diff | Should -BeNullOrEmpty -Because "[$id] $privilege_right should equal '$expected_label'; actual: $($actualNorm -join ', ')"
                }
            }
        }
    }

    # --- Advanced Audit Policy (auditpol) ---
    Context "Advanced Audit Policy Configuration" {
        $apRules = $script:Rules | Where-Object { $_.type -eq 'auditpol' }
        It "<id> — <title>" -ForEach $apRules -Tag @('AuditPol', "<profile>", "Section-<section>") {
            param($id, $title, $subcategory_guid, $expected, $op)
            $actual = Get-AuditPolSettingByGuid -Guid $subcategory_guid
            $actual | Should -Not -BeNullOrEmpty -Because "[$id] auditpol returned no setting for $subcategory_guid"
            if ($op -eq 'include') {
                # 'expected' is e.g. 'Success' or 'Failure'; actual must include it
                ($actual -like "*$expected*") | Should -BeTrue -Because "[$id] $expected must be enabled; actual: $actual"
            } else {
                $actual | Should -Be $expected -Because "[$id] expected '$expected'; actual: '$actual'"
            }
        }
    }
}
