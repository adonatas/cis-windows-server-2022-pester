#Requires -Version 5.1
#Requires -Modules @{ ModuleName="Pester"; ModuleVersion="5.0.0" }
<#
    CIS Microsoft Windows Server 2022 Benchmark v5.0.0
    Data-driven Pester suite - Domain Controller, Computer Configuration only.
    Profiles included: Level 1 - DC, Level 2 - DC, Next Generation Windows Security - DC.
    User-configuration recommendations (section 19) are intentionally excluded.

    Usage:
        Invoke-Pester -Path .\CIS-WS2022-DC.Tests.ps1                       # run everything
        Invoke-Pester -Path .\CIS-WS2022-DC.Tests.ps1 -TagFilter L1-DC      # L1 only
        Invoke-Pester -Path .\CIS-WS2022-DC.Tests.ps1 -TagFilter Section-17 # one CIS section
        Invoke-Pester -Path .\CIS-WS2022-DC.Tests.ps1 -Output Detailed
#>

# -------------------- Load rules at discovery time --------------------
$script:CIS_ScriptRoot = $PSScriptRoot
function ConvertTo-HashtableDeep {
    param($Object)
    if ($null -eq $Object) { return $null }
    if ($Object -is [string] -or $Object -is [ValueType]) { return $Object }
    if ($Object -is [System.Collections.IDictionary]) {
        $h = @{}; foreach ($k in $Object.Keys) { $h[$k] = ConvertTo-HashtableDeep $Object[$k] }
        return $h
    }
    if ($Object -is [System.Management.Automation.PSCustomObject] -or
        $Object -is [System.Management.Automation.PSObject]) {
        if ($Object.PSObject.Properties.Count -gt 0 -and -not ($Object -is [array])) {
            $h = @{}
            foreach ($p in $Object.PSObject.Properties) { $h[$p.Name] = ConvertTo-HashtableDeep $p.Value }
            return $h
        }
    }
    if ($Object -is [System.Collections.IEnumerable]) {
        return ,@(foreach ($i in $Object) { ConvertTo-HashtableDeep $i })
    }
    return $Object
}

function Import-CisRules {
    param([string]$Type)
    $rulesPath = Join-Path $PSScriptRoot 'CIS-WS2022-DC-Rules.json'
    if (-not (Test-Path $rulesPath)) { throw "Rules file not found: $rulesPath" }
    $all = Get-Content -Raw -LiteralPath $rulesPath | ConvertFrom-Json
    $out = @()
    foreach ($r in $all) {
        if ($r.type -eq $Type) { $out += ,(ConvertTo-HashtableDeep $r) }
    }
    ,$out
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

    # ------------ Helper: secedit export (cached) ------------
    function Initialize-SecEdit {
        if (-not $script:SeceditCache) {
            $tmp = Join-Path $env:TEMP "cis-secedit-$([guid]::NewGuid()).inf"
            $null = & secedit.exe /export /cfg $tmp /quiet 2>&1
            if (-not (Test-Path $tmp)) {
                throw "secedit /export failed - must run elevated"
            }
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
        ,($raw -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    }

    # ------------ Helper: auditpol ------------
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
        if ($null -eq $Actual -or "$Actual" -eq '') { return $false }
        $a = 0; if (-not [int]::TryParse("$Actual", [ref]$a)) { return $false }
        $e = [int]$Expected
        $base = switch ($Op) {
            '>=' { $a -ge $e }
            '<=' { $a -le $e }
            '==' { $a -eq $e }
            default { $false }
        }
        if ($base -and $null -ne $ExtraNe -and "$ExtraNe" -ne '') {
            return ($a -ne [int]$ExtraNe)
        }
        return $base
    }

    function Compare-RegistryValue {
        param($Actual, $Expected, $Op, $ValueType)
        if ($null -eq $Actual) { return $false }
        if ($ValueType -in 'REG_DWORD','REG_QWORD') {
            return Test-IntCompare -Actual $Actual -Op $Op -Expected $Expected
        }
        if ($ValueType -eq 'REG_MULTI_SZ') {
            $expList = @()
            if ($Expected -is [string]) {
                $expList = @($Expected -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
            } elseif ($Expected -is [System.Collections.IList]) {
                $expList = @($Expected)
            }
            $actList = @($Actual) | ForEach-Object { "$_".Trim() } | Where-Object { $_ }
            if ($expList.Count -eq 0 -and $actList.Count -eq 0) { return $true }
            if ($expList.Count -ne $actList.Count) { return $false }
            return -not (Compare-Object ($expList | Sort-Object) ($actList | Sort-Object))
        }
        # REG_SZ / default
        if ($null -eq $Expected -or "$Expected" -eq '') {
            return ($null -eq $Actual -or "$Actual" -eq '')
        }
        return ("$Actual".Trim() -ieq "$Expected".Trim())
    }
}

Describe "CIS Microsoft Windows Server 2022 Benchmark v5.0.0 (Domain Controller, Computer Configuration)" {

    Context "Registry-backed recommendations" {
        It "<id> - <title>" -ForEach (Import-CisRules registry) -Tag 'Registry' {
            $actual = Get-RegistryValueSafe -Path $key -Name $value_name
            $result = Compare-RegistryValue -Actual $actual -Expected $expected_value -Op $op -ValueType $value_type
            $result | Should -BeTrue -Because "[$id] $key\$value_name should be $op $expected_value ($value_type); actual: '$actual'"
        }
    }

    Context "Multi-value registry recommendations" {
        It "<id> - <title>" -ForEach (Import-CisRules registry_multi) -Tag 'Registry' {
            $ok = $true
            $missing = @()
            foreach ($vname in $expected_values.Keys) {
                $required = $expected_values[$vname]
                $actual   = Get-RegistryValueSafe -Path $key -Name $vname
                if ($null -eq $actual) { $ok = $false; $missing += "$vname (missing)"; continue }
                foreach ($req in $required) {
                    if ("$actual" -notlike "*$req*") { $ok = $false; $missing += "$vname lacks '$req'" }
                }
            }
            $ok | Should -BeTrue -Because "[$id] missing: $($missing -join '; ')"
        }
    }

    Context "secedit INF recommendations (Account Policy / System Access)" {
        It "<id> - <title>" -ForEach (Import-CisRules secedit_inf) -Tag 'SecEdit' {
            $actual = Get-SecEditValue -Section $inf_section -Key $inf_key
            if ($op -eq 'configured_non_default') {
                $actual | Should -Not -BeNullOrEmpty -Because "[$id] $inf_section\$inf_key not configured"
                $actual.Trim('"') | Should -Not -Be $default_value -Because "[$id] still using default name"
                return
            }
            (Test-IntCompare -Actual $actual -Op $op -Expected $value -ExtraNe $extra_ne) |
                Should -BeTrue -Because "[$id] $inf_section\$inf_key should be $op $value (extra_ne=$extra_ne); actual: '$actual'"
        }
    }

    Context "User Rights Assignment" {
        It "<id> - <title>" -ForEach (Import-CisRules user_rights) -Tag 'UserRights' {
            $actual = Get-SecEditPrivilegeAccounts -PrivilegeRight $privilege_right
            $exp = @(); if ($expected_accounts) { $exp = @($expected_accounts) }
            $actualNorm   = @($actual | ForEach-Object { $_.Trim() } | Sort-Object -Unique)
            $expectedNorm = @($exp    | ForEach-Object { $_.Trim() } | Sort-Object -Unique)

            if ($op -eq 'include') {
                $missing = @($expectedNorm | Where-Object { $actualNorm -notcontains $_ })
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

    Context "Advanced Audit Policy Configuration" {
        It "<id> - <title>" -ForEach (Import-CisRules auditpol) -Tag 'AuditPol' {
            $actual = Get-AuditPolSettingByGuid -Guid $subcategory_guid
            $actual | Should -Not -BeNullOrEmpty -Because "[$id] auditpol returned no setting for $subcategory_guid"
            if ($op -eq 'include') {
                ("$actual" -like "*$expected*") | Should -BeTrue -Because "[$id] '$expected' must be enabled; actual: $actual"
            } else {
                $actual | Should -Be $expected -Because "[$id] expected '$expected'; actual: '$actual'"
            }
        }
    }
}
