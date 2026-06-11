#Requires -Version 5.1
#Requires -Modules @{ ModuleName="Pester"; ModuleVersion="5.0.0" }
<#
.SYNOPSIS
    Runs the CIS WS2022 DC Pester suite and writes results to CSV.

.DESCRIPTION
    Wrapper around Invoke-Pester that:
      - Runs CIS-WS2022-DC.Tests.ps1
      - Writes a CSV (date, hostname, rule_id, compliance) to the current directory
      - Prints a short summary to the console

.PARAMETER OutputCsv
    CSV file name (default: cis-audit-<hostname>-<yyyyMMdd-HHmm>.csv in current dir).

.PARAMETER Tag
    Optional Pester tag filter (e.g. L1-DC, Registry, SecEdit).

.EXAMPLE
    .\Invoke-CISAudit.ps1

.EXAMPLE
    .\Invoke-CISAudit.ps1 -Tag Registry -OutputCsv .\reg-only.csv
#>
param(
    [string]$OutputCsv,
    [string[]]$Tag
)

$ErrorActionPreference = 'Stop'
$testFile = Join-Path $PSScriptRoot 'CIS-WS2022-DC.Tests.ps1'
if (-not (Test-Path $testFile)) { throw "Test file not found: $testFile" }

$timestamp = Get-Date
$hostname  = [System.Net.Dns]::GetHostName()
if (-not $OutputCsv) {
    $stamp = $timestamp.ToString('yyyyMMdd-HHmm')
    $OutputCsv = Join-Path (Get-Location) "cis-audit-$hostname-$stamp.csv"
}

if (-not (Get-Module Pester | Where-Object Version -ge '5.0')) {
    Import-Module Pester -MinimumVersion 5.0 -Force
}

$cfg = New-PesterConfiguration
$cfg.Run.Path = $testFile
$cfg.Run.PassThru = $true
$cfg.Output.Verbosity = 'None'
if ($Tag) { $cfg.Filter.Tag = $Tag }

Write-Host "Running CIS WS2022 DC audit on $hostname..." -ForegroundColor Cyan
$result = Invoke-Pester -Configuration $cfg

function Get-RuleId {
    param($Test)
    # ExpandedName format: "1.1.1 - Ensure '...' (Automated)" -- the id is the leading token.
    if ($Test.ExpandedName -match '^(\d+(?:\.\d+){1,6})\b') { return $Matches[1] }
    return $Test.ExpandedName
}

$rows = @()
foreach ($t in $result.Tests) {
    $rows += [pscustomobject]@{
        date       = $timestamp.ToString('yyyy-MM-dd HH:mm:ss')
        hostname   = $hostname
        rule_id    = Get-RuleId $t
        compliance = switch ($t.Result) {
            'Passed'  { 'pass' }
            'Failed'  { 'fail' }
            'Skipped' { 'skip' }
            default   { $t.Result.ToString().ToLower() }
        }
    }
}

$rows | Sort-Object rule_id | Export-Csv -LiteralPath $OutputCsv -NoTypeInformation -Encoding UTF8

$pass = ($rows | Where-Object compliance -eq 'pass').Count
$fail = ($rows | Where-Object compliance -eq 'fail').Count
$skip = ($rows | Where-Object compliance -eq 'skip').Count
Write-Host ""
Write-Host "Results: $($rows.Count) rules  |  pass: $pass  fail: $fail  skip: $skip" -ForegroundColor Yellow
Write-Host "CSV written: $OutputCsv" -ForegroundColor Green
