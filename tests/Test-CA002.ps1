$ErrorActionPreference = "Stop"

$Path = Join-Path $PSScriptRoot "../policies/CA-002-Require-MFA.json"
$Policy = Get-Content $Path -Raw | ConvertFrom-Json

if ($Policy.displayName -ne "CA-002-BASE-Require-MFA-All-Users") {
    throw "FAIL: Incorrect policy name"
}

if ($Policy.state -ne "enabledForReportingButNotEnforced") {
    throw "FAIL: Policy must remain report-only"
}

if ("All" -notin @($Policy.conditions.users.includeUsers)) {
    throw "FAIL: All users must be included"
}

if ("All" -notin @($Policy.conditions.applications.includeApplications)) {
    throw "FAIL: All cloud applications must be included"
}

if ("all" -notin @($Policy.conditions.clientAppTypes)) {
    throw "FAIL: All client types must be included"
}

if ("mfa" -notin @($Policy.grantControls.builtInControls)) {
    throw "FAIL: MFA control is missing"
}

if (@($Policy.conditions.users.excludeGroups) -ne
    @("11111111-1111-4111-8111-111111111111")) {
    throw "FAIL: Incorrect break-glass exclusion"
}

Write-Host "PASS: CA-002 security validation completed." -ForegroundColor Green
