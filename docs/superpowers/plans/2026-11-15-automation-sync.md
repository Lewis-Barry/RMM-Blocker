# Automation Sync Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** One PowerShell script (`automation/Sync-RMMGuard.ps1`) that keeps the RMM Guard WDAC policy, macOS deny list and Defender indicators in a tenant in sync with the retrieval links, plus pipeline templates, a help page and an Automation section in the retrieval-links modal.

**Architecture:** A single self-contained script: pure functions (parsing, guards, diffs, request bodies) tested with Pester by loading the script's AST without running it, then thin I/O functions (Graph through `Invoke-MgGraphRequest`, Defender through `Invoke-RestMethod`) and an `Invoke-Sync` entry point on the last line. The site gets `automation.js` (command builder, tested in `tests.js`), `help-automation.html` and modal markup. The setup script from the spec already exists and gets two small additions.

**Tech Stack:** PowerShell 7.2+, Microsoft.Graph.Authentication, Pester 5/6, vanilla JS modules, GitHub Actions, Azure Pipelines.

**Spec:** `docs/superpowers/specs/2026-11-15-automation-sync-design.md` (read it first; this plan does not repeat its reasoning).

**House rules (AGENTS.md):** before every commit that touches the site run `node build.mjs` and set the **Last updated** chip in `index.html` to the commit date (`Nov 15, 2026` form). Run `node run-tests.mjs <chrome path>` when `app.js` logic changes. Run `node --test scripts/ worker/` after changing scripts.

---

## File map

| File | Responsibility |
|---|---|
| `automation/Sync-RMMGuard.ps1` | Create | Fetch, validate, diff and apply. Pure functions first, I/O after, `Invoke-Sync` last |
| `automation/Sync-RMMGuard.Tests.ps1` | Create | Pester tests for every pure function, with positive controls from the repo's own data |
| `automation/Setup-RMMGuardApp.ps1` | Modify | Add `-FederatedIssuer`/`-FederatedSubject` and `-ManagedIdentityObjectId` |
| `automation/github-workflow.yml` | Create | GitHub Actions template (pilot + production) |
| `automation/azure-pipelines.yml` | Create | Azure DevOps template (pilot + production) |
| `automation.js` | Create | `buildSyncCommand(excluded)` for the modal |
| `tests.js` | Modify | Tests for `buildSyncCommand` |
| `index.html`, `app.js`, `styles.css` | Modify | Automation section in the links modal |
| `help-automation.html` | Create | The guide |
| `help.html`, `help-ioc.html`, `help-macos.html` | Modify | "Automation" in the Guides nav |
| `tool-pages.mjs`, `build.mjs` | Modify | Sitemap entry and llms.txt line |
| `.github/workflows/tests.yml` | Modify | Run Pester in CI |
| `AGENTS.md` | Modify | Maintenance rules for the automation folder |

---

### Task 1: Command builder for the modal

**Files:**
- Create: `automation.js`
- Modify: `tests.js` (import line 1-5, new test block)

- [ ] **Step 1: Write the failing test.** Add to the imports at the top of `tests.js`:

```js
import { buildSyncCommand } from "./automation.js";
```

and add this block right after the existing `testMacBuilder` call site's sibling tests run (put it as a new top-level function and call it where the other `test*` groups are awaited at the bottom of the file; follow the same pattern as `testMacBuilder`):

```js
function testAutomation() {
  test("Sync command without exclusions has no -Exclude", () => {
    const command = buildSyncCommand(new Set());
    assert(command === "./Sync-RMMGuard.ps1 -Target Wdac,Macos -WdacPolicyName 'RMM Guard - WDAC' -Interactive -WhatIf", command);
  });
  test("Sync command lists exclusions sorted and quoted", () => {
    const command = buildSyncCommand(new Set(["TeamViewer", "AnyDesk"]));
    assert(command.includes("-Exclude 'AnyDesk','TeamViewer' "), command);
  });
  test("Sync command doubles single quotes in tool names", () => {
    const command = buildSyncCommand(new Set(["O'Tool", "O&O Syspectr"]));
    assert(command.includes("-Exclude 'O&O Syspectr','O''Tool' "), command);
  });
}
```

- [ ] **Step 2: Run to verify it fails.** Run: `node run-tests.mjs "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"`. Expected: the page fails to load the module (`automation.js` 404), non-zero exit.

- [ ] **Step 3: Implement** `automation.js`:

```js
// The PowerShell command shown in the retrieval-links modal. Interactive and -WhatIf, so a first paste only previews;
// Defender indicators need an app identity, so the interactive command covers WDAC and macOS.
const quote = name => `'${name.replaceAll("'", "''")}'`;

export function buildSyncCommand(excluded) {
  const names = [...excluded].sort((a, b) => a.localeCompare(b));
  return [
    "./Sync-RMMGuard.ps1 -Target Wdac,Macos -WdacPolicyName 'RMM Guard - WDAC'",
    names.length ? `-Exclude ${names.map(quote).join(",")}` : "",
    "-Interactive -WhatIf",
  ].filter(Boolean).join(" ");
}
```

- [ ] **Step 4: Run the tests.** Same command. Expected: all pass, `0 failures`.

- [ ] **Step 5: Commit.**

```bash
git add automation.js tests.js
git commit -m "feat: build the Sync-RMMGuard command for the retrieval-links modal"
```

---

### Task 2: Script skeleton and WDAC pure functions

**Files:**
- Create: `automation/Sync-RMMGuard.ps1`
- Create: `automation/Sync-RMMGuard.Tests.ps1`

- [ ] **Step 1: Write the failing tests.** Create `automation/Sync-RMMGuard.Tests.ps1`:

```powershell
# Invoke-Pester ./automation : loads every statement of Sync-RMMGuard.ps1 except the final Invoke-Sync call,
# so the pure functions can be tested without signing in or touching a tenant.
BeforeAll {
    $script:Root = Split-Path $PSScriptRoot -Parent
    $ast = [System.Management.Automation.Language.Parser]::ParseFile("$PSScriptRoot/Sync-RMMGuard.ps1", [ref]$null, [ref]$null)
    $code = ($ast.EndBlock.Statements | Where-Object { $_.Extent.Text -ne 'Invoke-Sync' } | ForEach-Object { $_.Extent.Text }) -join "`n"
    . ([scriptblock]::Create($code))
    $script:PolicyXml = Get-Content -Raw "$script:Root/Blocking_RMMsv5.xml"
}

Describe 'WDAC' {
    It 'normalises BOM and whitespace between tags' {
        ConvertTo-NormalizedXml "`u{FEFF}<a>`r`n  <b />`n</a>  " | Should -Be '<a><b /></a>'
    }
    It 'turns a WDAC wildcard into an anchored, case-insensitive regex' {
        $regex = ConvertTo-WildcardRegex '*\ctes.exe'
        'C:\Program Files\CTES.exe' | Should -Match $regex
        'C:\x\ctes.exe.bak' | Should -Not -Match $regex
    }
    It 'accepts the published policy (positive control)' {
        $facts = Test-WdacPolicy $script:PolicyXml
        $facts.Version | Should -Match '^\d+\.\d+\.\d+\.\d+$'
        $facts.Rules.Count | Should -Be ([regex]::Matches($script:PolicyXml, '<Deny ').Count)
    }
    It 'rejects a deny rule that hits <Canary>' -ForEach @(
        @{ Canary = 'explorer.exe'; Path = '*\explorer.exe' }
        @{ Canary = 'everything';   Path = '*' }
        @{ Canary = 'System32';     Path = '*\System32\*' }
        @{ Canary = 'Intune agent'; Path = '*\Microsoft Intune Management Extension\*' }
    ) {
        $bad = $script:PolicyXml -replace 'FilePath="\*\\ctes\.exe"', "FilePath=`"$Path`""
        { Test-WdacPolicy $bad } | Should -Throw '*would block*'
    }
    It 'rejects <Name>' -ForEach @(
        @{ Name = 'another PolicyID'; From = '01A11AD0-7091'; To = '11111111-7091' }
        @{ Name = 'audit mode added'; From = '<Rule><Option>Enabled:UMCI</Option></Rule>'; To = '<Rule><Option>Enabled:UMCI</Option></Rule><Rule><Option>Enabled:Audit Mode</Option></Rule>' }
        @{ Name = 'a supplemental policy'; From = 'PolicyType="Base Policy"'; To = 'PolicyType="Supplemental Policy"' }
    ) {
        $bad = (ConvertTo-NormalizedXml $script:PolicyXml).Replace($From, $To)
        { Test-WdacPolicy $bad } | Should -Throw 'WDAC:*'
    }
    It 'rejects a third Allow rule' {
        $bad = $script:PolicyXml -replace '(<Allow [^>]*/>)', '$1<Allow ID="ID_ALLOW_X" FileName="*" />'
        { Test-WdacPolicy $bad } | Should -Throw '*two Allow*'
    }
    It 'rejects an HTML page served with status 200' {
        { Test-WdacPolicy '<!doctype html><html><body>Just a moment...</body></html>' } | Should -Throw 'WDAC:*'
    }
    It 'builds the App Control body with the template ids verified live' {
        $body = New-WdacBody 'Name' 'Description' '<SiPolicy />'
        $body.templateReference.templateId | Should -Be '4321b946-b76b-4450-8afd-769c08b16ffc_1'
        $choice = $body.settings[0].settingInstance
        $choice.settingInstanceTemplateReference.settingInstanceTemplateId | Should -Be '1de98212-6949-42dc-a89c-e0ff6e5da04b'
        $choice.choiceSettingValue.settingValueTemplateReference.settingValueTemplateId | Should -Be 'b28c7dc4-c7b2-4ce2-8f51-6ebfd3ea69d3'
        $xml = $choice.choiceSettingValue.children[0]
        $xml.settingInstanceTemplateReference.settingInstanceTemplateId | Should -Be '4d709667-63d7-42f2-8e1b-b780f6c3c9c7'
        $xml.simpleSettingValue.settingValueTemplateReference.settingValueTemplateId | Should -Be '88f6f096-dedb-4cf1-ac2f-4b41e303adb5'
        $xml.simpleSettingValue.value | Should -Be '<SiPolicy />'
    }
}
```

- [ ] **Step 2: Run to verify it fails.** Run: `pwsh -NoProfile -c "Invoke-Pester ./automation -Output Detailed"`. Expected: FAIL, `Sync-RMMGuard.ps1` not found.

- [ ] **Step 3: Implement.** Create `automation/Sync-RMMGuard.ps1`:

```powershell
<#
.SYNOPSIS
    Keeps the RMM Guard WDAC policy, macOS deny list and Defender indicators in your tenant in sync with rmmguard.com.

.DESCRIPTION
    Reads https://rmmguard.com/api/wdac.xml, /api/macos.json and /api/iocs.csv with your exclusions, validates them
    against fixed safety rules, and creates or updates the Intune policies and Defender indicators. Exit is an error
    when any target fails or is stopped by a safety rule, so a scheduled pipeline run turns red.
    Guide: https://rmmguard.com/help-automation.html

.EXAMPLE
    ./Sync-RMMGuard.ps1 -Target Wdac,Macos -WdacPolicyName 'RMM Guard - WDAC' -Interactive -WhatIf

.EXAMPLE
    ./Sync-RMMGuard.ps1 -Target Wdac,Macos,Ioc -WdacPolicyName 'RMM Guard - WDAC' -Exclude 'AnyDesk' `
        -Assignment AllDevices -TenantId contoso.onmicrosoft.com -ClientId <app id> -CertificatePath ./RMMGuardSync.pfx
#>
#Requires -Version 7.2
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][ValidateSet('Wdac', 'Macos', 'Ioc')][string[]]$Target,
    [string]$WdacPolicyName,
    [string]$MacosPolicyName = 'Block RMM tools (macOS)',
    [string[]]$Exclude = @(),
    [ValidatePattern('^(AllDevices|AllUsers|[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12})$')][string]$Assignment,
    [ValidatePattern('^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$')][string]$ExcludeGroupId,
    [ValidateRange(0, 365)][int]$MinimumReleaseAgeDays = 0,
    [switch]$Force,
    [string]$TenantId,
    [string]$ClientId,
    [switch]$Interactive,
    [switch]$Identity,
    [string]$ClientSecret,
    [string]$CertificateThumbprint,
    [string]$CertificatePath,
    [securestring]$CertificatePassword,
    [string]$FederatedToken
)

$ErrorActionPreference = 'Stop'
$script:Cmdlet = $PSCmdlet
$script:Site = 'https://rmmguard.com'
$script:Graph = 'https://graph.microsoft.com/beta'
$script:Defender = 'https://api.security.microsoft.com/api'
$script:PolicyId = '{01A11AD0-7091-7896-89DD-447C515BCB5D}'
$script:RuleOptions = @('Disabled:Script Enforcement', 'Enabled:UMCI', 'Enabled:Unsigned System Integrity Policy', 'Enabled:Update Policy No Reboot')
$script:WdacTemplateId = '4321b946-b76b-4450-8afd-769c08b16ffc_1'
# Files a deny rule must never match: the OS shell and core services, the scripting hosts, Defender and the Intune agent.
$script:WdacCanaries = @(
    'C:\Windows\explorer.exe'
    'C:\Windows\System32\svchost.exe'
    'C:\Windows\System32\lsass.exe'
    'C:\Windows\System32\winlogon.exe'
    'C:\Windows\System32\cmd.exe'
    'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
    'C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25010.11-0\MsMpEng.exe'
    'C:\Program Files (x86)\Microsoft Intune Management Extension\Microsoft.Management.Services.IntuneWindowsAgent.exe'
)
# Hosts a domain indicator must never equal or be a parent of: sign-in, Graph, Intune, Windows Update and Defender itself.
$script:IocCanaries = @(
    'login.microsoftonline.com', 'graph.microsoft.com', 'enrollment.manage.microsoft.com', 'fef.msua06.manage.microsoft.com',
    'windowsupdate.com', 'update.microsoft.com', 'security.microsoft.com', 'api.security.microsoft.com', 'events.data.microsoft.com'
)
# Mirrors broadTeamIds in macos.js; Sync-RMMGuard.Tests.ps1 fails when the two differ.
$script:BroadTeamIds = @{ UBF8T346G9 = 'Microsoft'; EQHXZ8M8AV = 'Google'; JQ525L2MZD = 'Adobe'; '2BUA8C4S2C' = '1Password'; '68WVV388M8' = 'Cloudflare' }
$script:MacDescriptionPrefix = 'RMM Guard macOS deny list'
$script:Files = @{}

# ---- Pure functions: no network, no tenant. Covered by Sync-RMMGuard.Tests.ps1. ----

function ConvertTo-NormalizedXml([string]$Text) {
    ($Text -replace '^\uFEFF', '' -replace '>\s+<', '><').Trim()
}

function ConvertTo-WildcardRegex([string]$Pattern) {
    '^' + ([regex]::Escape($Pattern) -replace '\\\*', '.*' -replace '\\\?', '.') + '$'
}

# Version and deny rules of any policy XML, without judging it (deployed policies may predate the current guards).
function Get-WdacFacts([string]$Text) {
    try { $xml = [xml]($Text -replace '^\uFEFF', '') } catch { throw "WDAC: the content is not XML ($($_.Exception.Message))." }
    $policy = $xml.SiPolicy
    if (-not $policy) { throw 'WDAC: the root element is not SiPolicy.' }
    [pscustomobject]@{
        Policy  = $policy
        Version = [string]$policy.VersionEx
        Rules   = @($policy.FileRules.Deny | Where-Object { $_ } | ForEach-Object { "$($_.FriendlyName)|$($_.FilePath)" })
    }
}

function Test-WdacPolicy([string]$Text) {
    $facts = Get-WdacFacts $Text
    $policy = $facts.Policy
    if ($policy.PolicyType -ne 'Base Policy') { throw "WDAC: PolicyType is '$($policy.PolicyType)', expected 'Base Policy'." }
    if ($policy.PolicyID -ne $script:PolicyId -or $policy.BasePolicyID -ne $script:PolicyId) { throw 'WDAC: PolicyID or BasePolicyID is not the RMM Guard policy.' }
    $options = (@($policy.Rules.Rule.Option) | Sort-Object) -join '|'
    if ($options -ne ($script:RuleOptions -join '|')) { throw "WDAC: rule options changed to: $options." }
    $allows = @($policy.FileRules.Allow | Where-Object { $_ })
    if ($allows.Count -ne 2 -or @($allows | Where-Object FileName -ne '*').Count) { throw 'WDAC: expected exactly two Allow FileName="*" rules.' }
    $denies = @($policy.FileRules.Deny | Where-Object { $_ })
    if (-not $denies.Count) { throw 'WDAC: the policy has no Deny rules.' }
    foreach ($deny in $denies) {
        if (-not $deny.FilePath) { throw "WDAC: Deny rule $($deny.ID) has no FilePath." }
        $regex = ConvertTo-WildcardRegex $deny.FilePath
        foreach ($canary in $script:WdacCanaries) {
            if ($canary -match $regex) { throw "WDAC: Deny rule '$($deny.FilePath)' ($($deny.FriendlyName)) would block $canary." }
        }
    }
    $facts
}

function New-WdacBody([string]$Name, [string]$Description, [string]$Xml, [string[]]$RoleScopeTagIds = @('0')) {
    @{
        name              = $Name
        description       = $Description
        platforms         = 'windows10'
        technologies      = 'mdm'
        roleScopeTagIds   = @($RoleScopeTagIds)
        templateReference = @{ templateId = $script:WdacTemplateId }
        settings          = @(@{
            '@odata.type'   = '#microsoft.graph.deviceManagementConfigurationSetting'
            settingInstance = @{
                '@odata.type'                    = '#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance'
                settingDefinitionId              = 'device_vendor_msft_policy_config_applicationcontrol_policies_{policyguid}_policiesoptions'
                settingInstanceTemplateReference = @{ settingInstanceTemplateId = '1de98212-6949-42dc-a89c-e0ff6e5da04b' }
                choiceSettingValue               = @{
                    '@odata.type'                 = '#microsoft.graph.deviceManagementConfigurationChoiceSettingValue'
                    value                         = 'device_vendor_msft_policy_config_applicationcontrol_configure_xml_selected'
                    settingValueTemplateReference = @{ settingValueTemplateId = 'b28c7dc4-c7b2-4ce2-8f51-6ebfd3ea69d3' }
                    children                      = @(@{
                        '@odata.type'                    = '#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance'
                        settingDefinitionId              = 'device_vendor_msft_policy_config_applicationcontrol_policies_{policyguid}_xml'
                        settingInstanceTemplateReference = @{ settingInstanceTemplateId = '4d709667-63d7-42f2-8e1b-b780f6c3c9c7' }
                        simpleSettingValue               = @{
                            '@odata.type'                 = '#microsoft.graph.deviceManagementConfigurationStringSettingValue'
                            value                         = $Xml
                            settingValueTemplateReference = @{ settingValueTemplateId = '88f6f096-dedb-4cf1-ac2f-4b41e303adb5' }
                        }
                    })
                }
            }
        })
    }
}

# ---- I/O functions and Invoke-Sync follow (tasks 4-7). ----
```

- [ ] **Step 4: Run the tests.** `pwsh -NoProfile -c "Invoke-Pester ./automation -Output Detailed"`. Expected: all `WDAC` tests pass. If the AST loader cannot see `$script:` constants from the functions, move the constants into the same `[scriptblock]` (they are statements of the EndBlock, so they are included; a failure here means the filter dropped them).

- [ ] **Step 5: Commit.**

```bash
git add automation/Sync-RMMGuard.ps1 automation/Sync-RMMGuard.Tests.ps1
git commit -m "feat: WDAC validation and request body for Sync-RMMGuard"
```

---

### Task 3: IOC, macOS and shared pure functions

**Files:**
- Modify: `automation/Sync-RMMGuard.ps1` (append before the `# ---- I/O functions` marker)
- Modify: `automation/Sync-RMMGuard.Tests.ps1` (append)

- [ ] **Step 1: Write the failing tests.** Append to the test file:

```powershell
Describe 'IOC' {
    BeforeAll {
        $script:Csv = Get-ChildItem "$script:Root/IOC/*.csv" | ForEach-Object { ,@(ConvertFrom-IocCsv (Get-Content -Raw $_.FullName)) }
        $script:Header = (Get-Content "$script:Root/IOC/Defender_IOC_LOLRMM_IPs.csv" -TotalCount 1)
        function Row($Type, $Value, $Action = 'Block', $Title = 'LOLRMM - Test') {
            "$script:Header`r`n$Type,$Value,2035-07-23T00:00:00Z,$Action,Medium,$Title,Network domain associated with Test - listed by LOLRMM.,Block it.,,,,true`r`n"
        }
    }
    It 'accepts every bundled CSV and maps the import fields (positive control)' {
        $all = @($script:Csv | ForEach-Object { $_ })
        $all.Count | Should -Be ((Get-ChildItem "$script:Root/IOC/*.csv" | ForEach-Object { (Get-Content $_.FullName).Count - 1 } | Measure-Object -Sum).Sum)
        $all[0].PSObject.Properties.Name | Should -Be @('indicatorType', 'indicatorValue', 'expirationTime', 'action', 'severity', 'title', 'description', 'recommendedActions', 'generateAlert')
        $all[0].generateAlert | Should -BeOfType [bool]
    }
    It 'rejects a domain that is or contains <Value>' -ForEach @(
        @{ Value = 'microsoft.com' }, @{ Value = 'login.microsoftonline.com' }, @{ Value = 'windowsupdate.com' }
    ) {
        { ConvertFrom-IocCsv (Row 'DomainName' $Value) } | Should -Throw '*would block*'
    }
    It 'accepts a subdomain under a canary, which does not block the canary itself' {
        @(ConvertFrom-IocCsv (Row 'DomainName' 'x.windowsupdate.com')).Count | Should -Be 1
    }
    It 'rejects <Name>' -ForEach @(
        @{ Name = 'an Allowed action'; Type = 'DomainName'; Action = 'Allowed'; Title = 'LOLRMM - Test' }
        @{ Name = 'a foreign title'; Type = 'DomainName'; Action = 'Block'; Title = 'Mine' }
        @{ Name = 'a file hash'; Type = 'FileSha256'; Action = 'Block'; Title = 'LOLRMM - Test' }
    ) {
        { ConvertFrom-IocCsv (Row $Type 'example.org' $Action $Title) } | Should -Throw 'IOC:*'
    }
    It 'rejects content that is not the indicator CSV' {
        { ConvertFrom-IocCsv '<!doctype html><html></html>' } | Should -Throw 'IOC:*'
    }
    It 'diffs adds, changed rows and removals by type and value' {
        $a = [pscustomobject]@{ indicatorType = 'DomainName'; indicatorValue = 'a.org'; title = 'LOLRMM - A'; description = 'd'; severity = 'Medium'; action = 'Block' }
        $b = [pscustomobject]@{ indicatorType = 'DomainName'; indicatorValue = 'b.org'; title = 'LOLRMM - B'; description = 'd'; severity = 'Medium'; action = 'Block' }
        $bOld = [pscustomobject]@{ id = '2'; indicatorType = 'DomainName'; indicatorValue = 'B.org'; title = 'LOLRMM - Old'; description = 'd'; severity = 'Medium'; action = 'Block' }
        $c = [pscustomobject]@{ id = '3'; indicatorType = 'DomainName'; indicatorValue = 'c.org'; title = 'LOLRMM - C'; description = 'd'; severity = 'Medium'; action = 'Block' }
        $diff = Compare-IocSet @($a, $b) @($bOld, $c)
        $diff.Upsert.indicatorValue | Should -Be @('a.org', 'b.org')
        $diff.Added | Should -Be 1
        $diff.Remove.id | Should -Be @('3')
    }
}

Describe 'macOS' {
    BeforeAll {
        # The real body, built by the site's own code: the same thing /api/macos.json serves without exclusions.
        $script:MacBody = node --input-type=module -e "import { parseMacProducts, buildIntunePolicy } from '$($script:Root.Replace('\', '/'))/macos.js'; import { readFileSync } from 'node:fs'; const d = parseMacProducts(JSON.parse(readFileSync('$($script:Root.Replace('\', '/'))/products.json', 'utf8'))); process.stdout.write(buildIntunePolicy(d.rules, d.version));" | ConvertFrom-Json -AsHashtable
    }
    It 'reads every denied binary from the policy body (positive control)' {
        $rules = Get-MacRules $script:MacBody.settings
        $rules.Count | Should -BeGreaterThan 0
        { Test-MacRules $rules } | Should -Not -Throw
        Get-MacVersion $script:MacBody.description | Should -Match '^\d+\.\d+\.\d+\.\d+$'
    }
    It 'rejects a broad Team ID without a Signing ID' {
        { Test-MacRules @([pscustomobject]@{ TeamId = 'UBF8T346G9'; SigningId = $null }) } | Should -Throw '*Microsoft*'
    }
    It 'rejects a malformed Team ID and an empty list' {
        { Test-MacRules @([pscustomobject]@{ TeamId = 'abc'; SigningId = $null }) } | Should -Throw '*Team ID*'
        { Test-MacRules @() } | Should -Throw '*denies nothing*'
    }
    It 'keeps the broad Team IDs in step with macos.js' {
        $js = Get-Content -Raw "$script:Root/macos.js"
        $fromJs = [regex]::Matches($js, '\["([A-Z0-9]{10})", "([^"]+)"\]') | ForEach-Object { "$($_.Groups[1].Value)=$($_.Groups[2].Value)" } | Sort-Object
        $fromPs = $script:BroadTeamIds.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" } | Sort-Object
        $fromPs | Should -Be $fromJs
    }
}

Describe 'Shared' {
    It 'counts additions and removals case-insensitively' {
        $change = Measure-SetChange @('A|1', 'B|2', 'C|3') @('a|1', 'D|4')
        $change.Added | Should -Be 1
        $change.Removed | Should -Be 2
    }
    It 'allows a first deployment of any size' { { Test-ChangeSize 0 900 0 -Label T } | Should -Not -Throw }
    It 'allows exactly 25 percent' { { Test-ChangeSize 100 25 25 -Label T } | Should -Not -Throw }
    It 'stops above 25 percent' { { Test-ChangeSize 100 26 0 -Label T } | Should -Throw '*-Force*' }
    It 'lets -Force through' { { Test-ChangeSize 100 0 90 -Force -Label T } | Should -Not -Throw }
    It 'decides release age' {
        $log = @([pscustomobject]@{ version = '1.0.0.22'; date = '2026-11-10' })
        $now = [datetime]'2026-11-15'
        Test-ReleaseAge $log '1.0.0.22' 0 $now | Should -BeNullOrEmpty
        Test-ReleaseAge $log '1.0.0.22' 5 $now | Should -BeNullOrEmpty
        Test-ReleaseAge $log '1.0.0.22' 6 $now | Should -Match '5 day'
        Test-ReleaseAge $log '1.0.0.23' 1 $now | Should -Match 'not listed'
    }
    It 'maps -Assignment values to Intune targets' {
        (ConvertTo-AssignmentTarget 'AllDevices').'@odata.type' | Should -Be '#microsoft.graph.allDevicesAssignmentTarget'
        (ConvertTo-AssignmentTarget 'AllUsers').'@odata.type' | Should -Be '#microsoft.graph.allLicensedUsersAssignmentTarget'
        (ConvertTo-AssignmentTarget '11111111-2222-3333-4444-555555555555').groupId | Should -Be '11111111-2222-3333-4444-555555555555'
    }
    It 'keeps existing assignments and adds only what is missing' {
        $existing = @([pscustomobject]@{ '@odata.type' = '#microsoft.graph.groupAssignmentTarget'; groupId = 'g1'; deviceAndAppManagementAssignmentFilterType = 'none' })
        Merge-AssignmentTargets $existing @(@{ '@odata.type' = '#microsoft.graph.groupAssignmentTarget'; groupId = 'g1' }) | Should -BeNullOrEmpty
        $merged = @(Merge-AssignmentTargets $existing @(@{ '@odata.type' = '#microsoft.graph.allDevicesAssignmentTarget' }))
        $merged.Count | Should -Be 2
        $merged[0].groupId | Should -Be 'g1'
    }
    It 'builds retrieval URLs with sorted, encoded exclusions' {
        Get-ApiUrl 'wdac.xml' @() | Should -Be 'https://rmmguard.com/api/wdac.xml'
        Get-ApiUrl 'wdac.xml' @('TeamViewer', 'O&O Syspectr') | Should -Be 'https://rmmguard.com/api/wdac.xml?exclude=O%26O%20Syspectr&exclude=TeamViewer'
    }
}
```

- [ ] **Step 2: Run to verify it fails.** `pwsh -NoProfile -c "Invoke-Pester ./automation -Output Detailed"`. Expected: the new `Describe` blocks fail with `ConvertFrom-IocCsv` / `Get-MacRules` / `Measure-SetChange` not recognised.

- [ ] **Step 3: Implement.** Insert before the `# ---- I/O functions` marker in `automation/Sync-RMMGuard.ps1`:

```powershell
$script:IocHeader = 'IndicatorType,IndicatorValue,ExpirationTime,Action,Severity,Title,Description,RecommendedActions,RbacGroups,Category,MitreTechniques,GenerateAlert'

# Rows of the indicator CSV as Defender import objects. Throws on anything the site never publishes.
function ConvertFrom-IocCsv([string]$Text) {
    $text = $Text -replace '^\uFEFF', ''
    if (($text -split '\r?\n', 2)[0] -ne $script:IocHeader) { throw 'IOC: the content is not the RMM Guard indicator CSV.' }
    foreach ($row in ($text | ConvertFrom-Csv)) {
        if ($row.IndicatorType -notin 'DomainName', 'IpAddress' -or $row.Action -ne 'Block' -or
            -not "$($row.Title)".StartsWith('LOLRMM - ') -or -not $row.IndicatorValue) {
            throw "IOC: invalid row for '$($row.IndicatorValue)' ($($row.IndicatorType), $($row.Action), $($row.Title))."
        }
        if ($row.IndicatorType -eq 'DomainName') {
            $value = $row.IndicatorValue.ToLowerInvariant()
            foreach ($canary in $script:IocCanaries) {
                if ($canary -eq $value -or $canary.EndsWith(".$value")) { throw "IOC: indicator '$value' would block $canary." }
            }
        }
        [pscustomobject]@{
            indicatorType      = $row.IndicatorType
            indicatorValue     = $row.IndicatorValue
            expirationTime     = $row.ExpirationTime
            action             = $row.Action
            severity           = $row.Severity
            title              = $row.Title
            description        = $row.Description
            recommendedActions = $row.RecommendedActions
            generateAlert      = $row.GenerateAlert -eq 'true'
        }
    }
}

# Upsert: new values plus values whose text changed. Remove: deployed values no longer wanted (they carry Defender ids).
function Compare-IocSet($Desired, $Deployed) {
    $key = { param($i) "$($i.indicatorType):$($i.indicatorValue)".ToLowerInvariant() }
    $current = @{}; foreach ($i in $Deployed) { $current[(& $key $i)] = $i }
    $wanted = @{}; foreach ($i in $Desired) { $wanted[(& $key $i)] = $i }
    $upsert = @($Desired | Where-Object {
        $old = $current[(& $key $_)]
        -not $old -or $old.title -ne $_.title -or $old.description -ne $_.description -or $old.severity -ne $_.severity -or $old.action -ne $_.action
    })
    [pscustomobject]@{
        Upsert = $upsert
        Added  = @($Desired | Where-Object { -not $current.ContainsKey((& $key $_)) }).Count
        Remove = @($Deployed | Where-Object { -not $wanted.ContainsKey((& $key $_)) })
    }
}

# Team ID / Signing ID pairs from a settings array: the /api/macos.json body or GET .../settings of a deployed policy.
function Get-MacRules($Settings) {
    $stack = [System.Collections.Generic.Stack[object]]::new()
    foreach ($setting in $Settings) { $stack.Push($setting.settingInstance) }
    while ($stack.Count) {
        $node = $stack.Pop()
        if ($node.settingDefinitionId -eq 'app_allowed_deniedbinaries') {
            return @(foreach ($item in $node.groupSettingCollectionValue) {
                $values = @{}
                foreach ($child in $item.children) { $values[$child.settingDefinitionId] = $child.simpleSettingValue.value }
                [pscustomobject]@{ TeamId = $values['app_allowed_deniedbinaries_item_teamid']; SigningId = $values['app_allowed_deniedbinaries_item_signingid'] }
            })
        }
        foreach ($group in $node.groupSettingCollectionValue) { foreach ($child in $group.children) { $stack.Push($child) } }
    }
    @()
}

function Test-MacRules($Rules) {
    if (-not @($Rules).Count) { throw 'macOS: the policy denies nothing.' }
    foreach ($rule in $Rules) {
        if ("$($rule.TeamId)" -cnotmatch '^[A-Z0-9]{10}$') { throw "macOS: invalid Team ID '$($rule.TeamId)'." }
        if ($script:BroadTeamIds.ContainsKey($rule.TeamId) -and -not $rule.SigningId) {
            throw "macOS: Team ID $($rule.TeamId) belongs to $($script:BroadTeamIds[$rule.TeamId]) and needs a Signing ID."
        }
    }
}

function Get-MacVersion([string]$Description) {
    if ($Description -match "^$([regex]::Escape($script:MacDescriptionPrefix)) v(\d+\.\d+\.\d+\.\d+)") { $Matches[1] }
}

function Measure-SetChange([string[]]$Old, [string[]]$New) {
    $oldSet = [System.Collections.Generic.HashSet[string]]::new([string[]]@($Old), [StringComparer]::OrdinalIgnoreCase)
    $newSet = [System.Collections.Generic.HashSet[string]]::new([string[]]@($New), [StringComparer]::OrdinalIgnoreCase)
    [pscustomobject]@{
        Added   = @($newSet | Where-Object { -not $oldSet.Contains($_) }).Count
        Removed = @($oldSet | Where-Object { -not $newSet.Contains($_) }).Count
    }
}

function Test-ChangeSize([int]$Deployed, [int]$Added, [int]$Removed, [switch]$Force, [string]$Label) {
    if ($Deployed -eq 0 -or $Force) { return }
    $limit = [math]::Floor($Deployed * 0.25)
    if ($Added -gt $limit -or $Removed -gt $limit) {
        throw "${Label}: $Added added and $Removed removed against $Deployed deployed is more than 25 percent. Review the change and rerun with -Force."
    }
}

# $null when the version may be applied, otherwise the reason to wait.
function Test-ReleaseAge($Changelog, [string]$Version, [int]$MinimumDays, [datetime]$Now) {
    if ($MinimumDays -le 0) { return $null }
    $entry = @($Changelog | Where-Object version -eq $Version)[0]
    if (-not $entry) { return "version $Version is not listed in changelog.json" }
    $age = ($Now.Date - ([datetime]$entry.date).Date).Days
    if ($age -lt $MinimumDays) { return "version $Version is $age day(s) old, the minimum is $MinimumDays" }
    $null
}

function ConvertTo-AssignmentTarget([string]$Value) {
    switch ($Value) {
        'AllDevices' { @{ '@odata.type' = '#microsoft.graph.allDevicesAssignmentTarget' } }
        'AllUsers' { @{ '@odata.type' = '#microsoft.graph.allLicensedUsersAssignmentTarget' } }
        default { @{ '@odata.type' = '#microsoft.graph.groupAssignmentTarget'; groupId = $Value } }
    }
}

# $null when every wanted target exists; otherwise existing plus missing, because /assign replaces the whole set.
function Merge-AssignmentTargets($Existing, $Wanted) {
    $key = { param($t) "$($t.'@odata.type')|$($t.groupId)" }
    $have = @($Existing | ForEach-Object { & $key $_ })
    $missing = @($Wanted | Where-Object { (& $key $_) -notin $have })
    if (-not $missing.Count) { return $null }
    @($Existing) + $missing
}

function Get-ApiUrl([string]$File, [string[]]$Exclude) {
    $query = (@($Exclude) | Where-Object { $_ } | Sort-Object -Unique | ForEach-Object { 'exclude=' + [uri]::EscapeDataString($_) }) -join '&'
    "$script:Site/api/$File" + ($query ? "?$query" : '')
}
```

- [ ] **Step 4: Run the tests.** `pwsh -NoProfile -c "Invoke-Pester ./automation -Output Detailed"`. Expected: all pass. If the IOC count test fails, `ConvertFrom-Csv` did not split the single string into rows: replace `($text | ConvertFrom-Csv)` with `($text -split '\r?\n' | Where-Object { $_ } | ConvertFrom-Csv)` (the published CSV has no quoted line breaks) and rerun.

- [ ] **Step 5: Commit.**

```bash
git add automation/Sync-RMMGuard.ps1 automation/Sync-RMMGuard.Tests.ps1
git commit -m "feat: IOC, macOS, change-size, release-age and assignment logic for Sync-RMMGuard"
```

---

### Task 4: Authentication

**Files:**
- Modify: `automation/Sync-RMMGuard.ps1` (append after the pure functions, below the `# ---- I/O functions` marker)
- Modify: `automation/Sync-RMMGuard.Tests.ps1` (append)

- [ ] **Step 1: Write the failing test.** Append:

```powershell
Describe 'Authentication' {
    It 'signs a client assertion that Entra can verify with the certificate' {
        $rsa = [System.Security.Cryptography.RSA]::Create(2048)
        $request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new('CN=Test', $rsa,
            [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
        $certificate = $request.CreateSelfSigned([DateTimeOffset]::UtcNow.AddMinutes(-5), [DateTimeOffset]::UtcNow.AddDays(1))
        $jwt = New-ClientAssertion $certificate 'tenant-id' 'client-id'
        $parts = $jwt.Split('.')
        $parts.Count | Should -Be 3
        $decode = { param($s) $s = $s.Replace('-', '+').Replace('_', '/'); [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($s.PadRight($s.Length + (4 - $s.Length % 4) % 4, '='))) }
        $header = & $decode $parts[0] | ConvertFrom-Json
        $payload = & $decode $parts[1] | ConvertFrom-Json
        $header.alg | Should -Be 'RS256'
        $header.x5t | Should -Be ([Convert]::ToBase64String($certificate.GetCertHash()).TrimEnd('=').Replace('+', '-').Replace('/', '_'))
        $payload.aud | Should -Be 'https://login.microsoftonline.com/tenant-id/oauth2/v2.0/token'
        $payload.iss | Should -Be 'client-id'
        $payload.sub | Should -Be 'client-id'
        $signature = $parts[2].Replace('-', '+').Replace('_', '/')
        $signature = [Convert]::FromBase64String($signature.PadRight($signature.Length + (4 - $signature.Length % 4) % 4, '='))
        $rsa.VerifyData([Text.Encoding]::UTF8.GetBytes("$($parts[0]).$($parts[1])"), $signature,
            [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1) | Should -BeTrue
    }
}
```

- [ ] **Step 2: Run to verify it fails.** Expected: `New-ClientAssertion` not recognised.

- [ ] **Step 3: Implement.** Append below the `# ---- I/O functions` marker:

```powershell
function ConvertTo-Base64Url([byte[]]$Bytes) {
    [Convert]::ToBase64String($Bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

# RFC 7523 client assertion signed with the certificate's private key; Entra identifies the key by its SHA-1 thumbprint.
function New-ClientAssertion([System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate, [string]$Tenant, [string]$Client) {
    $now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    $header = @{ alg = 'RS256'; typ = 'JWT'; x5t = (ConvertTo-Base64Url $Certificate.GetCertHash()) } | ConvertTo-Json -Compress
    $payload = @{
        aud = "https://login.microsoftonline.com/$Tenant/oauth2/v2.0/token"; iss = $Client; sub = $Client
        jti = [guid]::NewGuid().ToString(); nbf = $now - 60; exp = $now + 600
    } | ConvertTo-Json -Compress
    $unsigned = (ConvertTo-Base64Url ([Text.Encoding]::UTF8.GetBytes($header))) + '.' + (ConvertTo-Base64Url ([Text.Encoding]::UTF8.GetBytes($payload)))
    $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($Certificate)
    if (-not $rsa) { throw 'The certificate has no RSA private key.' }
    $signature = $rsa.SignData([Text.Encoding]::UTF8.GetBytes($unsigned), [System.Security.Cryptography.HashAlgorithmName]::SHA256,
        [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
    "$unsigned.$(ConvertTo-Base64Url $signature)"
}

function Resolve-Auth {
    $modes = @(
        if ($Interactive) { 'Interactive' }
        if ($Identity) { 'Identity' }
        if ($CertificateThumbprint -or $CertificatePath) { 'Certificate' }
        if ($FederatedToken) { 'Federated' }
        if ($ClientSecret) { 'Secret' }
    )
    if (-not $modes.Count -and $env:RMMGUARD_CLIENT_SECRET) { $modes = @('Secret') }
    if ($modes.Count -ne 1) {
        throw 'Choose one sign-in: -Interactive, -Identity, -CertificatePath, -CertificateThumbprint, -FederatedToken or -ClientSecret ($env:RMMGUARD_CLIENT_SECRET).'
    }
    $auth = @{ Mode = $modes[0]; TenantId = $TenantId; ClientId = $ClientId }
    if ($auth.Mode -in 'Secret', 'Certificate', 'Federated' -and (-not $TenantId -or -not $ClientId)) {
        throw "-TenantId and -ClientId are required with $($auth.Mode) sign-in."
    }
    switch ($auth.Mode) {
        'Secret' { $auth.Secret = $ClientSecret ? $ClientSecret : $env:RMMGUARD_CLIENT_SECRET }
        'Federated' { $auth.FederatedToken = $FederatedToken }
        'Certificate' {
            if ($CertificatePath) {
                $password = $CertificatePassword
                if (-not $password -and $env:RMMGUARD_CERT_PASSWORD) { $password = ConvertTo-SecureString $env:RMMGUARD_CERT_PASSWORD -AsPlainText -Force }
                $auth.Certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new((Resolve-Path $CertificatePath).Path, $password)
            } else {
                $auth.Certificate = @('CurrentUser', 'LocalMachine') | ForEach-Object { Get-Item "Cert:\$_\My\$CertificateThumbprint" -ErrorAction SilentlyContinue } | Select-Object -First 1
                if (-not $auth.Certificate) { throw "Certificate $CertificateThumbprint is not in CurrentUser\My or LocalMachine\My. On macOS or Linux use -CertificatePath." }
            }
        }
    }
    $auth
}

# One token per resource for every non-interactive mode, so Graph and Defender share the same sign-in.
function Get-AccessToken([string]$Resource) {
    if ($script:Auth.Mode -eq 'Identity') {
        if (-not $env:IDENTITY_ENDPOINT) { throw '-Identity works in an Azure Automation runbook with a managed identity (IDENTITY_ENDPOINT is not set).' }
        $uri = "$($env:IDENTITY_ENDPOINT)?resource=$([uri]::EscapeDataString($Resource))&api-version=2019-08-01"
        return (Invoke-RestMethod -Uri $uri -Headers @{ 'X-IDENTITY-HEADER' = $env:IDENTITY_HEADER; Metadata = 'true' }).access_token
    }
    $body = @{ client_id = $script:Auth.ClientId; scope = "$Resource/.default"; grant_type = 'client_credentials' }
    switch ($script:Auth.Mode) {
        'Secret' { $body.client_secret = $script:Auth.Secret }
        'Federated' {
            $body.client_assertion_type = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
            $body.client_assertion = $script:Auth.FederatedToken
        }
        'Certificate' {
            $body.client_assertion_type = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
            $body.client_assertion = New-ClientAssertion $script:Auth.Certificate $script:Auth.TenantId $script:Auth.ClientId
        }
    }
    (Invoke-RestMethod -Method Post -Uri "https://login.microsoftonline.com/$($script:Auth.TenantId)/oauth2/v2.0/token" -Body $body).access_token
}

function Connect-Graph {
    if ($script:Auth.Mode -eq 'Interactive') {
        $connect = @{ Scopes = 'DeviceManagementConfiguration.ReadWrite.All'; NoWelcome = $true }
        if ($TenantId) { $connect.TenantId = $TenantId }
        Connect-MgGraph @connect
    } else {
        Connect-MgGraph -AccessToken (ConvertTo-SecureString (Get-AccessToken 'https://graph.microsoft.com') -AsPlainText -Force) -NoWelcome
    }
}
```

- [ ] **Step 4: Run the tests.** Expected: all pass.

- [ ] **Step 5: Commit.**

```bash
git add automation/Sync-RMMGuard.ps1 automation/Sync-RMMGuard.Tests.ps1
git commit -m "feat: certificate, federated, secret and managed identity sign-in for Sync-RMMGuard"
```

---

### Task 5: Graph and Defender I/O, the three sync functions and Invoke-Sync

**Files:**
- Modify: `automation/Sync-RMMGuard.ps1` (append to the end)

These functions only call the network; they are verified live in Task 6, not with Pester.

- [ ] **Step 1: Append the I/O helpers.**

```powershell
function Invoke-Graph([string]$Method, [string]$Path, $Body) {
    $request = @{ Method = $Method; Uri = "$script:Graph$Path"; OutputType = 'PSObject' }
    if ($null -ne $Body) { $request.Body = $Body | ConvertTo-Json -Depth 32; $request.ContentType = 'application/json' }
    Invoke-MgGraphRequest @request
}

function Invoke-Defender([string]$Method, [string]$Path, $Body) {
    $request = @{ Method = $Method; Uri = "$script:Defender$Path"; Headers = @{ Authorization = "Bearer $script:DefenderToken" } }
    if ($null -ne $Body) { $request.Body = $Body | ConvertTo-Json -Depth 8; $request.ContentType = 'application/json' }
    Invoke-RestMethod @request
}

# One download per file per run; a non-200 or a body of the wrong type (a Cloudflare challenge page) stops the target.
function Get-RMMGuardFile([string]$File, [string]$Type) {
    if ($script:Files.ContainsKey($File)) { return $script:Files[$File] }
    $response = Invoke-WebRequest -Uri (Get-ApiUrl $File $Exclude) -SkipHttpErrorCheck
    $content = $response.Content -is [byte[]] ? [Text.Encoding]::UTF8.GetString($response.Content) : [string]$response.Content
    if ($response.StatusCode -ne 200) { throw "${File}: HTTP $($response.StatusCode). $($content.Trim())" }
    if ("$($response.Headers['Content-Type'])" -notmatch [regex]::Escape($Type)) { throw "${File}: unexpected content type $($response.Headers['Content-Type'])." }
    $script:Files[$File] = $content
}

function Find-Policy([string]$Name) {
    $filter = [uri]::EscapeDataString("name eq '$($Name.Replace("'", "''"))'")
    # The filter has returned extra rows in testing, so the name is checked here as well.
    $found = @((Invoke-Graph GET "/deviceManagement/configurationPolicies?`$filter=$filter&`$select=id,name,description").value | Where-Object name -ceq $Name)
    if ($found.Count -gt 1) { throw "More than one Intune policy is named '$Name'. Rename the duplicates first." }
    $found | Select-Object -First 1
}

function Get-WdacXml([string]$PolicyId) {
    $settings = @((Invoke-Graph GET "/deviceManagement/configurationPolicies/$PolicyId/settings").value)
    $value = $settings.settingInstance.choiceSettingValue.children | Where-Object settingDefinitionId -like '*_xml' |
        ForEach-Object { $_.simpleSettingValue.value } | Select-Object -First 1
    # Graph returns what was posted (plain text); decode in case the portal's upload stored base64.
    if ($value -and -not $value.TrimStart().StartsWith('<')) { $value = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($value)) }
    $value
}

function Find-WdacByPolicyId {
    $filter = [uri]::EscapeDataString("templateReference/templateFamily eq 'endpointSecurityApplicationControl'")
    foreach ($candidate in (Invoke-Graph GET "/deviceManagement/configurationPolicies?`$filter=$filter&`$select=id,name").value) {
        if ("$(Get-WdacXml $candidate.id)".Contains($script:PolicyId)) { return $candidate }
    }
}

function Set-Assignment([string]$PolicyId) {
    $wanted = @(
        if ($Assignment) { ConvertTo-AssignmentTarget $Assignment }
        if ($ExcludeGroupId) { @{ '@odata.type' = '#microsoft.graph.exclusionGroupAssignmentTarget'; groupId = $ExcludeGroupId } }
    )
    if (-not $wanted.Count -or -not $PolicyId) { return }
    # Only /assignments is reliable: $expand=assignments returned an empty list for an assigned policy in testing,
    # and a union built from that would wipe the existing assignments on the next /assign.
    $existing = @((Invoke-Graph GET "/deviceManagement/configurationPolicies/$PolicyId/assignments").value | ForEach-Object { $_.target })
    $targets = Merge-AssignmentTargets $existing $wanted
    if ($null -eq $targets) { return }
    $labels = ($wanted | ForEach-Object { "$($_.'@odata.type' -replace '^#microsoft\.graph\.', '') $($_.groupId)".Trim() }) -join ', '
    if ($script:Cmdlet.ShouldProcess($PolicyId, "Add assignment $labels")) {
        Invoke-Graph POST "/deviceManagement/configurationPolicies/$PolicyId/assign" @{ assignments = @($targets | ForEach-Object { @{ target = $_ } }) } | Out-Null
    }
}
```

- [ ] **Step 2: Append the three sync functions.**

```powershell
function Sync-Wdac {
    if (-not $WdacPolicyName) { throw 'WDAC: -WdacPolicyName is required.' }
    $xml = Get-RMMGuardFile 'wdac.xml' 'xml'
    $desired = Test-WdacPolicy $xml
    $policy = Find-Policy $WdacPolicyName
    if (-not $policy) {
        $other = Find-WdacByPolicyId
        if ($other) { throw "WDAC: the RMM Guard policy already exists as '$($other.name)'. Pass -WdacPolicyName '$($other.name)'." }
        if ($reason = Test-ReleaseAge $script:Changelog $desired.Version $MinimumReleaseAgeDays (Get-Date)) { return "skipped, $reason" }
        if (-not $script:Cmdlet.ShouldProcess($WdacPolicyName, "Create App Control for Business policy v$($desired.Version) with $($desired.Rules.Count) deny rules")) { return 'would be created' }
        $created = Invoke-Graph POST '/deviceManagement/configurationPolicies' (New-WdacBody $WdacPolicyName "RMM Guard WDAC policy, created by Sync-RMMGuard.ps1." $xml)
        Set-Assignment $created.id
        return "created v$($desired.Version), $($desired.Rules.Count) deny rules"
    }
    $current = Invoke-Graph GET "/deviceManagement/configurationPolicies/$($policy.id)?`$select=id,name,description,roleScopeTagIds,templateReference,settingCount"
    if ($current.templateReference.templateId -ne $script:WdacTemplateId -or $current.settingCount -ne 1) {
        throw "WDAC: '$WdacPolicyName' is not an App Control for Business XML policy. Refusing to change it."
    }
    $currentXml = Get-WdacXml $policy.id
    if (-not "$currentXml".Contains($script:PolicyId)) { throw "WDAC: '$WdacPolicyName' does not carry the RMM Guard PolicyID. Refusing to overwrite it." }
    if ((ConvertTo-NormalizedXml $currentXml) -eq (ConvertTo-NormalizedXml $xml)) {
        Set-Assignment $policy.id
        return "unchanged v$($desired.Version)"
    }
    $deployed = Get-WdacFacts $currentXml
    if ($deployed.Version -ne $desired.Version -and ($reason = Test-ReleaseAge $script:Changelog $desired.Version $MinimumReleaseAgeDays (Get-Date))) { return "skipped, $reason" }
    $change = Measure-SetChange $deployed.Rules $desired.Rules
    Test-ChangeSize $deployed.Rules.Count $change.Added $change.Removed -Force:$Force -Label 'WDAC'
    $summary = "v$($deployed.Version) -> v$($desired.Version), +$($change.Added)/-$($change.Removed) deny rules"
    if ($script:Cmdlet.ShouldProcess($WdacPolicyName, "Update $summary")) {
        Invoke-Graph PUT "/deviceManagement/configurationPolicies/$($policy.id)" (New-WdacBody $current.name $current.description $xml $current.roleScopeTagIds) | Out-Null
    }
    Set-Assignment $policy.id
    "updated $summary"
}

function Sync-Macos {
    $body = Get-RMMGuardFile 'macos.json' 'json' | ConvertFrom-Json -AsHashtable
    $rules = Get-MacRules $body.settings
    Test-MacRules $rules
    $version = Get-MacVersion $body.description
    if (-not $version) { throw 'macOS: the policy description carries no version.' }
    $body.name = $MacosPolicyName
    $keys = @($rules | ForEach-Object { "$($_.TeamId)|$($_.SigningId)" })
    $policy = Find-Policy $MacosPolicyName
    if (-not $policy) {
        if ($reason = Test-ReleaseAge $script:Changelog $version $MinimumReleaseAgeDays (Get-Date)) { return "skipped, $reason" }
        if (-not $script:Cmdlet.ShouldProcess($MacosPolicyName, "Create macOS deny list v$version with $($keys.Count) entries")) { return 'would be created' }
        $created = Invoke-Graph POST '/deviceManagement/configurationPolicies' $body
        Set-Assignment $created.id
        return "created v$version, $($keys.Count) entries"
    }
    if (-not "$($policy.description)".StartsWith($script:MacDescriptionPrefix)) {
        throw "macOS: '$MacosPolicyName' is not an RMM Guard deny list (description does not start with '$script:MacDescriptionPrefix'). Refusing to overwrite it."
    }
    $deployedKeys = @(Get-MacRules (Invoke-Graph GET "/deviceManagement/configurationPolicies/$($policy.id)/settings").value | ForEach-Object { "$($_.TeamId)|$($_.SigningId)" })
    $change = Measure-SetChange $deployedKeys $keys
    $deployedVersion = Get-MacVersion $policy.description
    if (-not $change.Added -and -not $change.Removed) {
        Set-Assignment $policy.id
        return "unchanged v$deployedVersion"
    }
    if ($deployedVersion -ne $version -and ($reason = Test-ReleaseAge $script:Changelog $version $MinimumReleaseAgeDays (Get-Date))) { return "skipped, $reason" }
    Test-ChangeSize $deployedKeys.Count $change.Added $change.Removed -Force:$Force -Label 'macOS'
    $summary = "v$deployedVersion -> v$version, +$($change.Added)/-$($change.Removed) entries"
    if ($script:Cmdlet.ShouldProcess($MacosPolicyName, "Update $summary")) {
        $current = Invoke-Graph GET "/deviceManagement/configurationPolicies/$($policy.id)?`$select=roleScopeTagIds"
        Invoke-Graph PUT "/deviceManagement/configurationPolicies/$($policy.id)" @{
            name = $policy.name; description = $body.description; platforms = $body.platforms; technologies = $body.technologies
            roleScopeTagIds = @($current.roleScopeTagIds); settings = $body.settings
        } | Out-Null
    }
    Set-Assignment $policy.id
    "updated $summary"
}

function Sync-Ioc {
    if ($script:Auth.Mode -eq 'Interactive') {
        throw 'IOC: Defender indicators need an app identity (-CertificatePath, -CertificateThumbprint, -FederatedToken, -Identity or -ClientSecret); -Interactive cannot reach the Defender API.'
    }
    $desired = @(ConvertFrom-IocCsv (Get-RMMGuardFile 'iocs.csv' 'csv'))
    # With Ti.ReadWrite the app only sees the indicators it created; the title filter also covers Ti.ReadWrite.All.
    $deployed = @((Invoke-Defender GET '/indicators?$top=10000').value | Where-Object { "$($_.title)".StartsWith('LOLRMM - ') })
    $diff = Compare-IocSet $desired $deployed
    if (-not $diff.Upsert.Count -and -not $diff.Remove.Count) { return "unchanged, $($desired.Count) indicators" }
    # The CSV has no version of its own; it is built from the same release as the WDAC policy.
    $version = (Get-WdacFacts (Get-RMMGuardFile 'wdac.xml' 'xml')).Version
    if ($reason = Test-ReleaseAge $script:Changelog $version $MinimumReleaseAgeDays (Get-Date)) { return "skipped, $reason" }
    Test-ChangeSize $deployed.Count $diff.Added $diff.Remove.Count -Force:$Force -Label 'IOC'
    $summary = "$($diff.Upsert.Count) to import ($($diff.Added) new), $($diff.Remove.Count) to delete, $($desired.Count) wanted"
    if (-not $script:Cmdlet.ShouldProcess('Defender indicators', $summary)) { return "would be updated: $summary" }
    for ($i = 0; $i -lt $diff.Upsert.Count; $i += 500) {
        $batch = $diff.Upsert[$i..([math]::Min($i + 499, $diff.Upsert.Count - 1))]
        $result = Invoke-Defender POST '/indicators/import' @{ Indicators = @($batch) }
        $failed = @($result.value | Where-Object isFailed)
        if ($failed.Count) { throw "IOC: $($failed.Count) indicators failed to import, first: $($failed[0].indicator) ($($failed[0].failureReason))." }
    }
    for ($i = 0; $i -lt $diff.Remove.Count; $i += 500) {
        $ids = @($diff.Remove[$i..([math]::Min($i + 499, $diff.Remove.Count - 1))] | ForEach-Object { [string]$_.id })
        Invoke-Defender POST '/indicators/BatchDelete' @{ IndicatorIds = $ids } | Out-Null
    }
    "updated: $summary"
}
```

- [ ] **Step 3: Append the entry point.** It must stay the last statement; the Pester loader skips exactly the line `Invoke-Sync`.

```powershell
function Invoke-Sync {
    $script:Auth = Resolve-Auth
    if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) { Install-Module Microsoft.Graph.Authentication -Scope CurrentUser -Force }
    Import-Module Microsoft.Graph.Authentication
    # Both tokens up front: a federated token from a pipeline is short-lived.
    if ($Target -contains 'Ioc' -and $script:Auth.Mode -ne 'Interactive') { $script:DefenderToken = Get-AccessToken 'https://api.securitycenter.microsoft.com' }
    if ($Target -contains 'Wdac' -or $Target -contains 'Macos') { Connect-Graph }
    $script:Changelog = $MinimumReleaseAgeDays -gt 0 ? @(Invoke-RestMethod "$script:Site/changelog.json") : @()
    $failed = 0
    foreach ($name in @('Wdac', 'Macos', 'Ioc') | Where-Object { $_ -in $Target }) {
        try {
            $result = & "Sync-$name"
            if ($result -like 'skipped*') { Write-Warning "${name}: $result" } else { Write-Host "${name}: $result" }
        } catch {
            $failed++
            Write-Host "${name}: FAILED. $($_.Exception.Message)" -ForegroundColor Red
        }
    }
    if ($failed) { throw "$failed of $($Target.Count) target(s) failed." }
}

Invoke-Sync
```

- [ ] **Step 4: Static checks and unit tests.**

Run: `pwsh -NoProfile -c "Invoke-Pester ./automation -Output Detailed; Invoke-ScriptAnalyzer automation/Sync-RMMGuard.ps1 | Where-Object RuleName -notin 'PSAvoidUsingWriteHost','PSAvoidUsingPositionalParameters' | Format-Table Line,RuleName,Message -Wrap"`
Expected: Pester all green; analyzer lists at most `PSAvoidUsingPlainTextForPassword` for `$ClientSecret`/`$FederatedToken` (accepted: both arrive as plain strings from pipelines) and `PSUseShouldProcessForStateChangingFunctions` for `Set-Assignment`/`Sync-*` (they call `$script:Cmdlet.ShouldProcess`). Fix anything else.

- [ ] **Step 5: Smoke test without a tenant.** Run: `pwsh -NoProfile -File automation/Sync-RMMGuard.ps1 -Target Wdac -WdacPolicyName X` Expected: error `Choose one sign-in: ...` (no network call made).

- [ ] **Step 6: Commit.**

```bash
git add automation/Sync-RMMGuard.ps1
git commit -m "feat: Graph and Defender sync for WDAC, macOS and indicators"
```

---

### Task 6: Live verification in the test tenant (needs Roy)

Test app "RMM Guard Sync" (`c2c0174d-8b83-41a3-b25a-2809f4984b4e`) in "Inforced by Roy" (`bb3b1f9d-d866-4b5a-abad-69d6a26bc446`), certificate `~/RMMGuardSync.pfx`. Ask Roy before the first non-`-WhatIf` run and let Roy type the certificate password (`$env:RMMGUARD_CERT_PASSWORD` or the prompt). Never assign the test policies.

```powershell
$common = @{ TenantId = 'bb3b1f9d-d866-4b5a-abad-69d6a26bc446'; ClientId = 'c2c0174d-8b83-41a3-b25a-2809f4984b4e'; CertificatePath = '~/RMMGuardSync.pfx' }
```

- [ ] **Step 1: Dry run.** `./automation/Sync-RMMGuard.ps1 -Target Wdac,Macos,Ioc -WdacPolicyName 'RMM Guard - TEST WDAC' @common -WhatIf`
Expected: `What if` lines for creating the WDAC policy, updating `Block RMM tools (macOS)` (v1.0.0.21 -> current), and importing every indicator; nothing changes in the tenant.

- [ ] **Step 2: First real run.** Same without `-WhatIf`. Expected: `Wdac: created`, `Macos: updated v1.0.0.21 -> v…`, `Ioc: updated: … to import`. Check in Graph that the macOS policy description and entries changed and its assignments are unchanged (`GET …/assignments`), which confirms `PUT` on a non-template policy.

- [ ] **Step 3: Second run is idempotent.** Expected: three `unchanged` lines, no writes.

- [ ] **Step 4: Exclusion change.** Add `-Exclude 'AnyDesk'`. Expected: WDAC `updated … -N deny rules` with N = AnyDesk's rule count, IOC `… to delete` equal to AnyDesk's indicators, macOS `-1` or more entries. Run once more without `-Exclude`: everything comes back.

- [ ] **Step 5: Guards in the real flow.** `-Exclude` with an unknown name (`'NoSuchTool'`) gives `HTTP 400` for every target and a non-zero exit. A policy name that exists but is not ours (create an empty settings-catalog Windows policy named `RMM Guard - FOREIGN` by hand, or reuse any existing policy name) gives `Refusing to …`.

- [ ] **Step 6: Record the open Defender items in the spec.** Under "Live verification", write down: (6) what importing an existing value did, (7) whether a domain indicator blocked a subdomain (check in the Defender portal's indicator details, or leave open with that note), (8) stays open unless a portal-uploaded App Control policy is available.

- [ ] **Step 7: Clean up.** Delete `RMM Guard - TEST WDAC` and any `RMM Guard - FOREIGN` policy. Delete the imported indicators with:

```powershell
$ast = [System.Management.Automation.Language.Parser]::ParseFile("$PWD/automation/Sync-RMMGuard.ps1", [ref]$null, [ref]$null)
. ([scriptblock]::Create((($ast.EndBlock.Statements | Where-Object { $_.Extent.Text -ne 'Invoke-Sync' }).Extent.Text) -join "`n"))
$CertificatePath = '~/RMMGuardSync.pfx'; $TenantId = $common.TenantId; $ClientId = $common.ClientId
$script:Auth = Resolve-Auth; $script:DefenderToken = Get-AccessToken 'https://api.securitycenter.microsoft.com'
$ids = @((Invoke-Defender GET '/indicators?$top=10000').value | Where-Object { $_.title -like 'LOLRMM - *' } | ForEach-Object { [string]$_.id })
for ($i = 0; $i -lt $ids.Count; $i += 500) { Invoke-Defender POST '/indicators/BatchDelete' @{ IndicatorIds = $ids[$i..([math]::Min($i + 499, $ids.Count - 1))] } }
```

Leave `Block RMM tools (macOS)` in place (it was Roy's, unassigned). The app itself is removed at the very end of the project with `Setup-RMMGuardApp.ps1 -Remove`.

- [ ] **Step 8: Commit** any fixes found, plus the spec update: `git commit -am "fix: findings from the live sync test"` / `docs: record Defender findings`.

---

### Task 7: Setup script: federated credential and managed identity

**Files:**
- Modify: `automation/Setup-RMMGuardApp.ps1`

- [ ] **Step 1: Add parameters** to the `param()` block:

```powershell
    [string]$FederatedSubject,                                        # e.g. repo:contoso/rmm-guard:ref:refs/heads/main
    [string]$FederatedIssuer = 'https://token.actions.githubusercontent.com',
    [ValidatePattern('^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$')][string]$ManagedIdentityObjectId,
```

and add to `.DESCRIPTION`:

```
    -FederatedSubject: also adds a federated credential (OIDC) for that subject, so GitHub Actions or Azure DevOps sign in
    without any secret or certificate. Combine with -CredentialType None.
    -ManagedIdentityObjectId: grants the same permissions to an existing managed identity (an Azure Automation account)
    instead of creating an app. With -Remove, takes those grants away again.
```

- [ ] **Step 2: Managed identity branch.** Directly after the `$grants = foreach …` block (role resolution) and before the create `ShouldProcess`, insert:

```powershell
if ($ManagedIdentityObjectId) {
    $principal = Invoke-Graph GET "/servicePrincipals/$ManagedIdentityObjectId`?`$select=id,displayName"
    $assigned = @((Invoke-Graph GET "/servicePrincipals/$ManagedIdentityObjectId/appRoleAssignments").value)
    foreach ($grant in $grants) {
        $existingGrant = $assigned | Where-Object { $_.resourceId -eq $grant.ResourceId -and $_.appRoleId -eq $grant.RoleId }
        if ($Remove) {
            if ($existingGrant -and $PSCmdlet.ShouldProcess($principal.displayName, "Remove $($grant.ResourceName) / $($grant.Role)")) {
                Invoke-Graph DELETE "/servicePrincipals/$ManagedIdentityObjectId/appRoleAssignments/$($existingGrant.id)" | Out-Null
                Write-Host "Removed $($grant.ResourceName) / $($grant.Role) from $($principal.displayName)."
            }
        } elseif (-not $existingGrant -and $PSCmdlet.ShouldProcess($principal.displayName, "Grant $($grant.ResourceName) / $($grant.Role)")) {
            Invoke-Graph POST "/servicePrincipals/$($grant.ResourceId)/appRoleAssignedTo" @{ principalId = $ManagedIdentityObjectId; resourceId = $grant.ResourceId; appRoleId = $grant.RoleId } | Out-Null
            Write-Host "Granted $($grant.ResourceName) / $($grant.Role) to $($principal.displayName)."
        }
    }
    return
}
```

Then move the existing `if ($Remove) { … }` block so it runs after this branch (the managed-identity path handles its own `-Remove`). The role resolution must therefore run before the `-Remove` block; that is only reads, so it is safe.

- [ ] **Step 3: Federated credential.** Inside the `try` after the credential `switch`, add:

```powershell
    if ($FederatedSubject) {
        Invoke-Graph POST "/applications/$($app.id)/federatedIdentityCredentials" @{
            name      = ('rmmguard-' + ($FederatedSubject -replace '[^A-Za-z0-9-]', '-')).Substring(0, [math]::Min(120, 9 + $FederatedSubject.Length))
            issuer    = $FederatedIssuer
            subject   = $FederatedSubject
            audiences = @('api://AzureADTokenExchange')
        } | Out-Null
        Write-Host "Added federated credential for $FederatedSubject."
    }
```

- [ ] **Step 4: Check.** `pwsh -NoProfile -c "Invoke-ScriptAnalyzer automation/Setup-RMMGuardApp.ps1 | Where-Object RuleName -notin 'PSAvoidUsingWriteHost','PSAvoidUsingPositionalParameters'"` shows nothing new; `./automation/Setup-RMMGuardApp.ps1 -TenantId inforcedbyroy.onmicrosoft.com -DisplayName 'RMM Guard OIDC test' -CredentialType None -FederatedSubject 'repo:example/example:ref:refs/heads/main' -WhatIf` prints one `What if` line and creates nothing. Ask Roy before running it for real; if run, remove with `-DisplayName 'RMM Guard OIDC test' -Remove`.

- [ ] **Step 5: Commit.** `git commit -am "feat: setup script adds OIDC credentials and grants to managed identities"`

---

### Task 8: Pipeline templates

**Files:**
- Create: `automation/github-workflow.yml`
- Create: `automation/azure-pipelines.yml`

- [ ] **Step 1: GitHub template.**

```yaml
# RMM Guard sync for GitHub Actions.
# Copy to .github/workflows/rmm-guard-sync.yml in a private repository, with Sync-RMMGuard.ps1 in the repository root.
# Setup, permissions and variables: https://rmmguard.com/help-automation.html#github
name: RMM Guard sync
on:
  schedule:
    - cron: '0 6 * * 1'   # Mondays 06:00 UTC
  workflow_dispatch:
permissions:
  contents: read
  id-token: write          # lets the job request an OIDC token for the app's federated credential
env:
  EXCLUDE: ''              # tool names to leave out, comma-separated, exactly as on rmmguard.com, e.g. AnyDesk,TeamViewer
jobs:
  pilot:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Sync the pilot policies
        shell: pwsh
        run: |
          $token = (Invoke-RestMethod -Uri "$env:ACTIONS_ID_TOKEN_REQUEST_URL&audience=api://AzureADTokenExchange" `
            -Headers @{ Authorization = "Bearer $env:ACTIONS_ID_TOKEN_REQUEST_TOKEN" }).value
          ./Sync-RMMGuard.ps1 -Target Wdac,Macos `
            -WdacPolicyName 'RMM Guard - WDAC (pilot)' -MacosPolicyName 'RMM Guard - macOS (pilot)' `
            -Exclude ($env:EXCLUDE -split ',' | Where-Object { $_ }) `
            -Assignment '${{ vars.RMMGUARD_PILOT_GROUP_ID }}' `
            -TenantId '${{ vars.RMMGUARD_TENANT_ID }}' -ClientId '${{ vars.RMMGUARD_CLIENT_ID }}' -FederatedToken $token
  production:
    needs: pilot           # a pilot run stopped by a safety rule also stops production
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Sync the production policies and Defender indicators
        shell: pwsh
        run: |
          $token = (Invoke-RestMethod -Uri "$env:ACTIONS_ID_TOKEN_REQUEST_URL&audience=api://AzureADTokenExchange" `
            -Headers @{ Authorization = "Bearer $env:ACTIONS_ID_TOKEN_REQUEST_TOKEN" }).value
          ./Sync-RMMGuard.ps1 -Target Wdac,Macos,Ioc -MinimumReleaseAgeDays 7 `
            -WdacPolicyName 'RMM Guard - WDAC' -MacosPolicyName 'RMM Guard - macOS' `
            -Exclude ($env:EXCLUDE -split ',' | Where-Object { $_ }) `
            -Assignment AllDevices -ExcludeGroupId '${{ vars.RMMGUARD_PILOT_GROUP_ID }}' `
            -TenantId '${{ vars.RMMGUARD_TENANT_ID }}' -ClientId '${{ vars.RMMGUARD_CLIENT_ID }}' -FederatedToken $token
# Certificate instead of OIDC: store the .pfx as base64 in secret RMMGUARD_CERT_BASE64 and its password in
# RMMGUARD_CERT_PASSWORD, then replace the token lines and -FederatedToken $token with:
#   env:
#     RMMGUARD_CERT_PASSWORD: ${{ secrets.RMMGUARD_CERT_PASSWORD }}
#   run: |
#     [IO.File]::WriteAllBytes("$env:RUNNER_TEMP/rmmguard.pfx", [Convert]::FromBase64String('${{ secrets.RMMGUARD_CERT_BASE64 }}'))
#     ./Sync-RMMGuard.ps1 ... -CertificatePath "$env:RUNNER_TEMP/rmmguard.pfx"
```

- [ ] **Step 2: Azure DevOps template.**

```yaml
# RMM Guard sync for Azure DevOps. Copy to the root of an Azure Repos repository, next to Sync-RMMGuard.ps1.
# Setup, service connection and variables: https://rmmguard.com/help-automation.html#azure-devops
trigger: none
schedules:
  - cron: '0 6 * * 1'      # Mondays 06:00 UTC
    displayName: Weekly RMM Guard sync
    branches:
      include: [main]
    always: true
pool:
  vmImage: ubuntu-latest
variables:
  - group: rmm-guard       # RMMGUARD_PILOT_GROUP_ID and EXCLUDE (comma-separated tool names, may be empty)
stages:
  - stage: pilot
    jobs:
      - job: sync
        steps:
          - task: AzureCLI@2
            displayName: Sync the pilot policies
            inputs:
              azureSubscription: rmm-guard   # workload identity federation service connection to the RMM Guard Sync app
              scriptType: pscore
              scriptLocation: inlineScript
              addSpnToEnvironment: true      # exposes tenantId, servicePrincipalId and idToken
              inlineScript: |
                ./Sync-RMMGuard.ps1 -Target Wdac,Macos `
                  -WdacPolicyName 'RMM Guard - WDAC (pilot)' -MacosPolicyName 'RMM Guard - macOS (pilot)' `
                  -Exclude ('$(EXCLUDE)' -split ',' | Where-Object { $_ }) -Assignment '$(RMMGUARD_PILOT_GROUP_ID)' `
                  -TenantId $env:tenantId -ClientId $env:servicePrincipalId -FederatedToken $env:idToken
  - stage: production
    dependsOn: pilot
    jobs:
      - job: sync
        steps:
          - task: AzureCLI@2
            displayName: Sync the production policies and Defender indicators
            inputs:
              azureSubscription: rmm-guard
              scriptType: pscore
              scriptLocation: inlineScript
              addSpnToEnvironment: true
              inlineScript: |
                ./Sync-RMMGuard.ps1 -Target Wdac,Macos,Ioc -MinimumReleaseAgeDays 7 `
                  -WdacPolicyName 'RMM Guard - WDAC' -MacosPolicyName 'RMM Guard - macOS' `
                  -Exclude ('$(EXCLUDE)' -split ',' | Where-Object { $_ }) `
                  -Assignment AllDevices -ExcludeGroupId '$(RMMGUARD_PILOT_GROUP_ID)' `
                  -TenantId $env:tenantId -ClientId $env:servicePrincipalId -FederatedToken $env:idToken
```

- [ ] **Step 3: Validate YAML syntax.** `node -e "for (const f of ['automation/github-workflow.yml','automation/azure-pipelines.yml']) { const t = require('fs').readFileSync(f,'utf8'); if (/\t/.test(t)) throw new Error(f + ' has tabs'); } console.log('ok')"` Expected: `ok`. If `actionlint` is installed, also run `actionlint automation/github-workflow.yml`.

- [ ] **Step 4: Commit.** `git add automation/*.yml && git commit -m "feat: GitHub Actions and Azure DevOps templates for the RMM Guard sync"`

---

### Task 9: Help page and navigation

**Files:**
- Create: `help-automation.html`
- Modify: `help.html:49-51`, `help-ioc.html:49-51`, `help-macos.html:49-51` (Guides nav)
- Modify: `tool-pages.mjs:160` (sitemap list), `build.mjs:153` (llms.txt pages list)

- [ ] **Step 1: Guides nav.** In each of the three help pages, after the `macOS` link inside `<nav class="help-nav" aria-labelledby="guides-title">`, add:

```html
        <a href="./help-automation.html">Automation</a>
```

- [ ] **Step 2: Sitemap and llms.txt.** In `tool-pages.mjs` change the list to `["", "browsers.html", "help.html", "help-ioc.html", "help-macos.html", "help-automation.html", "changelog.html", "tools/", ...pages]`. In `build.mjs` add after the macOS guide line:

```
- [Automate with PowerShell](https://rmmguard.com/help-automation.html): keep Intune and Defender in sync from GitHub Actions, Azure DevOps or an Azure Automation runbook
```

- [ ] **Step 3: Create `help-automation.html`.** Copy the full `<head>` from `help-macos.html` and replace: description/og/twitter description with `Keep the RMM Guard WDAC policy, macOS deny list and Defender indicators in sync automatically with one PowerShell script, from GitHub Actions, Azure DevOps or an Azure Automation runbook.`; title with `Automate RMM Guard with PowerShell, GitHub Actions and Azure DevOps | RMM Guard`; canonical and `og:url` with `https://rmmguard.com/help-automation.html`; breadcrumb item 2 with `"name": "Automate", "item": "https://rmmguard.com/help-automation.html"`. Copy the header, footer and the trailing copy-button `<script type="module">` unchanged. Guides nav: `Automation` gets `aria-current="page"`, `macOS` loses it. Body of `<main>`:

```html
    <aside class="help-sidebar">
      <nav class="help-nav" aria-labelledby="guides-title">
        <h2 id="guides-title">Guides</h2>
        <a href="./help.html">WDAC</a>
        <a href="./help-ioc.html">Defender IOCs</a>
        <a href="./help-macos.html">macOS</a>
        <a href="./help-automation.html" aria-current="page">Automation</a>
      </nav>
      <nav class="help-nav help-sections" aria-labelledby="sections-title">
        <h2 id="sections-title">On this page</h2>
        <a href="#how">1. How it works</a>
        <a href="#safety">2. Safety rules</a>
        <a href="#app">3. App registration</a>
        <a href="#github">4. GitHub Actions</a>
        <a href="#azure-devops">5. Azure DevOps</a>
        <a href="#runbook">6. Azure Automation</a>
        <a href="#local">7. Run it yourself</a>
        <a href="#troubleshooting">8. Troubleshooting</a>
      </nav>
    </aside>
    <article id="guide" class="help-guide" tabindex="-1">
      <div class="page-heading"><div><h1>Automate</h1><p>One PowerShell script keeps the WDAC policy, the macOS deny list and the Defender indicators in your tenant up to date with this site. Run it on a schedule and new tools are blocked without anyone downloading a file.</p><p><a href="./automation/Sync-RMMGuard.ps1" download>Download Sync-RMMGuard.ps1</a> · <a href="./automation/Setup-RMMGuardApp.ps1" download>Download Setup-RMMGuardApp.ps1</a></p></div></div>
      <aside class="help-warning" role="note">The policies are enforced. Every run can change what your devices block. Keep a pilot group, and let production follow a week later.</aside>
      <section id="how" class="help-step" aria-labelledby="how-title">
        <h2 id="how-title">1. How it works</h2>
        <ol>
          <li>The script downloads the <a href="./index.html">retrieval links</a> with your exclusions: <code>/api/wdac.xml</code>, <code>/api/macos.json</code> and <code>/api/iocs.csv</code>.</li>
          <li>It checks every file against fixed safety rules (step 2) before anything is sent to your tenant.</li>
          <li>It finds your policy by name. Missing: it creates it and assigns it. Present: it compares and only writes when something changed.</li>
          <li>Defender indicators are compared one by one: new ones are imported, changed ones updated, removed ones deleted. Indicators you created yourself are never touched.</li>
        </ol>
        <pre class="kql-code"><code>./Sync-RMMGuard.ps1 -Target Wdac,Macos,Ioc -WdacPolicyName 'RMM Guard - WDAC' -Exclude 'AnyDesk','TeamViewer' `
    -Assignment AllDevices -TenantId contoso.onmicrosoft.com -ClientId &lt;app id&gt; -CertificatePath ./RMMGuardSync.pfx -WhatIf</code></pre>
        <p><code>-WhatIf</code> shows what would change without changing it. Every run ends with one line per target: created, updated, unchanged or skipped.</p>
        <p>Exclusions are tool names exactly as the RMM page shows them. Copy them from <strong>Copy custom retrieval links</strong> on the RMM page, which shows the command with your current exclusions.</p>
      </section>
      <section id="safety" class="help-step" aria-labelledby="safety-title">
        <h2 id="safety-title">2. Safety rules</h2>
        <ul>
          <li><strong>Structure:</strong> the WDAC file must be the RMM Guard base policy (same PolicyID, same rule options, two allow-all rules). Indicators must be Block rules titled <code>LOLRMM - …</code>. macOS entries need a Team ID, and Microsoft, Google, Adobe, 1Password and Cloudflare need a Signing ID too.</li>
          <li><strong>Canaries:</strong> a deny rule that would match Explorer, svchost, lsass, PowerShell, Defender or the Intune agent, or an indicator for Microsoft sign-in, Intune, Windows Update or Defender, stops the run.</li>
          <li><strong>Size:</strong> when more than 25 percent of the deployed rules or indicators would be added or removed, the run stops. Review the change, then run once with <code>-Force</code>.</li>
          <li><strong>Ownership:</strong> the script only updates a WDAC policy that carries the RMM Guard PolicyID and a macOS policy whose description starts with <code>RMM Guard macOS deny list</code>. Your other policies are never overwritten.</li>
          <li><strong>Release age:</strong> with <code>-MinimumReleaseAgeDays 7</code> a new version is applied only once it has been published for seven days. Your own exclusion changes apply at once.</li>
          <li><strong>Pilot ring:</strong> the pilot and production WDAC policies share one PolicyID, so a device must never get both. Assign the pilot policy to the pilot group, and the production policy to all devices with <code>-ExcludeGroupId</code> set to the pilot group. The templates below do this. Defender indicators are tenant-wide and are only synced by the production run.</li>
          <li>A failure or a stop makes the run exit with an error, so the pipeline turns red and production does not run after a failed pilot.</li>
        </ul>
      </section>
      <section id="app" class="help-step" aria-labelledby="app-title">
        <h2 id="app-title">3. App registration</h2>
        <p>The script signs in as an app with two permissions: Microsoft Graph <code>DeviceManagementConfiguration.ReadWrite.All</code> and WindowsDefenderATP <code>Ti.ReadWrite</code>. <code>Ti.ReadWrite</code> only lets the app see and change the indicators it created itself. Indicators you imported earlier by hand stay in place; delete them in Defender once the sync runs.</p>
        <p><code>Setup-RMMGuardApp.ps1</code> creates the app, grants admin consent and adds a credential. Sign in as Global Administrator, or as Cloud Application Administrator plus Privileged Role Administrator.</p>
        <pre class="kql-code"><code># Certificate (default; works in tenants that block client secrets)
./Setup-RMMGuardApp.ps1 -TenantId contoso.onmicrosoft.com

# OIDC for GitHub Actions: no secret and no certificate
./Setup-RMMGuardApp.ps1 -TenantId contoso.onmicrosoft.com -CredentialType None -FederatedSubject 'repo:contoso/rmm-guard:ref:refs/heads/main'

# Remove the app, its permissions and the .pfx again
./Setup-RMMGuardApp.ps1 -TenantId contoso.onmicrosoft.com -Remove</code></pre>
        <p>The script prints the <strong>ClientId</strong> you need below. A client secret is possible with <code>-CredentialType Secret</code>, but many tenants block secrets and they expire; prefer OIDC or a certificate.</p>
      </section>
      <section id="github" class="help-step" aria-labelledby="github-title">
        <h2 id="github-title">4. GitHub Actions</h2>
        <ol>
          <li>Create a <strong>private</strong> repository. Add <code>Sync-RMMGuard.ps1</code> to its root and <a href="./automation/github-workflow.yml" download>github-workflow.yml</a> as <code>.github/workflows/rmm-guard-sync.yml</code>.</li>
          <li>Run <code>Setup-RMMGuardApp.ps1</code> with <code>-CredentialType None -FederatedSubject 'repo:&lt;owner&gt;/&lt;repo&gt;:ref:refs/heads/main'</code>.</li>
          <li>In the repository, <strong>Settings</strong> → <strong>Secrets and variables</strong> → <strong>Actions</strong> → <strong>Variables</strong>, add <code>RMMGUARD_TENANT_ID</code>, <code>RMMGUARD_CLIENT_ID</code> and <code>RMMGUARD_PILOT_GROUP_ID</code> (the object ID of your pilot device group). These are not secrets: OIDC needs none.</li>
          <li>Put your exclusions in <code>EXCLUDE</code> at the top of the workflow.</li>
          <li><strong>Actions</strong> → <strong>RMM Guard sync</strong> → <strong>Run workflow</strong>. Check both jobs, then the policies in Intune. After that it runs every Monday.</li>
        </ol>
        <p>Certificate instead of OIDC: the end of the workflow file shows the two secrets and the lines to change.</p>
      </section>
      <section id="azure-devops" class="help-step" aria-labelledby="azure-devops-title">
        <h2 id="azure-devops-title">5. Azure DevOps</h2>
        <ol>
          <li>Add <code>Sync-RMMGuard.ps1</code> and <a href="./automation/azure-pipelines.yml" download>azure-pipelines.yml</a> to the root of an Azure Repos repository.</li>
          <li>Run <code>Setup-RMMGuardApp.ps1 -CredentialType None</code> and note the ClientId.</li>
          <li><strong>Project settings</strong> → <strong>Service connections</strong> → <strong>New</strong> → <strong>Azure Resource Manager</strong> → <strong>Workload identity federation (manual)</strong>. Name it <code>rmm-guard</code>, enter the tenant, the ClientId and any subscription the app can read (the task requires one; give the app the Reader role on it). Copy the <strong>Issuer</strong> and <strong>Subject identifier</strong> it shows.</li>
          <li>In Entra, open the app → <strong>Certificates &amp; secrets</strong> → <strong>Federated credentials</strong> → <strong>Add</strong> → <strong>Other issuer</strong>, and paste both values. Then finish the service connection.</li>
          <li><strong>Pipelines</strong> → <strong>Library</strong> → variable group <code>rmm-guard</code> with <code>RMMGUARD_PILOT_GROUP_ID</code> and <code>EXCLUDE</code>.</li>
          <li>Create the pipeline from the YAML file and run it once by hand.</li>
        </ol>
      </section>
      <section id="runbook" class="help-step" aria-labelledby="runbook-title">
        <h2 id="runbook-title">6. Azure Automation</h2>
        <ol>
          <li>In your Automation account, <strong>Identity</strong> → <strong>System assigned</strong> → <strong>On</strong>. Copy the <strong>Object (principal) ID</strong>.</li>
          <li>Grant the permissions to it: <code>./Setup-RMMGuardApp.ps1 -TenantId contoso.onmicrosoft.com -ManagedIdentityObjectId &lt;object id&gt;</code>.</li>
          <li><strong>Runtime Environments</strong>: use PowerShell 7.4 and add the module <code>Microsoft.Graph.Authentication</code> from the gallery.</li>
          <li><strong>Runbooks</strong> → <strong>Create</strong>, type PowerShell, runtime 7.4. Paste the contents of <code>Sync-RMMGuard.ps1</code> and <strong>Publish</strong>.</li>
          <li>Add two weekly <strong>Schedules</strong> with parameters. Pilot: <code>TARGET</code> <code>["Wdac","Macos"]</code>, the pilot policy names, <code>ASSIGNMENT</code> your pilot group ID, <code>IDENTITY</code> <code>true</code>. Production: <code>["Wdac","Macos","Ioc"]</code>, the production names, <code>ASSIGNMENT</code> <code>AllDevices</code>, <code>EXCLUDEGROUPID</code> the pilot group, <code>MINIMUMRELEASEAGEDAYS</code> <code>7</code>, <code>IDENTITY</code> <code>true</code>.</li>
        </ol>
      </section>
      <section id="local" class="help-step" aria-labelledby="local-title">
        <h2 id="local-title">7. Run it yourself</h2>
        <p>With your own Intune admin account. Defender indicators need the app, so this covers WDAC and macOS:</p>
        <pre class="kql-code"><code>./Sync-RMMGuard.ps1 -Target Wdac,Macos -WdacPolicyName 'RMM Guard - WDAC' -Interactive -WhatIf</code></pre>
        <p>Already deployed the policies by hand from this site? Pass their names: the macOS export is called <code>Block RMM tools (macOS)</code>, and for WDAC use the name you gave it. The script recognises them and updates them in place. If it finds the RMM Guard WDAC policy under another name, it stops and tells you which name to pass.</p>
      </section>
      <section id="troubleshooting" class="help-step" aria-labelledby="troubleshooting-title">
        <h2 id="troubleshooting-title">8. Troubleshooting</h2>
        <ul>
          <li><strong>HTTP 400, unknown tool in exclude:</strong> a tool was renamed or removed. Copy the names again from the RMM page.</li>
          <li><strong>More than 25 percent:</strong> a large release or a big exclusion change. Run with <code>-WhatIf</code>, check the numbers, then once with <code>-Force</code>.</li>
          <li><strong>would block …:</strong> the published file contains a rule that would break Windows or Intune. Nothing was changed. <a href="https://github.com/Lewis-Barry/RMM-Blocker/issues/new" target="_blank" rel="noopener noreferrer">Report it <span aria-hidden="true">↗</span></a>.</li>
          <li><strong>Refusing to overwrite:</strong> the policy with that name is not an RMM Guard policy. Pick another name.</li>
          <li><strong>Skipped, version … days old:</strong> expected with <code>-MinimumReleaseAgeDays</code>. The next run applies it.</li>
          <li><strong>CredentialTypeNotAllowedAsPerAppPolicy:</strong> your tenant blocks client secrets. Use the certificate or OIDC.</li>
        </ul>
      </section>
    </article>
```

- [ ] **Step 4: Regenerate and check.** `node build.mjs && node build.mjs --check`. Expected: `llms.txt` and `sitemap.xml` updated, then `Generated files are up to date.` Open `help-automation.html` in a browser at 375px and 1400px width: no horizontal scroll, copy buttons on the code blocks.

- [ ] **Step 5: Commit.** `git add help-automation.html help.html help-ioc.html help-macos.html tool-pages.mjs build.mjs llms.txt sitemap.xml && git commit -m "docs: automation guide page"`

---

### Task 10: Automation section in the retrieval-links modal

**Files:**
- Modify: `index.html:167` (after `links-modal-list`), `app.js` (import and `links-open` handler around line 461), `styles.css` (one rule)

- [ ] **Step 1: Markup.** In `index.html`, directly after `<ul id="links-modal-list" class="rule-groups" role="list"></ul>`, add:

```html
      <section class="links-automation" aria-labelledby="links-automation-title">
        <h3 id="links-automation-title">Automation</h3>
        <p class="modal-desc">Want to automate this fully? One PowerShell script keeps Intune and Defender in sync on a schedule, from GitHub Actions, Azure DevOps or an Azure Automation runbook. This command previews it with your exclusions (click to copy):</p>
        <div id="links-command" class="chip-row"></div>
        <p class="modal-desc"><a href="./automation/Sync-RMMGuard.ps1" download>Download Sync-RMMGuard.ps1</a> · <a href="./help-automation.html">Read the automation guide</a></p>
      </section>
```

- [ ] **Step 2: Behaviour.** In `app.js` add `import { buildSyncCommand } from "./automation.js";` next to the other imports, and inside the `links-open` click handler, before `byId("links-modal").showModal();`, add:

```js
  byId("links-command").replaceChildren(chip(buildSyncCommand(excluded)));
```

- [ ] **Step 3: Style.** Append to `styles.css`:

```css
.links-automation { border-top: 1px solid var(--line); margin-top: 12px; padding: 12px 14px 0; }
.links-automation h3 { margin: 0 0 6px; font-size: 14px; }
.links-automation .modal-desc { margin: 8px 0; }
```

- [ ] **Step 4: Test.** Add to `testBuilder` in `tests.js`, next to the other modal tests:

```js
    test("Retrieval-links modal shows the sync command with the current exclusions", () => {
      const toggle = doc.querySelector('input[type="checkbox"][data-tool]');
      toggle.click();
      doc.getElementById("links-open").click();
      const command = doc.querySelector("#links-command .copy-chip span").textContent;
      assert(command.includes(`-Exclude '${toggle.dataset.tool.replaceAll("'", "''")}'`), command);
      assert(doc.querySelector('.links-automation a[href="./help-automation.html"]'), "Guide link missing");
      doc.getElementById("links-modal").close();
      toggle.click();
    });
```

Adapt the variable names (`doc`, the checkbox selector) to the ones `testBuilder` already uses for tool toggles; read the surrounding tests first. Run `node run-tests.mjs "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"`. Expected: all pass.

- [ ] **Step 5: Last updated, build, commit.** Set the chip in `index.html` to today's date, then `node build.mjs`, then:

```bash
git add index.html app.js styles.css tests.js llms.txt
git commit -m "feat: Automation section with the sync command in the retrieval-links modal"
```

---

### Task 11: CI and maintenance notes

**Files:**
- Modify: `.github/workflows/tests.yml`
- Modify: `AGENTS.md`

- [ ] **Step 1: CI.** Add after the `node --test` step:

```yaml
      - run: pwsh -NoProfile -c "Invoke-Pester -Path automation -CI"
```

(`ubuntu-latest` ships PowerShell 7 and Pester 5; the macOS test calls `node`, which the job already set up.)

- [ ] **Step 2: AGENTS.md.** Append:

```markdown
- `automation/Sync-RMMGuard.ps1` syncs the retrieval links into a tenant. Its guards mirror the site: `$script:BroadTeamIds` must equal `broadTeamIds` in `macos.js`, `$script:PolicyId` and `$script:RuleOptions` must match `Blocking_RMMsv5.xml`, and `$script:IocHeader` must match `iocHeaders` in `ioc.js`. Run `pwsh -c "Invoke-Pester ./automation"` after changing any of those or the script; the tests use the repo's own policy, CSVs and products.json as positive controls. Keep `Invoke-Sync` as the script's last line; the tests load everything above it.
- A new rule that a canary in `Sync-RMMGuard.ps1` rejects (for example a deny path matching `explorer.exe`) will stop every customer's sync. Fix the rule, not the canary.
```

- [ ] **Step 3: Full verification.** Run, and paste the summary lines into the PR description:

```bash
node build.mjs --check
node --test scripts/ worker/
pwsh -NoProfile -c "Invoke-Pester ./automation -CI"
node run-tests.mjs "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
```

Expected: up to date; all node tests pass; Pester `Failed: 0`; browser `0 failures`.

- [ ] **Step 4: Commit.** `git add .github/workflows/tests.yml AGENTS.md && git commit -m "ci: run the automation Pester tests"`

---

### Task 12: Wrap-up

- [ ] **Step 1:** Re-read the spec's deliverables table and tick each row against the branch (`git diff --stat main...HEAD`).
- [ ] **Step 2:** Ask Roy whether to keep the test app for later runs or remove it now (`./automation/Setup-RMMGuardApp.ps1 -TenantId inforcedbyroy.onmicrosoft.com -Remove`).
- [ ] **Step 3:** Ask Roy whether `docs/superpowers/` should stay in the branch or be dropped before the upstream PR (it is planning material, not site content).
- [ ] **Step 4:** Use superpowers:finishing-a-development-branch to decide on PR to `royklo/rmm-blocker` and/or upstream `Lewis-Barry/RMM-Blocker`.
