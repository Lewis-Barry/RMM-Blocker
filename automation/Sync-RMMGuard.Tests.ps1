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
    Context 'hardening' {
        BeforeAll {
            $script:X = ConvertTo-NormalizedXml $script:PolicyXml
            $script:Ctes = 'FilePath="*\ctes.exe"'
        }
        It 'rejects a changed <Which> alone' -ForEach @(
            @{ Which = 'BasePolicyID'; From = '<BasePolicyID>{01A11AD0'; To = '<BasePolicyID>{11111111' }
            @{ Which = 'PolicyID';     From = '<PolicyID>{01A11AD0';     To = '<PolicyID>{11111111' }
        ) {
            { Test-WdacPolicy $script:X.Replace($From, $To) } | Should -Throw 'WDAC:*'
        }
        It 'rejects one Allow removed' {
            $bad = [regex]::Replace($script:X, '<Allow [^>]*/>', '', 1)
            { Test-WdacPolicy $bad } | Should -Throw '*two Allow*'
        }
        It 'rejects an Allow with FileName x.exe' {
            $bad = [regex]::Replace($script:X, '(<Allow [^>]*FileName=)"\*"', '$1"x.exe"', 1)
            { Test-WdacPolicy $bad } | Should -Throw '*two Allow*'
        }
        It 'rejects a Deny with FileName next to FilePath' {
            { Test-WdacPolicy $script:X.Replace($script:Ctes, "$script:Ctes FileName=`"explorer.exe`"") } | Should -Throw '*uses FileName*'
        }
        It 'rejects a Deny with a Hash next to FilePath' {
            { Test-WdacPolicy $script:X.Replace($script:Ctes, "$script:Ctes Hash=`"00`"") } | Should -Throw '*uses Hash*'
        }
        It 'rejects a Deny without FilePath' {
            { Test-WdacPolicy $script:X.Replace(" $script:Ctes", '') } | Should -Throw 'WDAC:*'
        }
        It 'rejects the macro path <Path>' -ForEach @(
            @{ Path = '%SYSTEM32%\*' }
            @{ Path = '%OSDRIVE%\*' }
        ) {
            { Test-WdacPolicy $script:X.Replace($script:Ctes, "FilePath=`"$Path`"") } | Should -Throw '*only FilePath rules*'
        }
        It 'rejects the path <Path> that hits a canary' -ForEach @(
            @{ Path = '*\EXPLORER.EXE' }
            @{ Path = '*\explore?.exe' }
            @{ Path = '*.dll' }
            @{ Path = '*\omadmclient.exe' }
            @{ Path = '*\svchost.exe' }
            @{ Path = '*\lsass.exe' }
            @{ Path = '*\winlogon.exe' }
            @{ Path = '*\cmd.exe' }
            @{ Path = '*\powershell.exe' }
            @{ Path = '*\MsMpEng.exe' }
            @{ Path = '*\Microsoft.Management.Services.IntuneWindowsAgent.exe' }
            @{ Path = '*\ntdll.dll' }
            @{ Path = '*\System32\ntdll.dll' }
            @{ Path = '*\SysWOW64\ntdll.dll' }
            @{ Path = '*\msiexec.exe' }
            @{ Path = '*\conhost.exe' }
            @{ Path = '*\AgentExecutor.exe' }
            @{ Path = '*\MsSense.exe' }
        ) {
            { Test-WdacPolicy $script:X.Replace($script:Ctes, "FilePath=`"$Path`"") } | Should -Throw '*would block*'
        }
        It 'rejects a structure change: <Name>' -ForEach @(
            @{ Name = 'DeniedSigners under scenario 12'; Mutate = {
                $script:X.Replace('</FileRules>', '</FileRules><Signers><Signer ID="ID_SIGNER_X" Name="Windows"><CertRoot Type="Wellknown" Value="06" /></Signer></Signers>').
                    Replace('<ProductSigners>', '<ProductSigners><DeniedSigners><DeniedSigner SignerId="ID_SIGNER_X" /></DeniedSigners>') } }
            @{ Name = 'scenario 131 FileRuleRef removed'; Mutate = { [regex]::Replace($script:X, '(Value="131".*?)<FileRuleRef RuleID="[^"]+" />', '$1') } }
            @{ Name = 'scenario 131 FileRuleRef repointed'; Mutate = { [regex]::Replace($script:X, '(Value="131".*?<FileRuleRef RuleID=")[^"]+', '${1}ID_DENY_A_D91474AD759E53010A953C20F82F02DE') } }
            @{ Name = 'MinimumFileVersion on an Allow'; Mutate = { [regex]::Replace($script:X, '(<Allow [^>]*FileName="\*")', '$1 MinimumFileVersion="65535.65535.65535.65535"', 1) } }
            @{ Name = 'an extra SigningScenario'; Mutate = { $script:X.Replace('</SigningScenarios>', '<SigningScenario Value="12" ID="ID_X" FriendlyName="x"><ProductSigners /></SigningScenario></SigningScenarios>') } }
            @{ Name = 'a deny ref added to scenario 131'; Mutate = { [regex]::Replace($script:X, '(Value="131".*?<FileRulesRef>)', '$1<FileRuleRef RuleID="ID_DENY_A_D91474AD759E53010A953C20F82F02DE" />') } }
            @{ Name = 'a FileAttrib element'; Mutate = { $script:X.Replace('</FileRules>', '<FileAttrib ID="ID_FILEATTRIB_X" FileName="explorer.exe" /></FileRules>') } }
        ) {
            { Test-WdacPolicy (& $Mutate) } | Should -Throw '*structure*'
        }
        It 'rejects a dangling UMCI reference' {
            $bad = [regex]::Replace($script:X, '<Deny [^>]*ID="ID_DENY_A_D91474AD759E53010A953C20F82F02DE"[^>]*/>', '')
            { Test-WdacPolicy $bad } | Should -Throw '*one to one*'
        }
        It 'rejects a Deny without a UMCI reference' {
            $bad = $script:X.Replace('<FileRuleRef RuleID="ID_DENY_A_D91474AD759E53010A953C20F82F02DE" />', '')
            $bad | Should -Not -Be $script:X
            { Test-WdacPolicy $bad } | Should -Throw '*one to one*'
        }
        It 'accepts a BOM-prefixed policy' {
            { Test-WdacPolicy ("`u{FEFF}" + $script:PolicyXml) } | Should -Not -Throw
        }
        It 'rejects a policy with zero Deny rules' {
            { Test-WdacPolicy ([regex]::Replace($script:X, '<Deny [^>]*/>', '')) } | Should -Throw '*no Deny*'
        }
        It 'rejects a DOCTYPE' {
            { Test-WdacPolicy $script:X.Replace('<SiPolicy ', '<!DOCTYPE SiPolicy [<!ENTITY e "x">]><SiPolicy ') } | Should -Throw 'WDAC:*'
        }
        It 'accepts the worker-filtered policy and returns fewer rules' {
            $names = '["AnyDesk","TeamViewer","O&O Syspectr"]'
            $js = "import { filterPolicy } from '$script:Root/worker/index.js'; import { readFileSync } from 'node:fs'; process.stdout.write(filterPolicy(readFileSync('$script:Root/Blocking_RMMsv5.xml', 'utf8'), new Set($names)).replace(/^\uFEFF/, ''))"
            $filtered = (& node --input-type=module -e $js) -join "`n"
            $LASTEXITCODE | Should -Be 0
            $full = Test-WdacPolicy $script:PolicyXml
            $facts = Test-WdacPolicy $filtered
            $facts.Rules.Count | Should -BeLessThan $full.Rules.Count
        }
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
        { Test-MacRules (Get-MacRules @()) } | Should -Throw '*denies nothing*'
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
        # The same shape Invoke-RestMethod returns: one object holding the array.
        $log = ConvertFrom-Changelog (ConvertFrom-Json -NoEnumerate '[{"version":"1.0.0.22","date":"2026-11-10"},{"version":"1.0.0.21","date":"2026-11-01"}]')
        $log.Count | Should -Be 2
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
