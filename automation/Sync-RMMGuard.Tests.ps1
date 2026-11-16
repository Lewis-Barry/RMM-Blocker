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
            $bad = ([regex]'<Allow [^>]*/>').Replace($script:X, '', 1)
            [regex]::Matches($bad, '<Allow ').Count | Should -Be 1
            { Test-WdacPolicy $bad } | Should -Throw 'WDAC: expected exactly two Allow FileName="`*" rules.'
        }
        It 'rejects an Allow with FileName x.exe' {
            $bad = ([regex]'(<Allow [^>]*FileName=)"\*"').Replace($script:X, '$1"x.exe"', 1)
            [regex]::Matches($bad, '<Allow [^>]*FileName="\*"').Count | Should -Be 1
            [regex]::Matches($bad, 'FileName="x\.exe"').Count | Should -Be 1
            { Test-WdacPolicy $bad } | Should -Throw 'WDAC: expected exactly two Allow FileName="`*" rules.'
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
            @{ Name = 'MinimumFileVersion on an Allow'; Mutate = { ([regex]'(<Allow [^>]*FileName="\*")').Replace($script:X, '$1 MinimumFileVersion="65535.65535.65535.65535"', 1) } }
            @{ Name = 'an extra SigningScenario'; Mutate = { $script:X.Replace('</SigningScenarios>', '<SigningScenario Value="12" ID="ID_X" FriendlyName="x"><ProductSigners /></SigningScenario></SigningScenarios>') } }
            @{ Name = 'a deny ref added to scenario 131'; Mutate = { [regex]::Replace($script:X, '(Value="131".*?<FileRulesRef>)', '$1<FileRuleRef RuleID="ID_DENY_A_D91474AD759E53010A953C20F82F02DE" />') } }
            @{ Name = 'a FileAttrib element'; Mutate = { $script:X.Replace('</FileRules>', '<FileAttrib ID="ID_FILEATTRIB_X" FileName="explorer.exe" /></FileRules>') } }
        ) {
            { Test-WdacPolicy (& $Mutate) } | Should -Throw 'WDAC: the policy structure outside the deny rules changed*'
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
    It 'accepts a subdomain under a canary outside the first-party suffixes, which does not block the canary itself' {
        @(ConvertFrom-IocCsv (Row 'DomainName' 'x.contoso.sharepoint.com')).Count | Should -Be 1
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
    It 'has no -Force and no change-size limit: the content checks are the safety net' {
        $ast = [System.Management.Automation.Language.Parser]::ParseFile("$PSScriptRoot/Sync-RMMGuard.ps1", [ref]$null, [ref]$null)
        $ast.ParamBlock.Parameters.Name.VariablePath.UserPath | Should -Not -Contain 'Force'
        Get-Command Test-ChangeSize -ErrorAction SilentlyContinue | Should -BeNullOrEmpty
    }
    It 'defaults the WDAC policy name' {
        $ast = [System.Management.Automation.Language.Parser]::ParseFile("$PSScriptRoot/Sync-RMMGuard.ps1", [ref]$null, [ref]$null)
        ($ast.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'WdacPolicyName' }).DefaultValue.Value | Should -Be 'RMM Guard - WDAC'
    }
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

Describe 'IOC hardening' {
    BeforeAll {
        $script:H = (Get-Content "$script:Root/IOC/Defender_IOC_LOLRMM_IPs.csv" -TotalCount 1)
        function IocRow($Type, $Value, $Exp = '2035-07-23T00:00:00Z', $Sev = 'Medium', $Alert = 'true') {
            "$script:H`r`n$Type,$Value,$Exp,Block,$Sev,LOLRMM - Test,d,r,,,,$Alert`r`n"
        }
    }
    It 'rejects IP indicator <V>' -ForEach @(
        @{ V = '20.190.151.68' }, @{ V = '13.107.246.40' }, @{ V = '127.0.0.1' }, @{ V = '10.1.2.3' }, @{ V = '::1' }, @{ V = 'example.org' }
    ) { { ConvertFrom-IocCsv (IocRow 'IpAddress' $V) } | Should -Throw 'IOC:*' }
    It 'accepts a real public IP from the bundled CSV' {
        $line = Get-Content "$script:Root/IOC/Defender_IOC_LOLRMM_IPs.csv" | Select-Object -Skip 1 -First 1
        @(ConvertFrom-IocCsv "$script:H`r`n$line`r`n").Count | Should -Be 1
    }
    It 'rejects domain indicator <V>' -ForEach @(
        @{ V = 'microsoft.com.' }, @{ V = '" microsoft.com"' }, @{ V = '*.microsoft.com' }, @{ V = 'https://login.microsoftonline.com/' },
        @{ V = 'LOGIN.MICROSOFTONLINE.COM' }, @{ V = 'office.com' }, @{ V = 'apple.com' }, @{ V = 'windows.net' }
    ) { { ConvertFrom-IocCsv (IocRow 'DomainName' $V) } | Should -Throw 'IOC:*' }
    It 'accepts <V>' -ForEach @(@{ V = 'ndowsupdate.com' }, @{ V = 'support.services.microsoft.com' }) {
        @(ConvertFrom-IocCsv (IocRow 'DomainName' $V)).Count | Should -Be 1
    }
    It 'rejects <Name>' -ForEach @(
        @{ Name = 'a past expiration'; Exp = '2000-01-01T00:00:00Z'; Sev = 'Medium'; Alert = 'true' }
        @{ Name = 'an expiration 10 days ahead'; Exp = ([datetime]::UtcNow.AddDays(10).ToString('o')); Sev = 'Medium'; Alert = 'true' }
        @{ Name = 'severity Critical'; Exp = '2035-07-23T00:00:00Z'; Sev = 'Critical'; Alert = 'true' }
        @{ Name = 'GenerateAlert yes'; Exp = '2035-07-23T00:00:00Z'; Sev = 'Medium'; Alert = 'yes' }
    ) { { ConvertFrom-IocCsv (IocRow 'DomainName' 'example.org' $Exp $Sev $Alert) } | Should -Throw 'IOC:*' }
    It 'rejects duplicate rows' {
        $row = 'DomainName,example.org,2035-07-23T00:00:00Z,Block,Medium,LOLRMM - T,d,r,,,,true'
        { ConvertFrom-IocCsv "$script:H`r`n$row`r`n$($row.ToUpper().Replace('LOLRMM - T','LOLRMM - T'))`r`n" } | Should -Throw '*duplicate*'
    }
    It 'upserts on a <Field> change' -ForEach @(@{ Field = 'description' }, @{ Field = 'severity' }, @{ Field = 'action' }) {
        $new = [pscustomobject]@{ indicatorType = 'DomainName'; indicatorValue = 'a.org'; title = 'LOLRMM - A'; description = 'd'; severity = 'Medium'; action = 'Block' }
        $old = [pscustomobject]@{ id = '1'; indicatorType = 'DomainName'; indicatorValue = 'a.org'; title = 'LOLRMM - A'; description = 'd'; severity = 'Medium'; action = 'Block' }
        $old.$Field = 'changed'
        @((Compare-IocSet @($new) @($old)).Upsert).Count | Should -Be 1
    }
}

Describe 'macOS hardening' {
    BeforeAll {
        $script:MacBody = node --input-type=module -e "import { parseMacProducts, buildIntunePolicy } from '$($script:Root.Replace('\', '/'))/macos.js'; import { readFileSync } from 'node:fs'; const d = parseMacProducts(JSON.parse(readFileSync('$($script:Root.Replace('\', '/'))/products.json', 'utf8'))); process.stdout.write(buildIntunePolicy(d.rules, d.version));" 2>$null | ConvertFrom-Json -AsHashtable
        function Fresh { $script:MacBody | ConvertTo-Json -Depth 100 | ConvertFrom-Json -AsHashtable }
    }
    It 'rule count equals the number in the description' {
        $n = [regex]::Match($script:MacBody.description, 'Denies (\d+) binary identifiers').Groups[1].Value
        $n | Should -Not -BeNullOrEmpty
        @(Get-MacRules $script:MacBody.settings).Count | Should -Be ([int]$n)
    }
    It 'rejects Team ID <V>' -ForEach @(@{ V = 'abcdefghij' }, @{ V = 'ABCDEFGHI' }) {
        { Test-MacRules @([pscustomobject]@{ TeamId = $V; SigningId = $null }) } | Should -Throw '*Team ID*'
    }
    It 'rejects Microsoft Team ID even with a Signing ID' {
        { Test-MacRules @([pscustomobject]@{ TeamId = 'UBF8T346G9'; SigningId = 'com.microsoft.x' }) } | Should -Throw '*Microsoft*'
    }
    It 'returns no version without the prefix' { Get-MacVersion 'Something v1.0.0.1' | Should -BeNullOrEmpty }
    It 'accepts the real body' { { Test-MacBody (Fresh) } | Should -Not -Throw }
    It 'rejects an extra top-level key' { $b = Fresh; $b.extra = 1; { Test-MacBody $b } | Should -Throw 'macOS:*' }
    It 'rejects platforms windows10' { $b = Fresh; $b.platforms = 'windows10'; { Test-MacBody $b } | Should -Throw 'macOS:*' }
    It 'rejects a second setting' { $b = Fresh; $b.settings += $b.settings[0]; { Test-MacBody $b } | Should -Throw 'macOS:*' }
    It 'rejects a foreign settingDefinitionId deep in the tree' {
        $b = Fresh
        $deny = $b.settings[0].settingInstance.groupSettingCollectionValue[0].children[0].groupSettingCollectionValue[0].children[0]
        $deny.groupSettingCollectionValue[0].children[0].settingDefinitionId = 'evil_setting'
        { Test-MacBody $b } | Should -Throw '*unexpected setting*'
    }
}

Describe 'Shared hardening' {
    It 'merges g1 and g2' {
        $e = @([pscustomobject]@{ '@odata.type' = '#microsoft.graph.groupAssignmentTarget'; groupId = 'g1' })
        @(Merge-AssignmentTargets $e @(@{ '@odata.type' = '#microsoft.graph.groupAssignmentTarget'; groupId = 'g2' })).Count | Should -Be 2
    }
}

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
        $now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
        $header.alg | Should -Be 'RS256'
        $header.typ | Should -Be 'JWT'
        $payload.jti | Should -Match '^[0-9a-f]{8}-'
        $payload.nbf | Should -BeLessOrEqual $now
        $payload.exp | Should -BeGreaterThan $now
        ($payload.exp - $payload.nbf) | Should -BeLessOrEqual 600
        $header.x5t | Should -Be ([Convert]::ToBase64String($certificate.GetCertHash()).TrimEnd('=').Replace('+', '-').Replace('/', '_'))
        $payload.aud | Should -Be 'https://login.microsoftonline.com/tenant-id/oauth2/v2.0/token'
        $payload.iss | Should -Be 'client-id'
        $payload.sub | Should -Be 'client-id'
        $signature = $parts[2].Replace('-', '+').Replace('_', '/')
        $signature = [Convert]::FromBase64String($signature.PadRight($signature.Length + (4 - $signature.Length % 4) % 4, '='))
        $rsa.VerifyData([Text.Encoding]::UTF8.GetBytes("$($parts[0]).$($parts[1])"), $signature,
            [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1) | Should -BeTrue
    }
    Context 'Resolve-Auth rules' {
        BeforeEach { $savedSecret = $env:RMMGUARD_CLIENT_SECRET; $env:RMMGUARD_CLIENT_SECRET = $null }
        AfterEach { $env:RMMGUARD_CLIENT_SECRET = $savedSecret }
        It 'rejects two sign-in modes' {
            $Interactive = [switch]$true; $Identity = [switch]$true
            { Resolve-Auth } | Should -Throw '*Choose one*'
        }
        It 'rejects no sign-in mode' { { Resolve-Auth } | Should -Throw '*Choose one*' }
        It 'falls back to the secret from the environment' {
            $env:RMMGUARD_CLIENT_SECRET = 'envsecret'; $TenantId = 't'; $ClientId = 'c'
            $auth = Resolve-Auth
            $auth.Mode | Should -Be 'Secret'
            $auth.Secret | Should -Be 'envsecret'
        }
        It 'lets -Interactive win over the environment secret' {
            $env:RMMGUARD_CLIENT_SECRET = 'envsecret'; $Interactive = [switch]$true
            (Resolve-Auth).Mode | Should -Be 'Interactive'
        }
        It 'requires tenant and client id with a secret' {
            $ClientSecret = 'x'; $TenantId = $null; $ClientId = 'c'
            { Resolve-Auth } | Should -Throw '*-TenantId and -ClientId*'
        }
        It 'rejects both certificate parameters' {
            $TenantId = 't'; $ClientId = 'c'; $CertificatePath = '/x.pfx'; $CertificateThumbprint = 'AB'
            { Resolve-Auth } | Should -Throw '*not both*'
        }
        It 'treats [ in a certificate path literally' {
            $TenantId = 't'; $ClientId = 'c'; $CertificatePath = '/nonexistent/[a].pfx'
            { Resolve-Auth } | Should -Throw '*Cannot find path*'
        }
    }

    Context 'Get-AccessToken requests' {
        BeforeEach { Mock Invoke-RestMethod { [pscustomobject]@{ access_token = 'T' } } }
        AfterEach { $env:IDENTITY_ENDPOINT = $null; $env:IDENTITY_HEADER = $null }
        It 'posts a client secret request' {
            $script:Auth = @{ Mode = 'Secret'; TenantId = 't1'; ClientId = 'c1'; Secret = 's' }
            Get-AccessToken 'https://api.securitycenter.microsoft.com' | Should -Be 'T'
            Should -Invoke Invoke-RestMethod -Exactly 1 -ParameterFilter {
                $Uri -eq 'https://login.microsoftonline.com/t1/oauth2/v2.0/token' -and $Method -eq 'Post' -and
                $Body.scope -eq 'https://api.securitycenter.microsoft.com/.default' -and
                $Body.grant_type -eq 'client_credentials' -and $Body.client_secret -eq 's' }
        }
        It 'posts a federated assertion without a secret' {
            $script:Auth = @{ Mode = 'Federated'; TenantId = 't1'; ClientId = 'c1'; FederatedToken = 'fed' }
            Get-AccessToken 'https://graph.microsoft.com' | Out-Null
            Should -Invoke Invoke-RestMethod -Exactly 1 -ParameterFilter {
                $Body.client_assertion_type -eq 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer' -and
                $Body.client_assertion -eq 'fed' -and -not $Body.ContainsKey('client_secret') }
        }
        It 'asks the managed identity endpoint' {
            $env:IDENTITY_ENDPOINT = 'http://localhost/msi'; $env:IDENTITY_HEADER = 'h'
            $script:Auth = @{ Mode = 'Identity' }
            Get-AccessToken 'https://graph.microsoft.com' | Out-Null
            Should -Invoke Invoke-RestMethod -Exactly 1 -ParameterFilter {
                $Uri -like '*resource=https%3A%2F%2Fgraph.microsoft.com*' -and $Headers['X-IDENTITY-HEADER'] -eq 'h' }
        }
    }
}

Describe 'Download' {
    BeforeEach { $script:Files = @{}; $Exclude = @('AnyDesk') }
    It 'returns the body on the first and the cached call, and downloads once' {
        Mock Invoke-WebRequest { [pscustomobject]@{ StatusCode = 200; Content = '<SiPolicy />'; Headers = @{ 'Content-Type' = @('application/xml;charset=utf-8') } } }
        Get-RMMGuardFile 'wdac.xml' 'xml' | Should -Be '<SiPolicy />'
        Get-RMMGuardFile 'wdac.xml' 'xml' | Should -Be '<SiPolicy />'
        Should -Invoke Invoke-WebRequest -Times 1 -Exactly -ParameterFilter { $Uri -eq 'https://rmmguard.com/api/wdac.xml?exclude=AnyDesk' }
    }
    It 'stops on <Name>' -ForEach @(
        @{ Name = 'HTTP 400'; Status = 400; Served = 'text/plain'; Text = 'Unknown tool in exclude: X'; Expected = '*HTTP 400*Unknown tool*' }
        @{ Name = 'an HTML page'; Status = 200; Served = 'text/html'; Text = '<html></html>'; Expected = '*content type*' }
    ) {
        # Not $Body or $Type: inside the mock those resolve to Invoke-WebRequest's -Body and Get-RMMGuardFile's -Type.
        Mock Invoke-WebRequest { [pscustomobject]@{ StatusCode = $Status; Content = $Text; Headers = @{ 'Content-Type' = @($Served) } } }
        { Get-RMMGuardFile 'wdac.xml' 'xml' } | Should -Throw $Expected
    }
}

# The sync functions with Graph, Defender and the download mocked: what is written, and what is not.
Describe 'Sync decisions' {
    BeforeAll {
        $root = $script:Root.Replace('\', '/')
        $script:MacJson = (node --input-type=module -e "import { parseMacProducts, buildIntunePolicy } from '$root/macos.js'; import { readFileSync } from 'node:fs'; const d = parseMacProducts(JSON.parse(readFileSync('$root/products.json', 'utf8'))); process.stdout.write(buildIntunePolicy(d.rules, d.version));" 2>$null) -join "`n"
        $script:IocText = Get-Content -Raw "$script:Root/IOC/Defender_IOC_LOLRMM_Domains_Part2.csv"
        $script:Version = (Get-WdacFacts $script:PolicyXml).Version
        # GET .../settings of an App Control policy as Graph returns it: the body's settings, as objects.
        function WdacSettings([string]$Xml) { [pscustomobject]@{ value = @((New-WdacBody 'n' 'd' $Xml).settings | ConvertTo-Json -Depth 32 | ConvertFrom-Json) } }
        function Confirm([bool]$Answer) { $script:Cmdlet = [pscustomobject]@{ Answer = $Answer } | Add-Member ScriptMethod ShouldProcess { $this.Answer } -PassThru }
    }
    BeforeEach {
        $WdacPolicyName = 'RMM Guard - WDAC'; $MacosPolicyName = 'Block RMM tools (macOS)'; $RingPolicyName = @(); $Exclude = @()
        $Assignment = $null; $ExcludeGroupId = $null; $MinimumReleaseAgeDays = 0
        $script:Changelog = @(); $script:Files = @{}; $script:Auth = @{ Mode = 'Secret' }; $script:Written = $null
        Confirm $true
        Mock Get-RMMGuardFile { switch ($File) { 'wdac.xml' { $script:PolicyXml } 'macos.json' { $script:MacJson } 'iocs.csv' { $script:IocText } } }
    }

    Context 'WDAC' {
        BeforeEach { $script:Deployed = $script:PolicyXml; $script:Template = $script:WdacTemplateId }
        It 'stops when the RMM Guard PolicyID exists under another name' {
            Mock Invoke-Graph {
                if ($Path -like '*name%20eq*') { [pscustomobject]@{ value = @() } }
                elseif ($Path -like '*templateFamily*') { [pscustomobject]@{ value = @([pscustomobject]@{ id = 'p2'; name = 'RMM Guard - WDAC (pilot)' }) } }
                elseif ($Path -like '*/p2/settings') { WdacSettings $script:PolicyXml }
            }
            { Sync-Wdac } | Should -Throw "*already exists as 'RMM Guard - WDAC (pilot)'*"
            Should -Invoke Invoke-Graph -Times 0 -Exactly -ParameterFilter { $Method -ne 'GET' }
        }
        It 'creates the policy when the other name is the other ring' {
            $RingPolicyName = @('RMM Guard - WDAC (pilot)')
            Mock Invoke-Graph {
                if ($Method -eq 'POST') { $script:Written = $Body; [pscustomobject]@{ id = 'new' } }
                elseif ($Path -like '*name%20eq*') { [pscustomobject]@{ value = @() } }
                elseif ($Path -like '*templateFamily*') { [pscustomobject]@{ value = @([pscustomobject]@{ id = 'p2'; name = 'RMM Guard - WDAC (pilot)' }) } }
                elseif ($Path -like '*/p2/settings') { WdacSettings $script:PolicyXml }
            }
            Sync-Wdac | Should -BeLike "created v$script:Version,*"
            Should -Invoke Invoke-Graph -Times 1 -Exactly -ParameterFilter { $Method -eq 'POST' -and $Path -eq '/deviceManagement/configurationPolicies' }
            $script:Written.name | Should -Be 'RMM Guard - WDAC'
            $script:Written.settings[0].settingInstance.choiceSettingValue.children[0].simpleSettingValue.value | Should -Be $script:PolicyXml
        }
        Context 'existing policy' {
            BeforeEach {
                Mock Invoke-Graph {
                    if ($Path -like '*name%20eq*') { [pscustomobject]@{ value = @([pscustomobject]@{ id = 'p1'; name = 'RMM Guard - WDAC'; description = 'd' }) } }
                    elseif ($Path -like '*/p1/settings') { WdacSettings $script:Deployed }
                    elseif ($Path -like '*/p1?*') { [pscustomobject]@{ id = 'p1'; name = 'RMM Guard - WDAC'; description = 'd'; roleScopeTagIds = @('0'); templateReference = [pscustomobject]@{ templateId = $script:Template }; settingCount = 1 } }
                }
            }
            It 'reports unchanged for the same XML with other whitespace, and writes nothing' {
                $script:Deployed = ConvertTo-NormalizedXml $script:PolicyXml
                Sync-Wdac | Should -Be "unchanged v$script:Version"
                Should -Invoke Invoke-Graph -Times 0 -Exactly -ParameterFilter { $Method -ne 'GET' }
            }
            It 'refuses a policy without the RMM Guard PolicyID' {
                $script:Deployed = '<SiPolicy><PolicyID>{11111111-2222-3333-4444-555555555555}</PolicyID></SiPolicy>'
                { Sync-Wdac } | Should -Throw '*Refusing*'
                Should -Invoke Invoke-Graph -Times 0 -Exactly -ParameterFilter { $Method -ne 'GET' }
            }
            It 'refuses a policy from another template' {
                $script:Template = 'd3849ba8-bf95-467c-9640-aa2334eae9e3_1'
                { Sync-Wdac } | Should -Throw '*Refusing*'
            }
            It 'reports the update under -WhatIf and does not PUT' {
                $script:Deployed = ([regex]'<Deny [^>]*/>').Replace((ConvertTo-NormalizedXml $script:PolicyXml), '', 1)
                Confirm $false
                Sync-Wdac | Should -Be "would be updated: v$script:Version -> v$script:Version, +1/-0 deny rules"
                Should -Invoke Invoke-Graph -Times 0 -Exactly -ParameterFilter { $Method -ne 'GET' }
            }
            It 'PUTs the fetched XML when the change is confirmed' {
                $script:Deployed = ([regex]'<Deny [^>]*/>').Replace((ConvertTo-NormalizedXml $script:PolicyXml), '', 1)
                Mock Invoke-Graph -ParameterFilter { $Method -eq 'PUT' } { $script:Written = $Body }
                Sync-Wdac | Should -BeLike 'updated *'
                $script:Written.settings[0].settingInstance.choiceSettingValue.children[0].simpleSettingValue.value | Should -Be $script:PolicyXml
            }
        }
    }

    Context 'macOS' {
        BeforeEach {
            $script:MacDescription = ($script:MacJson | ConvertFrom-Json).description
            Mock Invoke-Graph {
                if ($Path -like '*name%20eq*') { [pscustomobject]@{ value = @([pscustomobject]@{ id = 'm1'; name = 'Block RMM tools (macOS)'; description = $script:MacDescription }) } }
                elseif ($Path -like '*/m1/settings') { [pscustomobject]@{ value = @(($script:MacJson | ConvertFrom-Json).settings) } }
            }
        }
        It 'refuses a policy whose description lacks the RMM Guard prefix' {
            $script:MacDescription = 'My own macOS policy'
            { Sync-Macos } | Should -Throw '*Refusing*'
            Should -Invoke Invoke-Graph -Times 0 -Exactly -ParameterFilter { $Method -ne 'GET' }
        }
        It 'reports unchanged for the same rule set and writes nothing' {
            Sync-Macos | Should -BeLike 'unchanged v*'
            Should -Invoke Invoke-Graph -Times 0 -Exactly -ParameterFilter { $Method -ne 'GET' }
        }
    }

    Context 'IOC' {
        BeforeEach { $script:Present = @(ConvertFrom-IocCsv $script:IocText) }
        It 'refuses -Interactive' {
            $script:Auth = @{ Mode = 'Interactive' }
            Mock Invoke-Defender {}
            { Sync-Ioc } | Should -Throw '*app identity*'
            Should -Invoke Invoke-Defender -Times 0 -Exactly
        }
        It 'reports unchanged and imports or deletes nothing' {
            Mock Invoke-Defender { [pscustomobject]@{ value = $script:Present } }
            Sync-Ioc | Should -Be "unchanged, $($script:Present.Count) indicators"
            Should -Invoke Invoke-Defender -Times 0 -Exactly -ParameterFilter { $Method -ne 'GET' }
        }
        It 'reports additions under -WhatIf and does not POST' {
            Mock Invoke-Defender { [pscustomobject]@{ value = @($script:Present | Select-Object -Skip 5) } }
            Confirm $false
            Sync-Ioc | Should -Be "would be updated: 5 to import (5 new), 0 to delete, $($script:Present.Count) wanted"
            Should -Invoke Invoke-Defender -Times 0 -Exactly -ParameterFilter { $Method -ne 'GET' }
        }
    }

    Context 'Assignment' {
        BeforeEach {
            $script:Existing = @([pscustomobject]@{ target = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.groupAssignmentTarget'; groupId = 'g1' } })
            Mock Invoke-Graph { if ($Method -eq 'GET') { [pscustomobject]@{ value = $script:Existing } } else { $script:Written = $Body } }
        }
        It 'keeps the existing targets and posts the union' {
            $Assignment = 'AllDevices'
            Set-Assignment 'p1'
            Should -Invoke Invoke-Graph -Times 1 -Exactly -ParameterFilter { $Method -eq 'POST' -and $Path -eq '/deviceManagement/configurationPolicies/p1/assign' }
            $targets = @($script:Written.assignments.target)
            $targets.Count | Should -Be 2
            $targets[0].groupId | Should -Be 'g1'
            $targets[1].'@odata.type' | Should -Be '#microsoft.graph.allDevicesAssignmentTarget'
        }
        It 'posts nothing when every wanted target exists' {
            $script:Existing += [pscustomobject]@{ target = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.allDevicesAssignmentTarget' } }
            $Assignment = 'AllDevices'
            Set-Assignment 'p1'
            Should -Invoke Invoke-Graph -Times 0 -Exactly -ParameterFilter { $Method -ne 'GET' }
        }
    }
}

Describe 'Graph paging' {
    It 'follows @odata.nextLink and returns every item' {
        Mock Invoke-Graph {
            if ($Path -eq '/x?$top=2') { [pscustomobject]@{ value = @(1, 2); '@odata.nextLink' = 'https://graph.microsoft.com/beta/x?$top=2&$skiptoken=t' } }
            elseif ($Path -eq '/x?$top=2&$skiptoken=t') { [pscustomobject]@{ value = @(3) } }
        }
        @(Get-GraphAll '/x?$top=2') | Should -Be @(1, 2, 3)
        Should -Invoke Invoke-Graph -Times 2 -Exactly
        Should -Invoke Invoke-Graph -Times 1 -Exactly -ParameterFilter { $Path -eq '/x?$top=2&$skiptoken=t' }
    }
    It 'finds the RMM Guard PolicyID on the second page' {
        $RingPolicyName = @()
        Mock Invoke-Graph {
            if ($Path -like '*templateFamily*' -and $Path -notlike '*skiptoken*') { [pscustomobject]@{ value = @([pscustomobject]@{ id = 'a'; name = 'Other' }); '@odata.nextLink' = 'https://graph.microsoft.com/beta/deviceManagement/configurationPolicies?$skiptoken=t' } }
            elseif ($Path -like '*skiptoken*') { [pscustomobject]@{ value = @([pscustomobject]@{ id = 'b'; name = 'Hidden' }) } }
            elseif ($Path -like '*/a/settings') { [pscustomobject]@{ value = @((New-WdacBody 'n' 'd' '<SiPolicy><PolicyID>{11111111-2222-3333-4444-555555555555}</PolicyID></SiPolicy>').settings | ConvertTo-Json -Depth 32 | ConvertFrom-Json) } }
            elseif ($Path -like '*/b/settings') { [pscustomobject]@{ value = @((New-WdacBody 'n' 'd' $script:PolicyXml).settings | ConvertTo-Json -Depth 32 | ConvertFrom-Json) } }
        }
        (Find-WdacByPolicyId).name | Should -Be 'Hidden'
    }
    It 'stops when Defender returns 10000 indicators' {
        $script:Auth = @{ Mode = 'Secret' }; $script:Files = @{ 'iocs.csv' = (Get-Content -Raw "$script:Root/IOC/Defender_IOC_LOLRMM_IPs.csv") }
        Mock Invoke-Defender { [pscustomobject]@{ value = @(1..10000 | ForEach-Object { [pscustomobject]@{ title = 'x' } }) } }
        { Sync-Ioc } | Should -Throw 'IOC: more than 10000 indicators are visible; paging is not supported.'
    }
}

# Adversarial review: ownership by parsed XML, assignment before the guards, stricter macOS and IOC writes.
Describe 'Review fixes' {
    BeforeAll {
        $root = $script:Root.Replace('\', '/')
        $script:MacJson = (node --input-type=module -e "import { parseMacProducts, buildIntunePolicy } from '$root/macos.js'; import { readFileSync } from 'node:fs'; const d = parseMacProducts(JSON.parse(readFileSync('$root/products.json', 'utf8'))); process.stdout.write(buildIntunePolicy(d.rules, d.version));" 2>$null) -join "`n"
        $script:IocText = Get-Content -Raw "$script:Root/IOC/Defender_IOC_LOLRMM_Domains_Part2.csv"
        $script:Version = (Get-WdacFacts $script:PolicyXml).Version
        # A customer's supplemental policy: its own PolicyID, the RMM Guard GUID as BasePolicyID.
        $script:Supplemental = '<?xml version="1.0"?><SiPolicy xmlns="urn:schemas-microsoft-com:sipolicy" PolicyType="Supplemental Policy"><VersionEx>10.0.0.0</VersionEx><PolicyID>{22222222-2222-2222-2222-222222222222}</PolicyID><BasePolicyID>{01A11AD0-7091-7896-89DD-447C515BCB5D}</BasePolicyID><FileRules><Allow ID="ID_ALLOW_X" FileName="mytool.exe"/></FileRules></SiPolicy>'
        function WdacSettings([string]$Xml) { [pscustomobject]@{ value = @((New-WdacBody 'n' 'd' $Xml).settings | ConvertTo-Json -Depth 32 | ConvertFrom-Json) } }
        function Confirm([bool]$Answer) { $script:Cmdlet = [pscustomobject]@{ Answer = $Answer } | Add-Member ScriptMethod ShouldProcess { $this.Answer } -PassThru }
        function FreshMac { $script:MacJson | ConvertFrom-Json -AsHashtable }
    }
    BeforeEach {
        $WdacPolicyName = 'RMM Guard - WDAC'; $MacosPolicyName = 'Block RMM tools (macOS)'; $RingPolicyName = @(); $Exclude = @()
        $Assignment = $null; $ExcludeGroupId = $null; $MinimumReleaseAgeDays = 0
        $script:Changelog = @(); $script:Files = @{}; $script:Auth = @{ Mode = 'Secret' }; $script:Posts = @()
        Confirm $true
        Mock Get-RMMGuardFile { switch ($File) { 'wdac.xml' { $script:PolicyXml } 'macos.json' { $script:MacJson } 'iocs.csv' { $script:IocText } } }
    }

    Context 'WDAC ownership (I1)' {
        It 'recognises only the RMM Guard base policy' {
            Test-RMMGuardBase $script:PolicyXml | Should -BeTrue
            Test-RMMGuardBase ($script:PolicyXml -replace '01A11AD0-7091-7896-89DD-447C515BCB5D', '01a11ad0-7091-7896-89dd-447c515bcb5d') | Should -BeTrue
            Test-RMMGuardBase $script:Supplemental | Should -BeFalse
            Test-RMMGuardBase 'not xml' | Should -BeFalse
            Test-RMMGuardBase $null | Should -BeFalse
        }
        It 'refuses a supplemental policy on our base: no PUT, no assignment' {
            $Assignment = 'AllDevices'
            Mock Invoke-Graph {
                if ($Method -ne 'GET') { $script:Posts += "$Method $Path" }
                elseif ($Path -like '*name%20eq*') { [pscustomobject]@{ value = @([pscustomobject]@{ id = 'p1'; name = 'RMM Guard - WDAC'; description = 'd' }) } }
                elseif ($Path -like '*/p1/settings') { WdacSettings $script:Supplemental }
                elseif ($Path -like '*/p1/assignments') { [pscustomobject]@{ value = @() } }
                elseif ($Path -like '*/p1?*') { [pscustomobject]@{ id = 'p1'; name = 'RMM Guard - WDAC'; description = 'd'; roleScopeTagIds = @('0'); templateReference = [pscustomobject]@{ templateId = $script:WdacTemplateId }; settingCount = 1 } }
            }
            { Sync-Wdac } | Should -Throw '*Refusing*'
            $script:Posts | Should -BeNullOrEmpty
        }
        It 'does not report a supplemental policy, a lower-case GUID is ours, and undecodable XML is not ours' {
            Mock Invoke-Graph {
                if ($Path -like '*templateFamily*') { [pscustomobject]@{ value = @([pscustomobject]@{ id = 's'; name = 'Supp' }, [pscustomobject]@{ id = 'j'; name = 'Junk' }, [pscustomobject]@{ id = 'l'; name = 'Lower' }) } }
                elseif ($Path -like '*/s/settings') { WdacSettings $script:Supplemental }
                elseif ($Path -like '*/j/settings') { WdacSettings 'not-base64!!' }
                elseif ($Path -like '*/l/settings') { WdacSettings ($script:PolicyXml -replace '01A11AD0-7091-7896-89DD-447C515BCB5D', '01a11ad0-7091-7896-89dd-447c515bcb5d') }
            }
            (Find-WdacByPolicyId).name | Should -Be 'Lower'
            $RingPolicyName = @('Lower')
            Find-WdacByPolicyId | Should -BeNullOrEmpty
        }
        It 'refuses -RingPolicyName naming this policy (M11)' {
            $RingPolicyName = @('rmm guard - wdac')
            { Sync-Wdac } | Should -Throw "*-RingPolicyName must name the other ring's policy, not this one.*"
        }
    }

    Context 'assignment before the guards (I2)' {
        BeforeEach {
            $ExcludeGroupId = 'bbbbbbbb-0000-0000-0000-000000000003'
            Mock Invoke-Graph {
                if ($Method -ne 'GET') { $script:Posts += [pscustomobject]@{ Call = "$Method $Path"; Body = $Body } }
                elseif ($Path -like '*name%20eq*') { [pscustomobject]@{ value = @([pscustomobject]@{ id = 'p1'; name = 'RMM Guard - WDAC'; description = 'd' }) } }
                elseif ($Path -like '*/p1/settings') { WdacSettings $script:Deployed }
                elseif ($Path -like '*/p1/assignments') { [pscustomobject]@{ value = @([pscustomobject]@{ target = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.allDevicesAssignmentTarget' } }) } }
                elseif ($Path -like '*/p1?*') { [pscustomobject]@{ id = 'p1'; name = 'RMM Guard - WDAC'; description = 'd'; roleScopeTagIds = @('0'); templateReference = [pscustomobject]@{ templateId = $script:WdacTemplateId }; settingCount = 1 } }
            }
        }
        It 'posts the exclusion even when the release is too young' {
            $MinimumReleaseAgeDays = 7
            $script:Changelog = @([pscustomobject]@{ version = $script:Version; date = (Get-Date).AddDays(-2).ToString('yyyy-MM-dd') })
            $script:Deployed = ([regex]'<Deny [^>]*/>').Replace((ConvertTo-NormalizedXml $script:PolicyXml), '', 1) -replace '<VersionEx>[^<]+</VersionEx>', '<VersionEx>1.0.0.1</VersionEx>'
            Sync-Wdac | Should -BeLike 'skipped*'
            $script:Posts.Call | Should -Be @('POST /deviceManagement/configurationPolicies/p1/assign')
            $script:Posts[0].Body.assignments.target.groupId | Should -Contain 'bbbbbbbb-0000-0000-0000-000000000003'
        }
        It 'reports unchanged with -ceq and still assigns' {
            $script:Deployed = $script:PolicyXml
            Sync-Wdac | Should -Be "unchanged v$script:Version"
            $script:Posts.Call | Should -Be @('POST /deviceManagement/configurationPolicies/p1/assign')
        }
        It 'treats a case-only XML difference as a change (M1)' {
            $script:Deployed = $script:PolicyXml.Replace('FilePath="*\ctes.exe"', 'FilePath="*\CTES.exe"')
            Confirm $false
            Sync-Wdac | Should -BeLike 'would be updated:*'
        }
    }

    Context 'macOS (M2, M3, M4)' {
        It 'rejects a case-shifted key' {
            $b = FreshMac; $b.Remove('name'); $b['Name'] = 'x'
            { Test-MacBody $b } | Should -Throw 'macOS:*'
        }
        It 'rejects a foreign setting under choiceSettingValue.children' {
            $b = FreshMac
            $b.settings[0].settingInstance.choiceSettingValue = @{ children = @(@{ settingDefinitionId = 'com.apple.security.firewall_enablefirewall' }) }
            { Test-MacBody $b } | Should -Throw '*unexpected setting*'
        }
        It 'rejects a foreign setting in a PSCustomObject tree' {
            $b = FreshMac
            $b.settings[0].settingInstance.extra = [pscustomobject]@{ list = @([pscustomobject]@{ settingDefinitionId = 'evil' }) }
            { Test-MacBody $b } | Should -Throw '*unexpected setting*'
        }
        It 'refuses a deployed policy with settings beyond the deny list' {
            $Assignment = 'AllDevices'
            $script:MacDescription = ($script:MacJson | ConvertFrom-Json).description
            Mock Invoke-Graph {
                if ($Method -ne 'GET') { $script:Posts += "$Method $Path" }
                elseif ($Path -like '*name%20eq*') { [pscustomobject]@{ value = @([pscustomobject]@{ id = 'm1'; name = 'Block RMM tools (macOS)'; description = $script:MacDescription }) } }
                elseif ($Path -like '*/m1/settings') { [pscustomobject]@{ value = @(@(($script:MacJson | ConvertFrom-Json).settings) + [pscustomobject]@{ settingInstance = [pscustomobject]@{ settingDefinitionId = 'com.apple.security.firewall_enablefirewall' } }) } }
                elseif ($Path -like '*/m1/assignments') { [pscustomobject]@{ value = @() } }
            }
            { Sync-Macos } | Should -Throw "macOS: 'Block RMM tools (macOS)' has settings beyond the RMM Guard deny list. Refusing to overwrite them."
            $script:Posts | Should -BeNullOrEmpty
        }
    }

    Context 'IOC (M5, M6)' {
        BeforeEach { $script:Present = @(ConvertFrom-IocCsv $script:IocText) }
        It 'ignores LOLRMM-titled indicators of other types' {
            Mock Invoke-Defender { [pscustomobject]@{ value = @($script:Present) + [pscustomobject]@{ id = '9'; indicatorType = 'FileSha256'; indicatorValue = 'ab'; title = 'LOLRMM - Hash' } } }
            Sync-Ioc | Should -Be "unchanged, $($script:Present.Count) indicators"
        }
        It 'stops when BatchDelete <Name>' -ForEach @(
            @{ Name = 'fails (404)'; Fail = $true; Reply = $null }
            @{ Name = 'reports failures in a body'; Fail = $false; Reply = [pscustomobject]@{ value = @([pscustomobject]@{ id = '9'; isFailed = $true }) } }
        ) {
            $script:Fail = $Fail; $script:Reply = $Reply
            Mock Invoke-Defender {
                if ($Method -eq 'GET') { [pscustomobject]@{ value = @($script:Present) + [pscustomobject]@{ id = '9'; indicatorType = 'DomainName'; indicatorValue = 'gone.example.org'; title = 'LOLRMM - Gone' } } }
                elseif ($script:Fail) { throw 'Response status code does not indicate success: 404 (Not Found).' }
                else { $script:Reply }
            }
            { Sync-Ioc } | Should -Throw 'IOC: 1 indicators could not be deleted*'
        }
    }

    Context 'Invoke-Sync (M10)' {
        It 'refuses one name for the WDAC and the macOS policy before signing in' {
            $Target = @('Wdac', 'Macos'); $WdacPolicyName = 'RMM Guard'; $MacosPolicyName = 'RMM Guard'
            Mock Resolve-Auth { throw 'signed in' }
            { Invoke-Sync } | Should -Throw '*two separate Intune policies*'
        }
        It 'defines no function a Graph module command or alias would shadow' {
            # Aliases win over functions: a Connect-Graph function was silently replaced by the module's alias for a bare
            # Connect-MgGraph, which signed in with whatever delegated account was cached instead of the app.
            $module = Get-Module -ListAvailable Microsoft.Graph.Authentication | Select-Object -First 1
            if (-not $module) { Set-ItResult -Skipped -Because 'Microsoft.Graph.Authentication is not installed'; return }
            $module = Import-Module $module -PassThru
            $ast = [System.Management.Automation.Language.Parser]::ParseFile("$PSScriptRoot/Sync-RMMGuard.ps1", [ref]$null, [ref]$null)
            $functions = $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true).Name
            @($functions | Where-Object { $module.ExportedAliases.ContainsKey($_) -or $module.ExportedCommands.ContainsKey($_) }) | Should -BeNullOrEmpty
        }
        It 'counts a repeated target once' {
            $Target = @('Wdac', 'Wdac')
            Mock Resolve-Auth { @{ Mode = 'Secret' } }
            Mock Get-Module { 'present' }
            Mock Import-Module {}
            Mock Connect-RMMGuardGraph {}
            Mock Write-Host {}
            Mock Sync-Wdac { throw 'WDAC: boom' }
            { Invoke-Sync } | Should -Throw '1 of 1 target(s) failed.'
            Should -Invoke Sync-Wdac -Times 1 -Exactly
        }
    }
}

Describe 'Second review' {
    BeforeAll {
        $script:X2 = ConvertTo-NormalizedXml $script:PolicyXml
        $script:Ctes2 = 'FilePath="*\ctes.exe"'
        $script:H2 = (Get-Content "$script:Root/IOC/Defender_IOC_LOLRMM_IPs.csv" -TotalCount 1)
        function DomainRow($Value) { "$script:H2`r`nDomainName,$Value,2035-07-23T00:00:00Z,Block,Medium,LOLRMM - Test,d,r,,,,true`r`n" }
        $root = $script:Root.Replace('\', '/')
        $script:MacJson = (node --input-type=module -e "import { parseMacProducts, buildIntunePolicy } from '$root/macos.js'; import { readFileSync } from 'node:fs'; const d = parseMacProducts(JSON.parse(readFileSync('$root/products.json', 'utf8'))); process.stdout.write(buildIntunePolicy(d.rules, d.version));" 2>$null) -join "`n"
        $script:IocText = Get-Content -Raw "$script:Root/IOC/Defender_IOC_LOLRMM_Domains_Part2.csv"
        $script:Version = (Get-WdacFacts $script:PolicyXml).Version
        function WdacSettings([string]$Xml) { [pscustomobject]@{ value = @((New-WdacBody 'n' 'd' $Xml).settings | ConvertTo-Json -Depth 32 | ConvertFrom-Json) } }
        function Confirm([bool]$Answer) { $script:Cmdlet = [pscustomobject]@{ Answer = $Answer } | Add-Member ScriptMethod ShouldProcess { $this.Answer } -PassThru }
        function Target($Type, $GroupId) { [pscustomobject]@{ target = [pscustomobject]@{ '@odata.type' = "#microsoft.graph.$Type"; groupId = $GroupId } } }
        $script:Pilot = 'aaaaaaaa-0000-0000-0000-000000000001'
    }
    BeforeEach {
        $WdacPolicyName = 'RMM Guard - WDAC'; $MacosPolicyName = 'Block RMM tools (macOS)'; $RingPolicyName = @(); $Exclude = @()
        $Assignment = $null; $ExcludeGroupId = $null; $MinimumReleaseAgeDays = 0
        $script:Changelog = @(); $script:Files = @{}; $script:Auth = @{ Mode = 'Secret' }; $script:Posts = @()
        Confirm $true
        Mock Get-RMMGuardFile { switch ($File) { 'wdac.xml' { $script:PolicyXml } 'macos.json' { $script:MacJson } 'iocs.csv' { $script:IocText } } }
    }

    Context 'WDAC canaries (C1)' {
        It 'rejects the path <Path> that hits a Windows or Microsoft binary' -ForEach @(
            @{ Path = '*\kernel32.dll' }, @{ Path = '*\csrss.exe' }, @{ Path = '*\WinSxS\*' }, @{ Path = '*\Microsoft.NET\*' },
            @{ Path = '*\WindowsApps\*' }, @{ Path = '*\Common Files\*' }, @{ Path = '*\rundll32.exe' }, @{ Path = '*\MpCmdRun.exe' }
        ) {
            { Test-WdacPolicy $script:X2.Replace($script:Ctes2, "FilePath=`"$Path`"") } | Should -Throw '*would block*'
        }
    }

    Context 'IOC first-party hosts (C2)' {
        It 'rejects <V>' -ForEach @(@{ V = 'r.manage.microsoft.com' }, @{ V = 'login.windows.net' }, @{ V = 'winatp-gw-cus.microsoft.com' }, @{ V = 'x.windowsupdate.com' }) {
            { ConvertFrom-IocCsv (DomainRow $V) } | Should -Throw 'IOC:*first-party*'
        }
        It 'accepts the first-party hosts the site blocks on purpose: <V>' -ForEach @(@{ V = 'support.services.microsoft.com' }, @{ V = 'agentreportingstore.blob.core.windows.net' }) {
            @(ConvertFrom-IocCsv (DomainRow $V)).Count | Should -Be 1
        }
    }

    Context 'release age only for additions (I1)' {
        BeforeEach {
            $MinimumReleaseAgeDays = 7
            $script:Changelog = @([pscustomobject]@{ version = $script:Version; date = (Get-Date).AddDays(-1).ToString('yyyy-MM-dd') })
            Confirm $false
        }
        Context 'WDAC' {
            BeforeEach {
                Mock Invoke-Graph {
                    if ($Path -like '*name%20eq*') { [pscustomobject]@{ value = @([pscustomobject]@{ id = 'p1'; name = 'RMM Guard - WDAC'; description = 'd' }) } }
                    elseif ($Path -like '*/p1/settings') { WdacSettings $script:Deployed }
                    elseif ($Path -like '*/p1?*') { [pscustomobject]@{ id = 'p1'; name = 'RMM Guard - WDAC'; description = 'd'; roleScopeTagIds = @('0'); templateReference = [pscustomobject]@{ templateId = $script:WdacTemplateId }; settingCount = 1 } }
                }
            }
            It 'applies a removal-only change at once, even on an older deployed version' {
                $extra = '<Deny ID="ID_DENY_ZZZ" FriendlyName="Old tool" FilePath="*\oldtool.exe" />'
                $script:Deployed = $script:X2.Replace('<FileRules>', "<FileRules>$extra").Replace('<FileRulesRef>', '<FileRulesRef><FileRuleRef RuleID="ID_DENY_ZZZ" />') -replace '<VersionEx>[^<]+</VersionEx>', '<VersionEx>1.0.0.1</VersionEx>'
                Sync-Wdac | Should -BeLike 'would be updated:*+0/-1 deny rules'
            }
            It 'holds an addition on the same version until the release is old enough' {
                $script:Deployed = ([regex]'<Deny [^>]*/>').Replace($script:X2, '', 1)
                Sync-Wdac | Should -BeLike 'skipped*'
            }
        }
        Context 'macOS' {
            BeforeEach {
                $script:DeployedDescription = ($script:MacJson | ConvertFrom-Json).description
                Mock Invoke-Graph {
                    if ($Path -like '*name%20eq*') { [pscustomobject]@{ value = @([pscustomobject]@{ id = 'm1'; name = 'Block RMM tools (macOS)'; description = $script:DeployedDescription }) } }
                    elseif ($Path -like '*/m1/settings') { [pscustomobject]@{ value = @($script:DeployedMac.settings) } }
                }
                # The deployed policy as Graph returns it, with its list of denied binaries changed by $Edit.
                function DeployedMac([scriptblock]$Edit) {
                    $body = $script:MacJson | ConvertFrom-Json
                    $list = $body.settings[0].settingInstance.groupSettingCollectionValue[0].children[0].groupSettingCollectionValue[0].children[0]
                    $list.groupSettingCollectionValue = @(& $Edit $list.groupSettingCollectionValue)
                    $body
                }
            }
            It 'applies a removal-only change at once, even on an older deployed version' {
                $script:DeployedMac = DeployedMac { param($items) $extra = $items[0] | ConvertTo-Json -Depth 16 | ConvertFrom-Json; $extra.children[0].simpleSettingValue.value = 'ZZZZZZZZZZ'; $items; $extra }
                $script:DeployedDescription = $script:DeployedDescription -replace 'v\d+\.\d+\.\d+\.\d+', 'v1.0.0.1'
                Sync-Macos | Should -BeLike 'would be updated:*+0/-1 entries'
            }
            It 'holds an addition on the same version until the release is old enough' {
                $script:DeployedMac = DeployedMac { param($items) $items | Select-Object -Skip 1 }
                Sync-Macos | Should -BeLike 'skipped*'
            }
        }
        Context 'IOC' {
            BeforeEach { $script:Present = @(ConvertFrom-IocCsv $script:IocText) }
            It 'deletes withdrawn indicators at once' {
                $extra = [pscustomobject]@{ id = '99'; indicatorType = 'DomainName'; indicatorValue = 'withdrawn.example'; title = 'LOLRMM - Old'; description = 'd'; severity = 'Medium'; action = 'Block' }
                Mock Invoke-Defender { [pscustomobject]@{ value = @($script:Present) + $extra } }
                Sync-Ioc | Should -Be "would be updated: 0 to import (0 new), 1 to delete, $($script:Present.Count) wanted"
            }
            It 'holds new indicators until the release is old enough' {
                Mock Invoke-Defender { [pscustomobject]@{ value = @($script:Present | Select-Object -Skip 1) } }
                Sync-Ioc | Should -BeLike 'skipped*'
            }
        }
    }

    Context 'rings never overlap (I2)' {
        BeforeEach {
            $script:RingTargets = @()
            $RingPolicyName = @('RMM Guard - WDAC (pilot)')
            Mock Invoke-Graph {
                if ($Method -ne 'GET') { $script:Posts += "$Method $Path" }
                elseif ($Path -like '*name%20eq*pilot*') { [pscustomobject]@{ value = @($script:RingTargets.Count -ge 0 -and $script:RingExists ? [pscustomobject]@{ id = 'r1'; name = 'RMM Guard - WDAC (pilot)'; description = 'd' } : $null) | Where-Object { $_ } } }
                elseif ($Path -like '*/r1/assignments') { [pscustomobject]@{ value = @($script:RingTargets) } }
                elseif ($Path -like '*name%20eq*') { [pscustomobject]@{ value = @([pscustomobject]@{ id = 'p1'; name = 'RMM Guard - WDAC'; description = 'd' }) } }
                elseif ($Path -like '*/p1/settings') { WdacSettings $script:PolicyXml }
                elseif ($Path -like '*/p1/assignments') { [pscustomobject]@{ value = @() } }
                elseif ($Path -like '*/p1?*') { [pscustomobject]@{ id = 'p1'; name = 'RMM Guard - WDAC'; description = 'd'; roleScopeTagIds = @('0'); templateReference = [pscustomobject]@{ templateId = $script:WdacTemplateId }; settingCount = 1 } }
            }
        }
        It 'assigns production to all devices when the pilot ring targets the excluded pilot group' {
            $script:RingExists = $true; $script:RingTargets = @(Target 'groupAssignmentTarget' $script:Pilot)
            $Assignment = 'AllDevices'; $ExcludeGroupId = $script:Pilot
            Sync-Wdac | Should -Be "unchanged v$script:Version"
            $script:Posts | Should -Be @('POST /deviceManagement/configurationPolicies/p1/assign')
        }
        It 'assigns the pilot when production excludes the pilot group' {
            $script:RingExists = $true; $script:RingTargets = @((Target 'allDevicesAssignmentTarget'), (Target 'exclusionGroupAssignmentTarget' $script:Pilot))
            $Assignment = $script:Pilot
            Sync-Wdac | Should -Be "unchanged v$script:Version"
        }
        It 'refuses the pilot when a hand-deployed policy covers all devices without excluding the pilot' {
            $script:RingExists = $true; $script:RingTargets = @(Target 'allDevicesAssignmentTarget')
            $Assignment = $script:Pilot
            { Sync-Wdac } | Should -Throw 'WDAC:*Refusing*'
            $script:Posts | Should -BeNullOrEmpty
        }
        It 'refuses production on all devices when the pilot group is not excluded' {
            $script:RingExists = $true; $script:RingTargets = @(Target 'groupAssignmentTarget' $script:Pilot)
            $Assignment = 'AllDevices'
            { Sync-Wdac } | Should -Throw 'WDAC:*Refusing*'
        }
        It 'assigns when the other ring does not exist yet' {
            $script:RingExists = $false
            $Assignment = $script:Pilot
            Sync-Wdac | Should -Be "unchanged v$script:Version"
            $script:Posts | Should -Be @('POST /deviceManagement/configurationPolicies/p1/assign')
        }
    }

    Context 'rule options changed by hand (S1)' {
        BeforeEach {
            $script:Deployed = $script:X2.Replace('<Rule><Option>Enabled:UMCI</Option></Rule>', '<Rule><Option>Enabled:UMCI</Option></Rule><Rule><Option>Enabled:Audit Mode</Option></Rule>')
            Mock Invoke-Graph {
                if ($Method -ne 'GET') { $script:Posts += "$Method $Path" }
                elseif ($Path -like '*name%20eq*') { [pscustomobject]@{ value = @([pscustomobject]@{ id = 'p1'; name = 'RMM Guard - WDAC'; description = 'd' }) } }
                elseif ($Path -like '*/p1/settings') { WdacSettings $script:Deployed }
                elseif ($Path -like '*/p1?*') { [pscustomobject]@{ id = 'p1'; name = 'RMM Guard - WDAC'; description = 'd'; roleScopeTagIds = @('0'); templateReference = [pscustomobject]@{ templateId = $script:WdacTemplateId }; settingCount = 1 } }
            }
        }
        It 'stops instead of switching an Audit Mode policy back to enforced' {
            { Sync-Wdac } | Should -Throw '*Audit Mode*Set them back in Intune*'
            $script:Posts | Should -BeNullOrEmpty
        }
    }

    Context 'IOC alert and expiry (S2)' {
        BeforeAll {
            function Ioc([hashtable]$Extra) {
                $i = [ordered]@{ indicatorType = 'DomainName'; indicatorValue = 'a.org'; title = 'LOLRMM - A'; description = 'd'; severity = 'Medium'; action = 'Block'; expirationTime = '2035-07-23T00:00:00Z'; generateAlert = $true }
                foreach ($k in $Extra.Keys) { $i[$k] = $Extra[$k] }
                [pscustomobject]$i
            }
        }
        It 'upserts when <Name> changed' -ForEach @(
            @{ Name = 'generateAlert'; Old = @{ id = '1'; generateAlert = $false } }
            @{ Name = 'expirationTime'; Old = @{ id = '1'; expirationTime = '2034-01-01T00:00:00Z' } }
        ) {
            @((Compare-IocSet @(Ioc @{}) @(Ioc $Old)).Upsert).Count | Should -Be 1
        }
        It 'treats Defender''s returned formats as equal: <Name>' -ForEach @(
            @{ Name = 'a parsed UTC date'; Old = @{ id = '1'; expirationTime = [datetime]::SpecifyKind([datetime]'2035-07-23', 'Utc') } }
            @{ Name = 'milliseconds'; Old = @{ id = '1'; expirationTime = '2035-07-23T00:00:00.000Z' } }
            @{ Name = 'an alert flag as text'; Old = @{ id = '1'; generateAlert = 'True' } }
            @{ Name = 'fields Defender left out'; Old = @{ id = '1'; expirationTime = $null; generateAlert = $null } }
        ) {
            @((Compare-IocSet @(Ioc @{}) @(Ioc $Old)).Upsert).Count | Should -Be 0
        }
    }

    Context 'AllUsers with an exclusion (S6)' {
        It 'refuses -Assignment AllUsers with -ExcludeGroupId' {
            $Assignment = 'AllUsers'; $ExcludeGroupId = $script:Pilot
            Mock Invoke-Graph {}
            { Sync-Wdac } | Should -Throw 'WDAC:*AllUsers*'
            Should -Invoke Invoke-Graph -Times 0 -Exactly
        }
    }

    Context 'module install (S4)' {
        It 'installs a pinned Microsoft.Graph.Authentication when none is present' {
            $Target = @('Wdac')
            Mock Resolve-Auth { @{ Mode = 'Secret' } }
            Mock Install-Module {}
            Mock Get-Module -ParameterFilter { $Name -eq 'Microsoft.Graph.Authentication' } {}
            Mock Import-Module {}
            Mock Connect-RMMGuardGraph {}
            Mock Write-Host {}
            Mock Sync-Wdac { 'unchanged' }
            Invoke-Sync
            Should -Invoke Install-Module -Times 1 -Exactly -ParameterFilter { $RequiredVersion -eq '2.39.0' }
        }
    }
}
