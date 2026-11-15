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
            @{ Name = 'a FileAttrib element'; Mutate = { $script:X.Replace('</FileRules>', '<FileAttrib ID="ID_FILEATTRIB_X" FileName="explorer.exe" /></FileRules>') } }
        ) {
            { Test-WdacPolicy (& $Mutate) } | Should -Throw '*structure*'
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
            $js = "import { filterPolicy } from '$script:Root/worker/index.js'; import { readFileSync } from 'node:fs'; process.stdout.write(filterPolicy(readFileSync('$script:Root/Blocking_RMMsv5.xml', 'utf8'), new Set($names)))"
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
