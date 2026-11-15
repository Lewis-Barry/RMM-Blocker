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
