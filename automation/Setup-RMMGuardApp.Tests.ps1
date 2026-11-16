# Invoke-Pester ./automation : runs Setup-RMMGuardApp.ps1 against a mocked Graph, so nothing reaches a tenant.
Describe 'Setup-RMMGuardApp' {
    # Globals: the mocks run inside the setup script's own script scope, so $script: would point there.
    AfterAll { Remove-Variable RMMSetupCalls, RMMSetupApps, RMMSetupFailOn, RMMSetupRole, RMMSetupOut -Scope Global -ErrorAction SilentlyContinue }
    BeforeAll {
        $script:Setup = "$PSScriptRoot/Setup-RMMGuardApp.ps1"
        $global:RMMSetupRole = { param($Value) [pscustomobject]@{ value = @([pscustomobject]@{ id = "sp-$Value"; displayName = $Value; appRoles = @([pscustomobject]@{ id = "role-$Value"; value = $Value; allowedMemberTypes = @('Application') }) }) } }
    }
    BeforeEach {
        $global:RMMSetupCalls = [System.Collections.Generic.List[string]]::new()
        $global:RMMSetupApps = @()
        $global:RMMSetupFailOn = $null
        Mock Get-Module { 'present' }
        Mock Import-Module {}
        Mock Connect-MgGraph {}
        Mock Get-MgContext { [pscustomobject]@{ TenantId = 'tenant' } }
        Mock Write-Host {}
        Mock Write-Warning {}
        Mock Start-Sleep {}
        Mock Invoke-MgGraphRequest {
            $call = "$Method $($Uri -replace '^https://graph.microsoft.com/v1.0', '')"
            $global:RMMSetupCalls.Add($call)
            if ($global:RMMSetupFailOn -and $call -like $global:RMMSetupFailOn) { throw "boom on $call" }
            switch -Wildcard ($call) {
                'GET /applications?*' { [pscustomobject]@{ value = $global:RMMSetupApps } }
                "GET /servicePrincipals?*00000003-0000-0000-c000-000000000000*" { & $global:RMMSetupRole 'DeviceManagementConfiguration.ReadWrite.All' }
                'GET /servicePrincipals?*fc780465-2017-40d4-a0c5-307022471b92*' { & $global:RMMSetupRole 'Ti.ReadWrite' }
                'POST /applications' { [pscustomobject]@{ id = 'app1'; appId = 'appid1' } }
                'POST /servicePrincipals' { [pscustomobject]@{ id = 'sp1' } }
                default { $null }
            }
        }
    }

    It '-Remove without a matching app keeps the .pfx' {
        $pfx = Join-Path $TestDrive 'other-tenant.pfx'
        Set-Content -LiteralPath $pfx -Value 'key'
        & $script:Setup -TenantId contoso.onmicrosoft.com -Remove -CertificatePath $pfx
        Test-Path -LiteralPath $pfx | Should -BeTrue
        $global:RMMSetupCalls | Where-Object { $_ -like 'DELETE*' } | Should -BeNullOrEmpty
    }
    It '-Remove deletes and purges the tagged app, then its .pfx' {
        $global:RMMSetupApps = @([pscustomobject]@{ id = 'app0'; appId = 'appid0'; displayName = 'RMM Guard Sync'; tags = @('RMMGuardSync') })
        $pfx = Join-Path $TestDrive 'mine.pfx'
        Set-Content -LiteralPath $pfx -Value 'key'
        & $script:Setup -TenantId contoso.onmicrosoft.com -Remove -CertificatePath $pfx
        $global:RMMSetupCalls | Should -Contain 'DELETE /applications/app0'
        $global:RMMSetupCalls | Should -Contain 'DELETE /directory/deletedItems/app0'
        Test-Path -LiteralPath $pfx | Should -BeFalse
    }
    It '-Remove never deletes an app without the RMMGuardSync tag' {
        $global:RMMSetupApps = @([pscustomobject]@{ id = 'app0'; appId = 'appid0'; displayName = 'RMM Guard Sync'; tags = @() })
        & $script:Setup -TenantId contoso.onmicrosoft.com -Remove -CertificatePath (Join-Path $TestDrive 'none.pfx')
        $global:RMMSetupCalls | Where-Object { $_ -like 'DELETE*' } | Should -BeNullOrEmpty
    }
    It 'deletes the app again when a later step fails' {
        $global:RMMSetupFailOn = 'POST /servicePrincipals'
        { & $script:Setup -TenantId contoso.onmicrosoft.com -CredentialType None } | Should -Throw '*boom*'
        $global:RMMSetupCalls | Should -Contain 'DELETE /applications/app1'
        $global:RMMSetupCalls | Should -Contain 'DELETE /directory/deletedItems/app1'
    }
    It 'creates nothing when the app itself cannot be created' {
        $global:RMMSetupFailOn = 'POST /applications'
        { & $script:Setup -TenantId contoso.onmicrosoft.com -CredentialType None } | Should -Throw '*boom*'
        $global:RMMSetupCalls | Where-Object { $_ -like 'DELETE*' } | Should -BeNullOrEmpty
    }
    It 'prints a removal command that targets this app and its .pfx, quoted for PowerShell' {
        $global:RMMSetupOut = [System.Collections.Generic.List[string]]::new()
        Mock Write-Host { $global:RMMSetupOut.Add("$Object") }
        & $script:Setup -TenantId contoso.onmicrosoft.com -DisplayName "Roy's Sync" -CredentialType None
        $remove = @($global:RMMSetupOut | Where-Object { $_ -like '*Remove*:*' })
        $remove.Count | Should -Be 1
        $remove[0] | Should -BeLike "*-TenantId 'contoso.onmicrosoft.com' -DisplayName 'Roy''s Sync' -Remove"
    }
    It 'gives two names that only differ in punctuation their own default .pfx' {
        $global:RMMSetupOut = [System.Collections.Generic.List[string]]::new()
        Mock Test-Path { $true }
        Mock Remove-Item { $global:RMMSetupOut.Add($LiteralPath) }
        foreach ($name in 'Second Sync', 'Second-Sync') {
            $global:RMMSetupApps = @([pscustomobject]@{ id = 'app0'; appId = 'appid0'; displayName = $name; tags = @('RMMGuardSync') })
            & $script:Setup -TenantId contoso.onmicrosoft.com -DisplayName $name -Remove
        }
        $global:RMMSetupOut.Count | Should -Be 2
        $global:RMMSetupOut[0] | Should -Not -Be $global:RMMSetupOut[1]
    }
    It 'gives an app with another display name its own default .pfx' {
        # The default name must differ per app, so -Remove for one app can never take another app's key.
        $tenant = "pester-$([guid]::NewGuid().ToString('N').Substring(0, 8)).onmicrosoft.com"
        $default = Join-Path $HOME "RMMGuardSync-$tenant.pfx"
        Set-Content -LiteralPath $default -Value 'key of the default app'
        try {
            $global:RMMSetupApps = @([pscustomobject]@{ id = 'app0'; appId = 'appid0'; displayName = 'Second Sync'; tags = @('RMMGuardSync') })
            & $script:Setup -TenantId $tenant -DisplayName 'Second Sync' -Remove
            Test-Path -LiteralPath $default | Should -BeTrue
        } finally {
            Remove-Item -LiteralPath $default -ErrorAction SilentlyContinue
        }
    }
}
