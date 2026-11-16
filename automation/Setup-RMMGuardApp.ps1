<#
.SYNOPSIS
    Creates or removes the app registration that Sync-RMMGuard.ps1 signs in with.

.DESCRIPTION
    Create (default): registers the app "RMM Guard Sync" in your tenant and grants it admin consent for
      - Microsoft Graph            DeviceManagementConfiguration.ReadWrite.All  (WDAC and macOS policies)
      - WindowsDefenderATP         Ti.ReadWrite                                 (Defender indicators it creates itself)
    and adds a credential that expires after -CredentialDays days:
      - Certificate (default): a self-signed certificate. Only its public key is uploaded to the app; the private key
        is saved as a password-protected .pfx at -CertificatePath, by default ~/RMMGuardSync-<TenantId>.pfx, or
        ~/RMMGuardSync-<DisplayName>-<TenantId>.pfx for another -DisplayName (readable by you only on macOS/Linux). Works in
        tenants whose app management policy blocks client secrets.
      - Secret: a client secret, shown once and never written to disk.
      - None: no credential, for OIDC (federated credential) or when you add one yourself.
    If any step after creating the app fails, the app is deleted again so nothing half-configured is left behind.

    -Remove: deletes every app registration this script created (display name AND the RMMGuardSync tag must match),
    including its service principal and permission grants, purges it from the deleted-items recycle bin, and then deletes
    the .pfx at -CertificatePath (only when an app was removed). Policies and indicators the app created are left in place.

    -FederatedSubject: also adds a federated credential (OIDC) for that subject, so GitHub Actions or Azure DevOps sign in
    without any secret or certificate. Combine with -CredentialType None.
    -ManagedIdentityObjectId: grants the same permissions to an existing managed identity (an Azure Automation account)
    instead of creating an app. With -Remove, takes those grants away again.

    You sign in interactively as an admin who can create apps and grant consent (Cloud Application Administrator
    plus Privileged Role Administrator, or Global Administrator).

.EXAMPLE
    ./Setup-RMMGuardApp.ps1 -TenantId contoso.onmicrosoft.com

.EXAMPLE
    ./Setup-RMMGuardApp.ps1 -TenantId contoso.onmicrosoft.com -Remove
#>
#Requires -Version 7.2
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$TenantId,
    [string]$DisplayName = 'RMM Guard Sync',
    [ValidateSet('Certificate', 'Secret', 'None')][string]$CredentialType = 'Certificate',
    [ValidateRange(1, 730)][int]$CredentialDays = 30,
    [string]$CertificatePath,                                         # default: ~/RMMGuardSync-<TenantId>.pfx, one file per tenant and app
    [string]$FederatedSubject,                                        # e.g. repo:contoso/rmm-guard:ref:refs/heads/main
    [string]$FederatedIssuer = 'https://token.actions.githubusercontent.com',
    [ValidatePattern('^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$')][string]$ManagedIdentityObjectId,
    [switch]$Remove
)

$ErrorActionPreference = 'Stop'
if (-not $CertificatePath) {
    # Another -DisplayName gets its own file, so removing one app never deletes the key of another.
    $name = $DisplayName -eq 'RMM Guard Sync' ? '' : "$DisplayName-"
    $CertificatePath = Join-Path $HOME ("RMMGuardSync-$name$TenantId.pfx" -replace '[^A-Za-z0-9.-]', '-')
}
$tag = 'RMMGuardSync'
$graphAppId = '00000003-0000-0000-c000-000000000000'
$defenderAppId = 'fc780465-2017-40d4-a0c5-307022471b92'   # WindowsDefenderATP
$wanted = @(
    @{ ResourceAppId = $graphAppId; Role = 'DeviceManagementConfiguration.ReadWrite.All'; Required = $true }
    @{ ResourceAppId = $defenderAppId; Role = 'Ti.ReadWrite'; Required = $false }
)

if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) {
    Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
}
Import-Module Microsoft.Graph.Authentication
Connect-MgGraph -TenantId $TenantId -Scopes Application.ReadWrite.All, AppRoleAssignment.ReadWrite.All -NoWelcome

$graph = 'https://graph.microsoft.com/v1.0'
function Invoke-Graph([string]$Method, [string]$Path, $Body) {
    $request = @{ Method = $Method; Uri = "$graph$Path"; OutputType = 'PSObject' }
    if ($null -ne $Body) { $request.Body = $Body | ConvertTo-Json -Depth 10; $request.ContentType = 'application/json' }
    Invoke-MgGraphRequest @request
}
# Directory writes replicate with a delay: a new service principal or a just-deleted app is not visible everywhere yet.
function Invoke-WithRetry([scriptblock]$Action) {
    for ($attempt = 1; ; $attempt++) {
        try { return & $Action } catch {
            if ($attempt -ge 6) { throw }
            Start-Sleep -Seconds (5 * $attempt)
        }
    }
}
function Remove-App($App) {
    Invoke-Graph DELETE "/applications/$($App.id)" | Out-Null
    Invoke-WithRetry { Invoke-Graph DELETE "/directory/deletedItems/$($App.id)" } | Out-Null
}

$quoted = $DisplayName.Replace("'", "''")
# The tag guard means -Remove can never delete an unrelated app that happens to share the display name.
$existing = @((Invoke-Graph GET "/applications?`$filter=displayName eq '$quoted'&`$select=id,appId,displayName,tags").value |
    Where-Object { $_.displayName -ceq $DisplayName -and $_.tags -contains $tag })



# Resolve each permission to its app role id on the resource's service principal instead of hard-coding GUIDs.
$grants = foreach ($permission in $wanted) {
    $resource = (Invoke-Graph GET "/servicePrincipals?`$filter=appId eq '$($permission.ResourceAppId)'&`$select=id,displayName,appRoles").value | Select-Object -First 1
    if (-not $resource) {
        if ($permission.Required) { throw "Service principal for $($permission.ResourceAppId) not found in this tenant." }
        Write-Warning "WindowsDefenderATP is not in this tenant (no Defender for Endpoint?). Skipping $($permission.Role); the Ioc target will not work."
        continue
    }
    $role = $resource.appRoles | Where-Object { $_.value -eq $permission.Role -and $_.allowedMemberTypes -contains 'Application' }
    if (-not $role) { throw "App role $($permission.Role) not found on $($resource.displayName)." }
    [pscustomobject]@{ ResourceAppId = $permission.ResourceAppId; ResourceId = $resource.id; ResourceName = $resource.displayName; RoleId = $role.id; Role = $permission.Role }
}

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

if ($Remove) {
    if (-not $existing) { Write-Host "No app registration '$DisplayName' tagged $tag found." }
    $removed = 0
    foreach ($app in $existing) {
        if ($PSCmdlet.ShouldProcess("$($app.displayName) (appId $($app.appId))", 'Delete app registration and purge it')) {
            Remove-App $app
            $removed++
            Write-Host "Removed and purged '$($app.displayName)' (appId $($app.appId))."
        }
    }
    # Only together with an app removed in this run: the .pfx of another tenant must never go because of a typo.
    if ($removed -and (Test-Path -LiteralPath $CertificatePath) -and $PSCmdlet.ShouldProcess($CertificatePath, 'Delete certificate file')) {
        Remove-Item -LiteralPath $CertificatePath
        Write-Host "Deleted $CertificatePath."
    }
    return
}

if ($existing) {
    throw "App registration '$DisplayName' (appId $($existing[0].appId)) already exists. Run with -Remove first, or pass another -DisplayName."
}
if ($CredentialType -eq 'Certificate' -and (Test-Path -LiteralPath $CertificatePath)) {
    throw "$CertificatePath already exists. Run with -Remove first, or pass another -CertificatePath."
}

if (-not $PSCmdlet.ShouldProcess($DisplayName, "Create app registration with $(($grants.Role) -join ', ') and credential type $CredentialType")) { return }

# Ask before creating anything, so a cancelled prompt leaves no app behind.
if ($CredentialType -eq 'Certificate') {
    $pfxPassword = Read-Host -AsSecureString "Password to protect $CertificatePath"
    if (-not $pfxPassword.Length) { throw 'A password is required to protect the private key.' }
}

$requiredResourceAccess = @($grants | Group-Object ResourceAppId | ForEach-Object {
    @{ resourceAppId = $_.Name; resourceAccess = @($_.Group | ForEach-Object { @{ id = $_.RoleId; type = 'Role' } }) }
})
$app = $null
$secret = $null
$certificate = $null
$finished = $false
# finally instead of catch: Ctrl+C during the retry waits must also roll back, and catch does not run on Ctrl+C.
try {
    $app = Invoke-Graph POST '/applications' @{
        displayName            = $DisplayName
        signInAudience         = 'AzureADMyOrg'
        tags                   = @($tag)
        notes                  = 'Created by Setup-RMMGuardApp.ps1 for Sync-RMMGuard.ps1 (rmmguard.com). Remove with Setup-RMMGuardApp.ps1 -Remove.'
        requiredResourceAccess = $requiredResourceAccess
    }
    $principal = Invoke-Graph POST '/servicePrincipals' @{ appId = $app.appId; tags = @($tag) }
    foreach ($grant in $grants) {
        Invoke-WithRetry {
            Invoke-Graph POST "/servicePrincipals/$($grant.ResourceId)/appRoleAssignedTo" @{
                principalId = $principal.id; resourceId = $grant.ResourceId; appRoleId = $grant.RoleId
            }
        } | Out-Null
        Write-Host "Granted $($grant.ResourceName) / $($grant.Role)."
    }

    $expires = [DateTimeOffset]::UtcNow.AddDays($CredentialDays)
    switch ($CredentialType) {
        'Certificate' {
            # .NET's CertificateRequest works the same on Windows, macOS and Linux, unlike New-SelfSignedCertificate.
            $rsa = [System.Security.Cryptography.RSA]::Create(2048)
            $request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
                "CN=$DisplayName", $rsa, [System.Security.Cryptography.HashAlgorithmName]::SHA256,
                [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
            $certificate = $request.CreateSelfSigned([DateTimeOffset]::UtcNow.AddMinutes(-5), $expires)
            Invoke-Graph PATCH "/applications/$($app.id)" @{
                keyCredentials = @(@{
                    type = 'AsymmetricX509Cert'; usage = 'Verify'; displayName = "CN=$DisplayName"
                    key  = [Convert]::ToBase64String($certificate.RawData)
                })
            } | Out-Null
            [System.IO.File]::WriteAllBytes($CertificatePath,
                $certificate.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx, $pfxPassword))
            if (-not $IsWindows) { [System.IO.File]::SetUnixFileMode($CertificatePath, [System.IO.UnixFileMode]'UserRead, UserWrite') }
        }
        'Secret' {
            $secret = Invoke-Graph POST "/applications/$($app.id)/addPassword" @{
                passwordCredential = @{ displayName = 'Sync-RMMGuard'; endDateTime = $expires.ToString('o') }
            }
        }
    }
    if ($FederatedSubject) {
        Invoke-Graph POST "/applications/$($app.id)/federatedIdentityCredentials" @{
            name      = ('rmmguard-' + ($FederatedSubject -replace '[^A-Za-z0-9-]', '-')).Substring(0, [math]::Min(120, 9 + $FederatedSubject.Length))
            issuer    = $FederatedIssuer
            subject   = $FederatedSubject
            audiences = @('api://AzureADTokenExchange')
        } | Out-Null
        Write-Host "Added federated credential for $FederatedSubject."
    }
    $finished = $true
} finally {
    if (-not $finished -and $app) {
        Write-Warning "Setup did not finish, deleting the half-created app '$DisplayName' again."
        Remove-App $app
        # The check above refused an existing file, so a .pfx here was written by this run.
        if ($CredentialType -eq 'Certificate' -and (Test-Path -LiteralPath $CertificatePath)) { Remove-Item -LiteralPath $CertificatePath }
    }
}

Write-Host ''
Write-Host "App registration '$DisplayName' is ready." -ForegroundColor Green
Write-Host "  TenantId    : $((Get-MgContext).TenantId)"
Write-Host "  ClientId    : $($app.appId)"
if ($certificate) {
    Write-Host "  Certificate : $CertificatePath (thumbprint $($certificate.Thumbprint))"
    Write-Host "  Expires     : $($certificate.NotAfter.ToUniversalTime().ToString('u'))"
}
if ($secret) {
    Write-Host "  Secret      : $($secret.secretText)" -ForegroundColor Yellow
    Write-Host "  Expires     : $($secret.endDateTime)"
    Write-Host '  Copy the secret now; it is not shown again and not saved anywhere.'
}
if ($CredentialType -eq 'None') { Write-Host '  Credential  : none. Add a federated credential (OIDC) or a certificate yourself.' }
# The removal command names this app and its key file, so copying it can never remove another sync app.
$quote = { "'" + ($args[0] -replace "'", "''") + "'" }
$removeCommand = "./Setup-RMMGuardApp.ps1 -TenantId $(& $quote $TenantId)"
if ($DisplayName -ne 'RMM Guard Sync') { $removeCommand += " -DisplayName $(& $quote $DisplayName)" }
$removeCommand += ' -Remove'
if ($certificate) { $removeCommand += " -CertificatePath $(& $quote $CertificatePath)" }
Write-Host "  Remove      : $removeCommand"
