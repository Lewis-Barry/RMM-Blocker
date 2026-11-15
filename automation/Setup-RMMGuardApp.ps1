<#
.SYNOPSIS
    Creates or removes the app registration that Sync-RMMGuard.ps1 signs in with.

.DESCRIPTION
    Create (default): registers the app "RMM Guard Sync" in your tenant and grants it admin consent for
      - Microsoft Graph            DeviceManagementConfiguration.ReadWrite.All  (WDAC and macOS policies)
      - WindowsDefenderATP         Ti.ReadWrite                                 (Defender indicators it creates itself)
    and, unless -NoSecret, adds a client secret that expires after -SecretDays days. The secret is shown once and is
    never written to disk.

    -Remove: deletes every app registration this script created (display name AND the RMMGuardSync tag must match),
    including its service principal and permission grants, and purges it from the deleted-items recycle bin so the
    name and secret are gone for good. Policies and indicators the app created are left in place.

    You sign in interactively as an admin who can create apps and grant consent (Cloud Application Administrator
    plus Privileged Role Administrator, or Global Administrator).

.EXAMPLE
    ./Setup-RMMGuardApp.ps1 -TenantId contoso.onmicrosoft.com

.EXAMPLE
    ./Setup-RMMGuardApp.ps1 -TenantId contoso.onmicrosoft.com -Remove
#>
#Requires -Version 7.0
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$TenantId,
    [string]$DisplayName = 'RMM Guard Sync',
    [ValidateRange(1, 730)][int]$SecretDays = 30,
    [switch]$NoSecret,
    [switch]$Remove
)

$ErrorActionPreference = 'Stop'
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
$quoted = $DisplayName.Replace("'", "''")
# The tag guard means -Remove can never delete an unrelated app that happens to share the display name.
$existing = @((Invoke-Graph GET "/applications?`$filter=displayName eq '$quoted'&`$select=id,appId,displayName,tags").value |
    Where-Object { $_.displayName -ceq $DisplayName -and $_.tags -contains $tag })

if ($Remove) {
    if (-not $existing) { Write-Host "No app registration '$DisplayName' tagged $tag found. Nothing to remove."; return }
    foreach ($app in $existing) {
        if ($PSCmdlet.ShouldProcess("$($app.displayName) (appId $($app.appId))", 'Delete app registration and purge it')) {
            Invoke-Graph DELETE "/applications/$($app.id)" | Out-Null
            Invoke-WithRetry { Invoke-Graph DELETE "/directory/deletedItems/$($app.id)" } | Out-Null
            Write-Host "Removed and purged '$($app.displayName)' (appId $($app.appId))."
        }
    }
    return
}

if ($existing) {
    throw "App registration '$DisplayName' (appId $($existing[0].appId)) already exists. Run with -Remove first, or pass another -DisplayName."
}

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

if (-not $PSCmdlet.ShouldProcess($DisplayName, "Create app registration with $(($grants.Role) -join ', ')")) { return }

$requiredResourceAccess = @($grants | Group-Object ResourceAppId | ForEach-Object {
    @{ resourceAppId = $_.Name; resourceAccess = @($_.Group | ForEach-Object { @{ id = $_.RoleId; type = 'Role' } }) }
})
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

$secret = $null
if (-not $NoSecret) {
    $secret = Invoke-Graph POST "/applications/$($app.id)/addPassword" @{
        passwordCredential = @{ displayName = 'Sync-RMMGuard'; endDateTime = (Get-Date).ToUniversalTime().AddDays($SecretDays).ToString('o') }
    }
}

Write-Host ''
Write-Host "App registration '$DisplayName' is ready." -ForegroundColor Green
Write-Host "  TenantId : $((Get-MgContext).TenantId)"
Write-Host "  ClientId : $($app.appId)"
if ($secret) {
    Write-Host "  Secret   : $($secret.secretText)" -ForegroundColor Yellow
    Write-Host "  Expires  : $($secret.endDateTime)"
    Write-Host '  Copy the secret now; it is not shown again and not saved anywhere.'
}
Write-Host "  Remove   : ./Setup-RMMGuardApp.ps1 -TenantId $TenantId -Remove"
