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
#Requires -Version 7.4
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][ValidateSet('Wdac', 'Macos', 'Ioc')][string[]]$Target,
    [string]$WdacPolicyName,
    [string]$MacosPolicyName = 'Block RMM tools (macOS)',
    [string[]]$RingPolicyName = @(),
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
    'C:\Windows\System32\ntdll.dll'
    'C:\Windows\SysWOW64\ntdll.dll'
    'C:\Windows\System32\omadmclient.exe'
    'C:\Windows\System32\msiexec.exe'
    'C:\Windows\System32\conhost.exe'
    'C:\Program Files (x86)\Microsoft Intune Management Extension\AgentExecutor.exe'
    'C:\Program Files\Windows Defender Advanced Threat Protection\MsSense.exe'
)
# SHA-256 of the policy with VersionEx, Settings, every Deny and the Deny FileRuleRefs removed: allows, signers and scenarios are fixed.
$script:WdacShape = 'FE8E5A67C78533BA256D928244F99DD689592A150614C4CA9A9AF6763C862653'
# Hosts a domain indicator must never equal or be a parent of: sign-in, Graph, Intune, Windows Update and Defender itself.
$script:IocCanaries = @(
    'login.microsoftonline.com', 'graph.microsoft.com', 'enrollment.manage.microsoft.com', 'fef.msua06.manage.microsoft.com',
    'windowsupdate.com', 'update.microsoft.com', 'security.microsoft.com', 'api.security.microsoft.com', 'events.data.microsoft.com',
    'device.login.microsoftonline.com', 'enterpriseregistration.windows.net', 'aadcdn.msftauth.net', 'login.live.com', 'ctldl.windowsupdate.com',
    'crl.microsoft.com', 'oneocsp.microsoft.com', 'www.msftconnecttest.com', 'outlook.office365.com', 'www.office.com', 'portal.azure.com',
    'contoso.sharepoint.com', 'contoso.azurewebsites.net', 'contoso.blob.core.windows.net', 'naprodimedatapri.azureedge.net',
    'api.push.apple.com', 'mdmenrollment.apple.com', 'deviceenrollment.apple.com'
)
# IPv4 ranges an IP indicator must not fall in: non-public space, Entra ID sign-in and the Microsoft 365 front doors.
$script:IocIpCanaries = @('0.0.0.0/8', '10.0.0.0/8', '127.0.0.0/8', '169.254.0.0/16', '172.16.0.0/12', '192.168.0.0/16', '224.0.0.0/4', '240.0.0.0/4', '100.64.0.0/10',
    '20.20.32.0/19', '20.190.128.0/18', '20.231.128.0/19', '40.126.0.0/18', '13.107.0.0/16', '52.96.0.0/14', '40.96.0.0/13')
# Mirrors broadTeamIds in macos.js; Sync-RMMGuard.Tests.ps1 fails when the two differ.
$script:BroadTeamIds = @{ UBF8T346G9 = 'Microsoft'; EQHXZ8M8AV = 'Google'; JQ525L2MZD = 'Adobe'; '2BUA8C4S2C' = '1Password'; '68WVV388M8' = 'Cloudflare' }
$script:MacDescriptionPrefix = 'RMM Guard macOS deny list'
$script:Files = @{}

# ---- Pure functions: no network, no tenant. Covered by Sync-RMMGuard.Tests.ps1. ----

function ConvertTo-NormalizedXml([string]$Text) {
    ($Text -replace '^\uFEFF', '' -replace '>\s+<', '><').Trim()
}

function ConvertTo-WildcardRegex([string]$Pattern) {
    '(?i)^' + ([regex]::Escape($Pattern) -replace '\\\*', '.*' -replace '\\\?', '.') + '$'
}

# Version and deny rules of any policy XML, without judging it (deployed policies may predate the current guards).
function Get-WdacFacts([string]$Text) {
    try { $xml = [xml]($Text -replace '^\uFEFF', '') } catch { throw "WDAC: the content is not XML ($($_.Exception.Message))." }
    if ($xml.DocumentType) { throw 'WDAC: a DOCTYPE is not allowed.' }
    $policy = $xml.SiPolicy
    if (-not $policy) { throw 'WDAC: the root element is not SiPolicy.' }
    [pscustomobject]@{
        Policy  = $policy
        Version = [string]$policy.VersionEx
        Rules   = @($policy.FileRules.Deny | Where-Object { $_ } | ForEach-Object { "$($_.FriendlyName)|$($_.FilePath)" })
    }
}

# Hash of everything except the parts that legitimately change (version, settings, deny rules and their UMCI references).
function Get-WdacShape([xml]$Xml) {
    $doc = $Xml.Clone()
    $xpath = '/s:SiPolicy/s:VersionEx | /s:SiPolicy/s:Settings | /s:SiPolicy/s:FileRules/s:Deny | //s:SigningScenario[@Value="12"]/s:ProductSigners/s:FileRulesRef/s:FileRuleRef[starts-with(@RuleID, "ID_DENY_")]'
    foreach ($node in @((Select-Xml -Xml $doc -Namespace @{ s = 'urn:schemas-microsoft-com:sipolicy' } -XPath $xpath).Node)) { [void]$node.ParentNode.RemoveChild($node) }
    $canonical = ConvertTo-NormalizedXml $doc.DocumentElement.OuterXml
    [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($canonical)))
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
        foreach ($attribute in $deny.Attributes.Name) {
            if ($attribute -notin 'ID', 'FriendlyName', 'FilePath') { throw "WDAC: Deny rule $($deny.ID) uses $attribute; only FilePath rules are accepted." }
        }
        if (-not $deny.FilePath) { throw "WDAC: Deny rule $($deny.ID) has no FilePath." }
        if ($deny.FilePath.Contains('%')) { throw "WDAC: Deny rule $($deny.ID) uses a macro in FilePath; only FilePath rules without macros are accepted." }
        $regex = ConvertTo-WildcardRegex $deny.FilePath
        foreach ($canary in $script:WdacCanaries) {
            if ($canary -match $regex) { throw "WDAC: Deny rule '$($deny.FilePath)' ($($deny.FriendlyName)) would block $canary." }
        }
    }
    $doc = $facts.Policy.OwnerDocument
    $shape = Get-WdacShape $doc
    if ($shape -ne $script:WdacShape) { throw "WDAC: the policy structure outside the deny rules changed (shape $shape). Download the latest Sync-RMMGuard.ps1 before syncing." }
    $refs = @((Select-Xml -Xml $doc -Namespace @{ s = 'urn:schemas-microsoft-com:sipolicy' } -XPath ('//s:SigningScenario[@Value="12"]/s:ProductSigners/s:FileRulesRef/s:FileRuleRef[starts-with(@RuleID, "ID_DENY_")]')).Node.RuleID)
    if (Compare-Object -ReferenceObject @($denies.ID) -DifferenceObject $refs) { throw 'WDAC: the Deny rules and their UMCI references do not match one to one.' }
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

$script:IocHeader = 'IndicatorType,IndicatorValue,ExpirationTime,Action,Severity,Title,Description,RecommendedActions,RbacGroups,Category,MitreTechniques,GenerateAlert'

# Rows of the indicator CSV as Defender import objects. Throws on anything the site never publishes.
function ConvertFrom-IocCsv([string]$Text) {
    $text = $Text -replace '^\uFEFF', ''
    if (($text -split '\r?\n', 2)[0] -ne $script:IocHeader) { throw 'IOC: the content is not the RMM Guard indicator CSV.' }
    $seen = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($row in ($text | ConvertFrom-Csv)) {
        if (-not $seen.Add("$($row.IndicatorType):$($row.IndicatorValue)".ToLowerInvariant())) { throw "IOC: duplicate indicator '$($row.IndicatorValue)'." }
        if ($row.IndicatorType -notin 'DomainName', 'IpAddress' -or $row.Action -ne 'Block' -or
            -not "$($row.Title)".StartsWith('LOLRMM - ') -or -not $row.IndicatorValue) {
            throw "IOC: invalid row for '$($row.IndicatorValue)' ($($row.IndicatorType), $($row.Action), $($row.Title))."
        }
        $value = $row.IndicatorValue.ToLowerInvariant()
        if ($row.IndicatorType -ceq 'DomainName') {
            # A plain host name only: a trailing dot, space, wildcard or URL would slip past the canary comparison.
            if ($value -cnotmatch '^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]$') { throw "IOC: '$value' is not a plain host name." }
            foreach ($canary in $script:IocCanaries) {
                if ($canary -eq $value -or $canary.EndsWith(".$value")) { throw "IOC: indicator '$value' would block $canary." }
            }
        } else {
            $ip = $null
            if ($row.IndicatorType -cne 'IpAddress' -or -not [ipaddress]::TryParse($value, [ref]$ip) -or $ip.AddressFamily -ne 'InterNetwork' -or $ip.ToString() -ne $value) { throw "IOC: '$value' is not a plain IPv4 address." }
            foreach ($range in $script:IocIpCanaries) {
                if ([Net.IPNetwork]::Parse($range).Contains($ip)) { throw "IOC: indicator '$value' is inside $range." }
            }
        }
        $expires = [datetime]::MinValue
        if (-not [datetime]::TryParse($row.ExpirationTime, [cultureinfo]::InvariantCulture, 'AdjustToUniversal', [ref]$expires) -or $expires -lt [datetime]::UtcNow.AddDays(30) -or
            $row.Severity -cnotin 'Informational', 'Low', 'Medium', 'High' -or $row.GenerateAlert -notin 'true', 'false') {
            throw "IOC: '$value' has an invalid expiration, severity or alert flag ($($row.ExpirationTime), $($row.Severity), $($row.GenerateAlert))."
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

# The body is posted as is, so nothing but the deny list may be in it.
function Test-MacBody($Body) {
    $allowed = 'app_app', 'app_allowed', 'app_allowed_deniedbinaries', 'app_allowed_deniedbinaries_item_teamid', 'app_allowed_deniedbinaries_item_signingid'
    if ((@($Body.Keys) | Sort-Object) -join ',' -ne 'description,name,platforms,roleScopeTagIds,settings,technologies' -or
        $Body.platforms -cne 'macOS' -or $Body.technologies -cne 'appleRemoteManagement' -or @($Body.settings).Count -ne 1) { throw 'macOS: the policy body is not the RMM Guard deny list.' }
    $stack = [System.Collections.Generic.Stack[object]]::new(); $stack.Push($Body.settings[0].settingInstance); $lists = 0
    while ($stack.Count) {
        $node = $stack.Pop()
        if ($node.settingDefinitionId -cnotin $allowed) { throw "macOS: unexpected setting '$($node.settingDefinitionId)'." }
        if ($node.settingDefinitionId -ceq 'app_allowed_deniedbinaries') { $lists++ }
        foreach ($group in $node.groupSettingCollectionValue) { foreach ($child in $group.children) { $stack.Push($child) } }
    }
    if ($lists -ne 1) { throw "macOS: expected one denied-binaries list, found $lists." }
}

function Test-MacRules($Rules) {
    # An empty function result arrives as $null, and @($null).Count is 1, so drop nulls before counting.
    $Rules = @($Rules | Where-Object { $_ })
    if (-not $Rules.Count) { throw 'macOS: the policy denies nothing.' }
    foreach ($rule in $Rules) {
        if ("$($rule.TeamId)" -cnotmatch '^[A-Z0-9]{10}$') { throw "macOS: invalid Team ID '$($rule.TeamId)'." }
        if ($script:BroadTeamIds.ContainsKey($rule.TeamId) -and -not $rule.SigningId) {
            throw "macOS: Team ID $($rule.TeamId) belongs to $($script:BroadTeamIds[$rule.TeamId]) and needs a Signing ID."
        }
        # Company Portal, the Intune agent and Defender are Microsoft-signed; RMM Guard denies nothing of Microsoft's on macOS.
        if ($rule.TeamId -ceq 'UBF8T346G9') { throw 'macOS: a rule denies Microsoft-signed binaries (Company Portal, Intune agent, Defender).' }
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
# Invoke-RestMethod hands a JSON array over as one object; enumerate it so each release is its own entry.
function ConvertFrom-Changelog($Response) { @($Response | ForEach-Object { $_ }) }

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

# ---- I/O functions and Invoke-Sync follow (tasks 4-7). ----

function ConvertTo-Base64Url([byte[]]$Bytes) {
    [Convert]::ToBase64String($Bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

# RFC 7523 client assertion signed with the certificate's private key; Entra identifies the key by its SHA-1 thumbprint.
function New-ClientAssertion([System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate, [string]$Tenant, [string]$Client) {
    $now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    $header = @{ alg = 'RS256'; typ = 'JWT'; x5t = (ConvertTo-Base64Url $Certificate.GetCertHash()) } | ConvertTo-Json -Compress
    $payload = @{
        aud = "https://login.microsoftonline.com/$Tenant/oauth2/v2.0/token"; iss = $Client; sub = $Client
        jti = [guid]::NewGuid().ToString(); nbf = $now - 60; exp = $now + 540
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
    if ($CertificatePath -and $CertificateThumbprint) { throw 'Use either -CertificatePath or -CertificateThumbprint, not both.' }
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
                $auth.Certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new((Resolve-Path -LiteralPath $CertificatePath).Path, $password)
            } else {
                $thumbprint = $CertificateThumbprint -replace '[^0-9A-Fa-f]', ''
                $auth.Certificate = @('CurrentUser', 'LocalMachine') | ForEach-Object { Get-Item "Cert:\$_\My\$thumbprint" -ErrorAction SilentlyContinue } | Select-Object -First 1
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

function Invoke-Graph([string]$Method, [string]$Path, $Body) {
    $request = @{ Method = $Method; Uri = "$script:Graph$Path"; OutputType = 'PSObject' }
    if ($null -ne $Body) { $request.Body = $Body | ConvertTo-Json -Depth 32; $request.ContentType = 'application/json' }
    Invoke-MgGraphRequest @request
}

# Every item of a Graph list: Invoke-MgGraphRequest returns one page, so follow @odata.nextLink.
function Get-GraphAll([string]$Path) {
    while ($Path) {
        $page = Invoke-Graph GET $Path
        $page.value
        $Path = "$($page.'@odata.nextLink')".Replace($script:Graph, '')
    }
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
    $content
}

function Find-Policy([string]$Name) {
    $filter = [uri]::EscapeDataString("name eq '$($Name.Replace("'", "''"))'")
    # The filter has returned extra rows in testing, so the name is checked here as well.
    $found = @(Get-GraphAll "/deviceManagement/configurationPolicies?`$filter=$filter&`$select=id,name,description" | Where-Object name -ceq $Name)
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

# The RMM Guard WDAC policy under another name, ignoring the other ring's policy (-RingPolicyName), which shares the PolicyID on purpose.
function Find-WdacByPolicyId {
    $filter = [uri]::EscapeDataString("templateReference/templateFamily eq 'endpointSecurityApplicationControl'")
    foreach ($candidate in Get-GraphAll "/deviceManagement/configurationPolicies?`$filter=$filter&`$select=id,name" | Where-Object { $_.name -cnotin $RingPolicyName }) {
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
    $existing = @(Get-GraphAll "/deviceManagement/configurationPolicies/$PolicyId/assignments" | ForEach-Object { $_.target })
    $targets = Merge-AssignmentTargets $existing $wanted
    if ($null -eq $targets) { return }
    $labels = ($wanted | ForEach-Object { "$($_.'@odata.type' -replace '^#microsoft\.graph\.', '') $($_.groupId)".Trim() }) -join ', '
    if ($script:Cmdlet.ShouldProcess($PolicyId, "Add assignment $labels")) {
        Invoke-Graph POST "/deviceManagement/configurationPolicies/$PolicyId/assign" @{ assignments = @($targets | ForEach-Object { @{ target = $_ } }) } | Out-Null
    }
}

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
    if (-not $script:Cmdlet.ShouldProcess($WdacPolicyName, "Update $summary")) { return "would be updated: $summary" }
    Invoke-Graph PUT "/deviceManagement/configurationPolicies/$($policy.id)" (New-WdacBody $current.name $current.description $xml $current.roleScopeTagIds) | Out-Null
    Set-Assignment $policy.id
    "updated $summary"
}

function Sync-Macos {
    $body = Get-RMMGuardFile 'macos.json' 'json' | ConvertFrom-Json -AsHashtable
    Test-MacBody $body
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
    if (-not $script:Cmdlet.ShouldProcess($MacosPolicyName, "Update $summary")) { return "would be updated: $summary" }
    $current = Invoke-Graph GET "/deviceManagement/configurationPolicies/$($policy.id)?`$select=roleScopeTagIds"
    Invoke-Graph PUT "/deviceManagement/configurationPolicies/$($policy.id)" @{
        name = $policy.name; description = $body.description; platforms = $body.platforms; technologies = $body.technologies
        roleScopeTagIds = @($current.roleScopeTagIds); settings = $body.settings
    } | Out-Null
    Set-Assignment $policy.id
    "updated $summary"
}

function Sync-Ioc {
    if ($script:Auth.Mode -eq 'Interactive') {
        throw 'IOC: Defender indicators need an app identity (-CertificatePath, -CertificateThumbprint, -FederatedToken, -Identity or -ClientSecret); -Interactive cannot reach the Defender API.'
    }
    $desired = @(ConvertFrom-IocCsv (Get-RMMGuardFile 'iocs.csv' 'csv'))
    # With Ti.ReadWrite the app only sees the indicators it created; the title filter also covers Ti.ReadWrite.All.
    $visible = @((Invoke-Defender GET '/indicators?$top=10000').value)
    if ($visible.Count -ge 10000) { throw 'IOC: more than 10000 indicators are visible; paging is not supported.' }
    $deployed = @($visible | Where-Object { "$($_.title)".StartsWith('LOLRMM - ') })
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

function Invoke-Sync {
    $script:Auth = Resolve-Auth
    if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) { Install-Module Microsoft.Graph.Authentication -Scope CurrentUser -Force -WhatIf:$false }
    Import-Module Microsoft.Graph.Authentication
    # Both tokens up front: a federated token from a pipeline is short-lived.
    if ($Target -contains 'Ioc' -and $script:Auth.Mode -ne 'Interactive') { $script:DefenderToken = Get-AccessToken 'https://api.securitycenter.microsoft.com' }
    if ($Target -contains 'Wdac' -or $Target -contains 'Macos') { Connect-Graph }
    $script:Changelog = $MinimumReleaseAgeDays -gt 0 ? (ConvertFrom-Changelog (Invoke-RestMethod "$script:Site/changelog.json")) : @()
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
