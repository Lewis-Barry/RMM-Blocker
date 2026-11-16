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
    # An empty function result arrives as $null, and @($null).Count is 1, so drop nulls before counting.
    $Rules = @($Rules | Where-Object { $_ })
    if (-not $Rules.Count) { throw 'macOS: the policy denies nothing.' }
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
