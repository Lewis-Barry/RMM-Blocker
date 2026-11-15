# Automation sync for the retrieval links: design

Date: 2026-11-15 · Branch: `feature/automation-sync`

## Goal

Let an MSP keep the three RMM Guard outputs deployed and current without visiting the site: one PowerShell script that reads the custom retrieval links (`/api/wdac.xml`, `/api/macos.json`, `/api/iocs.csv`) and creates or updates the matching Intune policies and Defender indicators. It runs from a GitHub Action, an Azure DevOps pipeline, an Azure Automation runbook or locally. A new help page explains the setup, and the retrieval-links modal points to it.

## Threat model

The script runs unattended with a privileged app identity (Intune configuration write, Defender indicator write) and pushes content from rmmguard.com to enforced production policies. Whoever influences the site, the Worker, upstream or its sync scripts, by intent or by mistake, decides what every connected device blocks.

Precedent: `*\dd.exe` (added 2026-10-08) and `*\perl.exe`/`*\wperl.exe` (1.0.0.10, 2026-10-10) blocked legitimate tools for a month until 8266bf6 (2026-11-10). No automated check catches a judgment error like that; only a pilot ring of real users does. The guards below catch structural damage (OS or management binaries, Microsoft endpoints, malformed content); the pilot ring and release age catch judgment errors; neither protects against an attacker who controls the site, because `changelog.json` comes from the same origin.

## Deliverables

| Path | What |
|---|---|
| `automation/Setup-RMMGuardApp.ps1` | Done (15e5d50). Creates the "RMM Guard Sync" app with admin consent for both permissions and a certificate (default), secret or no credential; rolls back on failure; `-Remove` deletes and purges the app and the .pfx. Step 1 of the guide |
| `automation/Sync-RMMGuard.ps1` | The script (served at `rmmguard.com/automation/Sync-RMMGuard.ps1`) |
| `automation/Sync-RMMGuard.Tests.ps1` | Pester tests for the pure functions |
| `automation/github-workflow.yml` | GitHub Actions template: pilot job and production job |
| `automation/azure-pipelines.yml` | Azure DevOps template: pilot stage and production stage |
| `automation.js` | Exports `buildSyncCommand(excluded)` for the modal; importable by `tests.js` |
| `help-automation.html` | New guide page; added to the Guides nav of the other help pages, to the help-page list in `tool-pages.mjs` (which generates `sitemap.xml`) and to the `llms.txt` template in `build.mjs` |
| `index.html`, `app.js`, `styles.css` | Automation section in the retrieval-links modal |
| `tests.js` | Tests for `buildSyncCommand` |

Customers copy the script into their own repo or runbook once. Nothing downloads the script at run time, so a compromised site cannot swap the code that holds the credentials.

## Script interface

```powershell
./Sync-RMMGuard.ps1
  -Target Wdac,Macos,Ioc                      # one or more
  [-WdacPolicyName <name>]                    # required when Target has Wdac
  [-MacosPolicyName 'Block RMM tools (macOS)']# default = name the site's export uses
  [-Exclude 'AnyDesk','TeamViewer']           # tool names, as on the site
  [-Assignment AllDevices|AllUsers|<group object id>]
  [-ExcludeGroupId <group object id>]         # e.g. the pilot group on the production policy
  [-MinimumReleaseAgeDays 0]
  [-Force]                                    # bypass the change-size guard only
  [-WhatIf]
  # authentication, one of:
  -Interactive                                # WDAC and macOS only
  -Identity                                   # Azure Automation managed identity
  -TenantId -ClientId -ClientSecret           # or $env:RMMGUARD_CLIENT_SECRET
  -TenantId -ClientId -CertificateThumbprint  # cert in the Windows/runbook store
  -TenantId -ClientId -CertificatePath        # .pfx; password from -CertificatePassword or $env:RMMGUARD_CERT_PASSWORD
  -TenantId -ClientId -FederatedToken         # GitHub/ADO OIDC id token
```

Each run ends with one summary line per target: created, updated, unchanged, skipped (release age) or failed, with versions and counts.

Exit codes: `0` when every target is created, updated, unchanged or skipped for release age (skips print a warning). `1` when any target fails or is stopped by a guard, so the pipeline run goes red.

## Flow per target

1. Fetch `https://rmmguard.com/api/<file>` with one `exclude=` per `-Exclude` value (`[uri]::EscapeDataString`). Non-2xx aborts the target; the Worker's HTTP 400 message (renamed tool) is shown as is.
2. Parse and validate the content (see Guards). A Cloudflare challenge page or any body that does not parse as XML/JSON/CSV fails here.
3. Release-age check when `-MinimumReleaseAgeDays` > 0. Content version: WDAC `VersionEx`; macOS the `v<version>` in the policy description; IOC has no version of its own, so the script also fetches `/api/wdac.xml` and uses its `VersionEx` (all three are built from the same `products.json` release). Look the version up in `https://rmmguard.com/changelog.json`; younger than the minimum or not listed means skip with a warning. When the deployed version already equals the fetched version (an exclusion change only), the check does not apply.
4. Read current state, diff, apply (honouring `-WhatIf`).

### WDAC (Intune App Control for Business)

- Find `configurationPolicies` with `name eq '<WdacPolicyName>'` (single quotes doubled). More than one match: abort.
- Read policies with `GET /beta/deviceManagement/configurationPolicies/{id}?$expand=settings`.
- Not found: before creating, scan every App Control for Business policy for our PolicyID `{01A11AD0-7091-7896-89DD-447C515BCB5D}`. Found under another name: abort and name it, so the admin passes that name instead of the script creating a second policy with the same PolicyID. Otherwise create an App Control for Business policy (XML upload) with the fetched XML and assign it.
- Found: refuse unless its stored XML carries our PolicyID. Compare normalised XML (BOM and whitespace between tags stripped) with the fetched XML; equal means unchanged. Otherwise `PUT` the policy with a body built from the GET result (name, description, platforms, technologies, roleScopeTagIds, templateReference, all settings) where only the XML value is replaced.

### macOS (settings catalog, Apple DDM denied binaries)

- Same lookup and create path. The body comes from `/api/macos.json`, with `name` set to `-MacosPolicyName`.
- Found: refuse unless the description starts with `RMM Guard macOS deny list`. Compare the set of Team ID/Signing ID pairs. If they differ, `PUT` with the GET result's metadata, the new settings and the new description.

### Defender indicators

- Token for `https://api.securitycenter.microsoft.com` (see Authentication). `-Interactive` cannot reach this API; the script stops with a message telling the user to use an app identity.
- Read `GET https://api.security.microsoft.com/api/indicators?$top=10000` and keep entries whose title starts with `LOLRMM - `.
- Desired set from the CSV, keyed on `indicatorType:indicatorValue` (lower-case). CSV column to import field: `IndicatorType`→`indicatorType`, `IndicatorValue`→`indicatorValue`, `ExpirationTime`→`expirationTime`, `Action`→`action`, `Severity`→`severity`, `Title`→`title`, `Description`→`description`, `RecommendedActions`→`recommendedActions`, `GenerateAlert`→`generateAlert` (boolean). Empty `RbacGroups`, `Category` and `MitreTechniques` are omitted.
- Missing, or present with a different title, description, severity or action: `POST /api/indicators/import` in batches of 500 (upsert). Surplus: `POST /api/indicators/BatchDelete` with their ids.
- Recommended permission is `Ti.ReadWrite`, not `.All`: the app then sees and deletes only the indicators it created itself, so it can never remove a customer's own indicators. Indicators imported earlier by hand stay in place and the guide says so.
- No pilot ring: indicators apply tenant-wide, so a pilot run would push to every device. The pipeline templates sync IOCs in the production job only, with the release age.

### Assignment

`AllDevices` maps to `allDevicesAssignmentTarget`, `AllUsers` to `allLicensedUsersAssignmentTarget`, a GUID to `groupAssignmentTarget`. `-ExcludeGroupId` adds an `exclusionGroupAssignmentTarget`. Group names are not accepted: resolving them needs `Group.Read.All` on an already privileged app and is ambiguous when names repeat. The script reads the current assignments only through `GET …/{id}/assignments` (never `$expand`, see Live verification 4) and posts the union to `/assign`, because `/assign` replaces the full set. Assignments are never removed.

### Pilot ring

The pilot and production WDAC policies carry the same PolicyID, so a device must never receive both. The templates assign the pilot policy to the pilot group, and the production policy to `AllDevices` with `-ExcludeGroupId <pilot group>`. The guide states this rule. The same layout applies to macOS.

## Guards (script side, independent of the Worker)

| Target | Guard |
|---|---|
| WDAC | Root `SiPolicy`, PolicyType `Base Policy`, PolicyID and BasePolicyID equal ours, rule options exactly the four in the current XML, exactly two `Allow FileName="*"` rules, every `Deny` has a `FilePath` |
| WDAC | Canaries: every Deny `FilePath` is converted from WDAC wildcard to a regex and tested against concrete paths: `C:\Windows\explorer.exe`, `C:\Windows\System32\svchost.exe`, `lsass.exe`, `winlogon.exe`, `cmd.exe`, `WindowsPowerShell\v1.0\powershell.exe`, `C:\ProgramData\Microsoft\Windows Defender\Platform\<ver>\MsMpEng.exe`, `C:\Program Files (x86)\Microsoft Intune Management Extension\Microsoft.Management.Services.IntuneWindowsAgent.exe`. Any match aborts |
| IOC | Every row: type `DomainName` or `IpAddress`, action `Block`, title `LOLRMM - …` |
| IOC | Canaries are concrete hostnames: `login.microsoftonline.com`, `graph.microsoft.com`, `enrollment.manage.microsoft.com`, `fef.msua06.manage.microsoft.com`, `windowsupdate.com`, `update.microsoft.com`, `security.microsoft.com`, `api.security.microsoft.com`, `events.data.microsoft.com`. A DomainName indicator hits when it equals a canary or the canary ends with `.` + the indicator (an indicator `microsoft.com` hits; `x.windowsupdate.com` does not). Any hit aborts |
| macOS | Every rule has a 10-character Team ID; the Team IDs of Microsoft, Google, Adobe, 1Password and Cloudflare need a Signing ID (mirrors `broadTeamIds` in `macos.js`) |
| All | Change-size guard: if the deployed set is non-empty and more than 25 % of it would be removed, or the additions exceed 25 % of it, abort unless `-Force`. A first deployment (new policy, or zero `LOLRMM - ` indicators visible) is exempt |

## Authentication

- Graph: `Connect-MgGraph` (Microsoft.Graph.Authentication) with `-Identity`, `-ClientSecretCredential`, `-CertificateThumbprint`, `-Certificate` (loaded from `-CertificatePath`), or `-AccessToken` after exchanging the federated token.
- Client secrets are a fallback only: Entra's default app management policy can block password credentials entirely (seen in the test tenant: `CredentialTypeNotAllowedAsPerAppPolicy`). The guide and templates default to OIDC, then certificate.
- Defender: `Get-DefenderToken`, built into the script. It sends a client-credentials request to `login.microsoftonline.com/<tenant>/oauth2/v2.0/token` with scope `https://api.securitycenter.microsoft.com/.default`, using a client secret, a federated `client_assertion` or a certificate-signed JWT assertion. With `-Identity` it uses the Automation `IDENTITY_ENDPOINT` instead.
- Both tokens are acquired up front, so a short-lived OIDC id token is used only at the start.
- Permissions: Graph `DeviceManagementConfiguration.ReadWrite.All`; WindowsDefenderATP `Ti.ReadWrite`. The guide includes a PowerShell snippet to grant both to a managed identity.

## Pipelines

- GitHub: weekly `schedule` plus `workflow_dispatch`, with `permissions: id-token: write`. OIDC is the default (federated credential on the app registration); the secret variant is documented. The `pilot` job syncs Wdac and Macos to the pilot policies with age 0. The `production` job syncs Wdac, Macos and Ioc with age 7, the production policies exclude the pilot group.
- Azure DevOps: the same two stages on a weekly schedule. Authentication uses a workload identity federation service connection (id token via `AzureCLI@2` `addSpnToEnvironment`); the variable-group secret variant is documented.
- Azure Automation runbook: guide only (PowerShell 7.4 runtime, import Microsoft.Graph.Authentication, system-assigned managed identity, grant permissions, paste script, weekly schedule; one runbook per ring).

## Website

- `help-automation.html` uses the same layout as the other guides, with the Guides tab "Automation". Sections:
  - how it works
  - safeguards and the pilot ring
  - app registration and permissions
  - GitHub
  - Azure DevOps
  - Azure Automation
  - run locally
  - troubleshooting (HTTP 400, guard aborts, `-Force`, `-WhatIf`, release-age skips)
- Retrieval-links modal: under the links, an **Automation** heading with:
  - the command from `buildSyncCommand` (current exclusions as `-Exclude`, single quotes doubled)
  - a download link to the script
  - the line "Want to automate this fully? Read the automation guide"

## Testing

- Pester: XML normalise/compare, WDAC invariants and canaries (each with a known-bad positive control), IOC field mapping, diff and guards, macOS diff and broad Team ID guard, change-size guard including the empty-deployed exemption, assignment union, query-string building, release-age decision (listed, too young, missing, same version).
- `tests.js`: `buildSyncCommand` with zero, one and several exclusions, including a name with a quote.
- Live in a test tenant before delivery: create, update, unchanged, `-WhatIf` and the IOC sync end to end.

## Live verification (test tenant, 2026-11-15)

Confirmed with an unassigned test policy that was deleted afterwards:

1. **App Control template and storage.** Creation uses template `4321b946-b76b-4450-8afd-769c08b16ffc_1` ("App Control for Business"). It has one choice setting, `device_vendor_msft_policy_config_applicationcontrol_policies_{policyguid}_policiesoptions` (instance template `1de98212-6949-42dc-a89c-e0ff6e5da04b`, value template `b28c7dc4-c7b2-4ce2-8f51-6ebfd3ea69d3`), with the option `device_vendor_msft_policy_config_applicationcontrol_configure_xml_selected`. Its child is the string setting `device_vendor_msft_policy_config_applicationcontrol_policies_{policyguid}_xml` (instance template `4d709667-63d7-42f2-8e1b-b780f6c3c9c7`, value template `88f6f096-dedb-4cf1-ac2f-4b41e303adb5`). The XML posted as plain text comes back byte-identical. A second template in the same family exists (`d3849ba8-bf95-467c-9640-aa2334eae9e3_1`); the PolicyID scan covers every policy in the family.
2. **`PUT /configurationPolicies/{id}`** with name, description, platforms, technologies, roleScopeTagIds, templateReference and settings replaces the settings and keeps the assignments.
3. **`/assign` replaces the full assignment set.** After posting exclusion group A and then exclusion group B, only B remained.
4. **`$expand=assignments` is unreliable.** It returned an empty list while `GET …/{id}/assignments` returned the assignment. The script must read assignments only through `/assignments`; a union built from the `$expand` result would wipe the customer's assignments on the next `/assign`.
5. **The `name eq` filter** returned `@odata.count` 78 alongside the single match, so the script also checks the name client-side.

Still open (needs an app with WindowsDefenderATP `Ti.ReadWrite`; verified while building):

6. Importing an indicator value that already exists (created by a user) under `Ti.ReadWrite`.
7. Whether a domain indicator also blocks subdomains (decides whether the IOC canary rule is complete).
8. Whether the Intune portal's XML upload stores the XML as plain text too (adoption of portal-created policies). The script decodes base64 when the value does not start with `<`.

## Test setup for the build

Test tenant app "RMM Guard Sync" created with `Setup-RMMGuardApp.ps1` (certificate, expires 2026-12-15): Graph `DeviceManagementConfiguration.ReadWrite.All` and WindowsDefenderATP `Ti.ReadWrite`, both consented and verified. The .pfx lives outside the repo. Remove after testing with `Setup-RMMGuardApp.ps1 -Remove`.

## Out of scope

PowerShell Gallery module, removing assignments, deleting policies, group-name resolution, run-time download of the script, IOC pilot scoping via device groups.

## Upstream note

`changelog.json` lacks 1.0.0.14 and 1.0.0.16 to 1.0.0.18. With `-MinimumReleaseAgeDays`, a version that is not listed is skipped, so upstream should add an entry for every version bump.
