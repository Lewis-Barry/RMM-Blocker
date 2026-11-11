# RMM and Remote Access Tool Blocker

## What the tool does

RMM Guard (https://rmmguard.com/) is a free builder that blocks unapproved RMM (remote monitoring and management) and remote access tools on Windows and macOS. Exclude the tools you trust, then export the policies. Nothing is uploaded.

**Why.** Blocking unwanted RMM and remote access tools is part of good endpoint security posture management (ESPM): only approved remote tools should run or connect. The Microsoft Digital Defense Report 2026 (page 69, "RMM tools as a post-compromise standard") says RMM abuse continues to grow and that "the appearance of an unsanctioned RMM agent has become one of the most reliable mid-stage indicators of a human-operated intrusion". RMM agents are typically introduced within minutes of a foothold and set to auto-launch on logon. Because RMM platforms ship with file transfer, scripting, screen sharing, unattended logon and session recording, one agent gives an attacker "the operational reach of a senior administrator".

**Features.**

- **Windows:** an App Control for Business (WDAC, formerly Windows Defender Application Control) deny policy that matches each tool's file name and path. Enforced, for Windows 11 24H2 and newer, deployed through Intune.
- **Network:** Defender indicator (IOC) CSVs of each tool's domains and IPs, for Windows and macOS devices.
- **macOS (preview):** an Intune deny list matched on the vendor's code signature (Team ID), for macOS 27 and newer on supervised Macs.
- **Browsers:** a second policy that blocks every web browser except Microsoft Edge.
- **Maintenance:** the tool list syncs monthly from [lolRMM](https://lolrmm.io), with every change reviewed in a pull request.

**Requirements.**

- **Microsoft Intune** to deploy the Windows and macOS policies.
- **Microsoft Defender for Endpoint** for the network indicators. Defender for Business is included in Business Premium.
- **Licences that include both:**
  - Microsoft 365 Business Premium
  - Microsoft Defender Suite for Business Premium (optional add-on to Business Premium that would allow KQL hunting)
  - Microsoft 365 E3
  - Microsoft 365 E5
  - Microsoft 365 E7
)

**Limits.** The Windows policy matches by file name and path, not hash or publisher signature, so renamed copies or tools run from unexpected folders can get past it. Pair it with the Defender indicators and treat it as one layer.

Targets Windows 11 24H2 and newer. Many rules use multiple or mid-path wildcards, which older Windows does not support.

https://lewis-barry.github.io/RMM-Blocker/

The **Browsers** tab (`browsers.html`) works the same way for `Browsers/Blocking_Web_Browsers_-_Except_Edge.xml`, which blocks every browser except Microsoft Edge. It has no IOC exports. The XML is edited by hand; each deny rule's `FriendlyName` is the browser name the page groups it under.

## Platforms

The RMM page has a **Platform** option: Windows (WDAC XML) and macOS, both on by default. Untick one to leave it out.

### Windows: App Control for Business using Intune (WDAC)

The WDAC XML blocks execution by filename and folder rules. Each tool's rules are removed from the policy when you check it. The policy targets Windows 11 24H2 and newer, is enforced rather than audit-only, and is uploaded to Intune as an App Control for Business policy ([Deploy WDAC](./help.html)). Defender IOCs add network blocking for known RMM domains and IPs, see [Optional Defender IOC export](#optional-defender-ioc-export).

### macOS app control (preview)

macOS 27 denies the same tools through the declarative App Settings configuration (`com.apple.configuration.app.settings`, `Allowed.DeniedBinaries`), exposed in the Intune settings catalog under Declarative Device Management. It needs a supervised Mac (Automated Device Enrollment) and has no audit mode. Rules match the vendor's code signature, not file paths:

- `teamId` (required) denies every binary the vendor signs.
- `teamId` plus `signingId` denies one binary. Required when the Team ID also signs unrelated software. Microsoft, Google, Adobe, 1Password and Cloudflare Team IDs are refused without a `signingId`. A Signing ID alone is not accepted, because one line could deny `com.apple.Safari` on every Mac.

The macOS card shares the page's exclusions and builds the Intune policy in the browser from the `macos` blocks in `products.json`:

- **Show rules for the portal**: one click-to-copy block per tool with its Team ID and Signing IDs, for manual entry in the settings catalog.
- **Download Intune JSON**: a settings catalog policy body for `POST /beta/deviceManagement/configurationPolicies`. The portal cannot import it, so the guide uses Graph Explorer. Definition ids: `app_app`, `app_allowed`, `app_allowed_deniedbinaries`, `..._item_teamid` and `..._item_signingid`.
- **Download PowerShell script**: the same body in a `.ps1` that installs the Graph PowerShell SDK if missing, signs in and posts it.

Add only tools whose signature was read from the vendor's real installer:

```
codesign -dvvv "/Applications/Example.app" 2>&1 | grep -E "^(Identifier|TeamIdentifier)="
```

Add the result to the product in `products.json`, bump `version`, run `node build.mjs`:

```json
"macos": {
  "rules": [{ "teamId": "H7UGFBUGV6" }],
  "cask": "teamviewer",
  "source": "https://download.teamviewer.com/download/TeamViewer.dmg",
  "verified": "2026-11-08"
}
```

`node build.mjs --check` runs the page's validation (`validateMacos` in `macos.js`). A rule without a valid `teamId` makes macOS reject the whole policy or deny the wrong vendor. `help-macos.html` is the deployment guide. The Defender IOC CSVs also apply on macOS when network protection is in block mode, so macOS has no IOC export.

## Adding or updating products

`products.json` is the only file to edit. Each product lists any of `paths` (WDAC wildcard file or folder rules), `domains`, `vendorDomains` (vendor-wide domains) and `ips`. List a shared path or indicator under every product that owns it. Bump `version` on every policy change, then run:

```
node build.mjs
```

This regenerates `Blocking_RMMsv5.xml`, the CSVs in `IOC` and `llms.txt`. Commit all outputs and never edit them by hand. CI runs `node build.mjs --check` and fails if they are stale. If a PR changes paths without a version bump, `.github/workflows/version-bump.yml` bumps it and regenerates the XML after merge. If domains pass 1,000, the build asks you to add the next `Domains_PartN.csv` to `iocSources` in `ioc.js`.

## Monthly lolRMM sync

`.github/workflows/lolrmm-sync.yml` runs on the 1st of each month and on demand. It reads `https://lolrmm.io/api/rmm_tools.json`, adds every Windows `.exe` and network domain no product lists yet, bumps the last part of `version`, regenerates the outputs, runs the checks and opens a `lolrmm-sync` pull request. Nothing reaches `main` until merged.

- `scripts/sync-lolrmm.mjs` does the work. It never adds generic file names, Windows or everyday app binaries, or shared hosting platforms such as GitHub or Azure.
- `scripts/lolrmm-ignore.json` lists tools never to add, each with a reason. Add rejected tools there or the next sync re-adds them.
- Review each new tool against these rules:
  - **R1 Block** if it can open a remote session or desktop, run remote commands or scripts, move files to a device, or tunnel into one. This covers remote access, tunnelling and RMM products.
  - **R2 Don't block** if it only monitors, inventories, runs ITSM or ITAM, deploys or patches software, backs up data or protects endpoints, unless R1 also applies.
  - **R3 Never block accessibility software**, even with a remote-support feature.
  - **R4 Don't block evidence-free entries.** If the lolRMM entry does not describe remote access and the name is a common product, leave it out until confirmed. Its domain may be the real product.
  - **Separate products.** If a name suggests an existing product but lolRMM does not show they are the same, keep them separate and record it in `scripts/lolrmm-separate.json`.
  - **Decide in the PR** when the rules don't settle it, such as employee-monitoring or backup products with a remote feature. Record exclusions in the ignore file.
- **Remove a tool from an open PR.** Check out `lolrmm-sync`, run `node scripts/lolrmm-reject.mjs "<product name as shown in the PR>" "<reason>"`, then commit and push. It removes the product's additions, adds it to the ignore list and rebuilds the outputs. Rejections survive the monthly rebuild because the job merges the branch's ignore list first. The script refuses to run on `main`.
- `changelog.json` records each release and `changelog.html` displays it.
- `node scripts/sync-lolrmm.mjs --dry-run` previews a sync without writing files.
- Actions must be allowed to create pull requests (Settings > Actions > General).

## Monthly macOS sync

A second job in the same workflow runs `scripts/sync-macos.mjs` on a macOS runner and adds Team IDs to the same `lolrmm-sync` PR:

1. **Re-verify.** Each product with a `cask` in its `macos` block is downloaded again through Homebrew, which checks the installer's sha256, and read with `codesign`. A missing Team ID fails the run, so a hijacked installer or changed signing identity never reaches a rule silently.
2. **Join.** Each product without macOS rules is matched to exactly one Homebrew cask whose homepage shares the registrable domain of the product's indicators or lolRMM website, and whose name shares a word with the product. Multiple matches, and same-vendor casks sharing no name with the product, are listed in the PR as "not added" with the reason.
3. **Read.** The installer is downloaded and every Mach-O binary is read with `codesign`. A rule is written only if all binaries carry one Team ID that is not in the broad-vendor list and not used by another product. Ad-hoc or unsigned binaries, mixed signers and failed downloads are listed, not added.
4. **Review.** The PR shows each tool's Team ID, cask and version, binary count, installer URL and the Signing IDs of its apps and helpers. Check that they name the remote tool and not another product from the same vendor (ESET's only cask is its antivirus, Parallels' are Parallels Desktop). To reject a tool for macOS but keep its Windows rules, add it to `scripts/macos-ignore.json` with a reason and delete its `macos` block. `node scripts/sync-macos.mjs --dry-run` previews a run on any Mac with Homebrew.

Only products already in `products.json` are considered. The Windows review (R1 to R4) decides what counts as remote access; the macOS job only decides whether the Mac build can be identified with certainty.

## Builder workflow

1. **Set exceptions.** Check trusted tools in the single list. The same selections feed both outputs. Search and filters only change visibility.
2. **Review downloads.** Both outputs show retained and removed counts and a line-by-line exclusion list. XML is always available, CSVs are optional. Download each format separately and import every CSV batch.

WDAC blocks execution by filename and folder rules. Defender IOCs block known RMM domains and IPs. Neither export creates allow rules. Nothing is uploaded and no framework or external dependency is used.

UI: dark by default with a header toggle for the page session, dense tool rows, a live download panel, independently scrolling panels, stacked panels on mobile, and progressive disclosure for technical notes. Rows use list semantics and headings, checkboxes and disclosures are native and keyboard accessible, focus is visible, fonts scale with text size, and Windows high-contrast mode uses native checkboxes.

## Deployment help

- [Deploy WDAC](./help.html): Intune XML upload, pilot assignment and verification, with screenshots in `WDACScreens`. The exported policy is enforced, not audit-only.
- [Import Defender IOCs](./help-ioc.html): protection requirements, CSV import and verification, with screenshots in `DefenderScreens`. CSVs default to all devices. Set `RbacGroups` to a pilot Defender device group before testing.

## GitHub Pages

1. Put the files in a GitHub repository with the XML beside `index.html` and the `IOC`, `WDACScreens` and `DefenderScreens` folders. Keep `help.html`, `help-ioc.html`, `theme.js`, `credits.js` and `LOLRMM-LICENSE.txt` beside the editor.
2. In **Settings > Pages**, choose **Deploy from a branch**.
3. Select your branch and **/ (root)**, then save.

No server-side processing, CDN or credentials are needed. Relative URLs work for project sites and custom domains. `.nojekyll` enables plain static hosting.

## Optional Defender IOC export

**Include IOC exports** is off by default, which means XML only and no CSVs are loaded. When on, the three CSVs in `IOC` are combined locally into one 665-indicator dataset (653 domains, 12 IPs). Tool selections remove matching indicators. Remaining rows keep their original **Block** action and metadata. No Allow indicators are created and indicators already in Defender are not deleted.

- Batches are regenerated after filtering, at most **500 data rows per file**, each with the original Defender header. No selections gives batches of 500 and 165. Excluding Datto RMM gives one 544-indicator batch.
- Each tool lists its matching IOCs, and search matches their domains and IPs. Tools without IOCs are marked. XML exclusions work regardless.
- Mapping uses the CSV's tool attribution, including all owners in descriptions marked `(+1 more)`. `build.mjs` writes the same product names into the XML and CSVs and never infers identity from a domain substring.
- A shared indicator is removed if any linked owner is excluded. A warning lists removed indicators that also affect unselected owners.
- IOC-only tools with no XML match stay blocked and are listed below the IOC card: Any Support, baramundi Management Suite, GatherPlace, Remote Desktop Plus, RMMCRAT, SkyFex and ZeroTier.
- Turning the toggle off hides CSV downloads and keeps XML selections. Reset restores both block lists. Selections and the toggle do not persist after reload.
- A CSV load or validation failure disables IOC downloads, not XML export. Toggle off and on to retry.
- The network discovery KQL is generated from all bundled IOC CSVs and includes every domain and IP. After IOC changes, regenerate the CSVs and check the KQL.

Review domain-wide and shared indicators before importing. The export cannot guarantee a selected tool is unable to connect under other network controls.

## Local preview and tests

Serve the directory with `python -m http.server 8080 --bind 127.0.0.1` and open `http://127.0.0.1:8080/`. Open `/tests.html` there for the browser XML and IOC regression suite. It covers CSV round-trips, the 500-row boundary, shared selections, generated downloads, theme switching, export summaries, search and filter isolation, optional CSV exports, reset, and desktop, mobile and short-window layouts.

`node run-tests.mjs [browser path]` runs the suite in headless Chrome or Edge with no installs. GitHub Actions runs it on every push and pull request. `node --test scripts/` runs the script tests.

## Policy behavior

- All tools start blocked. Selections last until reset or reload.
- Export removes the selected tools' filename and folder `Deny` elements and all `FileRuleRef` elements referencing their IDs, in every signing scenario.
- Allow rules, policy IDs, version, settings and unrelated rules are kept. With no selections, export returns the original source text. Modified XML may have normalized whitespace and self-closing tags.
- Each `Deny` rule's `FriendlyName` holds its product names from `products.json`. Shared ConnectWise and SolarWinds folder rules belong to multiple products. Selecting either removes the shared rule and shows a warning. Other rules for the unselected product stay.
- Search and filter visibility does not affect selections or export. Counts deduplicate shared rules.
- The XML is not an allow policy, not signed or compiled, and not a guarantee that a tool can run. Test it with your normal WDAC workflow before production.

After changing `products.json`, rebuild and run the regression suite. Invalid XML, duplicate IDs, unresolved references and rules without a product name produce visible errors instead of a partial policy.

## Attribution

Much of the product, path and network indicator data in `products.json` comes from [LOLRMM](https://github.com/magicsword-io/LOLRMM), licensed under Apache 2.0. A copy is in `LOLRMM-LICENSE.txt` (LOLRMM ships no NOTICE file). The footer's **Credits & licence** dialog (`credits.js`) states the source, that the data was modified, and that this tool is independent and provided as is.
