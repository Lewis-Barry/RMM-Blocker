# RMM and Remote Access Tool Blocker

A dependency-free static GitHub Pages site preloaded with `Blocking_RMMsv5.xml`
(the version and rule counts are in the editor footer and `products.json`).
Search friendly tool names, filenames or folders, check the tools you use, and
download the customized WDAC XML. Checked means **excluded from this block list**.
Unselected rules remain in place.

The policy is designed for **Windows 11 24H2 and newer** end-user devices. Many rules use more than one
wildcard or a mid-path wildcard, which older Windows versions do not support.

https://lewis-barry.github.io/RMM-Blocker/

The **Browsers** tab (`browsers.html`) works the same way for
`Browsers/Blocking_Web_Browsers_-_Except_Edge.xml`, which blocks every browser except Microsoft Edge.
It has no IOC exports. That XML is edited by hand: each deny rule's `FriendlyName` is the browser
name the page groups it under.

## macOS app control (preview)

The RMM page covers two platforms, both on by default under **Platform**: Windows (the WDAC XML) and macOS.
Untick one to leave it out. The macOS half denies the same tools on macOS 27 through Apple's declarative
**App Settings** configuration (`com.apple.configuration.app.settings` → `Allowed.DeniedBinaries`), which Intune
exposes in the settings catalog under Declarative Device Management. It needs a supervised Mac (Automated Device
Enrollment) and has no audit mode. Rules match the vendor's code signature, not file paths:

- `teamId` (required) denies every binary the vendor signs. Use it alone when the vendor only ships remote tools.
- `teamId` plus `signingId` denies one binary. Required when the Team ID also signs unrelated software:
  the Microsoft, Google, Adobe, 1Password and Cloudflare Team IDs are refused without a `signingId` (Chrome Remote
  Desktop lists only its host binaries, Cloudflare Tunnel only `cloudflared`). Signing ID alone is not accepted, even
  though Apple allows it, because one line could deny `com.apple.Safari` on every Mac.

The macOS card shares the page's exclusions and offers two routes to the same Intune policy, both built in the
browser from the `macos` blocks in `products.json`:

- **Show rules for the portal**: one block per tool with its Team ID and Signing IDs, click to copy, for typing the
  entries into the settings catalog by hand.
- **Download Intune JSON**: a settings catalog policy body for `POST /beta/deviceManagement/configurationPolicies`
  (the portal cannot import settings catalog JSON, so the guide uses Graph Explorer). Definition ids: `app_app` →
  `app_allowed` → `app_allowed_deniedbinaries` → `..._item_teamid` / `..._item_signingid`.

Only tools whose signature was read from the vendor's real installer are listed. To add one:

```
codesign -dvvv "/Applications/Example.app" 2>&1 | grep -E "^(Identifier|TeamIdentifier)="
```

then add to the product in `products.json`, bump `version`, and run `node build.mjs`:

```json
"macos": {
  "rules": [{ "teamId": "H7UGFBUGV6" }],
  "cask": "teamviewer",
  "source": "https://download.teamviewer.com/download/TeamViewer.dmg",
  "verified": "2026-11-08"
}
```

`node build.mjs --check` runs the same validation as the page (`validateMacos` in `macos.js`): a rule without a
valid `teamId` makes macOS reject the whole policy, or worse, denies the wrong vendor. `help-macos.html` is the
deployment guide. The Defender IOC CSVs already work on macOS when network protection runs in block mode, so the
macOS half adds no IOC export of its own.

## Adding or updating products

`products.json` is the only file to edit. Each product lists any of `paths`
(WDAC wildcard file or folder rules), `domains`, `vendorDomains` (broad vendor-wide
domains) and `ips`. List a shared path or indicator under every product that owns it.
Bump `version` whenever the policy changes, then run (if you forget on a PR that changes paths,
`.github/workflows/version-bump.yml` bumps it and regenerates the XML after the merge):

```
node build.mjs
```

This regenerates `Blocking_RMMsv5.xml` and the CSVs in `IOC`. Commit all of them.
Do not edit the generated files by hand. CI runs `node build.mjs --check` and fails
if they are out of date. If the domains grow past 1,000, the build asks you to add the
next `Domains_PartN.csv` to `iocSources` in `ioc.js`.

## Monthly lolRMM sync

`.github/workflows/lolrmm-sync.yml` runs on the 1st of each month (and on demand from the
Actions tab). It reads `https://lolrmm.io/api/rmm_tools.json` and adds every Windows `.exe`
and network domain that no product lists yet, bumps the last part of `version`, regenerates
the XML and CSVs, runs the checks, and opens a `lolrmm-sync` pull request for review.
Nothing reaches `main` until you merge that pull request.

- `scripts/sync-lolrmm.mjs` does the work. Generic file names, Windows and everyday app binaries,
  and shared hosting platforms such as GitHub or Azure are never added.
- `scripts/lolrmm-ignore.json` lists tools that must never be added, each with its reason.
  Add a rejected tool there, or the next sync adds it again.
- Review each new tool against these rules:
  - **R1 Block** when the tool can open a remote session or desktop, run remote commands or scripts,
    move files to a device, or tunnel into one. Remote access, tunnelling and RMM products are in this group.
  - **R2 Don't block** when it only monitors, inventories, runs ITSM or ITAM, deploys or patches software,
    backs up data or protects endpoints, unless R1 also applies.
  - **R3 Never block accessibility software**, even if it has a remote-support feature.
  - **R4 Don't block on evidence-free entries**. If the lolRMM entry has no description of remote access
    and the name is a common product, leave it out until someone confirms it. Its domain may be the real product.
  - **Separate products.** When a tool's name suggests an existing product but the lolRMM entry does not show they are the same, keep it separate. Record that in `scripts/lolrmm-separate.json` so future syncs stop suggesting a merge.
  - **Decide in the PR** when the rules do not settle it, such as employee-monitoring or backup products
    with a remote feature. Merge only after a decision, and record it in the ignore file if you exclude it.
- **Removing a tool from an open PR.** Check out `lolrmm-sync`, run
  `node scripts/lolrmm-reject.mjs "<product name as shown in the PR>" "<reason>"`, then commit and push.
  It removes that product's additions from the release, adds the tool to the ignore list, and rebuilds
  the XML and CSVs. Rejections survive the monthly rebuild, because the job merges the branch's ignore list first.
  The script refuses to run on `main`, so it can't change a merged release.
- `changelog.json` records each release. `changelog.html` displays it.
- Run `node scripts/sync-lolrmm.mjs --dry-run` to preview a sync without writing files.
- Repository settings must allow Actions to create pull requests (Settings > Actions > General).

## Monthly macOS sync

The lolRMM sync workflow has a second job on a macOS runner, `scripts/sync-macos.mjs`, which does for Team IDs
what the first job does for Windows paths, on the same `lolrmm-sync` pull request:

1. **Re-verify.** Every product with a `cask` in its `macos` block is downloaded again through Homebrew (which
   checks the installer's sha256) and read with `codesign`. A Team ID that is no longer present fails the run: a
   hijacked installer or a vendor that changed its signing identity never reaches a rule silently.
2. **Join.** Every product without macOS rules is matched to a Homebrew cask whose homepage shares the registrable
   domain of the product's own indicators or of its lolRMM website, and whose name shares a word with the product.
   Exactly one cask is required; several, or other casks from the same vendor that share no name with the
   product, are listed in the PR as "not added" with the reason.
3. **Read.** The installer is downloaded, every Mach-O binary is read with `codesign`, and a rule is written only
   when all binaries carry one Team ID that is not in the broad-vendor list and not used by another product.
   Ad-hoc or unsigned binaries, mixed signers and failed downloads are listed, not added.
4. **Review.** The PR shows per tool the Team ID, the cask and version, the number of binaries, the installer URL
   and the Signing IDs of its apps and helpers. Check that those name the remote tool and not another product of
   the same vendor (ESET's only cask is its antivirus; Parallels' are Parallels Desktop). To reject a tool for macOS
   while keeping its Windows rules, add it to `scripts/macos-ignore.json` with the reason and delete its `macos`
   block; the next run skips it. `node scripts/sync-macos.mjs --dry-run` previews a run on any Mac with Homebrew.

Only products already in `products.json` are considered, so the Windows review (R1 to R4) decides which tools are
remote access at all; the macOS job only decides whether their Mac build can be identified with certainty.

## Builder workflow

1. **Set exceptions.** Check trusted tools in the single list to exclude them.
   The same selections feed both outputs. Execution rules remain reviewable;
   enabling IOC exports adds network indicators.
   Search and filters only change visibility.
2. **Review downloads.** Both outputs appear on the right, with retained/removed counts
   and a line-by-line exclusion list. XML is always available; CSVs are optional.
   Download each desired format separately, and import every CSV batch.
   WDAC blocks execution via filename/folder rules. Defender IOCs block known
   RMM domains/IPs. Neither export creates allow rules.

The UI follows the Fluent-style Settings Catalog Viewer: a compact header,
a larger introductory instruction instead of a repeated page title,
dense tool rows and a live download panel. There is no path selector. Dark is the default;
the header switches between dark and light for the current page session.
Blue highlights exclusions and export actions. Compact rows and download cards
keep the main actions visible at normal desktop zoom, with independently scrolling
panels for expanded content. Mobile stacks the panels without horizontal clipping;
short desktop windows allow page scrolling. Technical/deployment notes use progressive disclosure.
Visible copy is limited to instructions, counts, controls and actionable warnings;
disabled IOC exports have no redundant status message.
Nothing is uploaded; no framework or external dependencies were added.

Tool rows use list semantics and headings. Native checkboxes and disclosures
support keyboard input; controls have visible focus and larger targets on touch devices.
Execution rules and IOCs use compact value/type rows in shaded groups.
Checkbox descriptions include relevant
warnings; disclosure names identify their tool. Fonts scale with text size,
and Windows high-contrast mode uses native checkboxes.

## Deployment help

[Deploy WDAC](./help.html) covers Intune XML upload, pilot assignment and verification,
using the screenshots in `WDACScreens`. The exported policy is enforced, not audit-only.

[Import Defender IOCs](./help-ioc.html) covers protection requirements, CSV import
and verification, using `DefenderScreens`. CSVs default to all devices; set
`RbacGroups` to a pilot Defender device group before testing.

## GitHub Pages

1. Put these files in a GitHub repository, keeping the XML beside `index.html`
   and including the `IOC`, `WDACScreens` and `DefenderScreens` folders.
   Keep `help.html`, `help-ioc.html`, `theme.js`, `credits.js` and
   `LOLRMM-LICENSE.txt` alongside the editor.
2. In **Settings > Pages**, choose **Deploy from a branch**.
3. Select your branch and **/ (root)**, then save.

No build, server-side processing, CDN or credentials are required. Relative URLs
support both repository project sites and custom domains. `.nojekyll` enables
plain static hosting. The provided XML is kept unchanged.

## Optional Defender IOC export

The **Include IOC exports** checkbox defaults to **off**. Off means XML-only;
IOC CSVs are not loaded or prepared. Enable them in the output panel.

When enabled, the three supplied CSVs in `IOC` are combined locally into one
665-indicator dataset (653 domains and 12 IPs). The same trusted-tool selections
remove matching indicators; all remaining rows retain their original **Block**
action and metadata. This does not create Allow indicators or delete indicators
already imported into Defender.

- Download the XML separately, then download and import **every IOC CSV batch**.
  Batches are regenerated after filtering, with at most **500 data rows per
  file**, plus the original Defender header. No selections produces batches of
  500 and 165; excluding Datto RMM produces a single 544-indicator batch.
- Each tool shows its matching IOCs when the toggle is on. Search also matches
  their domains/IPs. Tools without IOCs are explicitly marked; XML exclusions
  still work normally.
- Mapping uses the CSV's tool attribution, including the full owners in
  descriptions marked `(+1 more)`. `build.mjs` writes the same product names
  into the XML and the CSVs, so it never guesses identity from a domain substring.
- Shared indicators are removed if **any** linked owner is excluded. A warning
  lists removed indicators that also affect unselected owners.
- IOC-only tools without an XML match remain blocked and are listed below the IOC card.
  The bundled unmatched identities are Any Support, baramundi Management Suite,
  GatherPlace, Remote Desktop Plus, RMMCRAT, SkyFex and ZeroTier.
- Turning the toggle off hides CSV downloads without changing XML selections.
  Reset restores both block lists. Neither selections nor the toggle persist
  after reload.
- A CSV load/validation failure visibly disables IOC downloads, not XML export.
  Turn the toggle off and on to retry. Sources are kept unchanged.
- The network discovery KQL is generated from all bundled IOC CSVs and includes
  every current domain and IP. When IOCs change, regenerate the CSVs and verify
  the generated KQL includes them.

Review domain-wide/shared indicators before importing. The export cannot
guarantee that a selected tool can connect under other network controls.

## Local preview and regression tests

Serve this directory with `python -m http.server 8080 --bind 127.0.0.1`, then open
`http://127.0.0.1:8080/`. Open `/tests.html` on that server to run the browser-native
XML and IOC regression suite, including CSV round-trips and the 500-row boundary.
The suite also exercises shared selections, generated XML/CSV downloads, theme switching,
final export summaries,
search/filter isolation, optional CSV exports, reset and compact layouts across
desktop, mobile and short-window viewport sizes.

`node run-tests.mjs [browser path]` runs the same suite in headless Chrome or Edge
with no installs; GitHub Actions runs it on every push and pull request.

## Policy behavior

- All tools start blocked. Selections last until reset or page reload.
- Export removes the selected tools' filename and folder `Deny` elements and
  **all** `FileRuleRef` elements referencing their IDs, in every signing scenario.
- Allow rules, policy IDs, version, settings and unrelated rules are preserved.
  With no selections, export returns the original source text. Modified XML may
  have normalized whitespace and self-closing tag formatting.
- Each `Deny` rule's `FriendlyName` holds its product names from `products.json`.
  Shared ConnectWise and SolarWinds folder rules belong to multiple products:
  selecting either removes the shared folder rule and displays an explicit
  warning. Other rules for the unselected product are retained.
- Search/filter visibility does not affect selections or export. Counts
  deduplicate shared rules.
- Nothing is uploaded. Downloaded XML is not an added allow policy, a signed or
  compiled WDAC policy, or a guarantee that a tool can execute. Validate and test
  the result with your normal WDAC deployment workflow before production use.

After changing `products.json`, rebuild and run the regression suite. Invalid XML,
duplicate IDs, unresolved references and rules without a product name produce
visible errors instead of a downloadable partial policy.

## Attribution

Much of the product, path and network indicator data in `products.json` comes from
[LOLRMM](https://github.com/magicsword-io/LOLRMM) (Living Off the Land RMM),
licensed under the Apache License 2.0. A copy is in `LOLRMM-LICENSE.txt` (LOLRMM
ships no NOTICE file). The footer's **Credits & licence** dialog (`credits.js`)
states the source, that the data was modified, and that this tool is independent
and provided as is.
