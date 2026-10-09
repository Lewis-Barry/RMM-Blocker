# RMM Blocker

A dependency-free static GitHub Pages site preloaded with `Blocking_RMMsv5.xml`
(policy version `1.0.0.8`, 838 deny rules).
Search friendly tool names, filenames or folders, check the tools you use, and
download the customized WDAC XML. Checked means **excluded from this block list**.
Unselected rules remain in place.

## Builder workflow

1. **Set exceptions.** Check trusted tools in the single list to exclude them.
   The same selections feed both outputs. Execution rules remain reviewable;
   enabling IOC exports adds network indicators.
   Search and filters only change visibility.
2. **Review downloads.** Both outputs appear on the right, with retained/removed counts
   and a reviewable selection list. XML is always available; CSVs are optional.
   Download each desired format separately, and import every CSV batch.
   WDAC blocks execution via filename/folder rules. Defender IOCs block known
   RMM domains/IPs. Neither export creates allow rules.

The UI follows the Fluent-style Settings Catalog Viewer: a compact header,
dense tool rows and a live download panel. There is no path selector. Dark is the default;
the header switches between dark and light for the current page session.
Blue highlights exclusions and export actions. Spacing follows an 8px grid;
mobile stacks the panels. Technical/deployment notes use progressive disclosure.
Visible copy is limited to instructions, counts, controls and actionable warnings;
disabled IOC exports have no redundant status message.
Nothing is uploaded; no framework or external dependencies were added.

Tool rows use list semantics and headings. Native checkboxes and disclosures
support keyboard input; controls have larger targets and visible focus.
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
   Keep `help.html`, `help-ioc.html` and `theme.js` alongside the editor.
2. In **Settings > Pages**, choose **Deploy from a branch**.
3. Select your branch and **/ (root)**, then save.

No build, server-side processing, CDN or credentials are required. Relative URLs
support both repository project sites and custom domains. `.nojekyll` enables
plain static hosting. The provided XML is kept unchanged.

## Optional Defender IOC export

The **Include IOC exports** checkbox defaults to **off**. Off means XML-only;
IOC CSVs are not loaded or prepared. Enable them in the output panel.

When enabled, the three supplied CSVs in `IOC` are combined locally into one
585-indicator dataset (573 domains and 12 IPs). The same trusted-tool selections
remove matching indicators; all remaining rows retain their original **Block**
action and metadata. This does not create Allow indicators or delete indicators
already imported into Defender.

- Download the XML separately, then download and import **every IOC CSV batch**.
  Batches are regenerated after filtering, with at most **500 data rows per
  file**, plus the original Defender header. No selections produces batches of
  500 and 85; excluding Datto RMM produces a single 464-indicator batch.
- Each tool shows its matching IOCs when the toggle is on. Search also matches
  their domains/IPs. Tools without IOCs are explicitly marked; XML exclusions
  still work normally.
- Mapping uses the CSV's tool attribution, including the full owners in
  descriptions marked `(+1 more)`, and explicit product aliases. It never
  guesses tool identity from a domain substring.
- Shared indicators are removed if **any** linked owner is excluded. A warning
  lists removed indicators that also affect unselected owners.
- IOC-only tools without an XML match remain blocked and are listed for review.
  The bundled unmatched identities are Any Support, baramundi Management Suite,
  GatherPlace, Remote Desktop Plus, RMMCRAT, SkyFex and ZeroTier.
- Turning the toggle off hides CSV downloads without changing XML selections.
  Reset restores both block lists. Neither selections nor the toggle persist
  after reload.
- A CSV load/validation failure visibly disables IOC downloads, not XML export.
  Turn the toggle off and on to retry. Sources are kept unchanged.

Review domain-wide/shared indicators before importing. The export cannot
guarantee that a selected tool can connect under other network controls.

## Local preview and regression tests

Serve this directory with `python -m http.server 8080 --bind 127.0.0.1`, then open
`http://127.0.0.1:8080/`. Open `/tests.html` on that server to run the browser-native
XML and IOC regression suite, including CSV round-trips and the 500-row boundary.
The suite also exercises shared selections, generated XML/CSV downloads, theme switching,
final export summaries,
search/filter isolation, optional CSV exports and reset.

## Policy behavior

- All tools start blocked. Selections last until reset or page reload.
- Export removes the selected tools' filename and folder `Deny` elements and
  **all** `FileRuleRef` elements referencing their IDs, in every signing scenario.
- Allow rules, policy IDs, version, settings and unrelated rules are preserved.
  With no selections, export returns the original source text. Modified XML may
  have normalized whitespace and self-closing tag formatting.
- `catalog.js` maps known path and executable aliases to friendly tool names.
  Shared ConnectWise and SolarWinds folder rules belong to multiple products:
  selecting either removes the shared folder rule and displays an explicit
  warning. Other rules for the unselected product are retained.
- Unconfirmed identities appear as **Unclassified** entries showing their exact
  paths; they are not silently assigned to a product. Generic executable names
  also have an explicit generic group. Inspect matching rules before excluding.
- Search/filter visibility does not affect selections or export. Counts
  deduplicate shared rules.
- Nothing is uploaded. Downloaded XML is not an added allow policy, a signed or
  compiled WDAC policy, or a guarantee that a tool can execute. Validate and test
  the result with your normal WDAC deployment workflow before production use.

When replacing the bundled XML, review the mappings and run the regression suite.
New unmatched rules remain visible for manual inspection. Invalid XML, duplicate
IDs, unresolved references and ambiguous mappings produce visible errors instead
of a downloadable partial policy.
