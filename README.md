# RMM Block List Editor

A dependency-free static GitHub Pages site preloaded with `Blocking_RMMsv5.xml`
(policy version `1.0.0.8`, 838 deny rules).
Search friendly tool names, filenames or folders, check the tools you use, and
download the customized WDAC XML. Checked means **excluded from this block list**.
Unselected rules remain in place.

## GitHub Pages

1. Put these files in a GitHub repository, keeping the XML beside `index.html`.
2. In **Settings > Pages**, choose **Deploy from a branch**.
3. Select your branch and **/ (root)**, then save.

No build, server-side processing, CDN or credentials are required. Relative URLs
support both repository project sites and custom domains. `.nojekyll` enables
plain static hosting. The provided XML is kept unchanged.

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
