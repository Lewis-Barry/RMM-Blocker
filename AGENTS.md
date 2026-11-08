# Agent instructions

- Don't run `run-tests.mjs` or `tests.html` for simple front-end changes like copy, markup or styles. Run them only when asked, or when logic changes in `app.js`, `policy.js`, `ioc.js`, `kql.js`, `build.mjs` or `products.json`.
- Whenever adding, changing, or removing IOCs, regenerate the Defender CSVs with `node build.mjs`, verify the generated network discovery KQL includes the updated indicators, and commit all affected outputs. The KQL is built from the bundled IOC CSVs in `kql.js`; update its generation or tests if needed to keep every current IOC represented.
- `macos.js` and `macos-app.js` build the macOS deny lists from the `macos` blocks in `products.json`. A rule must carry a `teamId` or `signingId`; `node build.mjs --check` enforces that. Only add a rule after reading the signature from the vendor's real installer with `codesign -dvvv`, and record the installer URL in `source`.
