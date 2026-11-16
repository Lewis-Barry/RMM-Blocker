// The PowerShell command shown in the retrieval-links modal. Interactive and -WhatIf, so a first paste only previews;
// Defender indicators need an app identity, so the interactive command covers WDAC and macOS.
const quote = name => `'${name.replaceAll("'", "''")}'`;

export function buildSyncCommand(excluded) {
  const names = [...excluded].sort(); // same order as the links in app.js
  return [
    "./Sync-RMMGuard.ps1 -Target Wdac,Macos",
    names.length ? `-Exclude ${names.map(quote).join(",")}` : "",
    "-Interactive -WhatIf",
  ].filter(Boolean).join(" ");
}
