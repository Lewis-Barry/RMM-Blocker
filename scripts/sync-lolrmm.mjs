// Adds Windows executables and domains from the lolRMM API that products.json does not list yet,
// bumps the policy version and records the change in changelog.json: node scripts/sync-lolrmm.mjs [--dry-run]
// Prints a Markdown summary for the pull request. Run node build.mjs afterwards to regenerate the XML and CSVs.
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

const root = join(import.meta.dirname, "..");
const API = "https://lolrmm.io/api/rmm_tools.json";

// Platforms that host other people's software. Blocking these would break legitimate downloads.
const SHARED = [
  "github.com", "githubusercontent.com", "github.io", "ghcr.io", "gitlab.com", "bitbucket.org", "sourceforge.net",
  "amazonaws.com", "cloudfront.net", "azurewebsites.net", "azureedge.net", "windows.net", "blob.core.windows.net",
  "googleapis.com", "google.com", "firebaseapp.com", "microsoft.com", "live.com", "office.com", "sharepoint.com",
  "pages.dev", "workers.dev", "herokuapp.com", "netlify.app", "vercel.app", "ngrok.io", "ngrok-free.app",
  "trycloudflare.com", "cloudflare.com", "dropbox.com", "dropboxusercontent.com", "jsdelivr.net", "unpkg.com",
  "akamaized.net", "akamaihd.net", "apple.com", "mozilla.org", "discord.com", "discordapp.com", "telegram.org",
  "visualstudio.com", "zoom.us", "slack.com",
];
// Generic file names would block common software, so they are skipped.
const GENERIC = new Set([
  "agent", "client", "helper", "host", "install", "installer", "launcher", "main", "manager", "monitor", "run",
  "server", "service", "setup", "start", "svc", "tray", "uninstall", "update", "updater", "viewer",
]);
// shortcut: hand-picked Windows and everyday app binaries that some tool entries reuse, extend when review finds more
const SYSTEM = new Set([
  "tar", "curl", "ssh", "scp", "explorer", "svchost", "cmd", "powershell", "pwsh", "rundll32", "msiexec", "conhost",
  "dllhost", "taskmgr", "notepad", "notepad++", "regedit", "wscript", "cscript", "teams", "zoom", "slack", "chrome", "msedge", "firefox",
]);

const lower = value => value.toLowerCase();
const normalize = name => lower(name).replace(/[^a-z0-9]/g, "");
// Matches WDAC wildcards (*) against stored paths, case-insensitively.
const globToRegExp = pattern => new RegExp(`^${pattern.split("*").map(part => part.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join(".*")}$`, "i");
const bumpVersion = version => version.replace(/(\d+)$/, number => String(Number(number) + 1));
// Words that describe a product type rather than a vendor, so they never link two products.
const GENERIC_WORDS = new Set(["access", "agent", "client", "connect", "console", "control", "core", "cloud", "deploy", "desktop",
  "insight", "installer", "management", "manager", "monitoring", "remote", "server", "service", "services", "software", "support",
  "suite", "system", "tools", "update"]);
const tokens = text => text.toLowerCase().split(/[^a-z0-9]+/).filter(token => token.length >= 4);
const words = text => tokens(text).filter(word => !GENERIC_WORDS.has(word));
// The registrable label of a domain, e.g. n-able from remote.n-able.com, normalized to match product names.
const rootLabel = domain => { const labels = lower(domain).replace(/^\*\./, "").split("."); return normalize(labels[labels.length - 2] || labels[0]); };

// The Windows executables and network domains one lolRMM tool contributes, ignoring anything in the ignore set.
export function candidates(tool, ignore) {
  const paths = new Set();
  const domains = new Set();
  if (ignore.has(lower(tool.Name))) return { paths, domains };
  for (const disk of tool.Artifacts?.Disk || []) {
    if (!/^Windows$/i.test(disk.OS) || typeof disk.File !== "string") continue;
    const name = disk.File.split(/[\\/]/).pop();
    const stem = lower(name.replace(/\.exe$/i, ""));
    if (!/^[^*?<>]+\.exe$/i.test(name) || stem.length < 3 || GENERIC.has(stem) || SYSTEM.has(stem) || ignore.has(lower(name))) continue;
    paths.add(`*\\${name}`);
  }
  for (const network of tool.Artifacts?.Network || []) {
    for (const entry of network.Domains || []) {
      const domain = lower(entry.trim()).replace(/^www\./, "");
      if (!/^([a-z0-9-]+\.)+[a-z]{2,}$/.test(domain) || ignore.has(domain)) continue;
      if (SHARED.some(host => domain === host || domain.endsWith(`.${host}`))) continue;
      domains.add(domain);
    }
  }
  return { paths, domains };
}

// Adds what no product covers yet. Returns the updated products (sorted like products.json) and the changes made.
export function sync(data, tools, ignore) {
  const products = { ...data.products };
  const stored = Object.values(products);
  const patterns = stored.flatMap(product => product.paths || []).map(globToRegExp);
  const domains = new Set(stored.flatMap(product => [...(product.domains || []), ...(product.vendorDomains || [])]).map(lower));
  const vendors = stored.flatMap(product => product.vendorDomains || []).map(lower);
  const covered = domain => domains.has(domain) || vendors.some(vendor => domain.endsWith(`.${vendor}`));
  // Combined names such as "NinjaOne / NinjaRMM" also match each part, so a tool joins the product it belongs to.
  const byName = new Map();
  for (const name of Object.keys(products)) {
    for (const part of [name, ...name.split(" / ")]) if (!byName.has(normalize(part))) byName.set(normalize(part), name);
  }
  const changes = [];

  for (const tool of tools) {
    const found = candidates(tool, ignore);
    const newPaths = [...found.paths].filter(path => !patterns.some(pattern => pattern.test(path)));
    const newDomains = [...found.domains].filter(domain => !covered(domain));
    if (!newPaths.length && !newDomains.length) continue;

    // Exact name first. Otherwise a shared name word plus a matching domain places the tool ("high");
    // a shared name word alone only suggests a product for review ("medium").
    let name = byName.get(normalize(tool.Name));
    let placement;
    const suggestions = [];
    if (name) placement = "exact";
    else {
      const toolWords = words(tool.Name);
      const toolRoots = new Set([...found.domains].map(rootLabel));
      const toolTokens = tokens(tool.Name);
      for (const [existing, product] of Object.entries(products)) {
        if (!toolWords.some(word => words(existing).includes(word))) continue;
        // Every word of one part of the existing name must appear in the tool name, so "Faronics Core" does not join "Faronics Insight".
        const fullPart = existing.split(" / ").some(part => tokens(part).length && tokens(part).every(token => toolTokens.includes(token)));
        const identities = new Set([...existing.split(" / "), existing].map(normalize));
        for (const domain of [...(product.domains || []), ...(product.vendorDomains || [])]) identities.add(rootLabel(domain));
        const domainHit = [...toolRoots].some(root => identities.has(root));
        suggestions.push({ name: existing, confidence: fullPart && domainHit ? "high" : "medium" });
      }
      const high = suggestions.filter(match => match.confidence === "high");
      if (high.length === 1) {
        name = high[0].name;
        placement = "high";
      }
    }
    name ||= tool.Name.replace(/;/g, ",").trim();
    const isNew = !products[name];
    const product = products[name] ||= {};
    if (newPaths.length) product.paths = [...(product.paths || []), ...newPaths];
    if (newDomains.length) product.domains = [...(product.domains || []), ...newDomains];
    // Later tools skip anything already added, so a shared indicator is listed once.
    patterns.push(...newPaths.map(globToRegExp));
    newDomains.forEach(domain => domains.add(domain));
    byName.set(normalize(name), name);
    // Suggestions only matter for a new product that was not placed automatically.
    const suggested = isNew && !placement ? suggestions : [];
    changes.push({ name, isNew, paths: newPaths, domains: newDomains, placement, suggested, tool: tool.Name });
  }

  const sorted = Object.fromEntries(Object.entries(products).sort(([a], [b]) => a.localeCompare(b, "en", { sensitivity: "base" })));
  return { products: sorted, changes };
}

const summary = (changes, version, date) => {
  const paths = changes.reduce((total, change) => total + change.paths.length, 0);
  const domains = changes.reduce((total, change) => total + change.domains.length, 0);
  const lines = [`Policy ${version} (${date}): ${changes.length} tools updated, ${paths} executables and ${domains} domains added.`, ""];
  for (const change of changes) {
    const placed = change.placement === "high" ? ` (matched on name and domain, previously ${change.tool})` : "";
    lines.push(`- **${change.name}**${change.isNew ? " (new)" : ""}${placed}`);
    if (change.suggested.length) lines.push(`  - Review: may belong in ${change.suggested.map(match => `${match.name} (${match.confidence})`).join(", ")}. Merge with the product above, or keep it separate.`);
    for (const path of change.paths) lines.push(`  - \`${path}\``);
    for (const domain of change.domains) lines.push(`  - ${domain}`);
  }
  return lines.join("\n");
};

async function main() {
  const dryRun = process.argv.includes("--dry-run");
  const response = await fetch(API);
  if (!response.ok) throw new Error(`lolRMM API returned ${response.status}`);
  const tools = await response.json();
  if (!Array.isArray(tools) || tools.some(tool => typeof tool?.Name !== "string")) throw new Error("lolRMM API: unexpected format");

  const ignore = new Set(JSON.parse(readFileSync(join(import.meta.dirname, "lolrmm-ignore.json"), "utf8")).map(entry => lower(entry.name)));
  const productsPath = join(root, "products.json");
  const data = JSON.parse(readFileSync(productsPath, "utf8"));
  const { products, changes } = sync(data, tools, ignore);
  const date = new Date().toISOString().slice(0, 10);
  if (!changes.length) {
    console.log("No new lolRMM indicators.");
    return;
  }

  const version = bumpVersion(data.version);
  console.log(`${summary(changes, version, date)}\n\nReview each tool before merging. lolRMM also lists tools that are not remote management, and every executable or domain here is blocked on all devices once deployed. Apply the review rules in the README (R1 to R4). To remove a tool from this PR and future syncs, check out \`lolrmm-sync\` and run \`node scripts/lolrmm-reject.mjs "<name>" "<reason>"\`, then commit and push.`);
  if (dryRun) return;

  writeFileSync(productsPath, `${JSON.stringify({ ...data, version, products }, null, 2)}\n`);
  const changelogPath = join(root, "changelog.json");
  const log = JSON.parse(readFileSync(changelogPath, "utf8"));
  log.unshift({ version, date, source: "lolrmm.io", products: changes.map(({ name, isNew, paths, domains }) => ({ name, new: isNew, paths, domains })) });
  writeFileSync(changelogPath, `${JSON.stringify(log, null, 2)}\n`);
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) await main();
