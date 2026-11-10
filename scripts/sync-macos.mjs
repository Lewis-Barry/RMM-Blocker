// Adds macOS rules for products that have none yet, the way sync-lolrmm.mjs adds Windows paths:
// node scripts/sync-macos.mjs [--dry-run]   (macOS only: needs brew, hdiutil, pkgutil and codesign)
// Each product is joined to exactly one Homebrew cask by website domain and name; brew verifies the installer's
// sha256; codesign reads every Mach-O; a rule is written only when all binaries share one Team ID. Products with
// existing rules are re-read, and a changed Team ID fails the run. Prints a Markdown summary for the pull request.
import { readFileSync, writeFileSync, mkdtempSync, rmSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { bumpVersion } from "./sync-lolrmm.mjs";
import { validateMacos, broadTeamIds } from "../macos.js";

const root = join(import.meta.dirname, "..");
const LOLRMM = "https://lolrmm.io/api/rmm_tools.json";
const CASKS = "https://formulae.brew.sh/api/cask.json";
// Hosting platforms: a shared domain never links a product to a cask.
const SHARED = new Set(["github.com", "github.io", "gitlab.com", "sourceforge.net", "google.com", "microsoft.com", "apple.com", "cloudflare.com", "archive.org", "apache.org"]);
const GENERIC_WORDS = new Set(["the", "and", "remote", "desktop", "control", "access", "connect", "app", "pro", "client", "server", "rmm", "beta", "tools", "support", "agent", "host"]);

const lower = value => value.toLowerCase();
const normalize = name => lower(name).replace(/[^a-z0-9]/g, "");
const words = text => new Set(lower(text).split(/[^a-z0-9]+/).filter(word => word.length >= 3 && !GENERIC_WORDS.has(word)));
export const registrable = url => {
  try {
    const host = new URL(url.includes("://") ? url : `https://${url}`).hostname.replace(/^www\./, "").toLowerCase();
    const parts = host.split(".");
    return parts.slice(/\.(co|com|org|net|ac|gov)\.[a-z]{2}$/.test(host) ? -3 : -2).join(".");
  } catch { return null; }
};

// Pure: for every product without macOS rules, the single cask it maps to, or why it has none.
// Domains come from the product's own indicators and from the lolRMM website of a tool with the same name.
export function matchCasks(products, tools, casks, ignore = new Set()) {
  const casksByDomain = new Map();
  for (const cask of casks) {
    const domain = registrable(cask.homepage || "");
    if (!domain || SHARED.has(domain)) continue;
    (casksByDomain.get(domain) || casksByDomain.set(domain, []).get(domain)).push(cask);
  }
  const websites = new Map(tools.map(tool => [normalize(tool.Name), tool.Details?.Website || ""]));
  const results = [];
  for (const [name, product] of Object.entries(products)) {
    if (product.macos || ignore.has(lower(name))) continue;
    const parts = name.split(" / ");
    const domains = new Set([...(product.domains || []), ...(product.vendorDomains || [])].map(registrable));
    for (const part of [name, ...parts]) { const site = websites.get(normalize(part)); if (site) domains.add(registrable(site)); }
    domains.delete(null);
    const nameWords = new Set(parts.flatMap(part => [...words(part)]));
    const sameDomain = [...domains].filter(domain => !SHARED.has(domain)).flatMap(domain => casksByDomain.get(domain) || []);
    const named = sameDomain.filter(cask => [...words(`${cask.token} ${cask.name.join(" ")}`)].some(word => nameWords.has(word)));
    const exact = named.filter(cask => parts.some(part => normalize(part) === normalize(cask.token) || cask.name.some(n => normalize(n) === normalize(part))));
    const chosen = named.length === 1 ? named[0] : exact.length === 1 ? exact[0] : null;
    // Other casks of the same vendor that share no name with the product: the Team ID would deny those too.
    const unrelated = sameDomain.filter(cask => !named.includes(cask)).map(cask => cask.token);
    if (!named.length) continue;
    results.push({
      name, cask: chosen && { token: chosen.token, url: chosen.url, sha256: chosen.sha256, version: chosen.version },
      candidates: named.map(cask => cask.token), unrelated,
      skip: !chosen ? `several casks match: ${named.map(cask => cask.token).join(", ")}` : unrelated.length ? `vendor also ships ${unrelated.join(", ")}` : null,
    });
  }
  return results;
}

// Pure: turns one cask's signatures into a rule, or a reason to skip. signatures = [{ teamId, identifier, path }].
export function decide(name, signatures, products) {
  if (!signatures.length) return { skip: "no Mach-O binaries found in the installer" };
  const counts = new Map();
  for (const sig of signatures) counts.set(sig.teamId, (counts.get(sig.teamId) || 0) + 1);
  if (counts.size !== 1) return { skip: `mixed signers: ${[...counts].map(([id, n]) => `${id} ×${n}`).join(", ")}` };
  const teamId = signatures[0].teamId;
  if (!/^[A-Z0-9]{10}$/.test(teamId)) return { skip: "unsigned or ad-hoc signed; no Team ID to match" };
  if (broadTeamIds.has(teamId)) return { skip: `Team ID belongs to ${broadTeamIds.get(teamId)} and signs unrelated software` };
  const owner = Object.entries(products).find(([other, product]) => other !== name && product.macos?.rules.some(rule => rule.teamId === teamId));
  if (owner) return { skip: `Team ID already used by ${owner[0]}` };
  const identifiers = [...new Set(signatures.filter(sig => /\.app\/Contents\/MacOS\/|PrivilegedHelperTools|LaunchServices/.test(sig.path)).map(sig => sig.identifier))].sort();
  return { teamId, binaries: signatures.length, identifiers };
}

// Pure: writes the accepted rules into a copy of the data and bumps the version once.
export function apply(data, accepted, date) {
  if (!accepted.length) return data;
  const products = { ...data.products };
  for (const entry of accepted) {
    products[entry.name] = { ...products[entry.name], macos: { rules: [{ teamId: entry.teamId }], cask: entry.cask.token, source: entry.cask.url, verified: date } };
  }
  return { ...data, version: bumpVersion(data.version), products };
}

export function summary(accepted, skipped, verified) {
  const lines = [`macOS: ${accepted.length} tools gained Team ID rules, ${verified} existing Team IDs re-verified.`, ""];
  for (const entry of accepted) {
    lines.push(`- **${entry.name}**: Team ID \`${entry.teamId}\` from cask \`${entry.cask.token}\` ${entry.cask.version} (${entry.binaries} binaries, one signer). Installer: ${entry.cask.url}`);
    if (entry.identifiers.length) lines.push(`  - Signing IDs: ${entry.identifiers.slice(0, 8).map(id => `\`${id}\``).join(", ")}`);
  }
  if (skipped.length) {
    lines.push("", "Not added (add by hand after checking, or record in scripts/macos-ignore.json):");
    for (const entry of skipped) lines.push(`- ${entry.name}: ${entry.skip}`);
  }
  lines.push("", "A Team ID denies every binary the vendor signs. Check the Signing IDs name the remote tool, not another product from the same vendor, before merging.");
  return lines.join("\n");
}

// --- macOS side effects: brew download (sha256 checked by brew) and codesign ---
const sh = (command, options = {}) => execFileSync("/bin/zsh", ["-c", command], { encoding: "utf8", maxBuffer: 64 << 20, ...options });

export function readSignatures(token) {
  sh(`brew fetch --cask ${JSON.stringify(token)} >/dev/null`);
  const file = sh(`brew --cache --cask ${JSON.stringify(token)}`).trim();
  const work = mkdtempSync(join(tmpdir(), "rmm-mac-"));
  try {
    const type = sh(`file -b ${JSON.stringify(file)}`);
    const extract = /xar archive/.test(type) ? `pkgutil --expand-full "$F" "$W/pkg"`
      : /Zip archive/.test(type) ? `ditto -x -k "$F" "$W/zip" && find "$W/zip" -name "*.pkg" -exec sh -c 'pkgutil --expand-full "$1" "$W/pkg_$(basename "$1")"' _ {} \\;`
      : /gzip compressed/.test(type) ? `mkdir -p "$W/tgz" && tar -xzf "$F" -C "$W/tgz"`
      : `mkdir -p "$W/mnt" && hdiutil attach -nobrowse -readonly -noverify -mountpoint "$W/mnt" "$F" >/dev/null && find "$W/mnt" -maxdepth 3 -name "*.pkg" -exec sh -c 'pkgutil --expand-full "$1" "$W/pkg_$(basename "$1")"' _ {} \\; ; true`;
    // F and W are exported because the nested sh -c in find -exec reads them.
    const output = sh(`export F=${JSON.stringify(file)} W=${JSON.stringify(work)}; ${extract}
      find "$W" -type f -perm +111 2>/dev/null | while read -r b; do file -b "$b" | grep -q "Mach-O" || continue
        codesign -dvvv "$b" 2>&1 | awk -v p="$b" -F= '/^Identifier=/{id=$2} /^TeamIdentifier=/{t=$2} /^Signature=adhoc/{t="ADHOC"} END{print (t==""?"NONE":t) "|" id "|" p}'; done
      hdiutil detach "$W/mnt" -quiet -force 2>/dev/null; true`);
    return output.split("\n").filter(Boolean).map(line => { const [teamId, identifier, path] = line.split("|"); return { teamId, identifier, path }; });
  } finally {
    rmSync(work, { recursive: true, force: true });
  }
}

async function main() {
  const dryRun = process.argv.includes("--dry-run");
  const productsPath = join(root, "products.json");
  const data = JSON.parse(readFileSync(productsPath, "utf8"));
  const ignore = new Set(JSON.parse(readFileSync(join(import.meta.dirname, "macos-ignore.json"), "utf8")).map(entry => lower(entry.name)));
  const [tools, casks] = await Promise.all([LOLRMM, CASKS].map(async url => {
    const response = await fetch(url);
    if (!response.ok) throw new Error(`${url} returned ${response.status}`);
    return response.json();
  }));

  // Existing rules first: a Team ID that changed means a hijacked installer or a vendor change, and stops the run.
  let verified = 0;
  for (const [name, product] of Object.entries(data.products)) {
    if (!product.macos?.cask) continue;
    const found = new Set(readSignatures(product.macos.cask).map(sig => sig.teamId));
    const expected = new Set(product.macos.rules.map(rule => rule.teamId));
    const missing = [...expected].filter(teamId => !found.has(teamId));
    if (missing.length) throw new Error(`${name}: cask ${product.macos.cask} no longer carries Team ID ${missing.join(", ")} (found ${[...found].join(", ")}). Investigate before trusting any new rule.`);
    verified++;
  }

  const accepted = [];
  const skipped = [];
  for (const match of matchCasks(data.products, tools, casks, ignore)) {
    if (match.skip) { skipped.push(match); continue; }
    let decision;
    try { decision = decide(match.name, readSignatures(match.cask.token), data.products); } catch (error) { decision = { skip: `download or extraction failed: ${error.message.split("\n")[0]}` }; }
    if (decision.skip) skipped.push({ name: match.name, skip: decision.skip });
    else accepted.push({ name: match.name, cask: match.cask, ...decision });
  }
  const date = new Date().toISOString().slice(0, 10);
  const next = apply(data, accepted, date);
  for (const entry of accepted) validateMacos(entry.name, next.products[entry.name].macos);
  console.log(summary(accepted, skipped, verified));
  if (dryRun || !accepted.length) return;
  writeFileSync(productsPath, `${JSON.stringify(next, null, 2)}\n`);
  const changelogPath = join(root, "changelog.json");
  const log = JSON.parse(readFileSync(changelogPath, "utf8"));
  log.unshift({ version: next.version, date, source: "Homebrew installers, codesign", note: `macOS rules added for ${accepted.map(entry => entry.name).join(", ")}.`, products: [] });
  writeFileSync(changelogPath, `${JSON.stringify(log, null, 2)}\n`);
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) main().catch(error => { console.error(error.message); process.exit(1); });
