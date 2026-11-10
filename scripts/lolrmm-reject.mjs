// Removes a product's additions from the open lolRMM sync PR and blocks it from future syncs:
// node scripts/lolrmm-reject.mjs "<product name as shown in the PR>" "<reason>"
// Run it on the lolrmm-sync branch, then commit and push. It refuses to run on main.
import { readFileSync, writeFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

const root = join(import.meta.dirname, "..");
const lower = value => value.toLowerCase();

// Pure: returns the data with the product's additions from the latest release removed.
// mainVersion is the version on main, which a release left empty goes back to.
export function reject(data, log, name, mainVersion) {
  const products = { ...data.products };
  const latest = log[0];
  const hits = latest.products.filter(change => lower(change.name) === lower(name));
  for (const change of hits) {
    if (change.new) {
      delete products[change.name];
      continue;
    }
    const current = products[change.name] || {};
    const next = {
      ...current,
      paths: (current.paths || []).filter(path => !change.paths.includes(path)),
      domains: (current.domains || []).filter(domain => !change.domains.includes(domain)),
    };
    for (const field of ["paths", "domains"]) if (!next[field].length) delete next[field];
    products[change.name] = next;
  }
  const rest = { ...latest, products: latest.products.filter(change => lower(change.name) !== lower(name)) };
  // An empty release is dropped, and the version goes back to the one on main.
  // The changelog can't supply it: releases bumped before bump-version.mjs wrote entries are missing from it.
  const kept = rest.products.length > 0;
  const log2 = kept ? [rest, ...log.slice(1)] : log.slice(1);
  // The sync ignores by lolRMM tool name, which differs from the product name when a tool joined an existing product.
  const tools = [...new Set(hits.map(change => change.tool).filter(Boolean))];
  return { removed: hits.length, tools, data: { ...data, version: kept ? data.version : mainVersion, products }, log: log2 };
}

function main() {
  const [name, reason] = process.argv.slice(2);
  if (!name || !reason) throw new Error('usage: node scripts/lolrmm-reject.mjs "<product name>" "<reason>"');
  const branch = execFileSync("git", ["rev-parse", "--abbrev-ref", "HEAD"], { cwd: root }).toString().trim();
  if (branch === "main") throw new Error("Run this on the lolrmm-sync branch, not main.");

  const dataPath = join(root, "products.json");
  const changelogPath = join(root, "changelog.json");
  const data = JSON.parse(readFileSync(dataPath, "utf8"));
  const log = JSON.parse(readFileSync(changelogPath, "utf8"));
  const mainVersion = JSON.parse(execFileSync("git", ["show", "origin/main:products.json"], { cwd: root, encoding: "utf8" })).version;
  const result = reject(data, log, name, mainVersion);

  const ignorePath = join(root, "scripts", "lolrmm-ignore.json");
  const ignore = JSON.parse(readFileSync(ignorePath, "utf8"));
  // Releases synced before the changelog recorded tool names fall back to the product name.
  for (const tool of result.tools.length ? result.tools : [name]) {
    if (!ignore.some(entry => lower(entry.name) === lower(tool))) ignore.push({ name: tool, reason });
  }
  writeFileSync(ignorePath, `${JSON.stringify(ignore, null, 2)}\n`);

  if (!result.removed) {
    console.log(`${name} is blocked from future syncs. It has no additions in ${data.version}, so the PR is unchanged.`);
    return;
  }
  writeFileSync(dataPath, `${JSON.stringify(result.data, null, 2)}\n`);
  writeFileSync(changelogPath, `${JSON.stringify(result.log, null, 2)}\n`);
  execFileSync("node", [join(root, "build.mjs")], { cwd: root, stdio: "inherit" });
  console.log(`Removed ${name} from the PR and added it to scripts/lolrmm-ignore.json. Policy is now ${result.data.version}. Commit and push the branch.`);
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) main();
