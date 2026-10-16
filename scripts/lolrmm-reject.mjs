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
export function reject(data, log, name) {
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
  // An empty release is dropped, and the version goes back to the release before it.
  const log2 = rest.products.length ? [rest, ...log.slice(1)] : log.slice(1);
  return { removed: hits.length, data: { ...data, version: log2[0].version, products }, log: log2 };
}

function main() {
  const [name, reason] = process.argv.slice(2);
  if (!name || !reason) throw new Error('usage: node scripts/lolrmm-reject.mjs "<product name>" "<reason>"');
  const branch = execFileSync("git", ["rev-parse", "--abbrev-ref", "HEAD"], { cwd: root }).toString().trim();
  if (branch === "main") throw new Error("Run this on the lolrmm-sync branch, not main.");

  const ignorePath = join(root, "scripts", "lolrmm-ignore.json");
  const ignore = JSON.parse(readFileSync(ignorePath, "utf8"));
  if (!ignore.some(entry => lower(entry.name) === lower(name))) {
    ignore.push({ name, reason });
    writeFileSync(ignorePath, `${JSON.stringify(ignore, null, 2)}\n`);
  }

  const dataPath = join(root, "products.json");
  const changelogPath = join(root, "changelog.json");
  const data = JSON.parse(readFileSync(dataPath, "utf8"));
  const log = JSON.parse(readFileSync(changelogPath, "utf8"));
  const result = reject(data, log, name);
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
