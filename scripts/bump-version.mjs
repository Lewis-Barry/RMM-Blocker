// Bumps the policy version when deny paths changed since <base> but the version did not: node scripts/bump-version.mjs <base commit>
// Runs on every push to main, so merged PRs that add paths always ship under a new version.
import { readFileSync, writeFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { bumpVersion } from "./sync-lolrmm.mjs";

const pathSet = data => JSON.stringify(Object.values(data.products).flatMap(product => product.paths || []).map(path => path.toLowerCase()).sort());

export function bump(before, after) {
  if (after.version !== before.version || pathSet(after) === pathSet(before)) return null;
  return { ...after, version: bumpVersion(after.version) };
}

// The changelog.json entry for a bump: what each product gained, plus a count of deny paths that went away.
export function changelogEntry(before, after, version, date) {
  const lowered = (product, field) => new Set((product?.[field] || []).map(value => value.toLowerCase()));
  const products = Object.entries(after.products).map(([name, product]) => {
    const old = before.products[name];
    const added = field => (product[field] || []).filter(value => !lowered(old, field).has(value.toLowerCase()));
    return { name, new: !old, paths: added("paths"), domains: [...added("domains"), ...added("vendorDomains")] };
  }).filter(change => change.paths.length || change.domains.length);
  const afterPaths = new Set(JSON.parse(pathSet(after)));
  const removed = JSON.parse(pathSet(before)).filter(path => !afterPaths.has(path)).length;
  return { version, date, source: "Manual edit", ...(removed && { note: `${removed} deny path${removed === 1 ? "" : "s"} removed.` }), products };
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  const root = join(import.meta.dirname, "..");
  const productsPath = join(root, "products.json");
  const before = JSON.parse(execFileSync("git", ["show", `${process.argv[2]}:products.json`], { cwd: root, encoding: "utf8" }));
  const result = bump(before, JSON.parse(readFileSync(productsPath, "utf8")));
  if (!result) {
    console.log("No bump needed.");
  } else {
    writeFileSync(productsPath, `${JSON.stringify(result, null, 2)}\n`);
    const changelogPath = join(root, "changelog.json");
    const log = JSON.parse(readFileSync(changelogPath, "utf8"));
    log.unshift(changelogEntry(before, result, result.version, new Date().toISOString().slice(0, 10)));
    writeFileSync(changelogPath, `${JSON.stringify(log, null, 2)}\n`);
    console.log(`Bumped policy to ${result.version}.`);
  }
}
