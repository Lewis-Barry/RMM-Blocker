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

if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  const root = join(import.meta.dirname, "..");
  const productsPath = join(root, "products.json");
  const before = JSON.parse(execFileSync("git", ["show", `${process.argv[2]}:products.json`], { cwd: root, encoding: "utf8" }));
  const result = bump(before, JSON.parse(readFileSync(productsPath, "utf8")));
  if (!result) {
    console.log("No bump needed.");
  } else {
    writeFileSync(productsPath, `${JSON.stringify(result, null, 2)}\n`);
    console.log(`Bumped policy to ${result.version}.`);
  }
}
