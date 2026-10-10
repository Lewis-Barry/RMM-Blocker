// Run with: node --test scripts/
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { candidates, sync } from "./sync-lolrmm.mjs";

const none = new Set();
const tool = (Name, Disk = [], Domains = []) => ({ Name, Artifacts: { Disk, Network: [{ Domains }] } });
const exe = File => ({ File, OS: "Windows" });

test("candidates keep Windows executables and skip generic names, wildcards and shared hosts", () => {
  const found = candidates(tool("Tool",
    [exe("C:\\Program Files\\Acme\\AcmeAgent.exe"), exe("C:\\Program Files\\Acme\\agent.exe"), exe("C:\\Acme\\*\\x.exe"), { File: "Acme.exe", OS: "Linux" }],
    ["acme.com", "*.acme.com", "github.com", "raw.githubusercontent.com", "app.github.com", "acme-rmm.example.io"]), none);
  assert.deepEqual([...found.paths], ["*\\AcmeAgent.exe"]);
  assert.deepEqual([...found.domains].sort(), ["acme-rmm.example.io", "acme.com"]);
});

test("candidates skip Windows and everyday app binaries and fold www. into the apex domain", () => {
  const found = candidates(tool("Tool", [exe("C:\\Windows\\System32\\tar.exe"), exe("C:\\Program Files\\Teams\\teams.exe"), exe("C:\\x\\Tool.exe")],
    ["www.tool.com", "tool.com"]), none);
  assert.deepEqual([...found.paths], ["*\\Tool.exe"]);
  assert.deepEqual([...found.domains], ["tool.com"]);
});

test("candidates honour the ignore list by tool name and indicator", () => {
  const ignore = new Set(["acme", "acmeagent.exe", "acme.com"]);
  assert.deepEqual(candidates(tool("Acme", [exe("C:\\x\\Other.exe")], ["other.com"]), ignore).paths.size, 0);
  const found = candidates(tool("Other", [exe("C:\\x\\AcmeAgent.exe")], ["acme.com", "other.com"]), ignore);
  assert.deepEqual([...found.paths], []);
  assert.deepEqual([...found.domains], ["other.com"]);
});

test("sync adds only what no product covers and bumps nothing when nothing is new", () => {
  const data = { version: "1.0.0.9", products: { Acme: { paths: ["*\\acmeagent*.exe"], vendorDomains: ["acme.com"] } } };
  const { products, changes } = sync(data, [tool("Acme RMM", [exe("C:\\x\\AcmeAgent.exe")], ["portal.acme.com"])], none);
  assert.deepEqual(changes, []);
  assert.deepEqual(products, data.products);
});

test("sync adds to a matching product, creates new products and lists shared indicators once", () => {
  const data = { version: "1.0.0.9", products: { "Acme RMM": { paths: ["*\\acme.exe"] } } };
  const tools = [
    tool("ACME-RMM", [exe("C:\\x\\AcmeRemote.exe")], ["remote.acme.com"]),
    tool("Beta", [exe("C:\\x\\AcmeRemote.exe"), exe("C:\\y\\BetaRemote.exe")], ["beta.example.com"]),
  ];
  const { products, changes } = sync(data, tools, none);
  assert.deepEqual(changes.map(({ name, isNew }) => [name, isNew]), [["Acme RMM", false], ["Beta", true]]);
  assert.deepEqual(products["Acme RMM"], { paths: ["*\\acme.exe", "*\\AcmeRemote.exe"], domains: ["remote.acme.com"] });
  assert.deepEqual(products.Beta, { paths: ["*\\BetaRemote.exe"], domains: ["beta.example.com"] });
});

test("the current products.json re-serialises unchanged, so a sync diff only shows real additions", () => {
  const data = JSON.parse(readFileSync(join(import.meta.dirname, "..", "products.json"), "utf8"));
  const { products, changes } = sync(data, [], none);
  assert.deepEqual(changes, []);
  assert.equal(JSON.stringify(Object.keys(products)), JSON.stringify(Object.keys(data.products)));
});
