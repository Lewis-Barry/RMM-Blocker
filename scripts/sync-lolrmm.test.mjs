// Run with: node --test scripts/
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { candidates, sync } from "./sync-lolrmm.mjs";
import { reject } from "./lolrmm-reject.mjs";

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
  const found = candidates(tool("Tool", [exe("C:\\Windows\\System32\\tar.exe"), exe("C:\\Program Files\\Teams\\teams.exe"), exe("C:\\ProgramData\\RMMAgent\\packages\\Notepad++.exe"), exe("C:\\x\\Tool.exe")],
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

test("reject removes a product's additions from the latest release and drops a release left empty", () => {
  const data = { version: "1.0.0.10", products: { "Acme RMM": { paths: ["*\\acme.exe", "*\\AcmeRemote.exe"], domains: ["remote.acme.com"] }, Beta: { paths: ["*\\Beta.exe"] } } };
  const log = [
    { version: "1.0.0.10", products: [
      { name: "Beta", new: true, paths: ["*\\Beta.exe"], domains: [] },
      { name: "Acme RMM", new: false, paths: ["*\\AcmeRemote.exe"], domains: ["remote.acme.com"] },
    ] },
    { version: "1.0.0.9", products: [] },
  ];
  const first = reject(data, log, "beta");
  assert.equal(first.removed, 1);
  assert.deepEqual(Object.keys(first.data.products), ["Acme RMM"]);
  assert.equal(first.data.version, "1.0.0.10");
  assert.deepEqual(first.log[0].products.map(change => change.name), ["Acme RMM"]);

  const second = reject(first.data, first.log, "Acme RMM");
  assert.deepEqual(second.data.products["Acme RMM"], { paths: ["*\\acme.exe"] });
  assert.equal(second.log.length, 1);
  assert.equal(second.data.version, "1.0.0.9");
  assert.equal(reject(data, log, "Unknown").removed, 0);
});

test("a tool named after one part of a combined product joins that product", () => {
  const data = { version: "1.0.0.9", products: { "NinjaOne / NinjaRMM": { paths: ["*\\ninjaone\\*"] } } };
  const { products, changes } = sync(data, [tool("NinjaRMM", [], ["ninja-backup.com"])], none);
  assert.deepEqual(changes.map(({ name, isNew }) => [name, isNew]), [["NinjaOne / NinjaRMM", false]]);
  assert.deepEqual(products, { "NinjaOne / NinjaRMM": { paths: ["*\\ninjaone\\*"], domains: ["ninja-backup.com"] } });
});

test("a tool joins an existing product on name and domain, and only suggests one on name alone", () => {
  const data = { version: "1.0.0.9", products: {
    Level: { paths: ["*\\levelagent*.exe"], domains: ["level.io"] },
    "Faronics Insight": { paths: ["*\\FIStudentSvc*.exe"], domains: ["faronics.com"] },
  } };
  const placed = sync(data, [tool("Level.io", [], ["app.level.io"])], none).changes[0];
  assert.equal(placed.name, "Level");
  assert.equal(placed.placement, "high");

  const suggested = sync(data, [tool("Faronics Core", [exe("C:\\x\\FaronicsCore.exe")], ["faronics.com"])], none).changes[0];
  assert.equal(suggested.name, "Faronics Core");
  assert.equal(suggested.isNew, true);
  assert.equal(suggested.placement, undefined);
  assert.deepEqual(suggested.suggested.map(match => [match.name, match.confidence]), [["Faronics Insight", "medium"]]);
});

test("candidates skip placeholder names from the API such as <random>.exe", () => {
  const found = candidates(tool("Rodex RMM", [exe("C:\\x\\<random-6-9-char>.exe"), exe("C:\\x\\<impersonated-org>Agent.exe"), exe("C:\\x\\RodexAgent.exe")]), none);
  assert.deepEqual([...found.paths], ["*\\RodexAgent.exe"]);
});

test("a tool decided as a separate product gets no suggestions", () => {
  const data = { version: "1.0.0.9", products: { "Faronics Insight": { paths: ["*\\FIStudentSvc*.exe"], domains: ["faronics.com"] } } };
  const suggested = sync(data, [tool("Faronics Core", [exe("C:\\x\\FaronicsCore.exe")], ["faronics.com"])], none, new Set(["faronics core"])).changes[0];
  assert.deepEqual(suggested.suggested, []);
  assert.equal(suggested.name, "Faronics Core");
});
