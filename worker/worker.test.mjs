// node --test worker/worker.test.mjs : runs the Worker against the repo's own files instead of the live site.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import worker, { policyTools } from "./index.js";
import { parseCsv } from "../ioc.js";

const root = join(import.meta.dirname, "..");
globalThis.fetch = async url => {
  try {
    return new Response(await readFile(join(root, decodeURIComponent(new URL(url).pathname))));
  } catch {
    return new Response("", { status: 404 });
  }
};
const get = (path, ...exclude) => worker.fetch(new Request(
  `https://rmmguard.com/api/${path}?${new URLSearchParams(exclude.map(name => ["exclude", name]))}`));
// Response.text() drops the BOM, in the Worker as in the page.
const source = (await readFile(join(root, "Blocking_RMMsv5.xml"), "utf8")).replace(/^﻿/, "");
const ids = (text, tag, name) => [...text.matchAll(new RegExp(`<${tag}\\s[^>]*?\\s?${name}="([^"]*)"`, "g"))].map(match => match[1]);

test("no exclusions returns the published policy unchanged", async () => {
  assert.equal(await (await get("wdac.xml")).text(), source);
});

test("excluded tools lose their rules and references, others stay", async () => {
  // O&O Syspectr covers the XML entity in FriendlyName.
  const xml = await (await get("wdac.xml", "AnyDesk", "O&O Syspectr")).text();
  const tools = policyTools(xml);
  assert.ok(!tools.has("AnyDesk") && !tools.has("O&O Syspectr"));
  assert.equal(tools.size, policyTools(source).size - 2);
  const kept = new Set(ids(xml, "Deny", "ID"));
  assert.ok(kept.size < ids(source, "Deny", "ID").length);
  const allowed = new Set(ids(xml, "Allow", "ID"));
  const refs = ids(xml, "FileRuleRef", "RuleID");
  assert.ok(refs.every(id => kept.has(id) || allowed.has(id)), "a reference points at a removed rule");
  assert.equal(refs.filter(id => kept.has(id)).length, kept.size);
});

test("indicators come back as one CSV without the excluded tool", async () => {
  const all = parseCsv(await (await get("iocs.csv")).text());
  const some = parseCsv(await (await get("iocs.csv", "AnyDesk")).text());
  assert.ok(all.length > 501, "expected every batch in one file");
  assert.ok(some.length < all.length);
  assert.ok(!some.some(row => row[5] === "LOLRMM - AnyDesk"));
});

test("macOS JSON drops the excluded tool's rules", async () => {
  const count = async (...exclude) => JSON.stringify(JSON.parse(await (await get("macos.json", ...exclude)).text())).split("item_teamid").length;
  assert.ok(await count("AnyDesk") < await count());
});

test("unknown tool names and paths are refused", async () => {
  const response = await get("wdac.xml", "No Such Tool");
  assert.equal(response.status, 400);
  assert.match(await response.text(), /No Such Tool/);
  assert.equal((await get("nope.txt")).status, 404);
});
