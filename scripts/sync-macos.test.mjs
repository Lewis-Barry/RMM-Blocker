// Run with: node --test scripts/
import { test } from "node:test";
import assert from "node:assert/strict";
import { registrable, matchCasks, decide, apply, summary } from "./sync-macos.mjs";

const cask = (token, homepage, name = token) => ({ token, name: [name], homepage, url: `https://dl.example/${token}.pkg`, sha256: "x", version: "1.0" });
const tool = (Name, Website) => ({ Name, Details: { Website } });
const sig = (teamId, identifier, path = `/Applications/${identifier}.app/Contents/MacOS/${identifier}`) => ({ teamId, identifier, path });

test("registrable domain folds www and keeps two-level country suffixes", () => {
  assert.equal(registrable("https://www.teamviewer.com/en/"), "teamviewer.com");
  assert.equal(registrable("https://help.example.co.uk/x"), "example.co.uk");
  assert.equal(registrable("not a url"), null);
});

test("matchCasks joins a product to one cask by its own domain or the lolRMM website, plus a shared name", () => {
  const products = {
    Acme: { paths: ["*\\acme.exe"], domains: ["acme.com"] },
    Zeta: { paths: ["*\\zeta.exe"] },
    Done: { paths: ["*\\done.exe"], domains: ["done.io"], macos: { rules: [{ teamId: "ABCDEFGHIJ" }], source: "https://x", verified: "2026-01-01" } },
  };
  const casks = [cask("acme", "https://www.acme.com/"), cask("zeta-remote", "https://zeta.example/", "Zeta Remote"), cask("done", "https://done.io/")];
  const results = matchCasks(products, [tool("Zeta", "https://www.zeta.example")], casks);
  assert.deepEqual(results.map(r => [r.name, r.cask?.token, r.skip]), [["Acme", "acme", null], ["Zeta", "zeta-remote", null]]);
});

test("matchCasks skips when several casks match, when the vendor ships unrelated casks, or when ignored", () => {
  const products = { Splash: { domains: ["splash.com"] }, Para: { domains: ["para.com"] }, Eset: { domains: ["eset.com"] } };
  const casks = [cask("splash-business", "https://splash.com/", "Splash Business"), cask("splash-streamer", "https://splash.com/", "Splash Streamer"),
    cask("para-access", "https://para.com/", "Para Access"), cask("para-desktop", "https://para.com/", "Para Desktop VM"), cask("eset-av", "https://eset.com/", "Eset AV")];
  const results = matchCasks(products, [], casks, new Set(["eset"]));
  assert.match(results.find(r => r.name === "Splash").skip, /several casks/);
  const para = results.find(r => r.name === "Para");
  assert.equal(para.cask, null);
  assert.match(para.skip, /several casks/);
  assert.equal(results.find(r => r.name === "Eset"), undefined);
});

test("matchCasks never joins through a shared hosting domain and reports unrelated vendor casks", () => {
  const products = { Tool: { domains: ["github.com"] }, Tele: { domains: ["tele.dev"] } };
  const casks = [cask("tool", "https://github.com/x/tool"), cask("tele", "https://tele.dev/"), cask("tsh", "https://tele.dev/", "tsh")];
  const results = matchCasks(products, [], casks);
  assert.equal(results.find(r => r.name === "Tool"), undefined);
  assert.match(results.find(r => r.name === "Tele").skip, /vendor also ships tsh/);
});

test("decide accepts one Team ID across all binaries and lists the app and helper identifiers", () => {
  const result = decide("Acme", [sig("ABCDEFGHIJ", "com.acme.app"), sig("ABCDEFGHIJ", "com.acme.helper", "/Library/PrivilegedHelperTools/com.acme.helper"),
    sig("ABCDEFGHIJ", "libfoo", "/Applications/Acme.app/Contents/Frameworks/libfoo.dylib")], {});
  assert.deepEqual(result, { teamId: "ABCDEFGHIJ", binaries: 3, identifiers: ["com.acme.app", "com.acme.helper"] });
});

test("decide skips mixed signers, ad-hoc signatures, broad vendors and Team IDs already owned by another product", () => {
  assert.match(decide("A", [sig("ABCDEFGHIJ", "a"), sig("KLMNOPQRST", "b")], {}).skip, /mixed signers/);
  assert.match(decide("A", [sig("ADHOC", "a")], {}).skip, /ad-hoc/);
  assert.match(decide("A", [sig("NONE", "a")], {}).skip, /ad-hoc/);
  assert.match(decide("A", [sig("UBF8T346G9", "a")], {}).skip, /Microsoft/);
  assert.match(decide("A", [sig("ABCDEFGHIJ", "a")], { B: { macos: { rules: [{ teamId: "ABCDEFGHIJ" }] } } }).skip, /already used by B/);
  assert.match(decide("A", [], {}).skip, /no Mach-O/);
});

test("apply writes the rule with cask, source and date and bumps the version once", () => {
  const data = { version: "1.0.0.9", products: { Acme: { paths: ["*\\acme.exe"] } } };
  const next = apply(data, [{ name: "Acme", teamId: "ABCDEFGHIJ", cask: { token: "acme", url: "https://dl/acme.pkg" } }], "2026-02-01");
  assert.equal(next.version, "1.0.0.10");
  assert.deepEqual(next.products.Acme.macos, { rules: [{ teamId: "ABCDEFGHIJ" }], cask: "acme", source: "https://dl/acme.pkg", verified: "2026-02-01" });
  assert.equal(data.products.Acme.macos, undefined);
  assert.equal(apply(data, [], "2026-02-01"), data);
});

test("summary names the Team ID, cask, binary count, installer and Signing IDs for review", () => {
  const text = summary([{ name: "Acme", teamId: "ABCDEFGHIJ", cask: { token: "acme", url: "https://dl/acme.pkg", version: "2.1" }, binaries: 7, identifiers: ["com.acme.app"] }],
    [{ name: "Eset", skip: "vendor also ships eset-av" }], 3);
  assert.match(text, /\*\*Acme\*\*: Team ID `ABCDEFGHIJ` from cask `acme` 2\.1 \(7 binaries, one signer\)/);
  assert.match(text, /`com\.acme\.app`/);
  assert.match(text, /Eset: vendor also ships eset-av/);
  assert.match(text, /3 existing Team IDs re-verified/);
});
