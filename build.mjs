// Generates Blocking_RMMsv5.xml and the IOC CSVs from products.json: node build.mjs [--check]
// --check writes nothing and fails if the committed files are out of date.
import { readFileSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { join } from "node:path";
import { iocHeaders, iocSources, serializeCsv } from "./ioc.js";

const root = import.meta.dirname;
const { version, products } = JSON.parse(readFileSync(join(root, "products.json"), "utf8"));
if (!/^\d+\.\d+\.\d+\.\d+$/.test(version)) throw new Error(`products.json: invalid version ${version}`);

// Collect owners per path and per indicator so shared entries are emitted once.
const paths = new Map();
const indicators = new Map();
const add = (map, key, name, extra) => {
  const entry = map.get(key.toLowerCase()) || map.set(key.toLowerCase(), { key, names: [], ...extra }).get(key.toLowerCase());
  if (extra && entry.type !== extra.type) throw new Error(`products.json: ${key} listed as both a domain and an IP`);
  if (entry.names.includes(name)) throw new Error(`products.json: ${key} listed twice under ${name}`);
  entry.names.push(name);
  return entry;
};
for (const [name, product] of Object.entries(products)) {
  if (!name.trim() || name.includes(";")) throw new Error(`products.json: invalid product name "${name}"`);
  for (const field of Object.keys(product)) {
    if (!["paths", "domains", "vendorDomains", "ips"].includes(field)) throw new Error(`products.json: ${name} has unknown field "${field}"`);
  }
  for (const path of product.paths || []) {
    if (!path.startsWith("*\\")) throw new Error(`products.json: ${name} path must start with *\\: ${path}`);
    add(paths, path, name);
  }
  for (const domain of product.domains || []) add(indicators, domain, name, { type: "DomainName", vendor: false });
  for (const domain of product.vendorDomains || []) add(indicators, domain, name, { type: "DomainName" }).vendor = true;
  for (const ip of product.ips || []) {
    if (!/^[\d.]+$|:/.test(ip)) throw new Error(`products.json: ${name} has invalid IP ${ip}`);
    add(indicators, ip, name, { type: "IpAddress" });
  }
}

const escape = value => value.replace(/[&<>"]/g, char => `&${{ "&": "amp", "<": "lt", ">": "gt", '"': "quot" }[char]};`);
const rules = [...paths.values()].map(({ key, names }) => ({
  path: key,
  // FriendlyName carries the product names, which is how the editor groups rules.
  names: names.join("; "),
  id: `ID_DENY_A_${createHash("md5").update(key.toLowerCase()).digest("hex").toUpperCase()}`,
}));
const xml = `﻿<?xml version="1.0" encoding="utf-8"?>
<SiPolicy PolicyType="Base Policy" xmlns="urn:schemas-microsoft-com:sipolicy">
  <VersionEx>${version}</VersionEx>
  <PolicyID>{01A11AD0-7091-7896-89DD-447C515BCB5D}</PolicyID>
  <BasePolicyID>{01A11AD0-7091-7896-89DD-447C515BCB5D}</BasePolicyID>
  <PlatformID>{2E07F7E4-194C-4D20-B7C9-6F44A6C5A234}</PlatformID>
  <Rules>
${["Enabled:UMCI", "Required:WHQL", "Enabled:Inherit Default Policy", "Enabled:Unsigned System Integrity Policy",
  "Disabled:Script Enforcement", "Required:Enforce Store Applications", "Enabled:Update Policy No Reboot",
  "Enabled:Allow Supplemental Policies", "Enabled:Dynamic Code Security", "Enabled:Revoked Expired As Unsigned",
].map(option => `    <Rule>\n      <Option>${option}</Option>\n    </Rule>\n`).join("")}  </Rules>
  <FileRules>
    <Allow ID="ID_ALLOW_A_01A11AD07D26700D8EDAEAE7BCA230CA" FileName="*" />
    <Allow ID="ID_ALLOW_A_01A11AD07D267379A61354F55A54B548" FileName="*" />
${rules.map(rule => `    <Deny ID="${rule.id}" FriendlyName="${escape(rule.names)}" FilePath="${escape(rule.path)}" />\n`).join("")}  </FileRules>
  <SigningScenarios>
    <SigningScenario Value="12" ID="ID_SIGNINGSCENARIO_WINDOWS" FriendlyName="User Mode Code Integrity">
      <ProductSigners>
        <FileRulesRef>
          <FileRuleRef RuleID="ID_ALLOW_A_01A11AD07D26700D8EDAEAE7BCA230CA" />
${rules.map(rule => `          <FileRuleRef RuleID="${rule.id}" />\n`).join("")}        </FileRulesRef>
      </ProductSigners>
    </SigningScenario>
    <SigningScenario Value="131" ID="ID_SIGNINGSCENARIO_DRIVERS_1" FriendlyName="Kernel Mode Code Integrity">
      <ProductSigners>
        <FileRulesRef>
          <FileRuleRef RuleID="ID_ALLOW_A_01A11AD07D267379A61354F55A54B548" />
        </FileRulesRef>
      </ProductSigners>
    </SigningScenario>
  </SigningScenarios>
  <HvciOptions>2</HvciOptions>
  <Settings>
    <Setting Provider="AllHostIds" Key="AllKeys" ValueName="EnterpriseDefinedClsId">
      <Value>
        <Boolean>true</Boolean>
      </Value>
    </Setting>
    <Setting Provider="PolicyInfo" Key="Information" ValueName="Name">
      <Value>
        <String>Blocking RMMs - Remote Monitor and Management</String>
      </Value>
    </Setting>
    <Setting Provider="PolicyInfo" Key="Information" ValueName="Id">
      <Value>
        <String>129661</String>
      </Value>
    </Setting>
  </Settings>
</SiPolicy>
`;

const row = ({ type, key, names, vendor }) => [
  type, key, "2035-07-23T00:00:00Z", "Block", "Medium",
  `LOLRMM - ${names[0]}${names.length > 1 ? ` (+${names.length - 1} more)` : ""}`,
  `${type === "IpAddress" ? "IP address" : vendor ? "Vendor-wide network domain" : "Network domain"} associated with ${names.join("; ")} - listed by LOLRMM (Living Off the Land RMM) as a remote management or access tool.`,
  type === "IpAddress"
    ? "Block network traffic to/from this IP address and investigate any prior connections."
    : "Block connections to this domain and investigate any related activity.",
  "", "", "", "true",
];
const sorted = type => [...indicators.values()].filter(entry => entry.type === type)
  .sort((a, b) => a.key < b.key ? -1 : 1).map(row);
const domains = sorted("DomainName");
// The committed CSVs use LF line endings; editor downloads keep CRLF.
const csv = rows => serializeCsv(rows).replaceAll("\r\n", "\n");
const files = { "Blocking_RMMsv5.xml": xml };
// Defender imports at most 500 indicators per CSV.
for (let index = 0; index < domains.length; index += 500) {
  files[`IOC/Defender_IOC_LOLRMM_Domains_Part${index / 500 + 1}.csv`] = csv([iocHeaders, ...domains.slice(index, index + 500)]);
}
files["IOC/Defender_IOC_LOLRMM_IPs.csv"] = csv([iocHeaders, ...sorted("IpAddress")]);
const expected = iocSources.map(source => source.slice(2));
const csvs = Object.keys(files).filter(name => name.endsWith(".csv"));
if (JSON.stringify(csvs) !== JSON.stringify(expected)) {
  throw new Error(`CSV set changed to ${csvs.join(", ")}; update iocSources in ioc.js to match.`);
}

const stale = Object.keys(files).filter(name => {
  try { return readFileSync(join(root, name), "utf8") !== files[name]; } catch { return true; }
});
if (process.argv.includes("--check")) {
  if (stale.length) {
    console.error(`Out of date: ${stale.join(", ")}. Run node build.mjs and commit the result.`);
    process.exit(1);
  }
  console.log("Generated files are up to date.");
} else {
  for (const name of stale) writeFileSync(join(root, name), files[name]);
  console.log(`${rules.length} deny rules, ${indicators.size} IOCs. Updated: ${stale.join(", ") || "nothing"}.`);
}
