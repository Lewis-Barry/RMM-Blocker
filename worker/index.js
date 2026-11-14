// Cloudflare Worker on rmmguard.com/api/*: returns the latest published files minus the tools named in ?exclude=.
// Reads the live site on every request, so it never needs redeploying when products change.
import { iocSources, iocHeaders, combineIocs, filterIocs, serializeCsv } from "../ioc.js";
import { parseMacProducts, filterMacRules, buildIntunePolicy } from "../macos.js";

const site = "https://rmmguard.com/";
const policyFile = "Blocking_RMMsv5.xml";

class BadRequest extends Error {}

const entities = { amp: "&", lt: "<", gt: ">", quot: '"', apos: "'" };
const attribute = (tag, name) => tag.match(new RegExp(`\\s${name}="([^"]*)"`))?.[1]
  .replace(/&(amp|lt|gt|quot|apos);/g, (match, entity) => entities[entity]);
const ruleNames = tag => (attribute(tag, "FriendlyName") || "").split("; ").filter(Boolean);
const denyTags = /\s*<Deny\s[^>]*\/>/g;

// Tool names in the policy: the only names a link may exclude, same as the page.
export const policyTools = source => new Set((source.match(denyTags) || []).flatMap(ruleNames));

// String twin of exportPolicy in policy.js, because Workers have no DOMParser. tests.js checks the two agree.
export function filterPolicy(source, excluded) {
  if (!excluded.size) return source;
  const ids = new Set();
  const result = source.replace(denyTags, tag => {
    if (!ruleNames(tag).some(name => excluded.has(name))) return tag;
    ids.add(attribute(tag, "ID"));
    return "";
  });
  return result.replace(/\s*<FileRuleRef\s[^>]*\/>/g, tag => ids.has(attribute(tag, "RuleID")) ? "" : tag);
}

async function load(path) {
  const response = await fetch(new URL(path, site));
  if (!response.ok) throw new Error(`Unable to load ${path} (HTTP ${response.status}).`);
  return response.text();
}

const routes = {
  "/api/wdac.xml": ["application/xml", (policy, excluded) => filterPolicy(policy, excluded)],
  "/api/iocs.csv": ["text/csv", async (policy, excluded) => {
    const sources = await Promise.all(iocSources.map(async name => ({ name, text: await load(name) })));
    const { retained } = filterIocs(combineIocs(sources, policyTools(policy)), excluded);
    // One file with every row, unlike the page's 500-row batches.
    return serializeCsv([iocHeaders, ...retained.map(indicator => indicator.values)]);
  }],
  "/api/macos.json": ["application/json", async (policy, excluded) => {
    const data = parseMacProducts(JSON.parse(await load("products.json")));
    const covered = new Set(data.tools.map(tool => tool.name));
    const { retained } = filterMacRules(data, new Set([...excluded].filter(name => covered.has(name))));
    return buildIntunePolicy(retained, data.version);
  }],
};

export default {
  async fetch(request) {
    const url = new URL(request.url);
    const route = routes[url.pathname];
    if (!route) return new Response("Not found. Use /api/wdac.xml, /api/iocs.csv or /api/macos.json.\n", { status: 404 });
    try {
      const policy = await load(policyFile);
      const excluded = new Set(url.searchParams.getAll("exclude"));
      const known = policyTools(policy);
      const unknown = [...excluded].filter(name => !known.has(name));
      // Fail instead of ignoring: a renamed tool silently dropped from the exclusions would get blocked.
      if (unknown.length) throw new BadRequest(`Unknown tool in exclude: ${unknown.join(", ")}. Copy new links from ${site}`);
      return new Response(await route[1](policy, excluded), { headers: { "content-type": `${route[0]};charset=utf-8` } });
    } catch (error) {
      return new Response(`${error.message}\n`, { status: error instanceof BadRequest ? 400 : 502 });
    }
  },
};
