// Builds macOS 27 app control (Apple DDM com.apple.configuration.app.settings) deny lists from products.json.
// A denied binary is matched by Team ID (vendor-wide) or Team ID + Signing ID (one binary) and must carry at least one of the two.

const declarationType = "com.apple.configuration.app.settings";
// Intune settings catalog definition ids for the same declaration, from /beta/deviceManagement/configurationSettings.
const intuneIds = {
  root: "app_app",
  allowed: "app_allowed",
  denied: "app_allowed_deniedbinaries",
  teamId: "app_allowed_deniedbinaries_item_teamid",
  signingId: "app_allowed_deniedbinaries_item_signingid",
};

const teamIdPattern = /^[A-Z0-9]{10}$/;
// Team IDs that also sign everyday software. Denying one vendor-wide would stop Edge, Defender or Chrome on every Mac,
// so these are only accepted together with a Signing ID. Apple's own binaries have no Team ID and never match the pattern.
export const broadTeamIds = new Map([
  ["UBF8T346G9", "Microsoft"],
  ["EQHXZ8M8AV", "Google"],
  ["BQR82RBBHL", "Adobe"],
  ["2BUA8C4S2C", "1Password"],
  // Also signs the Cloudflare WARP client, so cloudflared is denied by Signing ID.
  ["68WVV388M8", "Cloudflare"],
]);

// Every rule needs a Team ID: Apple accepts Signing ID alone, but that would let a one-line products.json change deny
// com.apple.Safari or com.microsoft.teams2 on every supervised Mac, with no audit mode to catch it.
export function validateRule(name, rule) {
  if (!rule || typeof rule !== "object" || Array.isArray(rule)) throw new Error(`${name}: a macOS rule must be an object.`);
  const fields = Object.keys(rule);
  if (fields.some(field => !["teamId", "signingId"].includes(field))) throw new Error(`${name}: unknown macOS rule field.`);
  if (typeof rule.teamId !== "string" || !teamIdPattern.test(rule.teamId)) throw new Error(`${name}: invalid or missing Team ID ${JSON.stringify(rule.teamId)}.`);
  if (rule.signingId !== undefined && (typeof rule.signingId !== "string" || !/^[^\s"*]+$/.test(rule.signingId))) {
    throw new Error(`${name}: invalid Signing ID ${JSON.stringify(rule.signingId)}.`);
  }
  if (broadTeamIds.has(rule.teamId) && !rule.signingId) {
    throw new Error(`${name}: Team ID ${rule.teamId} belongs to ${broadTeamIds.get(rule.teamId)} and signs unrelated software; add a Signing ID.`);
  }
}

// The whole macos block of one product, shared by build.mjs and the page.
export function validateMacos(name, macos) {
  if (!macos || typeof macos !== "object") throw new Error(`${name}: macOS entry must be an object.`);
  for (const field of Object.keys(macos)) {
    if (!["rules", "source", "verified"].includes(field)) throw new Error(`${name}: macOS entry has unknown field "${field}".`);
  }
  if (!Array.isArray(macos.rules) || !macos.rules.length) throw new Error(`${name}: macOS entry has no rules.`);
  if (!/^\d{4}-\d{2}-\d{2}$/.test(macos.verified || "")) throw new Error(`${name}: macOS verified date must be YYYY-MM-DD.`);
  if (typeof macos.source !== "string" || !/^https:\/\//.test(macos.source)) throw new Error(`${name}: macOS source must be an https URL.`);
  for (const rule of macos.rules) validateRule(name, rule);
}

// Reads the products that have macOS rules. Shared rules are emitted once with every owner, like shared WDAC folders.
export function parseMacProducts(data) {
  if (!data || typeof data.products !== "object" || !/^\d+\.\d+\.\d+\.\d+$/.test(data.version || "")) {
    throw new Error("The bundled products.json is not valid.");
  }
  const rules = new Map();
  const tools = [];
  for (const [name, product] of Object.entries(data.products)) {
    if (!product.macos) continue;
    const { macos } = product;
    validateMacos(name, macos);
    const toolRules = [];
    for (const rule of macos.rules) {
      const key = JSON.stringify([rule.teamId || "", rule.signingId || ""]);
      const entry = rules.get(key) || rules.set(key, {
        id: key,
        teamId: rule.teamId,
        signingId: rule.signingId,
        kind: rule.signingId ? "Signing ID" : "Team ID",
        label: rule.signingId ? `${rule.signingId}${rule.teamId ? ` (${rule.teamId})` : ""}` : rule.teamId,
        names: [],
      }).get(key);
      if (entry.names.includes(name)) throw new Error(`${name}: duplicate macOS rule.`);
      entry.names.push(name);
      toolRules.push(entry);
    }
    tools.push({ name, rules: toolRules, source: macos.source, verified: macos.verified });
  }
  if (!tools.length) throw new Error("products.json has no macOS rules.");
  return {
    version: data.version,
    rules: [...rules.values()],
    tools: tools.sort((a, b) => a.name.localeCompare(b.name)),
  };
}

export async function loadMacProducts(url = "./products.json") {
  const response = await fetch(url);
  if (!response.ok) throw new Error(`Unable to load ${url} (HTTP ${response.status}).`);
  return parseMacProducts(await response.json());
}

// Excluding a tool removes every rule it owns, including rules shared with tools that stay blocked.
export function filterMacRules(data, excludedTools) {
  const known = new Set(data.tools.map(tool => tool.name));
  for (const name of excludedTools) {
    if (!known.has(name)) throw new Error(`Unknown tool selection: ${name}`);
  }
  const removed = [];
  const retained = [];
  for (const rule of data.rules) {
    (rule.names.some(name => excludedTools.has(name)) ? removed : retained).push(rule);
  }
  return {
    removed,
    retained,
    sharedRemoved: removed.filter(rule => rule.names.some(name => !excludedTools.has(name))),
  };
}

function binaryIdentifier(rule) {
  const identifier = {};
  if (rule.teamId) identifier.TeamID = rule.teamId;
  if (rule.signingId) identifier.SigningID = rule.signingId;
  return identifier;
}

const randomId = () => (globalThis.crypto?.randomUUID?.() || `${Date.now()}-${Math.random()}`).toUpperCase();

// The raw Apple declaration, for any MDM that accepts custom declarations. Identifier and ServerToken are fresh per download:
// a new ServerToken is what makes a device re-apply a changed declaration.
export function buildDeclaration(rules, version) {
  if (!rules.length) throw new Error("Every tool is excluded; the declaration would deny nothing.");
  return JSON.stringify({
    Type: declarationType,
    Identifier: randomId(),
    ServerToken: `rmm-guard-${version}-${randomId()}`,
    Payload: { Allowed: { DeniedBinaries: rules.map(binaryIdentifier) } },
  }, null, 2);
}

const stringValue = (settingDefinitionId, value) => ({
  "@odata.type": "#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance",
  settingDefinitionId,
  simpleSettingValue: { "@odata.type": "#microsoft.graph.deviceManagementConfigurationStringSettingValue", value },
});
const group = (settingDefinitionId, groupSettingCollectionValue) => ({
  "@odata.type": "#microsoft.graph.deviceManagementConfigurationGroupSettingCollectionInstance",
  settingDefinitionId,
  groupSettingCollectionValue,
});

// A settings catalog policy body for POST https://graph.microsoft.com/beta/deviceManagement/configurationPolicies.
export function buildIntunePolicy(rules, version) {
  if (!rules.length) throw new Error("Every tool is excluded; the policy would deny nothing.");
  const denied = rules.map(rule => ({
    children: [
      ...(rule.teamId ? [stringValue(intuneIds.teamId, rule.teamId)] : []),
      ...(rule.signingId ? [stringValue(intuneIds.signingId, rule.signingId)] : []),
    ],
  }));
  return JSON.stringify({
    name: "Block RMM tools (macOS)",
    description: `RMM Guard macOS deny list v${version}. Denies ${rules.length} binary identifiers through Apple DDM app settings. Requires macOS 27 and a supervised (Automated Device Enrollment) Mac.`,
    platforms: "macOS",
    technologies: "appleRemoteManagement",
    roleScopeTagIds: ["0"],
    settings: [{
      "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
      settingInstance: group(intuneIds.root, [{
        children: [group(intuneIds.allowed, [{ children: [group(intuneIds.denied, denied)] }])],
      }]),
    }],
  }, null, 2);
}

// Pre-filled issue so a visitor can send the codesign output for a tool that has no macOS rules yet.
export function reportMissingUrl(repository, toolName) {
  const title = `macOS rules for ${toolName}`;
  const body = [
    `Tool: ${toolName}`, "",
    "Install the Mac version, then run this on the app and on any helper or agent binary it installs, and paste the output:", "",
    "```", 'codesign -dvvv "/Applications/<App>.app" 2>&1 | grep -E "^(Identifier|TeamIdentifier)="', "```", "",
    "Download URL of the installer you checked:", "",
    "Does the vendor's Team ID also sign unrelated software (then list Signing IDs instead of the Team ID)?",
  ].join("\n");
  return `${repository}/issues/new?title=${encodeURIComponent(title)}&body=${encodeURIComponent(body)}`;
}
