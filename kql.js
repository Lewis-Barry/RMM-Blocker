// Only the keywords the generated query uses.
const KEYWORDS = new Set(["let", "dynamic", "where", "has_any", "or", "in", "project", "order", "by", "desc"]);

const escapeHtml = text => text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");

export function buildNetworkDiscoveryKql(indicators) {
  const domains = indicators.filter(indicator => indicator.type === "DomainName").map(indicator => indicator.value);
  const ips = indicators.filter(indicator => indicator.type === "IpAddress").map(indicator => indicator.value);
  const quote = value => `"${value.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
  const list = values => `dynamic([\n${values.map(value => `    ${quote(value)}`).join(",\n")}\n])`;
  return [
    "// RMM and Remote Access Tool Blocker - network discovery",
    "// Matches LOLRMM domains and IPs (Defender IOCs) against endpoint network connections.",
    "// Run in Microsoft Defender > Advanced hunting. Source: IOC/Defender_IOC_LOLRMM_*.csv",
    "// Domains match the hostname in RemoteUrl; a domain resolved to an IP not listed in RMMIPs is",
    "// only found when RemoteUrl carries the hostname.",
    `let RMMDomains = ${list(domains)};`,
    `let RMMIPs = ${list(ips)};`,
    "DeviceNetworkEvents",
    "| where RemoteUrl has_any (RMMDomains) or RemoteIP in~ (RMMIPs)",
    "| project Timestamp, DeviceName, ActionType, RemoteUrl, RemoteIP, RemotePort, InitiatingProcessFileName, InitiatingProcessFolderPath",
    "| order by Timestamp desc",
  ].join("\n");
}

const TOKEN = /(\/\/[^\n]*)|("(?:\\.|[^"\\])*")|(\b\d+(?:\.\d+)?\b)|([A-Za-z_][A-Za-z0-9_]*)|([^\sA-Za-z0-9_"]+)/g;

function lineStart(code, index) {
  const newline = code.lastIndexOf("\n", index - 1);
  return code.slice(newline + 1, index).trim() === "";
}

function isLetVariable(code, index) {
  return /\blet\s+$/.test(code.slice(0, index));
}

export function highlightKql(code) {
  let html = "";
  let last = 0;
  for (const match of code.matchAll(TOKEN)) {
    html += escapeHtml(code.slice(last, match.index));
    const [, comment, string, number, word, punct] = match;
    if (comment) html += `<span class="tok-comment">${escapeHtml(comment)}</span>`;
    else if (string) html += `<span class="tok-string">${escapeHtml(string)}</span>`;
    else if (number) html += `<span class="tok-num">${number}</span>`;
    else if (word) {
      const token = KEYWORDS.has(word) ? "tok-keyword"
        : isLetVariable(code, match.index) ? "tok-var"
        : /^[A-Z]/.test(word) && lineStart(code, match.index) ? "tok-table"
        : "";
      html += token ? `<span class="${token}">${escapeHtml(word)}</span>` : escapeHtml(word);
    } else html += `<span class="tok-op">${escapeHtml(punct)}</span>`;
    last = match.index + match[0].length;
  }
  return html + escapeHtml(code.slice(last));
}
