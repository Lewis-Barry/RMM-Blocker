import { classifyRule } from "./catalog.js";

const namespace = "urn:schemas-microsoft-com:sipolicy";

export function parsePolicy(source) {
  const document = new DOMParser().parseFromString(source, "application/xml");
  if (document.getElementsByTagName("parsererror").length ||
      document.documentElement.localName !== "SiPolicy" ||
      document.documentElement.namespaceURI !== namespace) {
    throw new Error("The bundled file is not a valid WDAC SiPolicy XML document.");
  }
  const fileRules = document.getElementsByTagNameNS(namespace, "FileRules");
  if (fileRules.length !== 1) throw new Error("Expected exactly one FileRules section.");
  const ids = new Set();
  for (const node of fileRules[0].children) {
    const id = node.getAttribute("ID");
    if (!id || ids.has(id)) throw new Error(`Missing or duplicate file rule ID: ${id}`);
    ids.add(id);
  }
  const references = Array.from(document.getElementsByTagNameNS(namespace, "FileRuleRef"));
  for (const reference of references) {
    if (!ids.has(reference.getAttribute("RuleID"))) {
      throw new Error(`Unresolved file rule reference: ${reference.getAttribute("RuleID")}`);
    }
  }
  const refCounts = new Map();
  for (const reference of references) {
    const id = reference.getAttribute("RuleID");
    refCounts.set(id, (refCounts.get(id) || 0) + 1);
  }
  const tools = new Map();
  const rules = Array.from(fileRules[0].children).filter(node => node.localName === "Deny").map(node => {
    const { names, unclassified } = classifyRule(node);
    const rule = {
      id: node.getAttribute("ID"),
      path: node.getAttribute("FilePath") || node.getAttribute("FileName") || "",
      kind: (node.getAttribute("FilePath") || "").endsWith("\\*") ? "Folder" : "Filename",
      names,
      references: refCounts.get(node.getAttribute("ID")) || 0,
    };
    for (const name of names) {
      if (!tools.has(name)) tools.set(name, { name, unclassified, rules: [] });
      tools.get(name).rules.push(rule);
    }
    return rule;
  });
  return {
    source,
    document,
    rules,
    tools: Array.from(tools.values()).sort((a, b) =>
      Number(a.unclassified) - Number(b.unclassified) || a.name.localeCompare(b.name)),
    version: document.getElementsByTagNameNS(namespace, "VersionEx")[0]?.textContent || "Unknown",
  };
}

export function excludedRuleIds(policy, excludedTools) {
  const knownTools = new Set(policy.tools.map(tool => tool.name));
  for (const name of excludedTools) {
    if (!knownTools.has(name)) throw new Error(`Unknown tool selection: ${name}`);
  }
  return new Set(policy.rules.filter(rule => rule.names.some(name => excludedTools.has(name))).map(rule => rule.id));
}

export function exportPolicy(policy, excludedTools) {
  const ids = excludedRuleIds(policy, excludedTools);
  if (!ids.size) return policy.source;
  const document = policy.document.cloneNode(true);
  const removeNode = node => {
    const preceding = node.previousSibling;
    if (preceding?.nodeType === 3 && !preceding.textContent.trim()) preceding.remove();
    node.remove();
  };
  for (const node of Array.from(document.getElementsByTagNameNS(namespace, "Deny"))) {
    if (ids.has(node.getAttribute("ID"))) removeNode(node);
  }
  for (const node of Array.from(document.getElementsByTagNameNS(namespace, "FileRuleRef"))) {
    if (ids.has(node.getAttribute("RuleID"))) removeNode(node);
  }
  const declaration = policy.source.match(/^\uFEFF?(<\?xml[^?]*\?>)/)?.[1] ||
    '<?xml version="1.0" encoding="utf-8"?>';
  const result = `${declaration}\n${new XMLSerializer().serializeToString(document)}`;
  parsePolicy(result);
  return result;
}
