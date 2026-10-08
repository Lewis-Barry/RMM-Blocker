import { parsePolicy, excludedRuleIds, exportPolicy } from "./policy.js";

const byId = id => document.getElementById(id);
const excluded = new Set();
let policy;
let tools = [];

function showError(error) {
  console.error(error);
  byId("error").textContent = `${error.message} No policy was downloaded. Reload the page to retry.`;
  byId("error").hidden = false;
}

function makeTool(tool, index) {
  const row = document.createElement("article");
  row.className = "tool";
  const top = document.createElement("div");
  top.className = "tool-top";
  const heading = document.createElement("div");
  const name = document.createElement("div");
  name.className = "tool-title";
  name.id = `tool-${index}`;
  name.textContent = tool.name;
  const counts = document.createElement("div");
  counts.className = "rule-count";
  const folders = tool.rules.filter(rule => rule.kind === "Folder").length;
  counts.textContent = `${tool.rules.length} rules: ${tool.rules.length - folders} filename, ${folders} folder`;
  heading.append(name, counts);
  const label = document.createElement("label");
  label.className = "exclude-label";
  const checkbox = document.createElement("input");
  checkbox.type = "checkbox";
  checkbox.setAttribute("aria-label", `Exclude ${tool.name} from block list`);
  const action = document.createElement("span");
  action.textContent = "Exclude from block list";
  checkbox.addEventListener("change", () => {
    if (checkbox.checked) excluded.add(tool.name);
    else excluded.delete(tool.name);
    update();
  });
  label.append(checkbox, action);
  top.append(heading, label);
  row.append(top);
  if (tool.unclassified) {
    const note = document.createElement("p");
    note.className = "unclassified-warning";
    note.textContent = "Tool identity not confirmed. This entry controls only the exact rule shown below.";
    row.append(note);
  }
  const warning = document.createElement("p");
  warning.className = "shared-warning";
  warning.hidden = true;
  row.append(warning);
  const details = document.createElement("details");
  const summary = document.createElement("summary");
  summary.textContent = "View matching rules";
  const list = document.createElement("ul");
  list.className = "rule-list";
  for (const rule of tool.rules) {
    const item = document.createElement("li");
    const path = document.createElement("code");
    path.textContent = rule.path;
    const meta = document.createElement("span");
    meta.className = "rule-meta";
    meta.textContent = `${rule.kind} | ${rule.id} | ${rule.references} FileRuleRef${rule.references === 1 ? "" : "s"}` +
      (rule.names.length > 1 ? ` | Shared with: ${rule.names.filter(name => name !== tool.name).join(", ")}` : "");
    item.append(path, meta);
    list.append(item);
  }
  details.append(summary, list);
  row.append(details);
  return {
    tool, row, checkbox, action, warning,
    searchText: `${tool.name} ${tool.rules.map(rule => `${rule.path} ${rule.path.replaceAll("*", "")}`).join(" ")}`.toLowerCase(),
  };
}

function update() {
  const ids = excludedRuleIds(policy, excluded);
  const query = byId("search").value.trim().toLowerCase();
  const filter = byId("filter").value;
  let visible = 0;
  for (const entry of tools) {
    const selected = excluded.has(entry.tool.name);
    const sharedRemoved = entry.tool.rules.filter(rule => ids.has(rule.id) && rule.names.length > 1);
    entry.checkbox.checked = selected;
    entry.row.classList.toggle("excluded", selected);
    entry.action.textContent = selected ? "Excluded from block list" : "Exclude from block list";
    entry.warning.hidden = !sharedRemoved.length;
    entry.warning.textContent = selected
      ? `Shared folder removal also affects: ${[...new Set(sharedRemoved.flatMap(rule => rule.names).filter(name => name !== entry.tool.name))].join(", ")}. Their other rules stay blocked unless also selected.`
      : `${sharedRemoved.length} shared folder rule(s) removed by another selected tool. This tool's other block rules are retained.`;
    entry.row.hidden = !entry.searchText.includes(query) ||
      (filter === "excluded" && !selected) || (filter === "blocked" && selected);
    if (!entry.row.hidden) visible++;
  }
  byId("remaining-count").textContent = policy.rules.length - ids.size;
  byId("excluded-count").textContent = excluded.size;
  byId("removed-count").textContent = ids.size;
  byId("reset").disabled = !excluded.size;
  byId("results").textContent = `${visible} of ${tools.length} entries shown`;
  byId("empty").hidden = visible !== 0;
  const refs = policy.rules.filter(rule => ids.has(rule.id)).reduce((count, rule) => count + rule.references, 0);
  byId("export-summary").textContent = excluded.size
    ? `Download will remove ${ids.size} deny rules and ${refs} file rule references. Excluded: ${[...excluded].sort().join(", ")}.`
    : "No exclusions selected. Download will contain the original block list, unchanged.";
}

byId("search").addEventListener("input", () => update());
byId("filter").addEventListener("change", () => update());
byId("reset").addEventListener("click", () => { excluded.clear(); update(); });
byId("download").addEventListener("click", () => {
  try {
    const xml = exportPolicy(policy, excluded);
    const url = URL.createObjectURL(new Blob([xml], { type: "application/xml;charset=utf-8" }));
    const link = document.createElement("a");
    link.href = url;
    link.download = excluded.size ? "Blocking_RMMsv5_custom.xml" : "Blocking_RMMsv5.xml";
    document.body.append(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    byId("error").hidden = true;
  } catch (error) {
    showError(error);
  }
});

async function initialize() {
  try {
    const response = await fetch("./Blocking_RMMsv5.xml");
    if (!response.ok) throw new Error(`Unable to load the bundled XML (HTTP ${response.status}).`);
    policy = parsePolicy(await response.text());
    if (!policy.rules.length) throw new Error("The bundled policy does not contain any deny rules.");
    tools = policy.tools.map(makeTool);
    const fragment = document.createDocumentFragment();
    for (const entry of tools) fragment.append(entry.row);
    byId("tools").append(fragment);
    byId("policy-version").textContent = `Policy version ${policy.version}`;
    const unclassified = policy.tools.filter(tool => tool.unclassified);
    byId("catalog-note").textContent = `${unclassified.length} entries have unconfirmed tool identities and are marked Unclassified. Generic executable names cannot always be attributed to a product; inspect those rules separately.`;
    update();
    byId("editor").hidden = false;
  } catch (error) {
    showError(error);
  } finally {
    byId("loading").hidden = true;
  }
}

initialize();
