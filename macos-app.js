import { loadMacProducts, filterMacRules, buildDeclaration, buildIntunePolicy, reportMissingUrl } from "./macos.js";

const byId = id => document.getElementById(id);
const repository = document.querySelector(".source-link").href.replace(/\/$/, "");
const excluded = new Set();
let data;
let tools = [];

function saveFile(text, name, type) {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const link = document.createElement("a");
  link.href = url;
  link.download = name;
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function showError(error) {
  console.error(error);
  byId("error").textContent = `${error.message} No file was downloaded. Reload the page to retry.`;
  byId("error").hidden = false;
}

function makeTool(tool, index) {
  const row = document.createElement("li");
  row.className = "tool";
  const top = document.createElement("div");
  top.className = "tool-top";
  const heading = document.createElement("div");
  const name = document.createElement("h3");
  name.className = "tool-title";
  name.id = `tool-${index}`;
  name.textContent = tool.name;
  const counts = document.createElement("div");
  counts.className = "rule-count";
  counts.id = `rule-count-${index}`;
  const teamIds = tool.rules.filter(rule => rule.kind === "Team ID").length;
  const signingIds = tool.rules.length - teamIds;
  counts.textContent = [
    teamIds ? `${teamIds} Team ID${teamIds === 1 ? "" : "s"}` : "",
    signingIds ? `${signingIds} Signing ID${signingIds === 1 ? "" : "s"}` : "",
    `verified ${tool.verified}`,
  ].filter(Boolean).join(" · ");
  heading.append(name, counts);
  const label = document.createElement("label");
  label.className = "exclude-label";
  const checkbox = document.createElement("input");
  checkbox.type = "checkbox";
  checkbox.setAttribute("aria-label", `Exclude ${tool.name} from block list`);
  checkbox.setAttribute("aria-describedby", counts.id);
  const action = document.createElement("span");
  action.textContent = "Exclude";
  checkbox.addEventListener("change", () => {
    if (checkbox.checked) excluded.add(tool.name);
    else excluded.delete(tool.name);
    update();
  });
  label.append(checkbox, action);
  top.append(heading, label);
  row.append(top);
  const warning = document.createElement("p");
  warning.className = "shared-warning";
  warning.id = `shared-warning-${index}`;
  warning.hidden = true;
  row.append(warning);
  const details = document.createElement("details");
  const summary = document.createElement("summary");
  summary.textContent = "Denied binaries";
  summary.setAttribute("aria-label", `Denied binaries for ${tool.name}`);
  const list = document.createElement("ul");
  list.className = "compact-rule-list execution-rule-list";
  list.setAttribute("role", "list");
  for (const rule of tool.rules) {
    const item = document.createElement("li");
    const value = document.createElement("code");
    value.textContent = rule.label;
    const kind = document.createElement("span");
    kind.className = "rule-type";
    kind.textContent = rule.kind;
    item.append(value, kind);
    list.append(item);
  }
  const source = document.createElement("p");
  source.className = "muted";
  const link = document.createElement("a");
  link.href = tool.source;
  link.target = "_blank";
  link.rel = "noopener noreferrer";
  link.textContent = "Installer checked";
  source.append("Source: ", link);
  details.append(summary, list, source);
  row.append(details);
  return {
    tool, row, checkbox, warning,
    searchText: `${tool.name} ${tool.rules.map(rule => rule.label).join(" ")}`.toLowerCase(),
  };
}

function update() {
  const { retained, removed, sharedRemoved } = filterMacRules(data, excluded);
  const query = byId("search").value.trim().toLowerCase();
  const filter = byId("filter").value;
  let visible = 0;
  for (const entry of tools) {
    const selected = excluded.has(entry.tool.name);
    const shared = entry.tool.rules.filter(rule => sharedRemoved.includes(rule));
    entry.checkbox.checked = selected;
    entry.row.classList.toggle("excluded", selected);
    entry.warning.hidden = !shared.length;
    entry.warning.textContent = selected
      ? `Shared rule also removed for ${[...new Set(shared.flatMap(rule => rule.names).filter(name => name !== entry.tool.name))].join(", ")}.`
      : `${shared.length} shared rule${shared.length === 1 ? "" : "s"} removed by another exclusion.`;
    entry.checkbox.setAttribute("aria-describedby", [`rule-count-${tools.indexOf(entry)}`, entry.warning.hidden ? "" : entry.warning.id].filter(Boolean).join(" "));
    entry.row.hidden = !entry.searchText.includes(query) ||
      (filter === "excluded" && !selected) || (filter === "blocked" && selected);
    if (!entry.row.hidden) visible++;
  }
  byId("remaining-count").textContent = retained.length;
  byId("removed-count").textContent = removed.length;
  byId("excluded-count").textContent = excluded.size;
  byId("reset").disabled = !excluded.size;
  byId("results").textContent = `${visible} / ${tools.length} tools`;
  byId("empty").hidden = visible !== 0;
  byId("selection-details").hidden = !excluded.size;
  byId("selection-summary").textContent = `Excluded tools (${excluded.size})`;
  byId("selection-list").replaceChildren(...[...excluded].sort().map(name => {
    const item = document.createElement("li");
    item.textContent = name;
    return item;
  }));
  // An empty deny list is a valid declaration that does nothing, so the downloads refuse it.
  for (const id of ["download-ddm", "download-intune"]) byId(id).disabled = !retained.length;
}

function download(build, name) {
  try {
    const { retained } = filterMacRules(data, excluded);
    saveFile(build(retained, data.version), excluded.size ? name.replace(/\.json$/, "_custom.json") : name, "application/json;charset=utf-8");
    byId("error").hidden = true;
  } catch (error) {
    showError(error);
  }
}

byId("search").addEventListener("input", () => update());
byId("filter").addEventListener("change", () => update());
byId("reset").addEventListener("click", () => { excluded.clear(); update(); });
byId("download-ddm").addEventListener("click", () => download(buildDeclaration, "RMM_Denied_Binaries_macOS.json"));
byId("download-intune").addEventListener("click", () => download(buildIntunePolicy, "RMM_Denied_Binaries_Intune.json"));
window.addEventListener("pageshow", () => { if (data) update(); });

async function initialize() {
  try {
    data = await loadMacProducts();
    tools = data.tools.map(makeTool);
    const fragment = document.createDocumentFragment();
    for (const entry of tools) fragment.append(entry.row);
    byId("tool-list").append(fragment);
    byId("policy-version").textContent = `· v${data.version}`;
    byId("report-missing").href = reportMissingUrl(repository, "<tool name>");
    update();
    byId("editor").hidden = false;
  } catch (error) {
    showError(error);
  } finally {
    byId("loading").hidden = true;
  }
}

initialize();
