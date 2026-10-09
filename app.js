import { parsePolicy, excludedRuleIds, exportPolicy } from "./policy.js";
import { loadIocs, filterIocs, exportIocBatches } from "./ioc.js";

const byId = id => document.getElementById(id);
const excluded = new Set();
byId("link-iocs").checked = false;
let policy;
let tools = [];
let iocData;
let iocLoading = false;
let iocError;
let iocExportKey;
let iocUrls = [];
function releaseIocDownloads() {
  for (const url of iocUrls) URL.revokeObjectURL(url);
  iocUrls = [];
  iocExportKey = undefined;
  byId("ioc-downloads").replaceChildren();
}

function showIocError(error) {
  console.error(error);
  iocError = error;
  releaseIocDownloads();
  byId("ioc-error").textContent = `${error.message} CSVs unavailable; XML unaffected. Disable and re-enable IOC exports to retry.`;
  byId("ioc-error").hidden = false;
}

function attachIocDetails() {
  for (const entry of tools) {
    entry.iocs = iocData.indicators.filter(indicator => indicator.tools.includes(entry.tool.name));
    entry.iocSearchText = entry.iocs.map(indicator => indicator.value).join(" ").toLowerCase();
    const list = document.createElement("ul");
    list.className = "rule-list";
    for (const indicator of entry.iocs) {
      const item = document.createElement("li");
      const value = document.createElement("code");
      value.textContent = `${indicator.type}: ${indicator.value}`;
      const owners = document.createElement("span");
      owners.className = "rule-meta";
      owners.textContent = `Source attribution: ${indicator.owners.map(owner => owner.name).join("; ")}`;
      item.append(value, owners);
      list.append(item);
    }
    const summary = document.createElement("summary");
    summary.textContent = `IOCs (${entry.iocs.length})`;
    entry.iocDetails.replaceChildren(summary, list);
  }
  const unlinked = new Map();
  for (const indicator of iocData.indicators) {
    for (const owner of indicator.owners.filter(owner => !owner.tool)) {
      unlinked.set(owner.name, (unlinked.get(owner.name) || 0) + 1);
    }
  }
  byId("ioc-unlinked").hidden = !unlinked.size;
  byId("ioc-unlinked-summary").textContent = `${unlinked.size} unmatched tools stay blocked`;
  const list = document.createDocumentFragment();
  for (const [name, count] of [...unlinked].sort(([a], [b]) => a.localeCompare(b))) {
    const item = document.createElement("li");
    item.textContent = `${name}: ${count} indicator${count === 1 ? "" : "s"}`;
    list.append(item);
  }
  byId("ioc-unlinked-list").replaceChildren(list);
}

function updateIocs() {
  const enabled = byId("link-iocs").checked;
  byId("link-iocs").closest("section").classList.toggle("enabled", enabled);
  byId("ioc-output").hidden = !enabled;
  byId("ioc-status").hidden = !enabled || !!iocError;
  for (const entry of tools) {
    entry.iocCount.hidden = !enabled || !iocData || !!entry.iocs.length || !excluded.has(entry.tool.name);
    entry.iocDetails.hidden = !enabled || !entry.iocs.length;
    entry.iocCount.classList.toggle("unclassified-warning", enabled && excluded.has(entry.tool.name) && !entry.iocs.length);
    entry.iocCount.textContent = "No linked IOCs.";
  }
  if (!enabled) {
    releaseIocDownloads();
    byId("ioc-status").textContent = "";
    return;
  }
  if (iocLoading) {
    byId("ioc-status").textContent = "Loading IOCs...";
    return;
  }
  if (iocError) {
    byId("ioc-status").textContent = "";
    return;
  }
  if (!iocData) return;
  const key = JSON.stringify([...excluded].sort());
  if (key === iocExportKey) return;
  try {
    const { removed, retained, sharedRemoved } = filterIocs(iocData, excluded);
    const batches = exportIocBatches(retained);
    releaseIocDownloads();
    byId("ioc-status").textContent = `${retained.length} indicators kept · ${removed.length} removed · ${batches.length} CSV${batches.length === 1 ? "" : "s"}`;
    for (const [index, batch] of batches.entries()) {
      const url = URL.createObjectURL(new Blob([batch.csv], { type: "text/csv;charset=utf-8" }));
      iocUrls.push(url);
      const link = document.createElement("a");
      link.href = url;
      link.download = `Defender_IOCs${excluded.size ? "_custom" : ""}_Part${index + 1}_of${batches.length}.csv`;
      link.textContent = `CSV ${index + 1} / ${batches.length} · ${batch.count} indicators ↓`;
      byId("ioc-downloads").append(link);
    }
    byId("ioc-shared").hidden = !sharedRemoved.length;
    byId("ioc-shared-summary").textContent = `${sharedRemoved.length} shared indicator${sharedRemoved.length === 1 ? "" : "s"} removed for other tools`;
    const list = document.createDocumentFragment();
    for (const indicator of sharedRemoved) {
      const item = document.createElement("li");
      item.textContent = `${indicator.value}: ${indicator.owners.map(owner => owner.name).join("; ")}`;
      list.append(item);
    }
    byId("ioc-shared-list").replaceChildren(list);
    iocExportKey = key;
  } catch (error) {
    showIocError(error);
    byId("ioc-status").textContent = "";
    byId("ioc-status").hidden = true;
  }
}

async function enableIocs() {
  if (!byId("link-iocs").checked || iocLoading) { update(); return; }
  iocError = undefined;
  byId("ioc-error").hidden = true;
  if (iocData) { update(); return; }
  iocLoading = true;
  update();
  try {
    iocData = await loadIocs(policy.tools.map(tool => tool.name));
    attachIocDetails();
  } catch (error) {
    iocData = undefined;
    showIocError(error);
  } finally {
    iocLoading = false;
    update();
  }
}

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
  const filenames = tool.rules.length - folders;
  counts.textContent = [
    filenames ? `${filenames} filename${filenames === 1 ? "" : "s"}` : "",
    folders ? `${folders} folder${folders === 1 ? "" : "s"}` : "",
  ].filter(Boolean).join(" · ");
  heading.append(name, counts);
  const label = document.createElement("label");
  label.className = "exclude-label";
  const checkbox = document.createElement("input");
  checkbox.type = "checkbox";
  checkbox.setAttribute("aria-label", `Exclude ${tool.name} from block list`);
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
  if (tool.unclassified) {
    const note = document.createElement("p");
    note.className = "unclassified-warning";
    note.textContent = "Unconfirmed identity. Review the exact rule before excluding.";
    row.append(note);
  }
  const warning = document.createElement("p");
  warning.className = "shared-warning";
  warning.hidden = true;
  row.append(warning);
  const details = document.createElement("details");
  const summary = document.createElement("summary");
  summary.textContent = "Execution rules";
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
  const iocCount = document.createElement("p");
  iocCount.className = "rule-count ioc-count";
  iocCount.hidden = true;
  const iocDetails = document.createElement("details");
  iocDetails.hidden = true;
  row.append(iocCount, iocDetails);
  return {
    tool, row, checkbox, action, warning, iocCount, iocDetails, iocs: [], iocSearchText: "",
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
    entry.action.textContent = selected ? "Excluded" : "Exclude";
    entry.warning.hidden = !sharedRemoved.length;
    entry.warning.textContent = selected
      ? `Shared folder also removed for ${[...new Set(sharedRemoved.flatMap(rule => rule.names).filter(name => name !== entry.tool.name))].join(", ")}. Other rules retained.`
      : `${sharedRemoved.length} shared folder rule${sharedRemoved.length === 1 ? "" : "s"} removed by another exclusion. Other rules retained.`;
    const searchText = `${entry.searchText} ${byId("link-iocs").checked ? entry.iocSearchText : ""}`;
    entry.row.hidden = !searchText.includes(query) ||
      (filter === "excluded" && !selected) || (filter === "blocked" && selected);
    if (!entry.row.hidden) visible++;
  }
  byId("remaining-count").textContent = policy.rules.length - ids.size;
  byId("excluded-count").textContent = excluded.size;
  byId("removed-count").textContent = ids.size;
  byId("reset").disabled = !excluded.size;
  byId("results").textContent = `${visible} / ${tools.length} tools`;
  byId("empty").hidden = visible !== 0;
  byId("selection-details").hidden = !excluded.size;
  byId("selection-summary").textContent = `Excluded tools (${excluded.size})`;
  byId("selection-list").textContent = [...excluded].sort().join(", ");
  updateIocs();
}

byId("search").addEventListener("input", () => update());
byId("filter").addEventListener("change", () => update());
byId("reset").addEventListener("click", () => { excluded.clear(); update(); });
byId("link-iocs").addEventListener("change", enableIocs);
window.addEventListener("pagehide", releaseIocDownloads);
window.addEventListener("pageshow", () => { if (policy) update(); });
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
    byId("policy-version").textContent = `· v${policy.version}`;
    update();
    byId("editor").hidden = false;
  } catch (error) {
    showError(error);
  } finally {
    byId("loading").hidden = true;
  }
}

initialize();
