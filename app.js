import { parsePolicy, excludedRuleIds, exportPolicy } from "./policy.js";
import { loadIocs, filterIocs, exportIocBatches, serializeCsv, iocHeaders } from "./ioc.js";
import { buildNetworkDiscoveryKql, highlightKql } from "./kql.js";

const byId = id => document.getElementById(id);
const excluded = new Set();
byId("link-iocs").checked = false;
let policy;
let tools = [];
let iocData;
let iocLoading = false;
let iocError;
let iocExportKey;
let iocBatches = [];
let iocPromise;
let kqlText = "";
let pendingCsv;
// One shared load for the IOC toggle and the KQL popup; a failure clears it so the next try refetches.
function loadIocsOnce() {
  return iocPromise ||= loadIocs(policy.tools.map(tool => tool.name)).catch(error => {
    iocPromise = undefined;
    throw error;
  });
}

function releaseIocDownloads() {
  iocBatches = [];
  iocExportKey = undefined;
  byId("ioc-download").hidden = true;
}

function showIocError(error) {
  console.error(error);
  iocError = error;
  releaseIocDownloads();
  byId("ioc-error").textContent = `${error.message} CSVs unavailable; XML unaffected. Disable and re-enable IOC exports to retry.`;
  byId("ioc-error").hidden = false;
}

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

function makeRuleItem(value, kind) {
  const item = document.createElement("li");
  const path = document.createElement("code");
  path.textContent = value;
  const type = document.createElement("span");
  type.className = "rule-type";
  type.textContent = kind;
  item.append(path, type);
  return item;
}

function attachIocDetails() {
  for (const entry of tools) {
    entry.iocs = iocData.indicators.filter(indicator => indicator.tools.includes(entry.tool.name));
    entry.iocSearchText = entry.iocs.map(indicator => indicator.value).join(" ").toLowerCase();
    const list = document.createElement("ul");
    list.className = "compact-rule-list ioc-list";
    list.setAttribute("role", "list");
    for (const indicator of entry.iocs) {
      list.append(makeRuleItem(indicator.value, indicator.type === "IpAddress" ? "IP address" : "Domain"));
    }
    const summary = document.createElement("summary");
    summary.textContent = `IOCs (${entry.iocs.length})`;
    summary.setAttribute("aria-label", `${summary.textContent} for ${entry.tool.name}`);
    entry.iocDetails.replaceChildren(summary, list);
  }
}

function csvText(indicators) {
  return serializeCsv([iocHeaders, ...indicators.map(indicator => indicator.values)]);
}

function updateCsvChoice() {
  const total = iocBatches.reduce((sum, batch) => sum + batch.count, 0);
  const skipped = pendingCsv.skipped.size;
  const files = `${iocBatches.length} CSV${iocBatches.length === 1 ? "" : "s"}`;
  byId("csv-download").disabled = skipped === total;
  byId("csv-download").textContent = skipped ? `Download without ${skipped}` : `Download ${files}`;
}

// Saves every batch, leaving out the skipped indicators. Staggered so browsers don't drop the extra files.
function downloadCsvs(skipped) {
  iocBatches.forEach((batch, index) => {
    const rows = batch.indicators.filter(indicator => !skipped.has(indicator));
    if (!rows.length) return;
    const name = skipped.size ? batch.name.replace(/\.csv$/, "_excluded.csv") : batch.name;
    setTimeout(() => saveFile(csvText(rows), name, "text/csv;charset=utf-8"), index * 500);
  });
}

function openCsvChoice(unmatched) {
  pendingCsv = { skipped: new Set() };
  byId("csv-modal-desc").textContent = "There is not a WDAC entry for every remote tool domain you could network block. Remove the tools you use within your business. Tick any indicator to leave it out of every CSV.";
  byId("csv-modal-list").replaceChildren(...unmatched.map(({ indicator, part }) => {
    const item = document.createElement("li");
    const box = document.createElement("input");
    box.type = "checkbox";
    box.setAttribute("aria-label", `Leave ${indicator.value} out of every CSV`);
    box.addEventListener("change", () => {
      if (box.checked) pendingCsv.skipped.add(indicator);
      else pendingCsv.skipped.delete(indicator);
      updateCsvChoice();
    });
    const code = document.createElement("code");
    code.textContent = indicator.value;
    const type = document.createElement("span");
    type.className = "rule-type";
    type.textContent = `${indicator.type === "IpAddress" ? "IP" : "Domain"} · CSV ${part}`;
    item.append(box, code, type);
    return item;
  }));
  updateCsvChoice();
  byId("csv-modal").showModal();
}

function updateIocs() {
  const enabled = byId("link-iocs").checked;
  byId("link-iocs").closest("section").classList.toggle("enabled", enabled);
  byId("ioc-output").hidden = !enabled;
  byId("ioc-status").hidden = !enabled || !!iocError;
  byId("tools").setAttribute("aria-busy", String(iocLoading));
  for (const entry of tools) {
    entry.iocCount.hidden = !enabled || !iocData || !!entry.iocs.length || !excluded.has(entry.tool.name);
    entry.iocDetails.hidden = !enabled || !entry.iocs.length;
    entry.iocCount.classList.toggle("unclassified-warning", enabled && excluded.has(entry.tool.name) && !entry.iocs.length);
    entry.iocCount.textContent = "No linked IOCs.";
    entry.checkbox.setAttribute("aria-describedby",
      [entry.counts, entry.warning, entry.iocCount]
        .filter(element => element && !element.hidden)
        .map(element => element.id).join(" "));
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
    const { retained, sharedRemoved } = filterIocs(iocData, excluded);
    const batches = exportIocBatches(retained);
    releaseIocDownloads();
    byId("ioc-status").textContent = `${retained.length} indicators kept · ${iocData.indicators.length - retained.length} removed · ${batches.length} CSV${batches.length === 1 ? "" : "s"}`;
    iocBatches = batches.map((batch, index) => ({
      ...batch,
      name: `Defender_IOCs${excluded.size ? "_custom" : ""}_Part${index + 1}_of${batches.length}.csv`,
    }));
    byId("ioc-download").textContent = `Download ${batches.length === 1 ? "1 CSV" : `${batches.length} CSVs`}`;
    byId("ioc-download").hidden = !batches.length;
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
    iocData = await loadIocsOnce();
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
  const warning = document.createElement("p");
  warning.className = "shared-warning";
  warning.id = `shared-warning-${index}`;
  warning.hidden = true;
  row.append(warning);
  const details = document.createElement("details");
  const summary = document.createElement("summary");
  summary.textContent = "Execution rules";
  summary.setAttribute("aria-label", `Execution rules for ${tool.name}`);
  const list = document.createElement("ul");
  list.className = "compact-rule-list execution-rule-list";
  list.setAttribute("role", "list");
  for (const rule of tool.rules) {
    list.append(makeRuleItem(rule.path, rule.kind));
  }
  details.append(summary, list);
  row.append(details);
  const iocCount = document.createElement("p");
  iocCount.className = "rule-count ioc-count";
  iocCount.id = `ioc-coverage-${index}`;
  iocCount.hidden = true;
  const iocDetails = document.createElement("details");
  iocDetails.hidden = true;
  row.append(iocCount, iocDetails);
  return {
    tool, row, checkbox, counts, warning, iocCount, iocDetails, iocs: [], iocSearchText: "",
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
  byId("selection-list").replaceChildren(...[...excluded].sort().map(name => {
    const item = document.createElement("li");
    item.textContent = name;
    return item;
  }));
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
    saveFile(xml, excluded.size ? "Blocking_RMMsv5_custom.xml" : "Blocking_RMMsv5.xml", "application/xml;charset=utf-8");
    byId("error").hidden = true;
  } catch (error) {
    showError(error);
  }
});

byId("ioc-download").addEventListener("click", () => {
  const unmatched = iocBatches.flatMap((batch, index) => batch.indicators
    .filter(indicator => !indicator.tools.length)
    .map(indicator => ({ indicator, part: index + 1 })));
  if (unmatched.length) openCsvChoice(unmatched);
  else downloadCsvs(new Set());
});
byId("csv-download").addEventListener("click", () => {
  downloadCsvs(pendingCsv.skipped);
  byId("csv-modal").close();
});
byId("csv-close").addEventListener("click", () => byId("csv-modal").close());
byId("csv-modal").addEventListener("click", event => {
  if (event.target === byId("csv-modal")) byId("csv-modal").close();
});

byId("kql-open").addEventListener("click", async () => {
  const errorBox = byId("kql-error");
  errorBox.hidden = true;
  byId("kql-code").textContent = "";
  byId("kql-copy").disabled = true;
  try {
    kqlText = buildNetworkDiscoveryKql((await loadIocsOnce()).indicators);
    byId("kql-code").innerHTML = highlightKql(kqlText);
    byId("kql-copy").disabled = false;
  } catch (error) {
    console.error(error);
    errorBox.textContent = `Unable to build the KQL: ${error.message}`;
    errorBox.hidden = false;
  }
  byId("kql-modal").showModal();
});

byId("kql-close").addEventListener("click", () => byId("kql-modal").close());
// A click on the dialog element itself lands on the backdrop, outside the content box.
byId("kql-modal").addEventListener("click", event => {
  if (event.target === byId("kql-modal")) byId("kql-modal").close();
});

byId("kql-copy").addEventListener("click", async () => {
  const button = byId("kql-copy");
  try {
    await navigator.clipboard.writeText(kqlText);
  } catch (error) {
    console.error(error);
    return;
  }
  button.textContent = "Copied";
  setTimeout(() => { button.textContent = "Copy query"; }, 1500);
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
    byId("tool-list").append(fragment);
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
