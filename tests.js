import { parsePolicy, exportPolicy, excludedRuleIds } from "./policy.js";
import { loadIocs, combineIocs, parseCsv, serializeCsv, iocHeaders, filterIocs, exportIocBatches } from "./ioc.js";
import { buildNetworkDiscoveryKql, highlightKql } from "./kql.js";
import { parseMacProducts, filterMacRules, buildDeclaration, buildIntunePolicy, reportMissingUrl } from "./macos.js";

const ns = "urn:schemas-microsoft-com:sipolicy";
const output = document.getElementById("test-output");
const status = document.getElementById("test-status");
let failures = 0;
let passed = 0;

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function contrastRatio(foreground, background) {
  const luminance = color => color.match(/[\d.]+/g).slice(0, 3).map(Number).map(value => {
    value /= 255;
    return value <= .04045 ? value / 12.92 : ((value + .055) / 1.055) ** 2.4;
  }).reduce((sum, value, index) => sum + value * [.2126, .7152, .0722][index], 0);
  const first = luminance(foreground);
  const second = luminance(background);
  return (Math.max(first, second) + .05) / (Math.min(first, second) + .05);
}

function expectError(action, text) {
  let error;
  try { action(); } catch (caught) { error = caught; }
  assert(error?.message.includes(text), `Expected error containing "${text}", received ${error?.message}`);
}

function elements(document, name) {
  return Array.from(document.getElementsByTagNameNS(ns, name));
}

function signature(node) {
  if (node.nodeType === 3) return node.textContent.trim() || null;
  if (node.nodeType !== 1) return null;
  return {
    name: node.localName,
    namespace: node.namespaceURI,
    attributes: Array.from(node.attributes).map(attr => [attr.name, attr.value]).sort(),
    children: Array.from(node.childNodes).map(signature).filter(value => value !== null),
  };
}

function test(name, action) {
  try {
    action();
    passed++;
    output.textContent += `PASS ${name}\n`;
  } catch (error) {
    failures++;
    output.textContent += `FAIL ${name}: ${error.message}\n`;
    console.error(error);
  }
}

async function waitFor(condition, message) {
  const deadline = Date.now() + 10000;
  while (!condition()) {
    if (Date.now() >= deadline) throw new Error(message);
    await new Promise(resolve => setTimeout(resolve, 25));
  }
}

// Runs an action that saves CSVs and returns each saved file's name and text instead of letting the browser download it.
async function collectCsvs(doc, action, expected) {
  const saved = [];
  const capture = event => {
    const link = event.target.closest("a[download]");
    if (!link?.download.endsWith(".csv")) return;
    event.preventDefault();
    saved.push(fetch(link.href).then(response => response.text()).then(text => ({ name: link.download, text })));
  };
  doc.addEventListener("click", capture, true);
  try {
    action();
    await waitFor(() => saved.length >= expected, "CSV downloads did not start");
    return await Promise.all(saved);
  } finally {
    doc.removeEventListener("click", capture, true);
  }
}

// Counts follow the data, so a products.json update changes the expected numbers without editing tests.
const batchSizes = count => Array.from({ length: Math.ceil(count / 500) }, (_, index) => Math.min(500, count - index * 500));
const csvCount = count => count === 1 ? "1 CSV" : `${count} CSVs`;
const linkedTo = (iocs, name) => iocs.indicators.filter(row => row.tools.includes(name)).length;

async function testBuilder(policy, iocs) {
  const dattoCount = linkedTo(iocs, "Datto RMM / Autotask");
  const keptCount = iocs.indicators.length - dattoCount;
  const frame = document.createElement("iframe");
  frame.hidden = true;
  frame.title = "Builder regression fixture";
  frame.src = "./index.html";
  document.body.append(frame);
  try {
    await waitFor(() => frame.contentDocument?.getElementById("editor")?.hidden === false,
      "Builder did not initialize");
    const document = frame.contentDocument;
    const byId = id => document.getElementById(id);
    const change = element => element.dispatchEvent(new frame.contentWindow.Event("change", { bubbles: true }));
    const input = element => element.dispatchEvent(new frame.contentWindow.Event("input", { bubbles: true }));
    const selection = document.querySelector('input[aria-label="Exclude Datto RMM / Autotask from block list"]');
    frame.hidden = false;
    frame.style.cssText = "position: fixed; top: 0; left: 0; border: 0; z-index: -1; pointer-events: none;";
    try {
      for (const [width, height] of [[1440, 768], [1280, 600], [1024, 600], [768, 768], [390, 844], [320, 568], [1024, 400]]) {
        frame.style.width = `${width}px`;
        frame.style.height = `${height}px`;
        test(`Compact builder fits ${width}x${height} without clipping downloads`, () => {
          const rect = selector => document.querySelector(selector).getBoundingClientRect();
          assert(document.documentElement.scrollWidth <= width, "Page overflows horizontally");
          const panel = rect(".export-panel");
          assert(panel.left >= 0 && panel.right <= width, "Download panel is outside the viewport");
          const row = rect(".tool");
          const touch = frame.contentWindow.matchMedia("(pointer: coarse)").matches;
          const wrappedTitle = width < 390 ? 24 : 0;
          assert(row.height <= (touch ? 108 : 96) + wrappedTitle, `Collapsed product row is too tall: ${row.height}px`);
          if (width > 800 && height >= 600) {
            const content = rect(".export-content");
            for (const selector of [".export-card", ".ioc-panel", "#kql-open"]) {
              const card = rect(selector);
              assert(card.top >= content.top && card.bottom <= content.bottom,
                `${selector} requires scrolling in the initial desktop layout`);
            }
          } else {
            assert(document.documentElement.scrollHeight > height, "Stacked or short layout cannot scroll");
          }
        });
      }
    } finally {
      frame.hidden = true;
      frame.removeAttribute("style");
    }
    test("Builder starts with one tool list, no exclusions and CSVs disabled", () => {
      assert(!document.querySelector(".page-heading"), "Repeated builder heading remains");
      assert(parseFloat(frame.contentWindow.getComputedStyle(document.querySelector(".builder-intro")).fontSize) >= 16,
        "Introductory instruction is too small");
      assert(!byId("paths") && document.querySelectorAll("#tools").length === 1, "Unexpected path selector or tool lists");
      assert(!byId("link-iocs").checked && byId("ioc-output").hidden, "CSVs enabled by default");
      assert(byId("ioc-status").hidden && !byId("ioc-status").textContent, "Disabled exports show redundant status copy");
      assert(!byId("export-summary"), "Redundant export narrative remains");
      assert(byId("excluded-count").textContent === "0", "Unexpected initial exclusion");
      assert(byId("remaining-count").textContent === String(policy.rules.length), "Initial rules incorrect");
    });
    test("Tool rows expose list items, headings and named native controls", () => {
      const list = byId("tool-list");
      assert(list.tagName === "UL" && list.getAttribute("role") === "list", "Tool list semantics missing");
      assert(list.children.length === policy.tools.length, "Tool list omits entries");
      for (const row of list.children) {
        const heading = row.querySelector(".tool-title");
        const checkbox = row.querySelector('input[type="checkbox"]');
        const summary = row.querySelector("summary");
        assert(row.tagName === "LI" && heading.tagName === "H3", "Row or heading semantics missing");
        assert(checkbox.labels.length === 1 && checkbox.getAttribute("aria-label").includes(heading.textContent),
          "Checkbox label does not identify its tool");
        assert(summary.getAttribute("aria-label") === `Execution rules for ${heading.textContent}`,
          "Disclosure name does not identify its tool");
        const descriptions = checkbox.getAttribute("aria-describedby").split(" ").map(byId);
        assert(descriptions.length && descriptions.every(element => element && !element.hidden),
          "Checkbox references missing or hidden descriptions");
      }
      assert(document.querySelector(".selection-count").getAttribute("aria-atomic") === "true",
        "Selection announcements lack context");
    });
    test("Execution rules show compact path/type rows in one shaded, unbulleted group", () => {
      const rows = new Map([...byId("tool-list").children].map(row =>
        [row.querySelector(".tool-title").textContent, row]));
      for (const tool of policy.tools) {
        const list = rows.get(tool.name).querySelector(".execution-rule-list");
        const style = frame.contentWindow.getComputedStyle(list);
        assert(list.tagName === "UL" && list.getAttribute("role") === "list", "Rule list semantics missing");
        assert(style.listStyleType === "none", "Rule bullets remain");
        assert(style.backgroundColor !== "rgba(0, 0, 0, 0)" && style.paddingLeft === "16px",
          "Rules do not share a shaded container");
        assert(list.children.length === tool.rules.length, "Displayed rules missing");
        for (const [index, item] of [...list.children].entries()) {
          assert(item.children.length === 2 && item.querySelector("code").textContent === tool.rules[index].path &&
            item.querySelector(".rule-type").textContent === tool.rules[index].kind,
          "Rule does not display only its original path and type");
          const itemStyle = frame.contentWindow.getComputedStyle(item);
          assert(itemStyle.backgroundColor === "rgba(0, 0, 0, 0)" && itemStyle.borderTopWidth === "0px" &&
            parseFloat(itemStyle.paddingTop) <= 8 && parseFloat(itemStyle.paddingBottom) <= 8,
          "Execution rule still uses a padded card");
        }
      }
    });
    const sharedSelection = document.querySelector('input[aria-label="Exclude ConnectWise Control / ScreenConnect from block list"]');
    sharedSelection.click();
    test("Shared-folder warnings describe the affected checkbox", () => {
      const warning = sharedSelection.closest(".tool").querySelector(".shared-warning");
      assert(!warning.hidden && sharedSelection.getAttribute("aria-describedby").split(" ").includes(warning.id),
        "Shared-folder warning is not associated with the control");
      assert(sharedSelection.labels[0].textContent.trim() === "Exclude", "Checkbox label changes with its state");
    });
    sharedSelection.click();
    test("Clearing an exclusion removes its hidden warning description", () => {
      const warning = sharedSelection.closest(".tool").querySelector(".shared-warning");
      assert(warning.hidden && !sharedSelection.getAttribute("aria-describedby").split(" ").includes(warning.id),
        "Hidden warning still describes the control");
    });
    test("Row text meets 4.5:1 contrast in both themes and selection states", () => {
      const row = selection.closest(".tool");
      const details = row.querySelector("details");
      const initialTheme = document.documentElement.dataset.theme;
      const initialOpen = details.open;
      const style = element => frame.contentWindow.getComputedStyle(element);
      try {
        details.open = true;
        for (const theme of ["dark", "light"]) {
          document.documentElement.dataset.theme = theme;
          for (const selected of [false, true]) {
            if (selection.checked !== selected) selection.click();
            for (const element of row.querySelectorAll(".tool-title, .rule-count, .exclude-label span, summary, code, .rule-type, dt, dd")) {
              if (element.closest("[hidden]")) continue;
              let surface = element;
              while (style(surface).backgroundColor === "rgba(0, 0, 0, 0)" && surface.parentElement) {
                surface = surface.parentElement;
              }
              assert(contrastRatio(style(element).color, style(surface).backgroundColor) >= 4.5,
                `${theme}: insufficient contrast for ${element.textContent}`);
              assert(parseFloat(style(element).fontSize) >= 14, "Row data text is smaller than 14px");
            }
          }
        }
        assert(parseFloat(style(row.querySelector(".exclude-label")).minHeight) >= 44,
          "Exclusion target is smaller than 44px");
        const minimumDisclosureHeight = frame.contentWindow.matchMedia("(pointer: coarse)").matches ? 44 : 32;
        assert(parseFloat(style(row.querySelector("summary")).minHeight) >= minimumDisclosureHeight,
          "Disclosure target is too small for the input device");
        assert(parseFloat(style(selection).width) >= 24 && parseFloat(style(selection).height) >= 24,
          "Checkbox is smaller than 24px");
      } finally {
        if (selection.checked) selection.click();
        details.open = initialOpen;
        document.documentElement.dataset.theme = initialTheme;
      }
    });
    selection.click();
    const expectedRemoved = excludedRuleIds(policy, new Set(["Datto RMM / Autotask"])).size;
    test("Tool selection updates the final XML summary and exclusion review", () => {
      assert(byId("excluded-count").textContent === "1", "Exclusion not counted");
      assert(byId("removed-count").textContent === String(expectedRemoved), "Wrong removed count");
      assert(byId("wdac-status").textContent.includes(`${expectedRemoved} removed`), "XML summary stale");
      assert(!byId("selection-details").hidden && byId("selection-list").textContent === "Datto RMM / Autotask",
        "Exclusion review missing");
    });
    test("Exclusion review lists one tool per line in alphabetical order", () => {
      try {
        sharedSelection.click();
        const list = byId("selection-list");
        assert(list.tagName === "UL" && list.getAttribute("role") === "list", "Exclusion list semantics missing");
        assert([...list.children].every(item => item.tagName === "LI"), "Exclusions are not separate list items");
        assert(JSON.stringify([...list.children].map(item => item.textContent)) ===
          JSON.stringify(["ConnectWise Control / ScreenConnect", "Datto RMM / Autotask"]),
        "Exclusion list is incomplete or unsorted");
        assert(frame.contentWindow.getComputedStyle(list).listStyleType === "none", "Exclusion bullets remain");
        assert(byId("selection-summary").textContent === "Excluded tools (2)", "Exclusion count is stale");
      } finally {
        if (sharedSelection.checked) sharedSelection.click();
      }
    });
    byId("link-iocs").click();
    await waitFor(() => !byId("ioc-download").hidden || !byId("ioc-error").hidden,
      "IOC exports were not prepared");
    test("Enabling IOC exports applies the existing selection to the CSV batches", () => {
      const sizes = batchSizes(keptCount);
      assert(byId("ioc-error").hidden, byId("ioc-error").textContent);
      assert(selection.checked && byId("link-iocs").checked, "Enabling IOC exports cleared selection");
      assert(byId("ioc-status").textContent === `${keptCount} indicators kept · ${dattoCount} removed · ${csvCount(sizes.length)}`,
        "IOC summary stale");
      assert(byId("ioc-download").textContent === `Download ${csvCount(sizes.length)}`, "Wrong CSV batch count or download label");
      assert(!selection.closest(".tool").querySelector("details").hidden, "XML rules not reviewable with IOC exports enabled");
    });
    test("IOC disclosures identify their tool and show compact value/type rows in a shaded group", () => {
      const details = selection.closest(".tool").querySelectorAll("details")[1];
      assert(details.querySelector("summary").getAttribute("aria-label") === `IOCs (${dattoCount}) for Datto RMM / Autotask`,
        "IOC disclosure name missing context");
      for (const row of byId("tool-list").children) {
        const name = row.querySelector(".tool-title").textContent;
        const expected = iocs.indicators.filter(indicator => indicator.tools.includes(name));
        const list = row.querySelector(".ioc-list");
        const style = frame.contentWindow.getComputedStyle(list);
        assert(list.getAttribute("role") === "list" && style.listStyleType === "none",
          "IOC list semantics missing or bullets remain");
        assert(style.backgroundColor !== "rgba(0, 0, 0, 0)" && style.paddingLeft === "16px",
          "IOCs do not share a shaded container");
        assert(list.children.length === expected.length, "Displayed IOCs missing");
        for (const [index, item] of [...list.children].entries()) {
          assert(item.children.length === 2 && item.querySelector("code").textContent === expected[index].value &&
            item.querySelector(".rule-type").textContent === (expected[index].type === "IpAddress" ? "IP address" : "Domain"),
          "IOC does not display only its original value and type");
          const itemStyle = frame.contentWindow.getComputedStyle(item);
          assert(itemStyle.backgroundColor === "rgba(0, 0, 0, 0)" && itemStyle.borderTopWidth === "0px" &&
            parseFloat(itemStyle.paddingTop) <= 8 && parseFloat(itemStyle.paddingBottom) <= 8,
          "IOC still uses a padded card");
        }
      }
      assert(byId("tools").getAttribute("aria-busy") === "false", "Loaded tool region remains busy");
    });
    const xmlOnlySelection = document.querySelector('input[aria-label="Exclude PsExec from block list"]');
    xmlOnlySelection.click();
    test("Missing IOC coverage is associated with the selected tool", () => {
      const coverage = xmlOnlySelection.closest(".tool").querySelector(".ioc-count");
      assert(!coverage.hidden && xmlOnlySelection.getAttribute("aria-describedby").split(" ").includes(coverage.id),
        "Missing IOC warning is not associated with the control");
    });
    xmlOnlySelection.click();
    // Unmatched indicators open the choice first, so accept it with nothing left out.
    const [firstCsv] = await collectCsvs(document, () => {
      byId("ioc-download").click();
      byId("csv-download").click();
    }, batchSizes(keptCount).length);
    const csvRows = parseCsv(firstCsv.text);
    test("Generated CSV download contains the filtered Defender rows and header", () => {
      assert(JSON.stringify(csvRows[0]) === JSON.stringify(iocHeaders), "Downloaded header incorrect");
      assert(csvRows.length === batchSizes(keptCount)[0] + 1, "Downloaded CSV batch does not contain its kept indicators");
      assert(csvRows.slice(1).every(row => row[3] === "Block" && row[5] !== "LOLRMM - Datto RMM / Autotask"),
        "Downloaded CSV contains selected IOCs or non-Block actions");
    });
    let xmlDownload;
    let xmlFilename;
    const captureDownload = event => {
      const link = event.target.closest("a[download]");
      if (!link?.download.endsWith(".xml")) return;
      event.preventDefault();
      xmlFilename = link.download;
      xmlDownload = fetch(link.href).then(response => {
        assert(response.ok, "Generated XML URL unavailable");
        return response.text();
      });
    };
    document.addEventListener("click", captureDownload, true);
    try {
      byId("download").click();
      assert(xmlDownload, "XML button did not produce a download");
      const xml = await xmlDownload;
      test("XML download button exports the same shared selection", () => {
        assert(xmlFilename === "Blocking_RMMsv5_custom.xml", "Customized filename incorrect");
        assert(xml === exportPolicy(policy, new Set(["Datto RMM / Autotask"])), "Downloaded XML has stale exclusions");
      });
    } finally {
      document.removeEventListener("click", captureDownload, true);
    }
    byId("theme-toggle").click();
    test("Changing theme preserves selections and both outputs", () => {
      assert(document.documentElement.dataset.theme === "light", "Theme did not change");
      assert(byId("theme-toggle").getAttribute("aria-label") === "Switch to dark theme", "Theme label stale");
      assert(selection.checked && byId("link-iocs").checked, "Theme changed export selections");
      assert(byId("ioc-download").textContent === `Download ${csvCount(batchSizes(keptCount).length)}`, "Theme changed IOC exports");
      assert(byId("wdac-status").textContent.includes(`${expectedRemoved} removed`), "Theme changed XML output");
    });
    byId("search").value = "no-such-tool-regression";
    input(byId("search"));
    byId("filter").value = "excluded";
    change(byId("filter"));
    test("Search and filters never change the final exports", () => {
      assert(!byId("empty").hidden, "Empty search message missing");
      assert(selection.checked && byId("excluded-count").textContent === "1", "Search changed selection");
      assert(byId("ioc-status").textContent.startsWith(`${keptCount} indicators kept`), "Search changed IOC output");
      assert(byId("removed-count").textContent === String(expectedRemoved), "Search changed XML output");
    });
    byId("link-iocs").click();
    test("Disabling IOC exports removes CSV links without changing XML selections", () => {
      assert(byId("ioc-output").hidden && byId("ioc-download").hidden, "CSV download retained");
      assert(byId("ioc-status").hidden && !byId("ioc-status").textContent, "Disabled IOC status remains visible");
      assert(selection.checked && byId("removed-count").textContent === String(expectedRemoved),
        "Disabling CSVs changed XML exclusions");
    });
    byId("link-iocs").click();
    byId("reset").click();
    test("Reset restores both block lists and their original batch sizes", () => {
      assert(!selection.checked && byId("excluded-count").textContent === "0", "Reset left selections");
      assert(byId("removed-count").textContent === "0", "Reset left XML removals");
      assert(byId("selection-details").hidden, "Reset left stale review");
      assert(byId("selection-list").children.length === 0, "Reset left stale exclusion items");
      const sizes = batchSizes(iocs.indicators.length);
      assert(byId("ioc-status").textContent === `${iocs.indicators.length} indicators kept · 0 removed · ${csvCount(sizes.length)}`,
        "IOC reset stale");
      assert(byId("ioc-download").textContent === `Download ${csvCount(sizes.length)}`, "Reset batches incorrect");
    });
    const unmatchedRows = iocs.indicators.filter(row => !row.tools.length);
    byId("ioc-download").click();
    test("Downloading CSVs with unmatched indicators asks first and lists them all", () => {
      assert(byId("csv-modal").open, "Unmatched download did not prompt");
      assert(byId("csv-modal-list").children.length === unmatchedRows.length, "Prompt lists the wrong unmatched rows");
      assert(byId("csv-modal-desc").textContent.startsWith("There is not a WDAC entry for every remote tool domain"), "Prompt helper text missing");
    });
    const leftOutRow = unmatchedRows[0];
    byId("csv-modal-list").querySelector("input").click();
    test("Ticking a row relabels Download with the count shown", () => {
      assert(!byId("csv-download").disabled && byId("csv-download").textContent === "Download without 1",
        "Download label or state stale after leaving a row out");
    });
    const fileCount = batchSizes(iocs.indicators.length).length;
    const saved = await collectCsvs(document, () => byId("csv-download").click(), fileCount);
    test("Download saves every CSV without only the ticked row", () => {
      assert(!byId("csv-modal").open, "Prompt stayed open after Download");
      assert(saved.length === fileCount && saved.every(file => file.name.endsWith("_excluded.csv")), "Files not saved as excluded");
      const rows = saved.flatMap(file => parseCsv(file.text).slice(1));
      assert(rows.length === iocs.indicators.length - 1 && !rows.some(row => row[1] === leftOutRow.value), "Ticked row still in CSVs");
    });
    byId("ioc-download").click();
    for (const box of byId("csv-modal-list").querySelectorAll("input")) box.click();
    test("Leaving out every unmatched row keeps Download enabled for the matched rows", () => {
      assert(!byId("csv-download").disabled && byId("csv-download").textContent === `Download without ${unmatchedRows.length}`,
        "Download label stale after leaving out every unmatched row");
    });
    const matchedFileCount = batchSizes(iocs.indicators.length - unmatchedRows.length).length;
    const matched = await collectCsvs(document, () => byId("csv-download").click(), matchedFileCount);
    test("Leaving out every unmatched row saves only matched indicators", () => {
      const rows = matched.flatMap(file => parseCsv(file.text).slice(1));
      assert(rows.length === iocs.indicators.length - unmatchedRows.length, "Matched-only CSVs have the wrong row count");
      assert(rows.every(row => row[5].startsWith("LOLRMM - ") && !unmatchedRows.some(item => item.value === row[1])),
        "Matched-only CSVs still contain unmatched rows");
    });
    byId("kql-open").click();
    await waitFor(() => byId("kql-modal").open && byId("kql-code").textContent.includes("DeviceNetworkEvents"),
      "KQL modal did not populate");
    test("KQL modal renders the highlighted network query and closes", () => {
      assert(byId("kql-modal").matches(":modal"), "Popup is not a native modal dialog");
      assert(!byId("kql-copy").disabled, "Copy disabled after the query loaded");
      assert(byId("kql-error").hidden, "KQL modal reported an error");
      assert(byId("kql-code").querySelector(".tok-table"), "KQL not syntax-highlighted");
      assert(byId("kql-code").querySelectorAll(".tok-string").length >= iocs.indicators.length, "KQL indicators missing from view");
      byId("kql-close").click();
      assert(!byId("kql-modal").open, "Modal did not close");
    });
  } finally {
    frame.remove();
  }
}

function verifyExport(policy, selection) {
  const ids = excludedRuleIds(policy, selection);
  const modified = parsePolicy(exportPolicy(policy, selection));
  const expectedRules = elements(policy.document, "FileRules")[0].children;
  const actualRules = elements(modified.document, "FileRules")[0].children;
  const retained = Array.from(expectedRules).filter(rule => !ids.has(rule.getAttribute("ID")));
  assert(actualRules.length === retained.length, "Incorrect retained file rule count");
  assert(JSON.stringify(Array.from(actualRules).map(signature)) === JSON.stringify(retained.map(signature)),
    "Retained rules changed");
  const expectedRefs = elements(policy.document, "FileRuleRef").filter(ref => !ids.has(ref.getAttribute("RuleID")));
  const actualRefs = elements(modified.document, "FileRuleRef");
  assert(JSON.stringify(actualRefs.map(signature)) === JSON.stringify(expectedRefs.map(signature)),
    "References were not removed completely or unrelated references changed");
  const stripEditable = document => {
    const clone = document.cloneNode(true);
    elements(clone, "FileRules")[0].remove();
    for (const reference of elements(clone, "FileRuleRef")) reference.remove();
    return signature(clone.documentElement);
  };
  assert(JSON.stringify(stripEditable(policy.document)) === JSON.stringify(stripEditable(modified.document)),
    "Non-editable policy content changed");
}

// The browser page shares app.js without the IOC panel.
async function testBrowserBuilder() {
  const frame = document.createElement("iframe");
  frame.hidden = true;
  frame.title = "Browser builder regression fixture";
  frame.src = "./browsers.html";
  document.body.append(frame);
  try {
    await waitFor(() => frame.contentDocument?.getElementById("editor")?.hidden === false ||
      frame.contentDocument?.getElementById("error")?.hidden === false, "Browser builder did not initialize");
    const doc = frame.contentDocument;
    test("Browser builder loads its own policy without IOC controls", () => {
      assert(doc.getElementById("error").hidden, doc.getElementById("error").textContent);
      assert(!doc.getElementById("link-iocs"), "IOC toggle present");
      const firefox = doc.querySelector('input[aria-label="Exclude Mozilla Firefox from block list"]');
      assert(firefox, "Firefox missing");
      assert(!doc.querySelector('input[aria-label="Exclude Microsoft Edge from block list"]'), "Edge is blocked");
      firefox.click();
      assert(doc.getElementById("excluded-count").textContent === "1", "Exclusion not counted");
      assert(Number(doc.getElementById("removed-count").textContent) > 0, "Firefox rules not removed");
    });
  } finally {
    frame.remove();
  }
}

async function run() {
  try {
    const response = await fetch("./Blocking_RMMsv5.xml");
    assert(response.ok, `Source fetch failed: ${response.status}`);
    const source = await response.text();
    const policy = parsePolicy(source);
    const data = await (await fetch("./products.json")).json();
    const products = Object.values(data.products);
    const unique = values => new Set(values.map(value => value.toLowerCase())).size;
    const expectedRules = unique(products.flatMap(product => product.paths || []));
    const expectedDomains = unique(products.flatMap(product => [...(product.domains || []), ...(product.vendorDomains || [])]));
    const expectedIps = unique(products.flatMap(product => product.ips || []));
    test("Bundled v5 XML matches products.json: version, deny rules and references", () => {
      assert(policy.version === data.version, "Policy version differs from products.json");
      assert(policy.rules.length === expectedRules, "Deny count differs from products.json");
      // Each deny rule is referenced once, plus one allow reference per signing scenario.
      assert(elements(policy.document, "FileRuleRef").length === expectedRules + 2, "Reference count differs from products.json");
    });
    test("No exclusions preserves original source exactly", () =>
      assert(exportPolicy(policy, new Set()) === source, "Source text changed"));
    test("Every deny rule is visible under its product", () => {
      const grouped = new Set(policy.tools.flatMap(tool => tool.rules.map(rule => rule.id)));
      assert(grouped.size === policy.rules.length, "Tool list hides deny rules");
    });
    test("Deny rules without a product name fail", () =>
      expectError(() => parsePolicy(source.replace(/(<Deny [^>]*FriendlyName=")[^"]*/, "$1")), "has no product name"));
    test("TeamViewer selection includes all TeamViewer and TV helper executables", () => {
      const selection = new Set(["TeamViewer"]);
      const ids = excludedRuleIds(policy, selection);
      const expected = policy.rules.filter(rule => /teamviewer|\\tv_(w32|w64|x64)\*?\.exe$|teamtaskmanager/i.test(rule.path));
      assert(expected.length >= 7 && ids.size === expected.length, "TeamViewer grouping incomplete");
      assert(expected.every(rule => ids.has(rule.id)), "TeamViewer helper missed");
      verifyExport(policy, selection);
    });
    test("AnyDesk removes folder and filename rules together", () => {
      const tool = policy.tools.find(tool => tool.name === "AnyDesk");
      assert(tool.rules.some(rule => rule.kind === "Folder"), "Folder missing");
      assert(tool.rules.some(rule => rule.kind === "Filename"), "Filename missing");
      verifyExport(policy, new Set([tool.name]));
    });
    test("Shared vendor folders deduplicate removals and retain other product rules", () => {
      const control = "ConnectWise Control / ScreenConnect";
      const automate = "ConnectWise Automate / LabTech";
      const shared = policy.rules.find(rule => rule.path.toLowerCase() === "*\\connectwise\\*");
      assert(shared.names.includes(control) && shared.names.includes(automate), "Missing shared ownership");
      const ids = excludedRuleIds(policy, new Set([control]));
      assert(ids.has(shared.id), "Shared folder not removed");
      assert(policy.tools.find(tool => tool.name === automate).rules.some(rule => !ids.has(rule.id)),
        "Unselected product's filename rules removed");
      verifyExport(policy, new Set([control, automate, "Dameware", "N-able / SolarWinds"]));
    });
    test("Each tool individually removes exactly its deny rules and all references", () => {
      for (const tool of policy.tools) verifyExport(policy, new Set([tool.name]));
    });
    test("Selecting every entry retains allow rules and leaves no deny references", () => {
      const selection = new Set(policy.tools.map(tool => tool.name));
      verifyExport(policy, selection);
      const document = new DOMParser().parseFromString(exportPolicy(policy, selection), "application/xml");
      assert(elements(document, "Deny").length === 0, "Deny rules remain");
      assert(elements(document, "Allow").length === 2, "Allow rules changed");
      assert(elements(document, "FileRuleRef").length === 2, "Allow references changed");
    });
    test("All references removed across multiple signing scenarios", () => {
      const clone = policy.document.cloneNode(true);
      const id = policy.tools.find(tool => tool.name === "AnyDesk").rules[0].id;
      const refs = elements(clone, "FileRulesRef");
      refs[1].append(elements(clone, "FileRuleRef").find(ref => ref.getAttribute("RuleID") === id).cloneNode(true));
      const duplicated = parsePolicy(new XMLSerializer().serializeToString(clone));
      verifyExport(duplicated, new Set(["AnyDesk"]));
    });
    test("Unknown tool selections fail explicitly", () =>
      expectError(() => exportPolicy(policy, new Set(["Not a tool"])), "Unknown tool selection"));
    test("Malformed XML, wrong namespace, duplicate IDs and dangling references fail", () => {
      expectError(() => parsePolicy("<SiPolicy>"), "valid WDAC");
      expectError(() => parsePolicy(source.replace(ns, "urn:wrong")), "valid WDAC");
      const [first, second] = policy.rules;
      expectError(() => parsePolicy(source.replace(second.id, first.id)), "duplicate file rule ID");
      expectError(() => parsePolicy(source.replace(/RuleID="[^"]+"/, 'RuleID="missing"')), "Unresolved file rule");
    });
    const toolNames = policy.tools.map(tool => tool.name);
    const iocs = await loadIocs(toolNames);
    test("CSV parsing round-trips commas, escaped quotes, multiline fields, BOM and empty cells", () => {
      const rows = [["first", "comma,value", 'quoted "text"', "line\r\nbreak", ""], ["", "plain", "", "", ""]];
      const csv = serializeCsv(rows);
      assert(JSON.stringify(parseCsv(`\uFEFF${csv}`)) === JSON.stringify(rows), "CSV round-trip failed");
      assert(JSON.stringify(parseCsv(csv.trimEnd())) === JSON.stringify(rows), "CSV without final newline failed");
    });
    test("Malformed CSV quoting fails explicitly", () => {
      expectError(() => parseCsv('"unclosed'), "Unterminated");
      expectError(() => parseCsv('"closed"text'), "Invalid CSV");
      expectError(() => parseCsv('unquoted"quote'), "Invalid CSV");
    });
    test("Combined sources contain every products.json domain and IP as a block IOC", () => {
      assert(iocs.indicators.length === expectedDomains + expectedIps, "Combined indicator count differs from products.json");
      assert(iocs.indicators.filter(row => row.type === "DomainName").length === expectedDomains, "Domain count differs from products.json");
      assert(iocs.indicators.filter(row => row.type === "IpAddress").length === expectedIps, "IP count differs from products.json");
      assert(iocs.indicators.every(row => row.values[3] === "Block"), "An indicator changed action");
    });
    test("Network discovery KQL embeds every indicator and both match paths", () => {
      const kql = buildNetworkDiscoveryKql(iocs.indicators);
      assert(kql.includes("let RMMDomains = dynamic(["), "Missing domain list");
      assert(kql.includes("let RMMIPs = dynamic(["), "Missing IP list");
      assert(kql.includes("DeviceNetworkEvents"), "Missing network table");
      assert(kql.includes("RemoteUrl has_any (RMMDomains)"), "Missing domain match");
      assert(kql.includes("RemoteIP in~ (RMMIPs)"), "Missing IP match");
      for (const indicator of iocs.indicators) {
        assert(kql.includes(`"${indicator.value}"`), `KQL omits ${indicator.value}`);
      }
      assert(!/www\./.test(kql), "KQL retained a www. prefix");
      assert(iocs.indicators.filter(indicator => indicator.type === "DomainName").length === expectedDomains,
        "Domain count after removing www. duplicates is incorrect");
    });
    test("KQL highlighting escapes HTML and tags comments, strings and tables", () => {
      const highlighted = highlightKql('// note\nlet X = dynamic(["a&b"]);\nDeviceNetworkEvents\n| where X');
      assert(highlighted.includes('class="tok-comment"'), "Comments not highlighted");
      assert(highlighted.includes('class="tok-string"'), "Strings not highlighted");
      assert(highlighted.includes("a&amp;b"), "String HTML not escaped");
      assert(highlighted.includes('class="tok-table"'), "Table name not highlighted");
      assert(!highlighted.includes("<script"), "Unescaped markup leaked");
    });
    test("No IOC exclusions preserves all metadata in batches of 500", () => {
      const result = filterIocs(iocs, new Set());
      assert(result.removed.length === 0, "Unexpected exclusions");
      const batches = exportIocBatches(result.retained);
      assert(JSON.stringify(batches.map(batch => batch.count)) === JSON.stringify(batchSizes(iocs.indicators.length)),
        "Incorrect initial batches");
      const rows = batches.flatMap(batch => {
        const parsed = parseCsv(batch.csv);
        assert(JSON.stringify(parsed[0]) === JSON.stringify(iocHeaders), "Defender header changed");
        return parsed.slice(1);
      });
      assert(JSON.stringify(rows) === JSON.stringify(iocs.indicators.map(row => row.values)), "IOC metadata changed");
    });
    test("TeamViewer removes exactly its linked IOCs and retains all other indicators", () => {
      const linked = linkedTo(iocs, "TeamViewer");
      const result = filterIocs(iocs, new Set(["TeamViewer"]));
      assert(result.removed.length === linked && result.retained.length === iocs.indicators.length - linked,
        "TeamViewer IOC count incorrect");
      assert(result.removed.every(row => row.values[5] === "LOLRMM - TeamViewer"), "Unrelated IOC removed");
      assert(!result.retained.some(row => row.values[5] === "LOLRMM - TeamViewer"), "TeamViewer IOC retained");
    });
    test("Ammyy selection removes its domain and all three IPs", () => {
      const result = filterIocs(iocs, new Set(["Ammyy Admin"]));
      assert(result.removed.length === 4, "Ammyy count incorrect");
      assert(result.removed.filter(row => row.type === "IpAddress").length === 3, "Ammyy IPs remain");
      assert(result.removed.filter(row => row.type === "DomainName").length === 1, "Ammyy domain remains");
    });
    test("Datto links its IOCs and recomputes the batches for the remaining indicators", () => {
      const result = filterIocs(iocs, new Set(["Datto RMM / Autotask"]));
      assert(result.removed.length === linkedTo(iocs, "Datto RMM / Autotask"), "Datto IOCs incomplete");
      assert(result.removed.every(row => row.values[5] === "LOLRMM - Datto RMM / Autotask"), "Incorrect Datto mapping");
      assert(JSON.stringify(exportIocBatches(result.retained).map(batch => batch.count)) ===
        JSON.stringify(batchSizes(iocs.indicators.length - result.removed.length)), "Batch count not recomputed after filtering");
    });
    test("Shared descriptions link all owners and warn when an unselected owner is affected", () => {
      const row = iocs.indicators.find(row => row.value === "kabuto.io");
      assert(row.tools.includes("Kabuto") && row.tools.includes("Syncro"), "Secondary owner missed");
      for (const name of ["Kabuto", "Syncro"]) {
        const result = filterIocs(iocs, new Set([name]));
        assert(result.removed.includes(row) && result.sharedRemoved.includes(row), "Shared IOC removal/warning missing");
      }
      const both = filterIocs(iocs, new Set(["Kabuto", "Syncro"]));
      assert(!both.sharedRemoved.includes(row), "Warning incorrectly claims an unselected owner");
      const nable = filterIocs(iocs, new Set(["N-able / SolarWinds"]));
      assert(nable.sharedRemoved.some(row => row.value === "beanywhere.com"), "N-able secondary attribution missed");
    });
    test("Unlinked IOC-only tools remain blocked when every XML tool is excluded", () => {
      const result = filterIocs(iocs, new Set(toolNames));
      const unlinked = iocs.indicators.filter(row => !row.tools.length);
      assert(result.retained.length === unlinked.length, "Unlinked IOC count changed");
      const owners = new Set(result.retained.flatMap(row => row.owners.map(owner => owner.name)));
      assert(owners.size === new Set(unlinked.flatMap(row => row.owners.map(owner => owner.name))).size, "Unlinked identity count changed");
      assert(result.retained.every(row => !row.tools.length && row.values[3] === "Block"), "Unlinked IOC was dropped or allowed");
    });
    test("XML-only selections do not remove unrelated IOCs", () => {
      assert(filterIocs(iocs, new Set(["PsExec"])).retained.length === iocs.indicators.length, "XML-only tool removed IOCs");
      expectError(() => filterIocs(iocs, new Set(["Not a tool"])), "Unknown IOC tool selection");
    });
    test("Every XML selection removes only its linked IOC rows", () => {
      for (const name of toolNames) {
        const result = filterIocs(iocs, new Set([name]));
        const expected = iocs.indicators.filter(row => row.tools.includes(name));
        assert(JSON.stringify(result.removed) === JSON.stringify(expected), `Incorrect IOC filtering for ${name}`);
        assert(result.retained.length + result.removed.length === iocs.indicators.length, "Indicators lost");
      }
    });
    test("CSV batches enforce the exact 500-data-row boundary without loss or duplication", () => {
      for (const count of [0, 1, 499, 500, 501, 1000, 1001]) {
        const indicators = Array.from({ length: count }, (_, index) => ({
          values: iocs.indicators[0].values.map((value, column) => column === 1 ? `ioc-${index}.example.invalid` : value),
        }));
        const batches = exportIocBatches(indicators);
        assert(batches.length === Math.ceil(count / 500), `Wrong file count for ${count}`);
        const exported = [];
        for (const batch of batches) {
          const rows = parseCsv(batch.csv);
          assert(rows.length - 1 === batch.count && batch.count <= 500 && batch.count > 0, "Import limit exceeded");
          assert(JSON.stringify(rows[0]) === JSON.stringify(iocHeaders), "Batch header missing");
          exported.push(...rows.slice(1));
        }
        assert(JSON.stringify(exported) === JSON.stringify(indicators.map(row => row.values)), "Batch data lost or changed");
      }
    });
    test("Invalid headers, duplicate indicators, non-Block actions and missing owners fail explicitly", () => {
      const sample = iocs.indicators[0].values;
      const source = rows => [{ name: "test.csv", text: serializeCsv(rows) }];
      expectError(() => combineIocs(source([["wrong"], sample]), toolNames), "unexpected Defender CSV header");
      expectError(() => combineIocs(source([iocHeaders, sample, sample]), toolNames), "duplicate indicator");
      const allowed = [...sample];
      allowed[3] = "Allow";
      expectError(() => combineIocs(source([iocHeaders, allowed]), toolNames), "invalid block indicator");
      const missing = [...sample];
      missing[6] = "";
      expectError(() => combineIocs(source([iocHeaders, missing]), toolNames), "missing tool attribution");
      const shared = [...iocs.indicators.find(row => row.value === "kabuto.io").values];
      shared[6] = shared[6].replace("Kabuto; Syncro", "Kabuto");
      expectError(() => combineIocs(source([iocHeaders, shared]), toolNames), "incomplete shared-tool attribution");
    });
    await testBuilder(policy, iocs);
    await testBrowserBuilder();
    await testMacBuilder();
    status.textContent = `${passed} passed, ${failures} failed (${policy.tools.length} products and ${iocs.indicators.length} IOCs tested).`;
    status.dataset.complete = "true";
    status.dataset.failures = String(failures);
  } catch (error) {
    status.textContent = `Test setup failed: ${error.message}`;
    status.dataset.complete = "true";
    status.dataset.failures = "1";
    console.error(error);
  }
}

run();

// macOS app control: pure generator checks, then the macos.html builder in a frame.
async function testMacBuilder() {
  const data = parseMacProducts(await (await fetch("./products.json")).json());
  test("macOS products parse with at least 7 verified tools and attributed rules", () => {
    assert(data.tools.length >= 7, `Only ${data.tools.length} macOS tools`);
    for (const tool of data.tools) {
      assert(tool.rules.length && tool.source.startsWith("https://") && /^\d{4}-\d{2}-\d{2}$/.test(tool.verified), `${tool.name} lacks rules, source or date`);
      for (const rule of tool.rules) assert(rule.names.includes(tool.name) && (rule.teamId || rule.signingId), `${tool.name} rule invalid`);
    }
  });
  test("Rules without a string Team ID, broad vendor Team IDs, bad sources and unknown fields are rejected", () => {
    const sample = (product, extra = {}) => ({ version: "1.0.0.1", products: { Sample: { macos: { rules: [product], source: "https://x", verified: "2026-01-01", ...extra } } } });
    expectError(() => parseMacProducts(sample({})), "invalid or missing Team ID");
    // Signing ID alone is valid for Apple but could deny com.apple.Safari fleet-wide from one products.json line.
    expectError(() => parseMacProducts(sample({ signingId: "com.apple.Safari" })), "invalid or missing Team ID");
    expectError(() => parseMacProducts(sample({ teamId: "short" })), "invalid or missing Team ID");
    expectError(() => parseMacProducts(sample({ teamId: 1234567890 })), "invalid or missing Team ID");
    expectError(() => parseMacProducts(sample({ teamId: ["ABCDEFGHIJ"] })), "invalid or missing Team ID");
    expectError(() => parseMacProducts(sample(null)), "must be an object");
    expectError(() => parseMacProducts(sample({ teamId: "ABCDEFGHIJ", cdHash: "x" })), "unknown macOS rule field");
    expectError(() => parseMacProducts(sample({ teamId: "ABCDEFGHIJ", signingId: "com.*" })), "invalid Signing ID");
    for (const teamId of ["UBF8T346G9", "EQHXZ8M8AV"]) {
      expectError(() => parseMacProducts(sample({ teamId })), "signs unrelated software");
      assert(parseMacProducts(sample({ teamId, signingId: "com.example.agent" })).rules.length === 1, "Broad Team ID with Signing ID refused");
    }
    expectError(() => parseMacProducts(sample({ teamId: "ABCDEFGHIJ" }, { source: "javascript:alert(1)" })), "https URL");
    expectError(() => parseMacProducts(sample({ teamId: "ABCDEFGHIJ" }, { verified: "yesterday" })), "YYYY-MM-DD");
    expectError(() => parseMacProducts({ version: "1", products: {} }), "not valid");
  });
  test("Excluding a tool removes exactly its rules and warns about shared ones", () => {
    const all = filterMacRules(data, new Set());
    assert(all.removed.length === 0 && all.retained.length === data.rules.length, "Unexpected initial removal");
    for (const tool of data.tools) {
      const result = filterMacRules(data, new Set([tool.name]));
      assert(result.removed.length === tool.rules.length, `${tool.name} removed count`);
      assert(result.removed.every(rule => rule.names.includes(tool.name)), `${tool.name} removed an unrelated rule`);
      assert(result.sharedRemoved.every(rule => rule.names.length > 1), "Shared warning for an unshared rule");
    }
    expectError(() => filterMacRules(data, new Set(["Not a tool"])), "Unknown tool selection");
  });
  test("Declaration uses Apple's app.settings shape and refuses an empty deny list", () => {
    const declaration = JSON.parse(buildDeclaration(data.rules, data.version));
    assert(declaration.Type === "com.apple.configuration.app.settings", "Wrong declaration type");
    assert(declaration.Identifier && declaration.ServerToken, "Identifier or ServerToken missing");
    const denied = declaration.Payload.Allowed.DeniedBinaries;
    assert(denied.length === data.rules.length, "Denied count differs");
    for (const entry of denied) {
      assert(Object.keys(entry).every(key => ["TeamID", "SigningID"].includes(key)), "Unexpected identifier key");
      assert(typeof entry.TeamID === "string" && /^[A-Z0-9]{10}$/.test(entry.TeamID), "Identifier without a string TeamID");
    }
    assert(JSON.parse(buildDeclaration(data.rules, data.version)).ServerToken !== declaration.ServerToken, "ServerToken repeats");
    expectError(() => buildDeclaration([], data.version), "deny nothing");
  });
  test("Intune body nests app_app > app_allowed > app_allowed_deniedbinaries with one child per field", () => {
    const policy = JSON.parse(buildIntunePolicy(data.rules, data.version));
    assert(policy.platforms === "macOS" && policy.technologies === "appleRemoteManagement", "Platform or technology wrong");
    const root = policy.settings[0].settingInstance;
    const allowed = root.groupSettingCollectionValue[0].children[0];
    const denied = allowed.groupSettingCollectionValue[0].children[0];
    assert(root.settingDefinitionId === "app_app" && allowed.settingDefinitionId === "app_allowed" &&
      denied.settingDefinitionId === "app_allowed_deniedbinaries", "Definition chain wrong");
    assert(denied.groupSettingCollectionValue.length === data.rules.length, "Intune rule count differs");
    for (const [index, item] of denied.groupSettingCollectionValue.entries()) {
      const expected = [data.rules[index].teamId && "app_allowed_deniedbinaries_item_teamid", data.rules[index].signingId && "app_allowed_deniedbinaries_item_signingid"].filter(Boolean);
      assert(JSON.stringify(item.children.map(child => child.settingDefinitionId)) === JSON.stringify(expected), "Child definitions differ");
    }
    expectError(() => buildIntunePolicy([], data.version), "deny nothing");
  });
  test("Vendor Team IDs that also sign unrelated software are only denied with a Signing ID", () => {
    const google = data.rules.filter(rule => rule.teamId === "EQHXZ8M8AV");
    assert(google.length && google.every(rule => rule.signingId), "Google Team ID denied vendor-wide");
  });
  test("Missing-data report link is a prefilled GitHub issue", () => {
    const url = new URL(reportMissingUrl("https://github.com/example/repo", "Tool <X>"));
    assert(url.pathname === "/example/repo/issues/new" && url.searchParams.get("title") === "macOS rules for Tool <X>", "Issue URL wrong");
    assert(url.searchParams.get("body").includes("codesign -dvvv"), "Issue body lacks the codesign command");
  });
  const frame = document.createElement("iframe");
  frame.hidden = true;
  frame.title = "macOS exports regression fixture";
  frame.src = "./index.html";
  document.body.append(frame);
  try {
    await waitFor(() => frame.contentDocument?.getElementById("editor")?.hidden === false, "Builder did not initialize");
    const doc = frame.contentDocument;
    const byId = id => doc.getElementById(id);
    const change = element => element.dispatchEvent(new frame.contentWindow.Event("change", { bubbles: true }));
    test("macOS exports start off and hidden", () => {
      assert(!byId("link-macos").checked && byId("mac-output").hidden && byId("mac-status").hidden, "macOS exports enabled by default");
      assert([...doc.querySelectorAll(".tool details")].every(details => !details.textContent.includes("macOS denied")), "macOS details shown while disabled");
    });
    byId("link-macos").checked = true;
    change(byId("link-macos"));
    await waitFor(() => !byId("mac-status").hidden && byId("mac-status").textContent.includes("rules kept"), "macOS rules did not load");
    const macRows = () => [...byId("tool-list").children].filter(row => !row.querySelector("details:last-of-type").hidden && row.textContent.includes("macOS denied"));
    test("Enabling macOS exports shows denied binaries for covered tools and both downloads", () => {
      assert(byId("mac-status").textContent.startsWith(`${data.rules.length} rules kept · 0 removed · ${data.tools.length} tools covered`), `Status wrong: ${byId("mac-status").textContent}`);
      assert(macRows().length === data.tools.length, `Covered rows ${macRows().length} differ from ${data.tools.length}`);
      assert(!byId("mac-download-intune").disabled && !byId("mac-download-ddm").disabled, "Downloads disabled at start");
      assert(byId("mac-report-missing").href.includes("/issues/new?"), "Report link not prefilled");
      for (const row of macRows()) {
        const summary = row.querySelector("details:last-of-type summary");
        assert(summary.getAttribute("aria-label").endsWith(`for ${row.querySelector(".tool-title").textContent}`), "Disclosure does not identify its tool");
      }
    });
    const teamViewer = doc.querySelector('input[aria-label="Exclude TeamViewer from block list"]');
    const psExec = doc.querySelector('input[aria-label="Exclude PsExec from block list"]');
    teamViewer.click();
    psExec.click();
    test("Excluding tools updates the macOS counts and marks uncovered exclusions", () => {
      const expected = filterMacRules(data, new Set(["TeamViewer"]));
      assert(byId("mac-status").textContent.startsWith(`${expected.retained.length} rules kept · ${expected.removed.length} removed`), "macOS counts stale");
      const warning = psExec.closest(".tool").querySelector(".ioc-count:last-of-type, [id^=mac-coverage]");
      const macCount = psExec.closest(".tool").querySelector("[id^=mac-coverage]");
      assert(!macCount.hidden && macCount.textContent.includes("No macOS rules"), "Uncovered exclusion not marked");
      assert(psExec.getAttribute("aria-describedby").split(" ").includes(macCount.id), "Mark not associated with the checkbox");
      assert(byId("excluded-count").textContent === "2" && byId("removed-count").textContent !== "0", "WDAC selection unaffected by the shared toggle");
      void warning;
    });
    test("Excluding every covered tool disables the macOS downloads, Reset restores them", () => {
      for (const tool of data.tools) {
        const box = doc.querySelector(`input[aria-label="Exclude ${tool.name} from block list"]`);
        if (box && !box.checked) box.click();
      }
      assert(byId("mac-status").textContent.startsWith("0 rules kept"), "Rules still kept");
      assert(byId("mac-download-intune").disabled && byId("mac-download-ddm").disabled, "Downloads enabled with nothing to deny");
      byId("reset").click();
      assert(byId("excluded-count").textContent === "0" && !byId("mac-download-intune").disabled, "Reset did not restore the deny list");
    });
    test("Disabling macOS exports hides its output without changing selections", () => {
      teamViewer.click();
      byId("link-macos").checked = false;
      change(byId("link-macos"));
      assert(byId("mac-output").hidden && byId("mac-status").hidden, "macOS output still shown");
      assert(byId("excluded-count").textContent === "1", "Selection changed by the toggle");
      assert(macRows().length === 0, "macOS details still shown");
      teamViewer.click();
    });
  } finally {
    frame.remove();
  }
}
