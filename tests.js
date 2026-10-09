import { parsePolicy, exportPolicy, excludedRuleIds } from "./policy.js";
import { loadIocs, combineIocs, parseCsv, serializeCsv, iocHeaders, filterIocs, exportIocBatches } from "./ioc.js";
import { buildNetworkDiscoveryKql, highlightKql } from "./kql.js";

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

async function testBuilder(policy, iocs) {
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
    await waitFor(() => byId("ioc-downloads").querySelectorAll("a").length > 0 || !byId("ioc-error").hidden,
      "IOC exports were not prepared");
    test("Enabling IOC exports applies the existing selection to one 454-indicator CSV", () => {
      assert(byId("ioc-error").hidden, byId("ioc-error").textContent);
      assert(selection.checked && byId("link-iocs").checked, "Enabling IOC exports cleared selection");
      assert(byId("ioc-status").textContent === "454 indicators kept · 121 removed · 1 CSV", "IOC summary stale");
      assert(byId("ioc-downloads").querySelectorAll("a").length === 1, "Wrong CSV batch count");
      assert(byId("ioc-downloads").querySelector("a").textContent === "CSV 1 / 1 · 454 indicators",
        "Unexpected IOC download label");
      assert(!selection.closest(".tool").querySelector("details").hidden, "XML rules not reviewable with IOC exports enabled");
    });
    test("Unmatched tools appear below and outside the IOC card", () => {
      const note = byId("ioc-unlinked");
      const card = byId("link-iocs").closest("section");
      assert(note.parentElement === card.parentElement && card.compareDocumentPosition(note) & Node.DOCUMENT_POSITION_FOLLOWING,
        "Unmatched tools remain inside the IOC card or are misplaced");
      assert(card.nextElementSibling === byId("kql-open"), "KQL action is not directly below the IOC card");
      assert(!note.hidden && byId("ioc-unlinked-list").children.length === 7, "Unmatched tools are missing");
    });
    test("IOC disclosures identify their tool and show compact value/type rows in a shaded group", () => {
      const details = selection.closest(".tool").querySelectorAll("details")[1];
      assert(details.querySelector("summary").getAttribute("aria-label") === "IOCs (121) for Datto RMM / Autotask",
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
    const csvResponse = await fetch(byId("ioc-downloads").querySelector("a").href);
    assert(csvResponse.ok, "Generated CSV URL unavailable");
    const csvRows = parseCsv(await csvResponse.text());
    test("Generated CSV download contains the filtered Defender rows and header", () => {
      assert(JSON.stringify(csvRows[0]) === JSON.stringify(iocHeaders), "Downloaded header incorrect");
      assert(csvRows.length === 455, "Downloaded CSV does not contain 454 indicators");
      assert(csvRows.slice(1).every(row => row[3] === "Block" && row[5] !== "LOLRMM - Datto RMM (CentraStage)"),
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
      assert(byId("ioc-downloads").querySelectorAll("a").length === 1, "Theme changed IOC exports");
      assert(byId("wdac-status").textContent.includes(`${expectedRemoved} removed`), "Theme changed XML output");
    });
    byId("search").value = "no-such-tool-regression";
    input(byId("search"));
    byId("filter").value = "excluded";
    change(byId("filter"));
    test("Search and filters never change the final exports", () => {
      assert(!byId("empty").hidden, "Empty search message missing");
      assert(selection.checked && byId("excluded-count").textContent === "1", "Search changed selection");
      assert(byId("ioc-status").textContent.startsWith("454 indicators kept"), "Search changed IOC output");
      assert(byId("removed-count").textContent === String(expectedRemoved), "Search changed XML output");
    });
    byId("link-iocs").click();
    test("Disabling IOC exports removes CSV links without changing XML selections", () => {
      assert(byId("ioc-output").hidden && !byId("ioc-downloads").children.length, "CSV links retained");
      assert(byId("ioc-status").hidden && !byId("ioc-status").textContent, "Disabled IOC status remains visible");
      assert(byId("ioc-unlinked").hidden, "Disabled IOC exports leave unmatched tools visible");
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
      assert(byId("ioc-status").textContent === "575 indicators kept · 0 removed · 2 CSVs", "IOC reset stale");
      assert(!byId("ioc-unlinked").hidden, "Re-enabling IOC exports leaves unmatched tools hidden");
      const links = [...byId("ioc-downloads").querySelectorAll("a")];
      assert(links.length === 2 && links[0].textContent.includes("500 indicators") &&
        links[1].textContent.includes("75 indicators"), "Reset batches incorrect");
    });
    byId("kql-open").click();
    await waitFor(() => byId("kql-modal").open && byId("kql-code").textContent.includes("DeviceNetworkEvents"),
      "KQL modal did not populate");
    test("KQL modal renders the highlighted network query and closes", () => {
      assert(byId("kql-modal").matches(":modal"), "Popup is not a native modal dialog");
      assert(!byId("kql-copy").disabled, "Copy disabled after the query loaded");
      assert(byId("kql-error").hidden, "KQL modal reported an error");
      assert(byId("kql-code").querySelector(".tok-table"), "KQL not syntax-highlighted");
      assert(byId("kql-code").querySelectorAll(".tok-string").length >= 575, "KQL indicators missing from view");
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

async function run() {
  try {
    const response = await fetch("./Blocking_RMMsv5.xml");
    assert(response.ok, `Source fetch failed: ${response.status}`);
    const source = await response.text();
    const policy = parsePolicy(source);
    test("Bundled v5 XML contains 838 deny rules and 840 references", () => {
      assert(policy.version === "1.0.0.8", "Policy version changed");
      assert(policy.rules.length === 838, "Deny count changed; review source and update test");
      assert(elements(policy.document, "FileRuleRef").length === 840, "Reference count changed");
    });
    test("No exclusions preserves original source exactly", () =>
      assert(exportPolicy(policy, new Set()) === source, "Source text changed"));
    test("Every deny rule is visible and assigned without ambiguous aliases", () => {
      const grouped = new Set(policy.tools.flatMap(tool => tool.rules.map(rule => rule.id)));
      assert(grouped.size === policy.rules.length, "Catalog hides deny rules");
      assert(!policy.tools.some(tool => tool.unclassified), "v5 should contain no unclassified rules");
    });
    test("New unconfirmed identities remain visible and can be excluded", () => {
      const unknown = parsePolicy(source.replace(policy.rules[0].path, "*\\unknown-test-tool*.exe"));
      const tool = unknown.tools.find(tool => tool.unclassified);
      assert(tool?.name === "Unclassified: unknown-test-tool.exe", "Unknown rule identity not explicit");
      verifyExport(unknown, new Set([tool.name]));
    });
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
    test("Combined sources contain 575 block IOCs: 563 domains and 12 IPs", () => {
      assert(iocs.indicators.length === 575, "Combined indicator count changed");
      assert(iocs.indicators.filter(row => row.type === "DomainName").length === 563, "Domain count changed");
      assert(iocs.indicators.filter(row => row.type === "IpAddress").length === 12, "IP count changed");
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
      assert(iocs.indicators.filter(indicator => indicator.type === "DomainName").length === 563,
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
    test("No IOC exclusions preserves all metadata in batches of 500 and 75", () => {
      const result = filterIocs(iocs, new Set());
      assert(result.removed.length === 0, "Unexpected exclusions");
      const batches = exportIocBatches(result.retained);
      assert(JSON.stringify(batches.map(batch => batch.count)) === "[500,75]", "Incorrect initial batches");
      const rows = batches.flatMap(batch => {
        const parsed = parseCsv(batch.csv);
        assert(JSON.stringify(parsed[0]) === JSON.stringify(iocHeaders), "Defender header changed");
        return parsed.slice(1);
      });
      assert(JSON.stringify(rows) === JSON.stringify(iocs.indicators.map(row => row.values)), "IOC metadata changed");
    });
    test("TeamViewer removes exactly four linked IOCs and retains all other indicators", () => {
      const result = filterIocs(iocs, new Set(["TeamViewer"]));
      assert(result.removed.length === 4 && result.retained.length === 571, "TeamViewer IOC count incorrect");
      assert(result.removed.every(row => row.values[5] === "LOLRMM - TeamViewer"), "Unrelated IOC removed");
      assert(!result.retained.some(row => row.values[5] === "LOLRMM - TeamViewer"), "TeamViewer IOC retained");
    });
    test("Ammyy selection removes its domain and all three IPs", () => {
      const result = filterIocs(iocs, new Set(["Ammyy Admin"]));
      assert(result.removed.length === 4, "Ammyy count incorrect");
      assert(result.removed.filter(row => row.type === "IpAddress").length === 3, "Ammyy IPs remain");
      assert(result.removed.filter(row => row.type === "DomainName").length === 1, "Ammyy domain remains");
    });
    test("Product aliases link Datto and shrink the combined dataset to one 454-row file", () => {
      const result = filterIocs(iocs, new Set(["Datto RMM / Autotask"]));
      assert(result.removed.length === 121, "Datto alias incomplete");
      assert(result.removed.every(row => row.values[5] === "LOLRMM - Datto RMM (CentraStage)"), "Incorrect Datto mapping");
      assert(JSON.stringify(exportIocBatches(result.retained).map(batch => batch.count)) === "[454]",
        "Batch count not recomputed after filtering");
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
      assert(result.retained.length === 11, "Unlinked IOC count changed");
      const owners = new Set(result.retained.flatMap(row => row.owners.map(owner => owner.name)));
      assert(owners.size === 7, "Unlinked identity count changed");
      assert(result.retained.every(row => !row.tools.length && row.values[3] === "Block"), "Unlinked IOC was dropped or allowed");
    });
    test("XML-only selections do not remove unrelated IOCs", () => {
      assert(filterIocs(iocs, new Set(["PsExec"])).retained.length === 575, "XML-only tool removed IOCs");
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
    status.textContent = `${passed} passed, ${failures} failed (${policy.tools.length} catalog entries and ${iocs.indicators.length} IOCs tested).`;
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
