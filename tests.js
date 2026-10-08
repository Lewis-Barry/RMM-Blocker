import { parsePolicy, exportPolicy, excludedRuleIds } from "./policy.js";

const ns = "urn:schemas-microsoft-com:sipolicy";
const output = document.getElementById("test-output");
const status = document.getElementById("test-status");
let failures = 0;
let passed = 0;

function assert(condition, message) {
  if (!condition) throw new Error(message);
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
    status.textContent = `${passed} passed, ${failures} failed (${policy.tools.length} catalog entries tested).`;
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
