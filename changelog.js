// Renders changelog.json, newest release first. Built with textContent so names from lolRMM are never parsed as HTML.
const list = document.getElementById("changelog-list");
const status = document.getElementById("changelog-status");

const element = (tag, text, className) => {
  const node = document.createElement(tag);
  if (text !== undefined) node.textContent = text;
  if (className) node.className = className;
  return node;
};

const entries = await fetch("./changelog.json").then(response => {
  if (!response.ok) throw new Error(`HTTP ${response.status}`);
  return response.json();
}).catch(() => null);

if (!entries) {
  status.textContent = "The changelog could not be loaded.";
} else {
  for (const entry of entries) {
    const section = element("section", undefined, "changelog-entry");
    const heading = element("h2", `Version ${entry.version}`);
    heading.append(element("span", ` · ${entry.date}`, "changelog-date"));
    section.append(heading);
    const changes = entry.products || [];
    const paths = changes.reduce((total, change) => total + change.paths.length, 0);
    const domains = changes.reduce((total, change) => total + change.domains.length, 0);
    section.append(element("p", changes.length
      ? `${changes.length} tools updated · ${paths} executables · ${domains} domains added${entry.source ? ` (source: ${entry.source})` : ""}`
      : entry.source || "No changes recorded."));
    if (entry.note) section.append(element("p", entry.note, "changelog-note"));
    const items = element("ul", undefined, "changelog-products");
    for (const change of changes) {
      const item = element("li");
      item.append(element("strong", change.name), change.new ? element("span", " New tool", "changelog-new") : "");
      const rows = element("ul", undefined, "changelog-items");
      for (const path of change.paths) {
        const row = element("li", undefined, "changelog-item");
        row.append(element("code", path));
        rows.append(row);
      }
      for (const domain of change.domains) rows.append(element("li", domain, "changelog-item"));
      item.append(rows);
      items.append(item);
    }
    section.append(items);
    list.append(section);
  }
}
