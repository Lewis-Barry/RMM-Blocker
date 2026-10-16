export const iocSources = [
  "./IOC/Defender_IOC_LOLRMM_Domains_Part1.csv",
  "./IOC/Defender_IOC_LOLRMM_Domains_Part2.csv",
  "./IOC/Defender_IOC_LOLRMM_IPs.csv",
];

export const iocHeaders = [
  "IndicatorType", "IndicatorValue", "ExpirationTime", "Action", "Severity",
  "Title", "Description", "RecommendedActions", "RbacGroups", "Category",
  "MitreTechniques", "GenerateAlert",
];

export function parseCsv(source) {
  const text = source.replace(/^\uFEFF/, "");
  const rows = [];
  let row = [];
  let field = "";
  let quoted = false;
  let closed = false;
  const finishRow = () => {
    row.push(field);
    if (row.length !== 1 || row[0] !== "") rows.push(row);
    row = [];
    field = "";
    closed = false;
  };
  for (let index = 0; index < text.length; index++) {
    const char = text[index];
    if (quoted) {
      if (char === '"') {
        if (text[index + 1] === '"') { field += '"'; index++; }
        else { quoted = false; closed = true; }
      } else field += char;
    } else if (char === ",") {
      row.push(field);
      field = "";
      closed = false;
    } else if (char === "\r" || char === "\n") {
      if (char === "\r" && text[index + 1] === "\n") index++;
      finishRow();
    } else if (char === '"' && field === "" && !closed) {
      quoted = true;
    } else {
      if (closed || char === '"') throw new Error("Invalid CSV quoting.");
      field += char;
    }
  }
  if (quoted) throw new Error("Unterminated quoted CSV field.");
  if (row.length || field || closed) finishRow();
  return rows;
}

export function serializeCsv(rows) {
  const encode = value => /[",\r\n]/.test(value) ? `"${value.replaceAll('"', '""')}"` : value;
  return `${rows.map(row => row.map(encode).join(",")).join("\r\n")}\r\n`;
}

export function combineIocs(sources, toolNames) {
  const knownTools = new Set(toolNames);
  const indicators = [];
  const keys = new Set();
  for (const { name, text } of sources) {
    let rows;
    try { rows = parseCsv(text); } catch (error) {
      throw new Error(`${name}: ${error.message}`);
    }
    if (JSON.stringify(rows[0]) !== JSON.stringify(iocHeaders)) {
      throw new Error(`${name}: unexpected Defender CSV header.`);
    }
    for (const [index, values] of rows.slice(1).entries()) {
      if (values.length !== iocHeaders.length ||
          !["DomainName", "IpAddress"].includes(values[0]) || !values[1].trim() ||
          values[3] !== "Block" || !values[5].startsWith("LOLRMM - ")) {
        throw new Error(`${name}: invalid block indicator at data row ${index + 1}.`);
      }
      const key = `${values[0]}:${values[1].toLowerCase()}`;
      if (keys.has(key)) throw new Error(`${name}: duplicate indicator ${values[1]}.`);
      keys.add(key);
      const attribution = values[6].match(/^(?:Vendor-wide network domain|Network domain|IP address) associated with (.+) - listed by LOLRMM\b/);
      if (!attribution) throw new Error(`${name}: missing tool attribution for ${values[1]}.`);
      const names = attribution[1].split(";").map(owner => owner.trim());
      if (names.some(owner => !owner)) throw new Error(`${name}: empty tool attribution for ${values[1]}.`);
      const extra = values[5].match(/\(\+(\d+) more\)$/);
      if (names.length !== (extra ? Number(extra[1]) + 1 : 1)) {
        throw new Error(`${name}: incomplete shared-tool attribution for ${values[1]}.`);
      }
      const primary = values[5].slice("LOLRMM - ".length).replace(/ \(\+\d+ more\)$/, "");
      if (primary !== names[0]) {
        throw new Error(`${name}: title and description attribution disagree for ${values[1]}.`);
      }
      // build.mjs uses the same product names in the XML and the CSVs.
      const owners = names.map(owner => ({ name: owner, tool: knownTools.has(owner) ? owner : null }));
      indicators.push({
        values,
        type: values[0],
        value: values[1],
        owners,
        tools: [...new Set(owners.map(owner => owner.tool).filter(Boolean))],
      });
    }
  }
  if (!indicators.length) throw new Error("The bundled IOC files contain no indicators.");
  return { indicators, knownTools };
}

export async function loadIocs(toolNames) {
  const sources = await Promise.all(iocSources.map(async name => {
    const response = await fetch(name);
    if (!response.ok) throw new Error(`Unable to load ${name} (HTTP ${response.status}).`);
    return { name, text: await response.text() };
  }));
  return combineIocs(sources, toolNames);
}

export function filterIocs(data, excludedTools) {
  for (const name of excludedTools) {
    if (!data.knownTools.has(name)) throw new Error(`Unknown IOC tool selection: ${name}`);
  }
  const removed = [];
  const retained = [];
  for (const indicator of data.indicators) {
    (indicator.tools.some(tool => excludedTools.has(tool)) ? removed : retained).push(indicator);
  }
  return {
    removed,
    retained,
    sharedRemoved: removed.filter(indicator =>
      indicator.owners.some(owner => !owner.tool || !excludedTools.has(owner.tool))),
  };
}

export function exportIocBatches(indicators) {
  const batches = [];
  for (let index = 0; index < indicators.length; index += 500) {
    const rows = indicators.slice(index, index + 500);
    batches.push({
      count: rows.length,
      indicators: rows,
      csv: serializeCsv([iocHeaders, ...rows.map(indicator => indicator.values)]),
    });
  }
  return batches;
}
