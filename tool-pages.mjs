// Static pages for search and answer engines: one per tool, an index of them, and the sitemap that lists them.
// Called by build.mjs, so a tool added to products.json gets its page in the same build.
const site = "https://rmmguard.com";

export const escape = value => value.replace(/[&<>"]/g, char => `&${{ "&": "amp", "<": "lt", ">": "gt", '"': "quot" }[char]};`);
export const slug = name => name.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");
export const covers = p => [
  p.paths?.length && "Windows",
  p.macos && "macOS",
  (p.domains?.length || p.vendorDomains?.length || p.ips?.length) && "network",
].filter(Boolean).join(", ");

const plural = (count, noun) => `${count} ${noun}${count === 1 ? "" : (noun.endsWith("s") ? "es" : "s")}`;
// "a", "a and b", "a, b and c"
const sentence = parts => parts.length > 1 ? `${parts.slice(0, -1).join(", ")} and ${parts.at(-1)}` : parts[0];
const list = items => `<ul class="mono-list">${items.map(item => `<li>${escape(item)}</li>`).join("")}</ul>`;

const author = { "@type": "Person", "@id": "https://conditionalaccess.uk/#author", name: "Lewis Barry", url: "https://conditionalaccess.uk/about/", jobTitle: "Principal Security Architect, Microsoft MVP for Intune", description: "Microsoft MVP for Intune. Principal Security Architect at inforcer. Specialist in Microsoft 365, Intune, Entra ID, and Conditional Access security.", image: { "@type": "ImageObject", url: "https://conditionalaccess.uk/site/assets/files/1/memvp-v1.520x0.png" }, sameAs: ["https://www.linkedin.com/in/lewis-barry/", "https://inforcer.com/"] };

// path is relative to the site root. <base> points there, so the shared scripts' ./ links keep working one folder down.
const shell = ({ path, title, description, crumbs, main }) => {
  const url = `${site}/${path.replace(/index\.html$/, "")}`;
  const graph = [author,
    { "@type": "WebSite", "@id": `${site}/#website`, name: "RMM Guard", url: `${site}/`, author: { "@id": author["@id"] } },
    { "@type": "BreadcrumbList", itemListElement: [["RMM Guard", `${site}/`], ...crumbs].map(([name, item], index) => ({ "@type": "ListItem", position: index + 1, name, item })) }];
  return `<!doctype html>
<html lang="en" data-theme="dark">
<head>
  <meta charset="utf-8">
  <base href="../">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="description" content="${escape(description)}">
  <meta name="theme-color" content="#1b1b1f">
  <title>${escape(title)} | RMM Guard</title>
  <meta name="author" content="Lewis Barry, Microsoft MVP for Intune">
  <link rel="canonical" href="${url}">
  <meta property="og:title" content="${escape(title)} | RMM Guard">
  <meta property="og:description" content="${escape(description)}">
  <meta property="og:url" content="${url}">
  <meta property="og:type" content="website">
  <meta property="og:image" content="${site}/social-card.png">
  <meta property="og:site_name" content="RMM Guard">
  <meta name="twitter:card" content="summary_large_image">
  <meta name="twitter:title" content="${escape(title)} | RMM Guard">
  <meta name="twitter:description" content="${escape(description)}">
  <meta name="twitter:image" content="${site}/social-card.png">
  <script type="application/ld+json">${JSON.stringify({ "@context": "https://schema.org", "@graph": graph }).replaceAll("<", "\\u003c")}</script>
  <link rel="icon" type="image/png" href="./RMMBlocker.png">
  <link rel="stylesheet" href="./styles.css">
  <script type="module" src="./theme.js"></script>
  <script type="module" src="./credits.js"></script>
  <script async src="./analytics.js"></script>
</head>
<body class="help-page">
  <a class="skip-link" href="./${path}#main">Skip to content</a>
  <header>
    <div class="container header-content">
      <a class="brand" href="./index.html" aria-label="RMM Guard home">
        <img class="brand-mark" src="./RMMBlocker.png" alt="">
        <span>RMM Guard</span>
      </a>
      <div class="header-actions">
        <nav aria-label="Main navigation"><a href="./index.html">RMM</a><a href="./tools/index.html" aria-current="page">Tools</a><a href="./browsers.html">Browsers</a><a href="./help.html">Help</a><a href="./changelog.html">Changelog</a></nav>
        <button id="credits-open" class="header-button" type="button" aria-haspopup="dialog">Credits &amp; licence</button>
        <span class="header-divider" aria-hidden="true"></span>
        <button id="theme-toggle" class="theme-toggle" type="button" aria-label="Switch to light theme">Light theme</button>
        <a class="source-link" href="https://github.com/Lewis-Barry/RMM-Blocker" target="_blank" rel="noopener noreferrer">GitHub <span aria-hidden="true">↗</span></a>
      </div>
    </div>
  </header>
  <main id="main" class="container tool-main" tabindex="-1">
${main}
  </main>
  <footer><div class="container footer-content"><a href="./index.html">Back to the builder</a><a href="./tools/index.html">All tools</a><a href="https://lolrmm.io" target="_blank" rel="noopener noreferrer">Data from lolRMM <span aria-hidden="true">↗</span></a></div></footer>
</body>
</html>
`;
};

const toolPage = (name, tool, version) => {
  const n = escape(name);
  const domains = [...(tool.domains || []), ...(tool.vendorDomains || [])];
  const ips = tool.ips || [];
  const network = [domains.length && plural(domains.length, "domain"), ips.length && plural(ips.length, "IP address")].filter(Boolean);
  const mac = tool.macos;
  const teamIds = mac ? [...new Set(mac.rules.map(rule => rule.teamId))] : [];
  const signingIds = mac ? mac.rules.map(rule => rule.signingId).filter(Boolean) : [];
  const windows = tool.paths?.length;
  const steps = [
    windows && `deploy an <strong>App Control for Business (WDAC)</strong> policy in Intune that denies its ${plural(windows, "file path")}`,
    network.length && `import its <strong>${sentence(network)}</strong> as Microsoft Defender block indicators`,
    mac && `on macOS deny Apple Team ID <strong>${teamIds.join(", ")}</strong>`,
  ].filter(Boolean);
  const summary = [
    windows && plural(windows, "Windows App Control (WDAC) deny rule"),
    network.length && `${plural(domains.length + ips.length, "Defender network indicator")}`,
    mac && "a macOS Team ID",
  ].filter(Boolean);
  const networkWords = sentence([domains.length && "domains", ips.length && "IP addresses"].filter(Boolean));
  return shell({
    path: `tools/${slug(name)}.html`,
    title: `How to Block ${name} with Intune and Defender`,
    description: `Block ${name} with Intune and Defender: ${sentence(summary)}. Free policy builder.`,
    crumbs: [["Tools", `${site}/tools/`], [name, `${site}/tools/${slug(name)}.html`]],
    main: `    <p class="crumbs"><a href="./index.html">RMM Guard</a> / <a href="./tools/index.html">Tools</a> / ${n}</p>
    <h1>How to block ${n} with Intune and Defender</h1>
    <p class="lead">To block ${n}, ${sentence(steps)}. RMM Guard blocks it by default and generates the files, free. Policy ${version}.</p>
    <div class="cta-row"><a class="button primary" href="./index.html">Build a policy that blocks ${n}</a></div>${windows ? `
    <section class="help-step">
      <h2>Which files does ${n} run from on Windows?</h2>
      <p>The policy denies these paths. Deploy it in Intune under <strong>Endpoint security → App Control for Business</strong>. <a href="./help.html">Step-by-step guide</a>.</p>
      ${list(tool.paths)}
    </section>` : ""}${network.length ? `
    <section class="help-step">
      <h2>Which ${networkWords} does ${n} connect to?</h2>
      <p>Block these in Microsoft Defender under <strong>Settings → Endpoints → Indicators</strong>. They apply to Windows and macOS devices. <a href="./help-ioc.html">Import guide</a>.</p>
      ${list([...domains, ...ips])}
    </section>` : ""}${mac ? `
    <section class="help-step">
      <h2>How do I block ${n} on a Mac?</h2>
      <p>Deny its code signature in the Intune settings catalog. Needs macOS 27 and a supervised Mac. <a href="./help-macos.html">macOS guide</a>.</p>
      <table class="facts"><tr><th>Apple Team ID</th><td><code>${teamIds.join("</code><br><code>")}</code></td></tr>${signingIds.length ? `<tr><th>Signing ID</th><td><code>${signingIds.map(escape).join("</code><br><code>")}</code></td></tr>` : ""}<tr><th>Read from</th><td>${escape(mac.source)}</td></tr><tr><th>Last verified</th><td>${mac.verified}</td></tr></table>
    </section>` : ""}
    <section class="help-step">
      <h2>If you use ${n}</h2>
      <p>Tick <strong>Exclude</strong> next to ${n} in the <a href="./index.html">builder</a> before you export. Its rules are left out of every file.</p>
    </section>${windows ? `
    <section class="help-step">
      <h2>Can ${n} get past the block?</h2>
      <p>The Windows rules match by file name and path, not by hash or signature, so a renamed copy can. ${network.length ? "The Defender indicators still block its network connections, which is why the two are used together." : "Treat the policy as one layer of defence."}</p>
    </section>` : ""}`,
  });
};

// Returns { "tools/<slug>.html": html, "tools/index.html": html, "sitemap.xml": xml }.
export const toolPages = (products, version) => {
  const names = Object.keys(products);
  const files = {};
  names.forEach(name => {
    const path = `tools/${slug(name)}.html`;
    if (path === "tools/index.html" || files[path]) throw new Error(`products.json: ${name} needs a name that gives a unique page address (${path})`);
    files[path] = toolPage(name, products[name], version);
  });
  const pages = Object.keys(files);
  files["tools/index.html"] = shell({
    path: "tools/index.html",
    title: `${names.length} RMM and Remote Access Tools You Can Block`,
    description: `Every RMM and remote access tool RMM Guard blocks, with the Windows file paths, network indicators and macOS signatures for each.`,
    crumbs: [["Tools", `${site}/tools/`]],
    main: `    <p class="crumbs"><a href="./index.html">RMM Guard</a> / Tools</p>
    <h1>${names.length} RMM and remote access tools you can block</h1>
    <p class="lead">Each page lists the Windows file paths, network indicators and macOS signatures RMM Guard uses to block that tool with Intune and Defender. Policy ${version}, synced monthly from <a href="https://lolrmm.io" target="_blank" rel="noopener noreferrer">lolRMM</a>.</p>
    <div class="cta-row"><a class="button primary" href="./index.html">Build your policy</a></div>
    <ul class="tool-index">
${names.map(name => `      <li><a href="./tools/${slug(name)}.html">${escape(name)}</a> <span class="muted">${covers(products[name])}</span></li>`).join("\n")}
    </ul>`,
  });
  files["sitemap.xml"] = `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
${["", "browsers.html", "help.html", "help-ioc.html", "help-macos.html", "changelog.html", "tools/", ...pages].map(path => `  <url><loc>${site}/${path}</loc></url>`).join("\n")}
</urlset>
`;
  return files;
};
