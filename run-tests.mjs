// Runs tests.html in headless Chrome/Edge with no dependencies: node run-tests.mjs [browser path]
import { createServer } from "node:http";
import { readFile, mkdtemp } from "node:fs/promises";
import { spawn } from "node:child_process";
import { tmpdir } from "node:os";
import { join, extname, normalize } from "node:path";

const root = import.meta.dirname;
const types = { ".html": "text/html", ".js": "text/javascript", ".css": "text/css", ".xml": "application/xml", ".csv": "text/csv", ".png": "image/png" };
const server = createServer(async (request, response) => {
  const path = normalize(decodeURIComponent(new URL(request.url, "http://x").pathname)).replace(/^[\\/]+/, "");
  try {
    const body = await readFile(join(root, path || "index.html"));
    response.writeHead(200, { "content-type": types[extname(path)] || "application/octet-stream" }).end(body);
  } catch {
    response.writeHead(404).end();
  }
}).listen(0, "127.0.0.1");
await new Promise(resolve => server.once("listening", resolve));

const browserPath = process.argv[2] || process.env.BROWSER || "google-chrome";
const browser = spawn(browserPath, [
  "--headless=new", "--disable-extensions", "--disable-features=msSmartScreenProtection", "--disable-gpu", "--no-first-run", "--no-sandbox", "--remote-debugging-port=0",
  `--user-data-dir=${await mkdtemp(join(tmpdir(), "rmm-tests-"))}`, "--window-size=1400,900",
  `http://127.0.0.1:${server.address().port}/tests.html`,
], { stdio: ["ignore", "ignore", "pipe"] });
const endpoint = await new Promise((resolve, reject) => {
  let log = "";
  browser.stderr.on("data", chunk => {
    log += chunk;
    const match = log.match(/DevTools listening on (ws:\/\/\S+)/);
    if (match) resolve(match[1]);
  });
  browser.once("exit", () => reject(new Error(`Browser exited before DevTools was ready:\n${log}`)));
});

const finish = code => { browser.kill(); server.close(); process.exit(code); };
setTimeout(() => { console.error("Timed out waiting for tests."); finish(1); }, 120000).unref();

const pages = await (await fetch(endpoint.replace(/^ws(:\/\/[^/]+).*/, "http$1/json/list"))).json();
const socket = new WebSocket(pages.find(page => page.url.endsWith("/tests.html")).webSocketDebuggerUrl);
await new Promise(resolve => socket.addEventListener("open", resolve, { once: true }));
let nextId = 0;
const evaluate = expression => new Promise(resolve => {
  const id = ++nextId;
  const listener = event => {
    const message = JSON.parse(event.data);
    if (message.id !== id) return;
    socket.removeEventListener("message", listener);
    resolve(message.result?.result?.value);
  };
  socket.addEventListener("message", listener);
  socket.send(JSON.stringify({ id, method: "Runtime.evaluate", params: { expression, returnByValue: true } }));
});

for (;;) {
  const result = await evaluate(`(() => {
    const status = document.getElementById("test-status");
    return status?.dataset.failures === undefined ? null
      : { failures: Number(status.dataset.failures), status: status.textContent, output: document.getElementById("test-output").textContent };
  })()`);
  if (result) {
    console.log(result.output);
    console.log(result.status);
    finish(result.failures ? 1 : 0);
  }
  await new Promise(resolve => setTimeout(resolve, 250));
}
