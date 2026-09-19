import { chromium } from "playwright";

const BASE = "http://localhost";
const scenarios = {
  visible: { ip: "203.0.113.20", start: "/", challengePath: "/challenge", finalPath: "/", hidden: false },
  hidden: { ip: "203.0.113.21", start: "/app2/", challengePath: "/app2/challenge", finalPath: "/app2/", hidden: true },
};

const name = process.argv[2];
const scenario = scenarios[name];
if (!scenario) {
  console.error(`unknown scenario "${name}"; expected one of: ${Object.keys(scenarios).join(", ")}`);
  process.exit(2);
}

function fail(message) {
  console.error(`✗ [${name}] ${message}`);
  process.exit(1);
}

// The widget runs its solver in workers created from blob: URLs such as blob:http://localhost/<uuid>;
// a blob URL belongs to the origin embedded in it, so check that origin's host.
function hostOf(raw) {
  const url = new URL(raw);
  return url.protocol === "blob:" ? new URL(url.pathname).hostname : url.hostname;
}

const browser = await chromium.launch();
try {
  const context = await browser.newContext({ extraHTTPHeaders: { "X-Forwarded-For": scenario.ip } });
  const external = [];
  context.on("request", (request) => {
    if (hostOf(request.url()) !== "localhost") external.push(request.url());
  });
  const page = await context.newPage();
  page.on("console", (msg) => console.log(`[browser:${msg.type()}] ${msg.text()}`));

  await page.goto(BASE + scenario.start);
  if (new URL(page.url()).pathname !== scenario.challengePath) {
    fail(`expected redirect to ${scenario.challengePath}, got ${page.url()}`);
  }

  // Read the widget's display style atomically, in-page, at the moment it attaches: if this
  // were split into a waitForSelector followed by a separate evaluate, a fast solve + submit
  // could navigate between the two steps and destroy the execution context.
  const displayHandle = await page.waitForFunction(
    () => {
      const el = document.querySelector("cap-widget");
      return el && getComputedStyle(el).display;
    },
    undefined,
    { timeout: 15_000 },
  );
  const display = await displayHandle.jsonValue();
  if (scenario.hidden !== (display === "none")) {
    fail(`expected widget hidden=${scenario.hidden}, got display=${display}`);
  }

  await page.waitForURL((url) => url.pathname === scenario.finalPath, { timeout: 60_000 });
  const body = (await page.textContent("body")) ?? "";
  if (!body.includes("Welcome to nginx")) {
    fail(`expected the nginx page after solving, got: ${body.slice(0, 200)}`);
  }

  await page.goto(BASE + scenario.start);
  if (new URL(page.url()).pathname !== scenario.finalPath) {
    fail(`second visit was challenged again: ${page.url()}`);
  }

  if (external.length > 0) {
    fail(`browser contacted non-local hosts: ${external.join(", ")}`);
  }
  console.log(`✓ [${name}] solved the Cap challenge and reached ${scenario.finalPath}`);
} finally {
  await browser.close();
}
