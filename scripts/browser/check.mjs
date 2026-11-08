import assert from "node:assert/strict";
import fs from "node:fs/promises";
import path from "node:path";
import { spawn } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { chromium } from "playwright";
import AxeBuilder from "@axe-core/playwright";

const binary = process.env.OUTPOST_BROWSER_BINARY;
const root = process.env.OUTPOST_BROWSER_ROOT;
assert(binary && root && path.isAbsolute(binary) && path.isAbsolute(root));
await fs.mkdir(root, { recursive: false, mode: 0o700 });
const fixture = path.join(root, "fixture");
const log = await fs.open(path.join(root, "fixture.log"), "wx", 0o600);
const child = spawn(
  binary,
  ["-test.run=^TestManagementBrowserFixture$", "-test.v", "-test.timeout=240s"],
  { env: { ...process.env, OUTPOST_BROWSER_FIXTURE: fixture }, stdio: ["ignore", log.fd, log.fd] },
);
let spawnError;
const exited = new Promise((resolve) => {
  child.once("exit", (code, signal) => resolve({ code, signal }));
  child.once("error", (error) => {
    spawnError = error;
    resolve({ code: null, signal: null, error: error.code });
  });
});
const cases = [];
let browser;
let browserVersion;
let persistentBrowser;
const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
async function ready() {
  for (let i = 0; i < 150; i++) {
    if (spawnError) throw spawnError;
    if (child.exitCode !== null)
      throw new Error(`fixture exited ${child.exitCode}; inspect fixture.log`);
    try {
      return JSON.parse(await fs.readFile(path.join(fixture, "ready.json"), "utf8"));
    } catch (e) {
      if (e.code !== "ENOENT") throw e;
    }
    await delay(100);
  }
  throw new Error("fixture startup deadline");
}
async function contains(page, selector, value) {
  await page.waitForFunction(
    ({ selector, value }) => document.querySelector(selector)?.textContent.includes(value),
    { selector, value },
    { timeout: 10000 },
  );
}
async function selectScope(page, meta) {
  await page.waitForSelector(`#node option[value="${meta.node}"]`, { state: "attached" });
  await page.locator("#node").selectOption(meta.node);
  await page.locator("#domain").selectOption(meta.domain);
  await contains(page, "#policy-state", "ACTIVE");
  await contains(page, "#report-state", "STALE");
}
async function test(name, fn) {
  await fn();
  cases.push(name);
  console.log(`PASS ${name}`);
}
try {
  const meta = await ready();
  browser = await chromium.launch({ headless: true, args: ["--disable-dev-shm-usage"] });
  browserVersion = browser.version();
  const context = async (role, extra = {}) =>
    browser.newContext({
      ignoreHTTPSErrors: true,
      locale: "en-US",
      viewport: { width: 1280, height: 900 },
      clientCertificates: [{ origin: meta.url, ...meta.clients[role] }],
      ...extra,
    });
  const owner = await context("owner"),
    page = await owner.newPage(),
    pageErrors = [],
    remote = [];
  page.on("pageerror", (error) => pageErrors.push(error.message));
  page.on("request", (req) => {
    if (!req.url().startsWith(meta.url + "/")) remote.push(req.url());
  });
  await test("authenticated coverage retains original report age and unknown space", async () => {
    await page.goto(meta.url);
    await selectScope(page, meta);
    assert.equal(await page.locator("#generations tbody tr").count(), 1);
    assert.match(await page.locator("#space").innerText(), /Unknown/);
    assert.match(await page.locator("#generations").innerText(), /No verified restore reported/);
    const original = await page.locator("#report-age").innerText();
    await page.locator("#refresh").click();
    await contains(page, "#notice", "View loaded");
    assert.equal(
      (await page.locator("#report-age").innerText()).split(" · View retrieved")[0],
      original.split(" · View retrieved")[0],
    );
  });
  await test("external target observations preserve original readback age and unconfirmed state", async () => {
    const row = page.locator("#external-copies tbody tr").filter({ hasText: meta.cloudTarget });
    assert.equal(await row.count(), 1);
    assert.match(await row.innerText(), /Complete at the recorded check time/);
    assert.match(await row.innerText(), /Missing data/);
    const verified = await row.locator("td").nth(4).innerText();
    const expected = await page.evaluate(
      (t) => new Date(t * 1000).toLocaleString("en", { timeZoneName: "short" }),
      meta.cloudVerifiedUnix,
    );
    assert.equal(verified, expected);
    const pending = page
      .locator("#external-copies tbody tr")
      .filter({ hasText: meta.pendingTarget });
    assert.match(await pending.innerText(), /Completeness unconfirmed/);
    assert.equal(await pending.locator("td").nth(4).innerText(), "Unknown");
    assert.match(await page.locator("#external-state").innerText(), /not current cloud health/);
    await page.locator("#refresh").click();
    await contains(page, "#notice", "View loaded");
    assert.equal(await row.locator("td").nth(4).innerText(), verified);
  });
  await test("expired scheduled audit remains a separate historical observation", async () => {
    await page.route("**/domains/**/report", async (route) => {
      const response = await route.fetch();
      const body = await response.json();
      const copy = body.externalCopies.find((entry) => entry.target === meta.cloudTarget);
      copy.audit.expiresUnix = copy.audit.observedUnix + 1;
      await route.fulfill({ response, json: body });
    });
    await page.locator("#refresh").click();
    await contains(page, "#notice", "View loaded");
    const row = page.locator("#external-copies tbody tr").filter({ hasText: meta.cloudTarget });
    assert.match(await row.innerText(), /Stale observation · Missing data/);
    assert.match(await row.innerText(), /Complete at the recorded check time/);
    await page.unroute("**/domains/**/report");
  });
  await test("legacy external report and assigned target without receipts remain unknown", async () => {
    const missing = "d".repeat(64);
    await page.route("**/domains/**/policy", async (route) => {
      const response = await route.fetch();
      const body = await response.json();
      body.targets.push({ id: missing, kind: "s3", maxObjectBytes: 65536 });
      await route.fulfill({ response, json: body });
    });
    await page.route("**/domains/**/report", async (route) => {
      const response = await route.fetch();
      const body = await response.json();
      body.format = "outpost-management-report-view-1";
      delete body.externalState;
      delete body.externalCopies;
      await route.fulfill({ response, json: body });
    });
    await page.locator("#refresh").click();
    await contains(page, "#notice", "View loaded");
    const row = page.locator("#external-copies tbody tr").filter({ hasText: missing });
    assert.equal(await row.count(), 1);
    assert.equal(await row.locator("td").nth(2).innerText(), "Unknown");
    assert.match(
      await page.locator("#external-state").innerText(),
      /no external-copy observation support/,
    );
    await page.unroute("**/domains/**/report");
    await page.unroute("**/domains/**/policy");
    await page.locator("#refresh").click();
    await contains(page, "#notice", "View loaded");
  });
  await test("bounded table pages preserve measured unknown progress", async () => {
    assert.equal(await page.locator("#jobs tbody tr").count(), 50);
    assert.match(await page.locator("#jobs").innerText(), /Unknown \/ Unknown/);
    await page.locator("#jobs").getByRole("button", { name: "Next page", exact: true }).click();
    assert.equal(await page.locator("#jobs tbody tr").count(), 11);
  });
  await test("English keyboard navigation and automated accessibility", async () => {
    await page.reload();
    await selectScope(page, meta);
    await page.keyboard.press("Control+Home");
    await page.locator(".skip").focus();
    await page.keyboard.press("Enter");
    assert.equal(await page.evaluate(() => document.activeElement.id), "main");
    const results = await new AxeBuilder({ page })
      .withTags(["wcag2a", "wcag2aa", "wcag21aa", "wcag22aa"])
      .analyze();
    await fs.writeFile(path.join(root, "axe-en.json"), JSON.stringify(results, null, 2));
    assert.deepEqual(
      results.violations.map((v) => ({ id: v.id, targets: v.nodes.map((n) => n.target) })),
      [],
    );
    await page.screenshot({ path: path.join(root, "desktop-en.png"), fullPage: true });
    await page.screenshot({ path: path.join(root, "desktop-viewport.png") });
  });
  await test("Russian narrow-screen layout and automated accessibility", async () => {
    await page.locator("#language").selectOption("ru");
    assert.equal(await page.locator("html").getAttribute("lang"), "ru");
    assert.match(await page.locator("h1").innerText(), /Управление/);
    assert.match(await page.locator("#notice").innerText(), /Представление загружено/);
    await page.setViewportSize({ width: 375, height: 900 });
    assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth));
    const results = await new AxeBuilder({ page })
      .withTags(["wcag2a", "wcag2aa", "wcag21aa", "wcag22aa"])
      .analyze();
    await fs.writeFile(path.join(root, "axe-ru.json"), JSON.stringify(results, null, 2));
    assert.deepEqual(
      results.violations.map((v) => ({ id: v.id, targets: v.nodes.map((n) => n.target) })),
      [],
    );
    await page.screenshot({ path: path.join(root, "narrow-ru.png"), fullPage: true });
    await page.screenshot({ path: path.join(root, "narrow-viewport.png") });
    await page.locator("#language").selectOption("en");
    await page.setViewportSize({ width: 1280, height: 900 });
  });
  await test("320px reflow and 200 percent text size retain operable controls", async () => {
    await page.setViewportSize({ width: 320, height: 900 });
    assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth));
    await page.setViewportSize({ width: 1280, height: 900 });
    await page.evaluate(() => {
      document.documentElement.style.fontSize = "32px";
    });
    assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth));
    await page.locator("#refresh").focus();
    await page.keyboard.press("Enter");
    await contains(page, "#notice", "View loaded");
    await page.screenshot({ path: path.join(root, "text-200.png"), fullPage: true });
    await page.evaluate(() => {
      document.documentElement.style.removeProperty("font-size");
    });
  });
  await test("scope change clears previous report and missing is not empty coverage", async () => {
    await page.locator("#domain").selectOption(meta.otherDomain);
    await contains(page, "#notice", "View loaded");
    await contains(page, "#report-state", "No signed report");
    assert.equal(await page.locator("#generations tbody tr").count(), 0);
    const copies = page.locator("#external-copies tbody tr");
    assert.equal(await copies.count(), 1);
    assert.equal(await copies.locator("td").nth(0).innerText(), meta.otherTarget);
    assert.equal(await copies.locator("td").nth(2).innerText(), "Unknown");
    assert.equal(await copies.filter({ hasText: meta.cloudTarget }).count(), 0);
    assert.equal(await copies.filter({ hasText: meta.pendingTarget }).count(), 0);
    assert.equal(await page.locator("#command-form button[type=submit]").isDisabled(), true);
    await page.locator("#domain").selectOption(meta.domain);
    await contains(page, "#report-state", "STALE");
  });
  await test("offline refresh retains explicitly last-known report and disables commands", async () => {
    await page.route("**/domains/**", (route) => route.abort("failed"));
    await page.locator("#refresh").click();
    await contains(page, "#notice", "Connection unavailable");
    assert.match(await page.locator("#report-state").innerText(), /Last known view/);
    assert.equal(await page.locator("#command-form button[type=submit]").isDisabled(), true);
    await page.unroute("**/domains/**");
    await page.locator("#refresh").click();
    await contains(page, "#notice", "View loaded");
  });
  await test("forbidden response removes previously displayed coverage", async () => {
    await page.route("**/domains/**", (route) =>
      route.fulfill({
        status: 403,
        contentType: "application/json",
        body: JSON.stringify({ format: "outpost-management-error-1", code: "DENIED" }),
      }),
    );
    await page.locator("#refresh").click();
    await contains(page, "#notice", "Access denied");
    assert.equal(await page.locator("#generations tbody tr").count(), 0);
    assert.equal(await page.locator("#external-copies tbody tr").count(), 0);
    assert.equal(await page.locator("#command-form button[type=submit]").isDisabled(), true);
    await page.unroute("**/domains/**");
    await page.locator("#refresh").click();
    await contains(page, "#notice", "View loaded");
  });
  let commandBody;
  await test("restore uses exact generation and preset, lost reply reuses original operation", async () => {
    await page.locator("#kind").selectOption("restore");
    await page.locator("#generation").fill(meta.generation);
    await page.locator("#preset").fill(meta.preset);
    await page
      .locator("#command-form")
      .getByRole("button", { name: "Review operation", exact: true })
      .click();
    await page.locator("#send-command").waitFor({ state: "visible" });
    assert.match(await page.locator("#command-summary").innerText(), new RegExp(meta.generation));
    let first = true;
    const bodies = [];
    await page.route("**/commands", async (route) => {
      if (route.request().method() !== "POST") return route.continue();
      bodies.push(route.request().postData());
      const response = await route.fetch();
      if (first) {
        first = false;
        await route.abort("failed");
      } else await route.fulfill({ response });
    });
    await page.locator("#send-command").click();
    await contains(page, "#notice", "Reply unavailable");
    commandBody = JSON.parse(bodies[0]);
    assert.equal(commandBody.generation, meta.generation);
    assert.equal(commandBody.preset, meta.preset);
    assert.equal(commandBody.kind, "restore");
    assert.equal(commandBody.versions, undefined);
    await page.reload();
    await selectScope(page, meta);
    await page
      .locator("#operations")
      .getByRole("button", { name: "Retry same request", exact: true })
      .click();
    await contains(page, "#notice", "Receipt received");
    assert.equal(bodies.length, 2);
    assert.equal(bodies[0], bodies[1]);
    assert.match(await page.locator("#operations").innerText(), /ADMITTED/);
    await page.unroute("**/commands");
  });
  await test("owner signed policy preview and lost apply reply survive reload", async () => {
    await page.locator("#config-file").setInputFiles(meta.config);
    await page
      .locator("#config-form")
      .getByRole("button", { name: "Preview changes", exact: true })
      .click();
    await page.locator("#apply-config").waitFor({ state: "visible" });
    assert.match(await page.locator("#config-changes").innerText(), /Candidate revision/);
    const bodies = [];
    let first = true;
    await page.route("**/configuration", async (route) => {
      if (route.request().method() !== "PUT") return route.continue();
      bodies.push(route.request().postData());
      const response = await route.fetch();
      if (first) {
        first = false;
        await route.abort("failed");
      } else await route.fulfill({ response });
    });
    await page.locator("#apply-config").click();
    await contains(page, "#notice", "Reply unavailable");
    await page.reload();
    await selectScope(page, meta);
    await page.locator("#config-file").setInputFiles(meta.config);
    await page
      .locator("#config-form")
      .getByRole("button", { name: "Preview changes", exact: true })
      .click();
    await page.locator("#apply-config").waitFor({ state: "visible" });
    await page.locator("#apply-config").click();
    await contains(page, "#notice", "Receipt received");
    assert.equal(bodies.length, 2);
    assert.equal(bodies[0], bodies[1]);
    assert.match(await page.locator("#operations").innerText(), /COMPLETE/);
    await page.unroute("**/configuration");
  });
  await test("receipt lookup and audit expose actual admission without claiming restore", async () => {
    await page.locator("#operation-id").fill(commandBody.operationId);
    await page
      .locator("#receipt-form")
      .getByRole("button", { name: "Read receipt", exact: true })
      .click();
    await contains(page, "#receipt-result", "ADMITTED");
    await page.locator("#audit-refresh").click();
    await page.waitForSelector("#audit tbody tr");
    assert.match(await page.locator("#audit").innerText(), new RegExp(commandBody.operationId));
    assert.match(await page.locator("#generations").innerText(), /No verified restore reported/);
    await page.reload();
    await selectScope(page, meta);
    const retained = await page.evaluate((id) => {
      const key = Object.keys(localStorage).find((key) => key.startsWith("outpost-operations-2-"));
      return JSON.parse(localStorage.getItem(key)).records.find((r) => r.operation === id);
    }, commandBody.operationId);
    assert.equal(retained.type, "command");
    assert.equal(retained.node, meta.node);
    assert.deepEqual(retained.body, commandBody);
  });
  await test("stale owner preview cannot overwrite a concurrent signed policy", async () => {
    await page.locator("#config-file").setInputFiles(meta.futureConfig);
    await page
      .locator("#config-form")
      .getByRole("button", { name: "Preview changes", exact: true })
      .click();
    await page.locator("#apply-config").waitFor({ state: "visible" });
    const raw = await fs.readFile(meta.futureConfig);
    const digest = createHash("sha256").update(raw).digest("hex");
    const body = {
      operationId: randomBytes(32).toString("hex"),
      reason: "POLICY_CHANGE",
      document: raw.toString("base64"),
      expectedRevision: 3,
      previewDigest: digest,
    };
    const response = await owner.request.put(
      `${meta.url}/api/v1/tenants/${meta.tenant}/nodes/${meta.node}/configuration`,
      { headers: { "X-Outpost-Request": "1", Origin: meta.url }, data: body },
    );
    assert.equal(response.status(), 200);
    await page.locator("#apply-config").click();
    await contains(page, "#notice", "State changed");
    assert.equal(await page.locator("#config-file").evaluate((input) => input.files.length), 1);
    const current = await owner.request.get(
      `${meta.url}/api/v1/tenants/${meta.tenant}/nodes/${meta.node}/configuration`,
    );
    assert.equal((await current.json()).digest, digest);
  });
  await test("owner cannot abandon an already published command", async () => {
    const row = page.locator("#operations tbody tr").filter({ hasText: commandBody.operationId });
    await row.getByRole("button", { name: "Review abandonment", exact: true }).click();
    await contains(page, "#resolution-summary", "COMMAND_PUBLISHED");
    assert.equal(await page.locator("#confirm-resolution").isDisabled(), true);
    await contains(page, "#notice", "cannot be abandoned");
    await page.locator("#cancel-resolution").click();
  });
  await test("owner abandonment at full journal survives lost reply with exact resolution replay", async () => {
    const session = await (await owner.request.get(`${meta.url}/api/v1/session`)).json();
    const original = await (
      await owner.request.get(
        `${meta.url}/api/v1/tenants/${meta.tenant}/operations/${meta.pendingCommand.operationId}`,
      )
    ).json();
    assert.equal(original.state, "ADMITTED");
    const record = {
      tenant: meta.tenant,
      node: meta.node,
      domain: meta.domain,
      type: "command",
      operation: meta.pendingCommand.operationId,
      fingerprint: meta.pendingCommand.operationId,
      body: meta.pendingCommand,
      receipt: original,
      saved: true,
    };
    const records = [record];
    while (records.length < 16) {
      const copy = structuredClone(record);
      copy.operation = (records.length + 200).toString(16).padStart(64, "0");
      copy.fingerprint = copy.operation;
      copy.body.operationId = copy.operation;
      copy.receipt.operationId = copy.operation;
      records.push(copy);
    }
    const resolving = await context("owner");
    await resolving.addInitScript(
      ({ actor, records }) => {
        const key = `outpost-operations-2-${actor}`;
        if (!localStorage.getItem(key))
          localStorage.setItem(
            key,
            JSON.stringify({ format: "outpost-browser-journal-2", revision: 1, records }),
          );
      },
      { actor: session.actor, records },
    );
    let view = await resolving.newPage();
    const bodies = [];
    await resolving.route("**/operations/*/resolution", async (route) => {
      if (route.request().method() !== "POST") return route.continue();
      bodies.push(route.request().postData());
      const response = await route.fetch();
      assert.equal(response.status(), 200);
      if (bodies.length === 1) await route.abort("failed");
      else await route.fulfill({ response });
    });
    await view.goto(meta.url);
    await selectScope(view, meta);
    const row = () => view.locator("#operations tbody tr").filter({ hasText: record.operation });
    await row().getByRole("button", { name: "Review abandonment", exact: true }).click();
    await contains(view, "#resolution-summary", original.requestDigest);
    assert.equal(await view.locator("#confirm-resolution").isDisabled(), false);
    await view.locator("#confirm-resolution").click();
    await contains(view, "#notice", "Reply unavailable");
    assert.equal(await view.locator("#operations tbody tr").count(), 16);
    await view.close();
    view = await resolving.newPage();
    await view.goto(meta.url);
    await selectScope(view, meta);
    await row().getByRole("button", { name: "Review abandonment", exact: true }).click();
    await contains(view, "#resolution-summary", "ALREADY_ABANDONED");
    await view.locator("#confirm-resolution").click();
    await contains(view, "#notice", "confirmed abandonment before publication");
    assert.equal(bodies.length, 2);
    assert.equal(bodies[0], bodies[1]);
    assert.equal(JSON.parse(bodies[0]).targetRequestDigest, original.requestDigest);
    await contains(view, "#operations", "Abandoned before publication");
    assert.equal(
      await row().getByRole("button", { name: "Retry same request", exact: true }).count(),
      0,
    );
    await row().getByRole("button", { name: "Remove completed local record", exact: true }).click();
    await view.waitForFunction(
      () => document.querySelectorAll("#operations tbody tr").length === 15,
    );
    const receipt = await (
      await resolving.request.get(
        `${meta.url}/api/v1/tenants/${meta.tenant}/operations/${record.operation}`,
      )
    ).json();
    assert.equal(receipt.state, "ABANDONED");
    const resolved = await (
      await resolving.request.get(
        `${meta.url}/api/v1/tenants/${meta.tenant}/operations/${JSON.parse(bodies[0]).operationId}`,
      )
    ).json();
    assert.equal(resolved.state, "COMPLETE");
    await resolving.close();
  });
  await test("viewer has no mutation controls or cross-scope API access", async () => {
    const viewer = await context("viewer"),
      view = await viewer.newPage();
    await view.goto(meta.url);
    await selectScope(view, meta);
    assert.equal(await view.locator("#command-form button[type=submit]").isDisabled(), true);
    assert.equal(await view.locator("#config-form button[type=submit]").isDisabled(), true);
    const response = await viewer.request.get(`${meta.url}/api/v1/tenants/${"0".repeat(64)}/nodes`);
    assert.equal(response.status(), 403);
    await viewer.close();
  });
  await test("unknown certificate cannot receive interface or session", async () => {
    const unknown = await context("unknown");
    for (const p of ["/", "/ui/app.js", "/api/v1/session"]) {
      const response = await unknown.request.get(meta.url + p);
      assert.equal(response.status(), 403);
    }
    await unknown.close();
  });
  await test("empty node list explains the next step instead of requesting an impossible selection", async () => {
    const empty = await context("owner"),
      view = await empty.newPage();
    await view.route("**/nodes?limit=32", (route) =>
      route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ format: "outpost-management-nodes-1", revision: 1, items: [] }),
      }),
    );
    await view.goto(meta.url);
    await contains(view, "#notice", "No enrolled nodes");
    assert.equal(await view.locator("#node").isDisabled(), true);
    await empty.close();
  });
  await test("persistent-storage failure blocks a new mutation before transmission", async () => {
    const blocked = await context("owner");
    await blocked.addInitScript(() => {
      Storage.prototype.setItem = function () {
        throw new DOMException("quota", "QuotaExceededError");
      };
    });
    const view = await blocked.newPage();
    let writes = 0;
    view.on("request", (r) => {
      if (r.method() === "POST" && r.url().endsWith("/commands")) writes++;
    });
    await view.goto(meta.url);
    await selectScope(view, meta);
    await view.locator("#kind").selectOption("pause");
    await view
      .locator("#command-form")
      .getByRole("button", { name: "Review operation", exact: true })
      .click();
    await view.locator("#send-command").click();
    await contains(view, "#notice", "cannot safely retain");
    assert.equal(writes, 0);
    await blocked.close();
  });
  await test("receipt storage failure after admission preserves original request and truthful status", async () => {
    const limited = await context("owner");
    await limited.addInitScript(() => {
      const original = Storage.prototype.setItem;
      let writes = 0;
      Storage.prototype.setItem = function (key, value) {
        if (key.startsWith("outpost-operations-2-") && ++writes === 2)
          throw new DOMException("quota", "QuotaExceededError");
        return original.call(this, key, value);
      };
    });
    const view = await limited.newPage();
    let request;
    view.on("request", (r) => {
      if (r.method() === "POST" && r.url().endsWith("/commands")) request = r.postDataJSON();
    });
    await view.goto(meta.url);
    await selectScope(view, meta);
    await view.locator("#kind").selectOption("pause");
    await view
      .locator("#command-form")
      .getByRole("button", { name: "Review operation", exact: true })
      .click();
    await view.locator("#send-command").click();
    await contains(view, "#notice", "The service returned a receipt");
    assert(request?.operationId);
    assert.doesNotMatch(await view.locator("#notice").innerText(), /no request was sent/);
    await view.reload();
    await selectScope(view, meta);
    const row = view.locator("#operations tbody tr").filter({ hasText: request.operationId });
    await row.getByRole("button", { name: "Refresh receipt", exact: true }).click();
    await contains(view, "#receipt-result", "ADMITTED");
    await limited.close();
  });
  await test("simultaneous tabs reuse one request and retain independent operations", async () => {
    const shared = await context("owner");
    const a = await shared.newPage(),
      b = await shared.newPage();
    const prepare = async (view, kind) => {
      await view.goto(meta.url);
      await selectScope(view, meta);
      await view.locator("#kind").selectOption(kind);
      await view.locator("#command-form button[type=submit]").click();
      await view.locator("#send-command").waitFor({ state: "visible" });
    };
    // The API has one large-response lane; prepare independently, submit concurrently.
    await prepare(a, "pause");
    await prepare(b, "pause");
    const sent = [];
    shared.on("request", (request) => {
      if (request.method() === "POST" && request.url().endsWith("/commands"))
        sent.push(request.postData());
    });
    await Promise.all([a.locator("#send-command").click(), b.locator("#send-command").click()]);
    try {
      await contains(a, "#notice", "Receipt received");
      await contains(b, "#notice", "Receipt received");
    } catch (e) {
      throw new Error(
        `${e.message}; first=${await a.locator("#notice").innerText()}; second=${await b.locator("#notice").innerText()}; writes=${sent.length}`,
      );
    }
    assert.equal(sent.length, 2);
    assert.equal(sent[0], sent[1]);
    const first = JSON.parse(sent[0]).operationId;
    assert.equal(await a.locator("#operations tbody tr").count(), 1);
    assert.equal(await b.locator("#operations tbody tr").count(), 1);
    // A new, different request cannot overwrite the first tab's receipt.
    await b.locator("#kind").selectOption("resume");
    await b.locator("#command-form button[type=submit]").click();
    await b.locator("#send-command").click();
    await contains(b, "#notice", "Receipt received");
    await a.waitForFunction(() => document.querySelectorAll("#operations tbody tr").length === 2);
    await a.close();
    await b.close();
    const reopened = await shared.newPage();
    await reopened.goto(meta.url);
    await selectScope(reopened, meta);
    assert.equal(await reopened.locator("#operations tbody tr").count(), 2);
    await reopened
      .locator("#operations tbody tr")
      .filter({ hasText: first })
      .getByRole("button", { name: "Refresh receipt", exact: true })
      .click();
    await contains(reopened, "#receipt-result", first);
    await shared.close();
  });
  await test("legacy tab journal migrates without losing request bytes or pending receipts", async () => {
    const legacy = await page.evaluate(() => {
      const key = Object.keys(localStorage).find((key) => key.startsWith("outpost-operations-2-"));
      return {
        key: key.replace("operations-2-", "operations-1-"),
        records: JSON.parse(localStorage.getItem(key)).records,
      };
    });
    const migrated = await context("owner");
    await migrated.addInitScript(({ key, records }) => {
      if (!sessionStorage.getItem("migration-fixture")) {
        sessionStorage.setItem(key, JSON.stringify(records));
        sessionStorage.setItem("migration-fixture", "1");
      }
    }, legacy);
    const view = await migrated.newPage();
    let writes = 0;
    view.on("request", (request) => {
      if (["POST", "PUT"].includes(request.method())) writes++;
    });
    await view.goto(meta.url);
    await selectScope(view, meta);
    const result = await view.evaluate(
      (key) => ({
        legacy: sessionStorage.getItem(key),
        current: JSON.parse(localStorage.getItem(key.replace("operations-1-", "operations-2-"))),
      }),
      legacy.key,
    );
    assert.equal(result.legacy, null);
    assert.deepEqual(
      result.current.records.map((r) => r.body),
      legacy.records.map((r) => r.body),
    );
    assert.equal(writes, 0);
    await migrated.close();
  });
  await test("changed role and domain scope hide saved records and reject stale review", async () => {
    const restricted = await context("owner");
    const view = await restricted.newPage();
    // A changed authorization response models the next authenticated session.
    // The actual API continues enforcing its own independent mTLS policy.
    const stored = await page.evaluate(() => {
      const key = Object.keys(localStorage).find((key) => key.startsWith("outpost-operations-2-"));
      return { key, raw: localStorage.getItem(key) };
    });
    await restricted.addInitScript(({ key, raw }) => localStorage.setItem(key, raw), stored);
    await view.goto(meta.url);
    await selectScope(view, meta);
    await view.locator("#kind").selectOption("pause");
    await view.locator("#command-form button[type=submit]").click();
    await view.locator("#send-command").waitFor({ state: "visible" });
    let writes = 0;
    view.on("request", (request) => {
      if (request.method() === "POST" && request.url().endsWith("/commands")) writes++;
    });
    await view.route("**/api/v1/session", async (route) => {
      const response = await route.fetch();
      const value = await response.json();
      value.roles = ["viewer"];
      value.scopes = value.scopes.filter((scope) => scope.domain !== meta.domain);
      await route.fulfill({ response, json: value });
    });
    await view.locator("#send-command").click();
    await contains(view, "#notice", "Access denied");
    assert.equal(await view.locator("#operations tbody tr").count(), 0);
    assert.equal(await view.locator("#generations tbody tr").count(), 0);
    assert.equal(await view.locator("#command-form button[type=submit]").isDisabled(), true);
    assert.equal(writes, 0);
    await restricted.close();
  });
  await test("missing browser locks and corrupt journal never fall back to unsafe admission", async () => {
    for (const fault of ["locks", "corrupt"]) {
      const blocked = await context("owner");
      await blocked.addInitScript((fault) => {
        if (fault === "locks") Object.defineProperty(navigator, "locks", { value: undefined });
        else {
          const read = Storage.prototype.getItem;
          Storage.prototype.getItem = function (key) {
            return key.startsWith("outpost-operations-2-") ? "broken" : read.call(this, key);
          };
        }
      }, fault);
      const view = await blocked.newPage();
      let writes = 0;
      view.on("request", (request) => {
        if (request.method() === "POST" && request.url().endsWith("/commands")) writes++;
      });
      await view.goto(meta.url);
      await selectScope(view, meta);
      await view.locator("#kind").selectOption("pause");
      await view.locator("#command-form button[type=submit]").click();
      if (fault === "locks") await view.locator("#send-command").click();
      await contains(view, "#notice", "cannot safely retain");
      assert.equal(writes, 0);
      await blocked.close();
    }
  });
  await test("journal capacity preserves pending work and requires fresh review after removal", async () => {
    const seeded = await page.evaluate(() => {
      const key = Object.keys(localStorage).find((key) => key.startsWith("outpost-operations-2-"));
      const value = JSON.parse(localStorage.getItem(key));
      const pending = value.records.find((r) => r.receipt?.state === "ADMITTED");
      while (value.records.length < 16) {
        const record = structuredClone(pending);
        record.operation = (value.records.length + 100).toString(16).padStart(64, "0");
        record.body.operationId = record.operation;
        record.receipt.operationId = record.operation;
        record.fingerprint = record.operation;
        value.records.push(record);
      }
      return { key, raw: JSON.stringify(value), pending: pending.operation };
    });
    const full = await context("owner");
    await full.addInitScript(({ key, raw }) => localStorage.setItem(key, raw), seeded);
    const view = await full.newPage();
    let writes = 0;
    view.on("request", (request) => {
      if (request.method() === "POST" && request.url().endsWith("/commands")) writes++;
    });
    await view.goto(meta.url);
    await selectScope(view, meta);
    await view.locator("#kind").selectOption("pause");
    await view.locator("#command-form button[type=submit]").click();
    await view.locator("#send-command").click();
    await contains(view, "#notice", "holds 16 operations");
    assert.equal(writes, 0);
    const pending = view.locator("#operations tbody tr").filter({ hasText: seeded.pending });
    assert.equal(
      await pending
        .getByRole("button", { name: "Remove completed local record", exact: true })
        .count(),
      0,
    );
    await view
      .locator("#operations")
      .getByRole("button", { name: "Remove completed local record", exact: true })
      .click();
    await view.locator("#send-command").click();
    await contains(view, "#notice", "State changed");
    assert.equal(writes, 0);
    await view.locator("#command-form button[type=submit]").click();
    await view.locator("#send-command").click();
    await contains(view, "#notice", "Receipt received");
    assert.equal(writes, 1);
    assert.equal(await view.locator("#operations tbody tr").count(), 16);
    await full.close();
  });
  await test("terminal removal cannot resurrect stale requests or downgrade confirmed receipts", async () => {
    const result = await page.evaluate(async () => {
      const { OperationJournal } = await import("/ui/journal.js");
      const session = await (await fetch("/api/v1/session")).json();
      const journal = new OperationJournal(session.actor, () => {});
      const records = journal.snapshot().records;
      const complete = records.find((r) => r.receipt?.state === "COMPLETE");
      const pending = records.find((r) => r.receipt?.state === "ADMITTED");
      const receipt = await journal.receipt(complete.operation, {
        ...complete.receipt,
        state: "ADMITTED",
      });
      let pendingRejected = false,
        staleRejected = false;
      try {
        await journal.remove(pending.operation);
      } catch (e) {
        pendingRejected = e.message === "CONFLICT";
      }
      await journal.remove(complete.operation);
      try {
        await journal.admit(complete);
      } catch (e) {
        staleRejected = e.message === "CONFLICT";
      }
      return {
        state: receipt.state,
        pendingRejected,
        staleRejected,
        retained: journal.snapshot().records.some((r) => r.operation === pending.operation),
      };
    });
    assert.deepEqual(result, {
      state: "COMPLETE",
      pendingRejected: true,
      staleRejected: true,
      retained: true,
    });
  });
  assert.deepEqual(pageErrors, []);
  assert.deepEqual(remote, []);
  await owner.close();
  await browser.close();
  browser = null;
  await test("actual browser restart preserves an uncertain operation and exact retry", async () => {
    const profile = path.join(root, "persistent-browser");
    const options = {
      headless: true,
      ignoreHTTPSErrors: true,
      locale: "en-US",
      clientCertificates: [{ origin: meta.url, ...meta.clients.owner }],
      args: ["--disable-dev-shm-usage"],
    };
    let persistent = await chromium.launchPersistentContext(profile, options);
    persistentBrowser = persistent;
    let view = await persistent.newPage();
    await view.goto(meta.url);
    await selectScope(view, meta);
    await view.locator("#kind").selectOption("pause");
    await view.locator("#command-form button[type=submit]").click();
    let original;
    await view.route("**/commands", async (route) => {
      original = route.request().postData();
      await route.fetch();
      await route.abort("failed");
    });
    await view.locator("#send-command").click();
    await contains(view, "#notice", "Reply unavailable");
    await persistent.close();
    persistent = await chromium.launchPersistentContext(profile, options);
    persistentBrowser = persistent;
    try {
      view = await persistent.newPage();
      await view.goto(meta.url);
      await selectScope(view, meta);
      let replay;
      view.on("request", (request) => {
        if (request.method() === "POST" && request.url().endsWith("/commands"))
          replay = request.postData();
      });
      await view
        .locator("#operations")
        .getByRole("button", { name: "Retry same request", exact: true })
        .click();
      await contains(view, "#notice", "Receipt received");
      assert.equal(replay, original);
      await contains(view, "#operations", JSON.parse(original).operationId);
    } finally {
      await persistent.close();
    }
  });
  await fs.writeFile(
    path.join(root, "result.json"),
    JSON.stringify(
      {
        state: "PASS",
        cases,
        browser: browserVersion,
        limits:
          "Synthetic loopback API; admission and UI checks do not establish worker execution, full accessibility or installed-service acceptance.",
      },
      null,
      2,
    ),
  );
  console.log(`BROWSER_PASS ${cases.length}`);
} catch (error) {
  await fs.writeFile(
    path.join(root, "result.json"),
    JSON.stringify({ state: "FAIL", cases, error: String(error.stack || error) }, null, 2),
  );
  throw error;
} finally {
  await persistentBrowser?.close();
  await browser?.close();
  child.kill("SIGTERM");
  const result = await Promise.race([exited, delay(5000).then(() => null)]);
  if (!result) {
    child.kill("SIGKILL");
    await exited;
  }
  await log.close();
}
