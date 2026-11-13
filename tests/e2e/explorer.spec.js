const { test, expect } = require("@playwright/test");
const { FIXTURE_NOW } = require("./clock");

async function loadCatalog(page) {
  await page.goto("/");
  await expect(page.locator("#status-banner")).not.toHaveText("Loading publication status.");
  const historyIndex = page.waitForResponse(
    (response) => response.url().includes("/data/history/index.json") && response.ok()
  );
  await page.locator("#catalog-load").click();
  await expect(page.locator("#catalog-status")).toContainText("Loaded");
  await expect(page.locator("#catalog-query")).toBeEnabled();
  await historyIndex;
}

function catalogCves(page) {
  return page.locator("#catalog-body tr td:first-child");
}

test.describe("Pulse explorer", () => {
  test.beforeEach(async ({ page }) => {
    await page.clock.setFixedTime(FIXTURE_NOW);
  });

  test("shows a neutral data status instead of a stale snapshot warning", async ({ page }) => {
    await page.goto("/");
    await expect(page.locator("#status-banner")).not.toHaveText("Loading publication status.");
    await expect(page.locator("#status-banner")).not.toContainText("Stale snapshot");
    await expect(page.locator("#data-status")).toContainText("Last successful verification");
    await expect(page.locator("#data-status")).toContainText("Last published snapshot");
    await expect(page.locator("#data-status-summary")).toContainText("independently verified");
    await expect(page.locator("#status-banner")).not.toContainText("timestamps are invalid");
    await expect(page.locator("#status-banner")).toHaveClass(/ok|warn/);
  });

  test("says timestamps are invalid when the snapshot is dated in the future", async ({ page }) => {
    await page.route("**/data/manifest.json", async (route) => {
      const response = await route.fetch();
      const doc = await response.json();
      await route.fulfill({ response, json: { ...doc, snapshot_generated_at: "2030-01-01T00:00:00Z" } });
    });
    await page.goto("/");
    await expect(page.locator("#status-banner")).toContainText("Snapshot timestamps are invalid");
  });

  async function withJson(page, name, mutate) {
    await page.route("**/data/" + name, async (route) => {
      const response = await route.fetch();
      await route.fulfill({ response, json: mutate(await response.json()) });
    });
  }

  async function withVerification(page, mutate) {
    // Move the snapshot well into the past so the age checks apply.
    await withJson(page, "manifest.json", (doc) => ({ ...doc, snapshot_generated_at: "2025-12-31T23:00:00Z" }));
    await withJson(page, "verification-status.json", mutate);
  }

  test("flags a failed scheduled collection after the last verification", async ({ page }) => {
    await withVerification(page, (doc) => ({
      ...doc,
      verified_at: "2026-01-01T00:00:00Z",
      last_attempt: {
        collect_run_id: "4242",
        conclusion: "failure",
        attempted_at: "2026-01-03T00:00:00Z",
        note: "fixture",
      },
    }));
    await page.goto("/");
    const banner = page.locator("#status-banner");
    await expect(banner).toContainText("Collection failed");
    await expect(banner).toContainText("Collect run 4242 failed");
    await expect(page.locator("#data-status")).toContainText("Latest collection attempt");
    await expect(page.locator("#data-status-summary")).toContainText("Latest scheduled collection failed");
  });

  test("flags verification overdue without a recorded failure", async ({ page }) => {
    await withVerification(page, (doc) => ({ ...doc, verified_at: "2026-01-01T00:00:00Z" }));
    await page.goto("/");
    await expect(page.locator("#status-banner")).toContainText("Verification overdue");
    await expect(page.locator("#status-banner")).toContainText("No successful verification for");
  });

  test("rejects a malformed failed-attempt record", async ({ page }) => {
    await withVerification(page, (doc) => ({ ...doc, last_attempt: { conclusion: "success" } }));
    await page.goto("/");
    await expect(page.locator("#data-status-summary")).toContainText("Verification evidence is invalid");
  });

  test("data status remains readable on mobile and in each theme", async ({ page }) => {
    await page.setViewportSize({ width: 390, height: 844 });
    await page.goto("/");
    await expect(page.locator("#data-status")).toBeVisible();
    await page.locator('[data-theme-choice="dark"]').click();
    await expect(page.locator("html")).toHaveAttribute("data-theme", "dark");
    await expect(page.locator("#data-status-heading")).toBeVisible();
    await page.locator('[data-theme-choice="light"]').click();
    await expect(page.locator("html")).toHaveAttribute("data-theme", "light");
    await page.locator('[data-theme-choice="system"]').click();
    await expect(page.locator("html")).toHaveAttribute("data-theme", "system");
    await page.locator("#data-status-heading").focus();
    await expect(page.locator("#data-status-heading")).toBeFocused();
  });

  test("searches by CVE ID", async ({ page }) => {
    await loadCatalog(page);
    await page.locator("#catalog-query").fill("CVE-2099-0001");
    await expect(catalogCves(page)).toHaveText(["CVE-2099-0001"]);
  });

  test("filters by vendor and product", async ({ page }) => {
    await loadCatalog(page);
    await page.locator("#catalog-vendor").selectOption("Acme");
    await page.locator("#catalog-product").selectOption("Widget");
    await expect(catalogCves(page)).toHaveText(["CVE-2099-1001"]);
  });

  test("filters by KEV date range", async ({ page }) => {
    await loadCatalog(page);
    await page.locator("#catalog-date-from").fill("2099-02-01");
    await page.locator("#catalog-date-to").fill("2099-02-28");
    await expect(catalogCves(page)).toHaveText(["CVE-2099-1000"]);
  });

  test("filters by CVSS numeric range", async ({ page }) => {
    await loadCatalog(page);
    await page.locator("#catalog-cvss-min").fill("9");
    await page.locator("#catalog-cvss-max").fill("10");
    await expect(catalogCves(page)).toHaveText(["CVE-2099-1000"]);
  });

  test("filters by CWE", async ({ page }) => {
    await loadCatalog(page);
    await page.locator("#catalog-cwe").selectOption("CWE-94");
    await expect(catalogCves(page)).toHaveText(["CVE-2099-1000"]);
  });

  test("filters by completeness and remediation", async ({ page }) => {
    await loadCatalog(page);
    await page.locator("#catalog-completeness").selectOption("unavailable");
    await page.locator("#catalog-remediation").selectOption("unavailable");
    await expect(catalogCves(page)).toHaveText(["CVE-2099-1001"]);
  });

  test("applies combined filters", async ({ page }) => {
    await loadCatalog(page);
    await page.locator("#catalog-vendor").selectOption("Acme");
    await page.locator("#catalog-completeness").selectOption("partial");
    await page.locator("#catalog-cvss-min").fill("4");
    await page.locator("#catalog-cvss-max").fill("5");
    await expect(catalogCves(page)).toHaveText(["CVE-2099-1002"]);
  });

  test("sorts and paginates", async ({ page }) => {
    await loadCatalog(page);
    await page.locator("#catalog-sort").selectOption("cve_id");
    await expect(catalogCves(page).first()).toHaveText("CVE-2099-0001");
    await expect(page.locator("#catalog-next")).toBeEnabled();
    await page.locator("#catalog-next").click();
    await expect(catalogCves(page).first()).toHaveText("CVE-2099-1023");
    await page.locator("#catalog-prev").click();
    await expect(catalogCves(page).first()).toHaveText("CVE-2099-0001");
  });

  test("shows empty results and unavailable values", async ({ page }) => {
    await loadCatalog(page);
    await page.locator("#catalog-query").fill("NO-SUCH-CVE");
    await expect(page.locator("#catalog-body")).toContainText("No published records match this search.");
    await page.locator("#catalog-clear").click();
    await page.locator("#catalog-cvss").selectOption("unavailable");
    await expect(catalogCves(page)).toContainText(["CVE-2099-1001"]);
    await expect(page.locator("#catalog-body")).toContainText("Unavailable");
    await expect(page.locator("#catalog-body")).toContainText("Unavailable enrichment");
  });

  test("loads per-CVE history with chronology and source attribution", async ({ page }) => {
    await loadCatalog(page);
    await page.locator("#catalog-query").fill("CVE-2099-0001");
    const details = page.locator("#catalog-body details").first();
    await details.locator("summary").click();
    await expect(details).toContainText("First observed publication");
    await expect(details).toContainText("2098-12-01T00:00:00Z");
    await expect(details).toContainText("CISA KEV dateAdded");
    await expect(details).toContainText("2099-01-01");
    await expect(details).toContainText("first_observed");
    await expect(details).toContainText("published_observation");
    await expect(details).toContainText("upstream_kev");
    await expect(details).toContainText("upstream_cvss");
    const text = await details.innerText();
    expect(text.indexOf("2098-12-01T00:00:00Z")).toBeLessThan(text.indexOf("2099-01-01T00:00:00Z"));
    expect(text.indexOf("2099-01-01T00:00:00Z")).toBeLessThan(text.indexOf("2099-01-10T12:00:00Z"));
  });

  test("exports filtered CSV and neutralizes formula injection", async ({ page }) => {
    await loadCatalog(page);
    await page.locator("#catalog-vendor").selectOption("=1+1");
    const downloadPromise = page.waitForEvent("download");
    await page.locator("#catalog-export").click();
    const download = await downloadPromise;
    const stream = await download.createReadStream();
    const chunks = [];
    for await (const chunk of stream) {
      chunks.push(chunk);
    }
    const csv = Buffer.concat(chunks).toString("utf8");
    expect(csv).toContain("cve_id");
    expect(csv).toContain("CVE-2099-1000");
    expect(csv).toContain("'=1+1");
    expect(csv).not.toMatch(/(^|,)=1\+1/);
  });

  test("keeps explorer usable on a mobile viewport", async ({ page }) => {
    await page.setViewportSize({ width: 390, height: 844 });
    await loadCatalog(page);
    await expect(page.locator("#catalog-query")).toBeVisible();
    await page.locator("#catalog-query").fill("CVE-2099-0002");
    await expect(catalogCves(page)).toHaveText(["CVE-2099-0002"]);
    await expect(page.locator(".theme-switch")).toBeVisible();
  });

  test("supports keyboard activation of catalog load", async ({ page }) => {
    await page.goto("/");
    await page.locator("#catalog-load").focus();
    await page.keyboard.press("Enter");
    await expect(page.locator("#catalog-status")).toContainText("Loaded");
    await page.locator("#catalog-query").focus();
    await page.keyboard.type("CVE-2099-0001");
    await expect(catalogCves(page)).toHaveText(["CVE-2099-0001"]);
  });

  test("switches System, Light, and Dark themes", async ({ page }) => {
    await page.goto("/");
    const root = page.locator("html");
    await page.locator('[data-theme-choice="light"]').click();
    await expect(root).toHaveAttribute("data-theme", "light");
    await expect(page.locator('[data-theme-choice="light"]')).toHaveAttribute("aria-pressed", "true");
    await page.locator('[data-theme-choice="dark"]').click();
    await expect(root).toHaveAttribute("data-theme", "dark");
    await page.locator('[data-theme-choice="system"]').click();
    await expect(root).toHaveAttribute("data-theme", "system");
  });

  test("opens a CVE detail view from the explorer", async ({ page }) => {
    await loadCatalog(page);
    await page.locator("#catalog-query").fill("CVE-2099-0001");
    await page.locator('#catalog-body a[href="#cve/CVE-2099-0001"]').click();
    await expect(page).toHaveURL(/#cve\/CVE-2099-0001$/);
    await expect(page.locator("#cve-detail")).toBeVisible();
    await expect(page.locator("#cve-detail-heading")).toHaveText("CVE-2099-0001");
    await expect(page.locator("#cve-detail")).toContainText("KEV exploitation confirmation");
    await expect(page.locator("#cve-detail")).toContainText("CVSS assessments");
    await expect(page.locator("#cve-detail-back")).toBeVisible();
  });

  test("renders CVSS, CWE, affected versions, and advisories", async ({ page }) => {
    await page.goto("/#cve/CVE-2099-1002");
    await expect(page.locator("#cve-detail")).toBeVisible();
    await expect(page.locator("#cve-detail")).toContainText("4.3");
    await expect(page.locator("#cve-detail")).toContainText("CWE-79");
    await expect(page.locator("#cve-detail")).toContainText("Less than");
    await expect(page.locator("#cve-detail")).toContainText("2.0.0");
    await expect(
      page.locator("#cve-detail a[href='https://vendor.example/advisory/CVE-2099-1002']").first()
    ).toBeVisible();
  });

  test("shows missing and conflicting intelligence states", async ({ page }) => {
    await page.goto("/#cve/CVE-2099-1000");
    await expect(page.locator("#cve-detail")).toContainText("CNA and NVD CVSS 3.1 scores differ");
    await page.goto("/#cve/CVE-2099-1001");
    await expect(page.locator("#cve-detail")).toContainText("No structured CVSS assessment is available");
    await expect(page.locator("#cve-detail")).toContainText("No explicit fixed-version evidence");
  });

  test("shows CISA SSVC absence honestly", async ({ page }) => {
    await page.goto("/#cve/CVE-2099-1001");
    await expect(page.locator("#cve-detail")).toContainText("CISA SSVC decision points");
    await expect(page.locator("#cve-detail")).toContainText("not evidence of low impact");
  });

  test("filters by CVSS version, attack vector, and NVD coverage", async ({ page }) => {
    await loadCatalog(page);
    await page.locator("#catalog-cvss-version").selectOption("3.1");
    await page.locator("#catalog-attack-vector").selectOption("NETWORK");
    await page.locator("#catalog-nvd").selectOption("ok");
    await expect(catalogCves(page)).toContainText(["CVE-2099-1000"]);
  });

  test("filters by SSVC decision points, explicit about missing CISA ADP data", async ({ page }) => {
    await loadCatalog(page);
    const total = await catalogCves(page).count();
    // The fixture catalog has no CISA ADP container, so every record's SSVC
    // decision points are explicitly unavailable, not silently omitted.
    await page.locator("#catalog-ssvc-exploitation").selectOption("unavailable");
    await expect(catalogCves(page)).toHaveCount(total);
    await page.locator("#catalog-ssvc-exploitation").selectOption("active");
    await expect(page.locator("#catalog-body")).toContainText("No published records match this search.");
    await page.locator("#catalog-ssvc-exploitation").selectOption("all");
    await page.locator("#catalog-ssvc-automatable").selectOption("yes");
    await expect(page.locator("#catalog-body")).toContainText("No published records match this search.");
  });

  test("filters by fixed-version evidence and vendor advisory", async ({ page }) => {
    await loadCatalog(page);
    await page.locator("#catalog-fixed-version").selectOption("available");
    await page.locator("#catalog-vendor-advisory").selectOption("available");
    await expect(catalogCves(page)).toHaveText(["CVE-2099-1002"]);
  });

  test("renders untrusted description text without HTML injection", async ({ page }) => {
    await page.goto("/#cve/CVE-2099-1001");
    await expect(page.locator("#cve-detail")).toContainText("<img src=x onerror=alert(1)>");
    await expect(page.locator("#cve-detail img")).toHaveCount(0);
    await expect(page.locator("#cve-detail script")).toHaveCount(0);
    const hrefs = await page.locator("#cve-detail a[href]").evaluateAll((nodes) =>
      nodes.map((node) => node.getAttribute("href") || "")
    );
    expect(hrefs.every((href) => href.startsWith("#") || href.startsWith("https://"))).toBeTruthy();
    expect(hrefs.some((href) => href.startsWith("javascript:"))).toBeFalsy();
  });

  test("keeps CVE detail usable on mobile and by keyboard", async ({ page }) => {
    await page.setViewportSize({ width: 390, height: 844 });
    await page.goto("/#cve/CVE-2099-0001");
    await expect(page.locator("#cve-detail")).toBeVisible();
    await page.locator("#cve-detail-back").focus();
    await expect(page.locator("#cve-detail-back")).toBeFocused();
    await page.keyboard.press("Enter");
    await expect(page).toHaveURL(/#catalog$/);
  });
});
