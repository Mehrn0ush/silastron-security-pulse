const { test, expect } = require("@playwright/test");

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
});
