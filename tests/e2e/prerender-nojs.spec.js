const { test, expect } = require("@playwright/test");

test.use({ javaScriptEnabled: false });

test.describe("Pre-rendered home sections", () => {

  test("status, overview, changes and recent sections are readable without JavaScript", async ({ page }) => {
    await page.goto("/");
    await expect(page.locator("#status-banner")).not.toBeEmpty();
    await expect(page.locator("#data-status-built")).toBeVisible();
    await expect(page.locator("#data-status-summary")).toContainText("independently verified");
    await expect(page.locator("#data-status-details")).toContainText("Last successful verification");
    await expect(page.locator("#overview-cards article.card")).toHaveCount(4);
    await expect(page.locator("#overview-cards")).toContainText("Known Exploited CVEs");
    await expect(page.locator("#changes-note")).not.toBeEmpty();
    await expect(page.locator("#changes-body")).not.toBeEmpty();
    expect(await page.locator("#recent-body tr").count()).toBeGreaterThan(1);
    await expect(page.locator("#recent-body")).toContainText("CVE-2099-");
    await expect(page.locator("#status-details")).toContainText("Collection outcome");
    await expect(page.locator("main")).not.toContainText("JavaScript is required to render the published snapshot");
  });

  test("only the explorer says it needs JavaScript", async ({ page }) => {
    await page.goto("/");
    await expect(page.locator("#catalog noscript p")).toContainText("The explorer needs JavaScript");
    await expect(page.locator("#status-banner")).not.toContainText("JavaScript");
    await expect(page.locator("#recent")).not.toContainText("JavaScript");
  });

  test("EPSS is described as not published, with the reason", async ({ page }) => {
    await page.goto("/methodology/");
    await expect(page.locator("main")).toContainText("EPSS is currently not published here");
    await expect(page.locator("main")).toContainText("explicit licence to redistribute");
    await expect(page.locator("main")).toContainText("not a probability of zero");
    await page.goto("/");
    await expect(page.locator("#recent-body")).toContainText("Disabled");
    await expect(page.locator("#recent-body")).not.toContainText("Estimated");
  });

  test("methodology page renders with signals, sources and limits", async ({ page }) => {
    await page.goto("/methodology/");
    await expect(page.locator("h1")).toHaveText("Methodology");
    await expect(page.locator("main")).toContainText("No composite risk score");
    await expect(page.locator("main")).toContainText("Sources");
    await expect(page.locator("main")).toContainText("Limits");
  });
});

