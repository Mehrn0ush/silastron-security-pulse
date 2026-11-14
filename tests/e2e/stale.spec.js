const { test, expect } = require("@playwright/test");
const { FIXTURE_NOW } = require("./clock");

const PAGES = ["/", "/methodology/", "/cve/CVE-2099-0001/", "/malware/", "/malware/weeks/2026-W40/", "/malware/ecosystems/npm/"];

test.describe("Stale notice from the footer stamps", () => {
  for (const path of PAGES) {
    test(`${path}: no notice when fresh, a notice when the data is over 3 days old`, async ({ page }) => {
      await page.clock.setFixedTime(FIXTURE_NOW);
      await page.goto(path);
      await expect(page.locator("footer[data-collected]")).toHaveCount(1);
      await expect(page.locator(".banner-label", { hasText: "Possibly out of date" })).toHaveCount(0);

      await page.clock.setFixedTime(new Date(FIXTURE_NOW.getTime() + 4 * 24 * 3600 * 1000));
      await page.goto(path);
      const notice = page.locator("p.banner.stale").first();
      await expect(notice).toContainText("Possibly out of date");
      await expect(notice).toContainText("collected on 2026-11-01");
    });
  }

  test("the notice appears with a footer stamp and is absent when the stamp is missing or invalid", async ({ page }) => {
    await page.clock.setFixedTime(new Date(FIXTURE_NOW.getTime() + 10 * 24 * 3600 * 1000));
    await page.route("**/methodology/", async (route) => {
      const response = await route.fetch();
      const body = (await response.text()).replace(/data-collected="[^"]*"/, 'data-collected="not-a-date"');
      await route.fulfill({ response, body });
    });
    await page.goto("/methodology/");
    await expect(page.locator(".banner-label", { hasText: "Possibly out of date" })).toHaveCount(0);
  });
});

test.describe("Stale notice without JavaScript", () => {
  test.use({ javaScriptEnabled: false });
  test("pages still show the collected and published stamps in the footer", async ({ page }) => {
    await page.goto("/malware/");
    await expect(page.locator("footer")).toContainText("Last collected");
    await expect(page.locator("footer")).toContainText("Last published");
  });
});
