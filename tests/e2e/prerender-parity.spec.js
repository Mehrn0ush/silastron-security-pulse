const { test, expect } = require("@playwright/test");

test.describe("Script refresh matches the pre-render", () => {
  test("banner, summary and detail lists are identical at the build instant", async ({ browser }) => {
    const plain = await browser.newContext({ javaScriptEnabled: false });
    const staticPage = await plain.newPage();
    await staticPage.goto("/");
    const builtAt = (await staticPage.locator("#data-status-built-at").innerText()).trim();
    const read = async (page) => ({
      banner: (await page.locator("#status-banner").innerText()).replace(/\s+/g, " ").trim(),
      summary: (await page.locator("#data-status-summary").innerText()).replace(/\s+/g, " ").trim(),
      data: (await page.locator("#data-status-details").innerText()).replace(/\s+/g, " ").trim(),
      meta: (await page.locator("#status-details").innerText()).replace(/\s+/g, " ").trim(),
    });
    const expected = await read(staticPage);
    await plain.close();

    const instant = new Date(builtAt.replace(" UTC", "Z").replace(" ", "T"));
    const live = await browser.newContext();
    const page = await live.newPage();
    await page.clock.setFixedTime(instant);
    await page.goto("/");
    await expect(page.locator("#data-status-built")).toBeHidden();
    const actual = await read(page);
    await live.close();
    expect(actual).toEqual(expected);
  });
});
