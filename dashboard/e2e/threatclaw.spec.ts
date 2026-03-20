import { test, expect } from "@playwright/test";

// ── Scénario 1 : Dashboard principal charge ──
test("dashboard loads successfully", async ({ page }) => {
  await page.goto("/");
  // Header THREATCLAW visible
  await expect(page.locator("text=THREATCLAW")).toBeVisible({ timeout: 10000 });
  // Bottom nav present
  await expect(page.locator("text=Board")).toBeVisible();
  await expect(page.locator("text=Agent")).toBeVisible();
  // Widget button visible
  await expect(page.locator("text=Widget")).toBeVisible();
});

// ── Scénario 2 : Page Agent charge et affiche les modes ──
test("agent page shows modes and controls", async ({ page }) => {
  await page.goto("/agent");
  await page.waitForTimeout(3000);
  // At least one mode should be visible
  const content = await page.textContent("body");
  expect(content).toContain("Investigateur");
  // Kill switch or urgence text
  expect(content).toContain("URGENCE");
});

// ── Scénario 3 : Marketplace charge les skills ──
test("marketplace shows skills", async ({ page }) => {
  await page.goto("/marketplace");
  await page.waitForTimeout(2000);
  const content = await page.textContent("body");
  // Should have at least some skill names
  expect(content).toContain("Vulnérabilités");
  // Trust filters
  expect(content).toContain("Officiels");
});

// ── Scénario 4 : Page Alertes charge ──
test("alertes page loads", async ({ page }) => {
  await page.goto("/alertes");
  await page.waitForTimeout(2000);
  const content = await page.textContent("body");
  // Should have tabs
  expect(content).toContain("Findings");
  // No crash/error page
  expect(content).not.toContain("Application error");
});

// ── Scénario 5 : Config page avec Core et Skills ──
test("config page shows settings", async ({ page }) => {
  // Set onboarded flag
  await page.goto("/");
  await page.evaluate(() => localStorage.setItem("threatclaw_onboarded", "true"));
  await page.goto("/setup");
  await page.waitForTimeout(2000);
  const content = await page.textContent("body");
  expect(content).toContain("Core");
  expect(content).toContain("Skills");
});
