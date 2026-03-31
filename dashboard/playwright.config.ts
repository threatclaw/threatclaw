import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: "./e2e",
  timeout: 30000,
  retries: 1,
  use: {
    baseURL: "http://127.0.0.1:3001",
    headless: true,
  },
  webServer: {
    command: "PORT=3001 npx next dev",
    port: 3001,
    reuseExistingServer: true,
    timeout: 30000,
  },
});
