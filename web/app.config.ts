import { defineConfig } from "@solidjs/start/config";

export default defineConfig({
  server: {
    preset: process.env.NITRO_PRESET || (process.env.CF_PAGES ? "cloudflare-pages" : undefined),
    prerender: {
      routes: ["/"],
      crawlLinks: true
    }
  }
});
