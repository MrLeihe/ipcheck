import { defineConfig } from "vite";
import { fileURLToPath } from "node:url";

export default defineConfig({
  base: "./",
  build: {
    outDir: fileURLToPath(new URL("../src/ipcheck/static", import.meta.url)),
    emptyOutDir: true,
  },
});
