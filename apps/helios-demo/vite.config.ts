import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import wasm from "vite-plugin-wasm";

export default defineConfig({
  plugins: [react(), wasm()],

  // Porta locale per la dev-server
  server: {
    port: 5174,

    // 🔁 Proxy verso lightclientdata.org per bypassare CORS
    proxy: {
      "/consensus": {
        target: "https://www.lightclientdata.org",
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/consensus/, ""), // rimuove il prefisso
      },
    },
  },
});
