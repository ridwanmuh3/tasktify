import { defineConfig } from "vite";
import { svelte } from "@sveltejs/vite-plugin-svelte";

const gatewayTarget = process.env.VITE_PROXY_TARGET || "http://localhost:3000";
const gatewayProxy = {
  target: gatewayTarget,
  changeOrigin: true
};

export default defineConfig({
  plugins: [svelte()],
  server: {
    port: 5173,
    strictPort: false,
    proxy: {
      "/api": gatewayProxy,
      "/health": gatewayProxy
    }
  },
  preview: {
    port: 4173,
    strictPort: false,
    proxy: {
      "/api": gatewayProxy,
      "/health": gatewayProxy
    }
  }
});
