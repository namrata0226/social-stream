import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

// In development the API and uploaded media are proxied, so cookies stay same-origin.
const API = process.env.VITE_DEV_API || "http://localhost:8000";

export default defineConfig({
  plugins: [react()],
  // Shaka Player (~870 KB) is its own lazy chunk, loaded only when a video plays
  build: { chunkSizeWarningLimit: 1000 },
  server: {
    port: 5173,
    proxy: {
      "/api": API,
      "/uploads": API,
    },
  },
});
