import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import tailwindcss from '@tailwindcss/vite'

const host = process.env.TAURI_DEV_HOST

// https://vite.dev/config/
export default defineConfig({
  base: process.env.TAURI_DEV_HOST !== undefined || process.env.TAURI_ENV_ARCH ? '/' : '/safe-sharing-webapp/',
  plugins: [vue(), tailwindcss()],
  clearScreen: false,
  server: {
    host: host || false,
    port: 5173,
    strictPort: true,
    hmr: host
      ? {
          protocol: 'ws',
          host: host,
          port: 5174,
        }
      : undefined,
  },
})
