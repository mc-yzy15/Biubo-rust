import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import path from 'path'

export default defineConfig({
  plugins: [react()],
  build: {
    outDir: path.resolve(__dirname, './dist'),
    emptyOutDir: true,
  },
  server: {
    port: 5173,
    proxy: {
      '/biubo-cgi': {
        target: 'http://localhost:9091',
        changeOrigin: true,
      },
      '/api/biubo': {
        target: 'http://localhost:9091',
        changeOrigin: true,
      },
      '/dashboard': {
        target: 'http://localhost:9091',
        changeOrigin: true,
      },
    },
  },
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
})
