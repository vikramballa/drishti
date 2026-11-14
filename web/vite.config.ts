import { defineConfig } from 'vite';

// Plain esbuild JSX (no Babel): smaller toolchain, faster builds.
export default defineConfig({
  esbuild: { jsx: 'automatic', jsxImportSource: 'preact' },
  build: { target: 'es2022', outDir: 'dist', assetsInlineLimit: 0, chunkSizeWarningLimit: 200 },
  server: { proxy: { '/api': { target: 'http://127.0.0.1:7878', ws: true } } },
});
