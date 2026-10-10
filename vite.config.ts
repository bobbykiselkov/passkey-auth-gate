import { fileURLToPath } from 'node:url';

import vue from '@vitejs/plugin-vue';
import { defineConfig } from 'vite';

// Builds the login and admin pages (client/) into dist/public, which the
// server serves under GATE_PREFIX. `base: './'` keeps asset URLs relative,
// so the same build works for any prefix: the pages live at <prefix>/login
// and <prefix>/admin, their assets at <prefix>/assets/*.
export default defineConfig({
  root: 'client',
  base: './',
  plugins: [vue()],
  build: {
    outDir: '../dist/public',
    emptyOutDir: true,
    assetsDir: 'assets',
    // Two small pages: no need for the modulepreload polyfill.
    modulePreload: { polyfill: false },
    rollupOptions: {
      input: {
        index: fileURLToPath(new URL('client/index.html', import.meta.url)),
        admin: fileURLToPath(new URL('client/admin.html', import.meta.url)),
      },
    },
  },
});
