import vue from '@vitejs/plugin-vue';
import { defineConfig } from 'vite';

// Builds the login page (client/) into dist/public, which the server
// serves under GATE_PREFIX. `base: './'` keeps asset URLs relative, so the
// same build works for any prefix: the page lives at <prefix>/login and
// its assets at <prefix>/assets/*.
export default defineConfig({
  root: 'client',
  base: './',
  plugins: [vue()],
  build: {
    outDir: '../dist/public',
    emptyOutDir: true,
    assetsDir: 'assets',
    // Single small page: no need for the modulepreload polyfill.
    modulePreload: { polyfill: false },
  },
});
