import { defineConfig } from 'tsup';

export default defineConfig({
  entry: {
    'index.umd': './src/index.ts'
  },
  clean: false,
  outDir: 'dist',
  dts: true,
  // we need to keep minify false, since webpack magic comments
  // will be stripped if minify.
  minify: false,
  format: ['esm'],
  target: 'es5',
  noExternal: ['@noble/curves', '@noble/ciphers'],
  tsconfig: 'tsconfig.json',
  esbuildOptions(options) {
    options.define.__BUILD_TS__ = Date.now().toString();
  }
});
