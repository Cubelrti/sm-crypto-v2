import { defineConfig } from 'tsup';

export default defineConfig({
  entry: ['./src/index.ts'],
  clean: true,
  outDir: 'dist',
  dts: true,
  // we need to keep minify false, since webpack magic comments
  // will be stripped if minify.
  minify: false,
  format: ['esm', 'cjs'],
  target: 'esnext',
  tsconfig: 'tsconfig.json',
  noExternal: ['big-integer'],
  esbuildOptions(options) {
    options.define.__BUILD_TS__ = Date.now().toString();
  }
});
