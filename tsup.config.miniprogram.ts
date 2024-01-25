import { defineConfig } from 'tsup';

export default defineConfig({
  entry: ['./src/index.ts'],
  clean: true,
  outDir: 'miniprogram_dist',
  dts: true,
  // we need to keep minify false, since webpack magic comments
  // will be stripped if minify.
  minify: false,
  format: ['cjs'],
  target: 'es5',
  noExternal: ['big-integer'],
  tsconfig: 'tsconfig.json',
  esbuildOptions(options) {
    options.define.__BUILD_TS__ = Date.now().toString();
    options.define.import = 'require';
    options.supported = {
      'dynamic-import': false,
    }
  }
});
