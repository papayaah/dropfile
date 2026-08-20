// Bundles the react-engage widget (React component + its CSS) into a single
// static JS/CSS pair under ../assets, which main.go embeds via //go:embed.
//
// Because @reactkits.dev/react-engage is linked with `file:` to the live source
// in ../../tradingdiary/packages/react-engage, every edit you make there flows
// into dropfile on the next `npm run build` (or live via `npm run watch`).
import * as esbuild from 'esbuild';

/** @type {import('esbuild').BuildOptions} */
const options = {
  entryPoints: {
    engage: 'src/mount.tsx', // -> ../assets/engage.js|css  (public widget)
    'engage-admin': 'src/admin.tsx', // -> ../assets/engage-admin.js|css (admin panel)
  },
  bundle: true,
  minify: true,
  format: 'iife',
  target: ['es2020'],
  outdir: '../assets',
  entryNames: '[name]',
  assetNames: 'asset-[name]',
  loader: { '.css': 'css', '.svg': 'dataurl', '.png': 'dataurl' },
  jsx: 'automatic',
  // react-engage is a `file:`-linked package; without this esbuild would resolve
  // its `react` import from tradingdiary and bundle a second React copy, breaking
  // hooks. preserveSymlinks pins all bare imports to dropfile/widget/node_modules.
  preserveSymlinks: true,
  define: { 'process.env.NODE_ENV': '"production"' },
  logLevel: 'info',
};

if (process.argv.includes('--watch')) {
  const ctx = await esbuild.context(options);
  await ctx.watch();
  console.log('[engage-widget] watching for changes... (rebuilds on react-engage edits)');
} else {
  await esbuild.build(options);
  console.log('[engage-widget] built ../assets/engage.js + ../assets/engage.css');
}
