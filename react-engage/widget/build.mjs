// Bundles the react-engage widget (React component + its CSS) into a single
// static JS/CSS pair under ../assets, which main.go embeds via //go:embed.
//
// React Engage is installed from npm so this bundle is reproducible and cannot
// accidentally include dependencies from a neighboring development checkout.
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
  outdir: '../../assets',
  entryNames: '[name]',
  assetNames: 'asset-[name]',
  loader: { '.css': 'css', '.svg': 'dataurl', '.png': 'dataurl' },
  jsx: 'automatic',
  define: { 'process.env.NODE_ENV': '"production"' },
  logLevel: 'info',
};

if (process.argv.includes('--watch')) {
  const ctx = await esbuild.context(options);
  await ctx.watch();
  console.log('[engage-widget] watching for changes... (rebuilds on react-engage edits)');
} else {
  await esbuild.build(options);
  console.log('[engage-widget] built assets/engage.js + assets/engage.css');
}
