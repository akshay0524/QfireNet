/**
 * globeWrapper.js — Vite-compatible re-export of react-globe.gl.
 *
 * react-globe.gl ships as an ESM module. Vite handles the default-export
 * interop transparently when you do a static or dynamic `import()` — but
 * only if the caller uses the module through Vite's bundler (not Node).
 *
 * This thin wrapper lets ThreatGlobe.jsx do:
 *   import('../../lib/globeWrapper').then(m => m.default)
 * and get a reliable constructor regardless of CJS/ESM interop.
 */
import Globe from 'react-globe.gl';
export default Globe;
