import react from '@vitejs/plugin-react';
import { defineConfig } from 'vite';

// The control plane that `npm run dev` and `npm run preview` send the API's paths to.
const controlPlane = process.env.AGENTGOV_URL || 'http://127.0.0.1:8000';
const proxy = Object.fromEntries(['/v1', '/auth', '/readyz', '/healthz'].map((path) => [path, { target: controlPlane }]));

// The headers the control plane serves the UI with (src/agentgov/api/app.py), so that a
// preview of the build runs under the same rules.
const UI_HEADERS = {
  'Content-Security-Policy':
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
    + "connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'no-referrer',
};

export default defineConfig(({ command }) => ({
  // Built, the UI's files refer to each other relatively: it works wherever the control
  // plane serves it. The dev server and the preview serve it at /ui/, as the control plane.
  base: command === 'build' ? './' : '/ui/',
  plugins: [react()],
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    target: 'es2022',
    // React in a file of its own: it stays cached when a new version of AgentGov changes
    // only the pages.
    rolldownOptions: { output: { codeSplitting: { groups: [{ name: 'react', test: /node_modules/ }] } } },
  },
  server: { proxy },
  preview: { proxy, headers: UI_HEADERS },
}));
