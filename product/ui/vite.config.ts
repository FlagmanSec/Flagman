// Vite builds the dashboard into dist/, which flagmand serves.
//
// `npm run dev` serves it on http://localhost:5173 and forwards /api to a
// running flagmand: the live sensor on port 8750 by default, or another one
// with FLAGMAN_API=http://127.0.0.1:8751 npm run dev (a replay).
import { svelte } from '@sveltejs/vite-plugin-svelte';
import { defineConfig } from 'vitest/config';

const api = process.env.FLAGMAN_API ?? 'http://127.0.0.1:8750';

export default defineConfig({
  plugins: [svelte()],
  server: { proxy: { '/api': api } },
  build: { target: 'es2022' },
  test: { include: ['src/**/*.test.ts'], environment: 'node' },
});
