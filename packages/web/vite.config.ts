import { defineConfig } from 'vite';
import path from 'path';

export default defineConfig({
  build: {
    outDir: path.resolve(__dirname, '../server/web'),
    emptyOutDir: true,
  },
  server: {
    proxy: {
      '/status': 'http://localhost:8800',
      '/messages': 'http://localhost:8800',
      '/inbox': 'http://localhost:8800',
      '/tap': 'http://localhost:8800',
      '/admin': 'http://localhost:8800',
      '/payment-info': 'http://localhost:8800',
    },
  },
});
