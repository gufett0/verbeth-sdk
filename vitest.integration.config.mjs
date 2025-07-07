export default {
  test: {
    globals: true,
    environment: 'node',
    testTimeout: 30000,
    hookTimeout: 30000,
    pool: 'forks',
    poolOptions: {
      forks: {
        singleFork: true
      }
    },
    include: ['tests/handshake.test.ts', '*.test.ts'],
    exclude: ['**/node_modules/**', 'packages/**']
  },
  define: {
    global: 'globalThis',
  }
};