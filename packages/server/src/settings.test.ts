import { describe, expect, it } from 'vitest';
import Database from 'better-sqlite3';
import { RuntimeSettingsStore } from './settings.js';
import { runtimeSettingsFromConfig, type Config } from './types.js';

const baseConfig: Config = {
  host: '127.0.0.1',
  port: 8800,
  dbBackend: 'sqlite',
  dbFile: ':memory:',
  maxEncryptedBytes: 65536,
  authTimestampTtlMs: 300_000,
  authAudience: 'SP123',
  stackflowNodeUrl: '',
  serverStxAddress: 'SP123',
  serverPrivateKey: '',
  sfContractId: '',
  reservoirContractId: '',
  chainId: 1,
  messagePriceSats: '1000',
  minFeeSats: '100',
  maxPendingPerSender: 5,
  maxPendingPerRecipient: 20,
  maxDeferredPerSender: 5,
  maxDeferredPerRecipient: 20,
  maxDeferredGlobal: 200,
  deferredMessageTtlMs: 86_400_000,
  maxBorrowPerTap: '100000',
  refreshCapacityCooldownMs: 86_400_000,
  inboxSessionTtlMs: 300_000,
  allowedOrigins: [],
  rateLimitWindowMs: 60_000,
  rateLimitMax: 120,
  rateLimitAuthMax: 60,
  rateLimitSendMax: 20,
  rateLimitAdminMax: 10,
  enableBrowserDecryptKey: false,
};

describe('RuntimeSettingsStore', () => {
  it('loads defaults and persists updates', () => {
    const db = new Database(':memory:');
    const store = new RuntimeSettingsStore(db, runtimeSettingsFromConfig(baseConfig));

    expect(store.get().maxBorrowPerTap).toBe('100000');
    expect(store.get().refreshCapacityCooldownMs).toBe(86_400_000);

    const next = store.update({
      messagePriceSats: '2500',
      minFeeSats: '250',
      maxBorrowPerTap: '75000',
      refreshCapacityCooldownMs: 3_600_000,
      maxPendingPerSender: 7,
    });

    expect(next.messagePriceSats).toBe('2500');
    expect(next.minFeeSats).toBe('250');
    expect(next.maxBorrowPerTap).toBe('75000');
    expect(next.refreshCapacityCooldownMs).toBe(3_600_000);
    expect(next.maxPendingPerSender).toBe(7);
    expect(store.get().maxBorrowPerTap).toBe('75000');
    expect(store.get().refreshCapacityCooldownMs).toBe(3_600_000);
  });
});
