import type { RuntimeSettings } from './types.js';

type DB = import('better-sqlite3').Database;

type RuntimeSettingKey =
  | 'messagePriceSats'
  | 'minFeeSats'
  | 'maxPendingPerSender'
  | 'maxPendingPerRecipient'
  | 'maxDeferredPerSender'
  | 'maxDeferredPerRecipient'
  | 'maxDeferredGlobal'
  | 'deferredMessageTtlMs'
  | 'maxBorrowPerTap'
  | 'receiveCapacityMultiplier'
  | 'rebalanceThresholdPct'
  | 'refreshCapacityCooldownMs';

const RUNTIME_SETTING_KEYS: RuntimeSettingKey[] = [
  'messagePriceSats',
  'minFeeSats',
  'maxPendingPerSender',
  'maxPendingPerRecipient',
  'maxDeferredPerSender',
  'maxDeferredPerRecipient',
  'maxDeferredGlobal',
  'deferredMessageTtlMs',
  'maxBorrowPerTap',
  'receiveCapacityMultiplier',
  'rebalanceThresholdPct',
  'refreshCapacityCooldownMs',
];

export class RuntimeSettingsStore {
  constructor(
    private readonly db: DB,
    private readonly defaults: RuntimeSettings,
  ) {
    this.init();
  }

  private init(): void {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS runtime_settings (
        key        TEXT PRIMARY KEY,
        value      TEXT NOT NULL,
        updated_at INTEGER NOT NULL
      )
    `);

    const now = Date.now();
    const stmt = this.db.prepare(`
      INSERT OR IGNORE INTO runtime_settings (key, value, updated_at)
      VALUES (?, ?, ?)
    `);
    for (const key of RUNTIME_SETTING_KEYS) {
      stmt.run(key, String(this.defaults[key]), now);
    }
  }

  get(): RuntimeSettings {
    const rows = this.db.prepare(`
      SELECT key, value
      FROM runtime_settings
      WHERE key IN (${RUNTIME_SETTING_KEYS.map(() => '?').join(', ')})
    `).all(...RUNTIME_SETTING_KEYS) as Array<{ key: RuntimeSettingKey; value: string }>;

    const raw = Object.fromEntries(rows.map(row => [row.key, row.value])) as Partial<Record<RuntimeSettingKey, string>>;
    return {
      messagePriceSats: raw.messagePriceSats ?? this.defaults.messagePriceSats,
      minFeeSats: raw.minFeeSats ?? this.defaults.minFeeSats,
      maxPendingPerSender: parseInt(raw.maxPendingPerSender ?? String(this.defaults.maxPendingPerSender), 10),
      maxPendingPerRecipient: parseInt(raw.maxPendingPerRecipient ?? String(this.defaults.maxPendingPerRecipient), 10),
      maxDeferredPerSender: parseInt(raw.maxDeferredPerSender ?? String(this.defaults.maxDeferredPerSender), 10),
      maxDeferredPerRecipient: parseInt(raw.maxDeferredPerRecipient ?? String(this.defaults.maxDeferredPerRecipient), 10),
      maxDeferredGlobal: parseInt(raw.maxDeferredGlobal ?? String(this.defaults.maxDeferredGlobal), 10),
      deferredMessageTtlMs: parseInt(raw.deferredMessageTtlMs ?? String(this.defaults.deferredMessageTtlMs), 10),
      maxBorrowPerTap: raw.maxBorrowPerTap ?? this.defaults.maxBorrowPerTap,
      receiveCapacityMultiplier: parseInt(raw.receiveCapacityMultiplier ?? String(this.defaults.receiveCapacityMultiplier), 10),
      rebalanceThresholdPct: parseInt(raw.rebalanceThresholdPct ?? String(this.defaults.rebalanceThresholdPct), 10),
      refreshCapacityCooldownMs: parseInt(raw.refreshCapacityCooldownMs ?? String(this.defaults.refreshCapacityCooldownMs), 10),
    };
  }

  update(patch: Partial<RuntimeSettings>): RuntimeSettings {
    const current = this.get();
    const next = validateRuntimeSettings({ ...current, ...patch });
    const now = Date.now();
    const stmt = this.db.prepare(`
      INSERT INTO runtime_settings (key, value, updated_at)
      VALUES (?, ?, ?)
      ON CONFLICT(key) DO UPDATE SET
        value = excluded.value,
        updated_at = excluded.updated_at
    `);
    for (const key of RUNTIME_SETTING_KEYS) {
      stmt.run(key, String(next[key]), now);
    }
    return next;
  }
}

export function validateRuntimeSettings(input: RuntimeSettings): RuntimeSettings {
  const uintString = (value: string, key: string): string => {
    if (!/^\d+$/.test(value)) throw new Error(`${key} must be a non-negative integer string`);
    return value;
  };
  const positiveInt = (value: number, key: string): number => {
    if (!Number.isInteger(value) || value < 0) throw new Error(`${key} must be a non-negative integer`);
    return value;
  };

  const messagePriceSats = uintString(String(input.messagePriceSats), 'messagePriceSats');
  const minFeeSats = uintString(String(input.minFeeSats), 'minFeeSats');
  const maxBorrowPerTap = uintString(String(input.maxBorrowPerTap), 'maxBorrowPerTap');
  const receiveCapacityMultiplier = positiveInt(input.receiveCapacityMultiplier, 'receiveCapacityMultiplier');
  const rebalanceThresholdPct = positiveInt(input.rebalanceThresholdPct, 'rebalanceThresholdPct');
  if (rebalanceThresholdPct < 100) {
    throw new Error('rebalanceThresholdPct must be at least 100');
  }
  if (BigInt(minFeeSats) > BigInt(messagePriceSats)) {
    throw new Error('minFeeSats must be less than or equal to messagePriceSats');
  }

  return {
    messagePriceSats,
    minFeeSats,
    maxPendingPerSender: positiveInt(input.maxPendingPerSender, 'maxPendingPerSender'),
    maxPendingPerRecipient: positiveInt(input.maxPendingPerRecipient, 'maxPendingPerRecipient'),
    maxDeferredPerSender: positiveInt(input.maxDeferredPerSender, 'maxDeferredPerSender'),
    maxDeferredPerRecipient: positiveInt(input.maxDeferredPerRecipient, 'maxDeferredPerRecipient'),
    maxDeferredGlobal: positiveInt(input.maxDeferredGlobal, 'maxDeferredGlobal'),
    deferredMessageTtlMs: positiveInt(input.deferredMessageTtlMs, 'deferredMessageTtlMs'),
    maxBorrowPerTap,
    receiveCapacityMultiplier,
    rebalanceThresholdPct,
    refreshCapacityCooldownMs: positiveInt(input.refreshCapacityCooldownMs, 'refreshCapacityCooldownMs'),
  };
}
