/**
 * Mailslot server — entry point
 */

import { secp256k1 } from '@noble/curves/secp256k1';
import { mkdir } from 'node:fs/promises';
import { dirname } from 'node:path';

import { createHash } from 'node:crypto';

import { loadConfig, runtimeSettingsFromConfig, type Config } from './types.js';
import { SqliteMessageStore } from './store.js';
import { ReservoirService } from './reservoir.js';
import { createMailServer } from './app.js';
import { pubkeyToStxAddress, hash160ToStxAddress } from './auth.js';
import { RuntimeSettingsStore } from './settings.js';

type ServerIdentitySource = 'env' | 'db' | 'generated';

function normalizePrivateKeyHex(value: string): string | null {
  const normalized = value.trim().replace(/^0x/, '').toLowerCase();
  if (!normalized) return null;
  // Accept 64-char (32-byte) keys or 66-char (32-byte + 01 compression flag) keys.
  if (/^[0-9a-f]{66}$/.test(normalized)) return normalized.slice(0, 64);
  return /^[0-9a-f]{64}$/.test(normalized) ? normalized : null;
}

function normalizePrincipal(value: string): string | null {
  const normalized = value.trim();
  return normalized ? normalized : null;
}

function isStandardPrincipal(value: string): boolean {
  return /^S[PT][0-9A-Z]{1,39}$/.test(value);
}

function isContractPrincipal(value: string): boolean {
  return /^S[A-Z][0-9A-Z]{1,39}\.[a-zA-Z][a-zA-Z0-9-]{0,39}$/.test(value);
}

function isPrincipal(value: string): boolean {
  return isStandardPrincipal(value) || isContractPrincipal(value);
}

function normalizeContractPrincipal(value: string): string | null {
  const normalized = value.trim();
  if (!normalized) return null;
  if (!isContractPrincipal(normalized)) {
    throw new Error('MAILSLOT_RESERVOIR_CONTRACT_ID must be a valid contract principal');
  }
  return normalized;
}

/**
 * Fetch the `stackflow-contract` data var from the reservoir contract on-chain.
 * Returns the contract principal string (e.g. "SP...sm-stackflow") or null.
 */
async function fetchSfContractFromReservoir(
  reservoirContractId: string,
  chainId: number,
): Promise<string | null> {
  const [addr, name] = reservoirContractId.split('.');
  if (!addr || !name) return null;

  const api = chainId === 1
    ? 'https://api.mainnet.hiro.so'
    : 'https://api.testnet.hiro.so';
  const url = `${api}/v2/data_var/${addr}/${name}/stackflow-contract`;

  try {
    const res = await fetch(url);
    if (!res.ok) return null;
    const json = await res.json() as { data?: string };
    const hex = json.data;
    if (!hex || !hex.startsWith('0x')) return null;

    const buf = Buffer.from(hex.slice(2), 'hex');
    // Expected: 0a (some) 06 (contract principal) version(1) hash160(20) nameLen(1) name(N)
    if (buf[0] !== 0x0a || buf[1] !== 0x06) return null;
    const version = buf[2];
    const hash160 = buf.subarray(3, 23).toString('hex');
    const nameLen = buf[23];
    const contractName = buf.subarray(24, 24 + nameLen).toString('ascii');

    const stxAddr = hash160ToStxAddress(hash160, version);
    return `${stxAddr}.${contractName}`;
  } catch {
    return null;
  }
}

function deriveStxAddressFromPrivateKey(privateKeyHex: string, chainId: number): string {
  const pubkey = secp256k1.getPublicKey(privateKeyHex, true);
  const pubkeyHex = Buffer.from(pubkey).toString('hex');
  return pubkeyToStxAddress(pubkeyHex, chainId !== 1);
}

function resolveServerIdentity(
  config: Config,
  db: import('better-sqlite3').Database,
): {
  privateKey: string;
  signerAddress: string;
  legacyReservoirAddress: string | null;
  source: ServerIdentitySource;
} {
  db.exec(`
    CREATE TABLE IF NOT EXISTS meta (
      key   TEXT PRIMARY KEY,
      value TEXT NOT NULL
    );
  `);

  const getMetaStmt = db.prepare('SELECT value FROM meta WHERE key = ?');
  const setMetaStmt = db.prepare(`
    INSERT INTO meta (key, value) VALUES (?, ?)
    ON CONFLICT(key) DO UPDATE SET value = excluded.value
  `);
  const getMeta = (key: string): string | null => {
    const row = getMetaStmt.get(key) as { value: string } | undefined;
    return row?.value ?? null;
  };
  const setMeta = (key: string, value: string): void => {
    setMetaStmt.run(key, value);
  };

  const envKeyRaw = config.serverPrivateKey.trim();
  if (envKeyRaw && !normalizePrivateKeyHex(envKeyRaw)) {
    throw new Error('MAILSLOT_SERVER_PRIVATE_KEY must be a 32-byte hex string');
  }

  const envAddressRaw = config.serverStxAddress.trim();
  const envAddress = normalizePrincipal(envAddressRaw);
  if (envAddress && !isPrincipal(envAddress)) {
    throw new Error('MAILSLOT_SERVER_STX_ADDRESS must be a valid STX principal');
  }
  const envStandardAddress = envAddress && isStandardPrincipal(envAddress) ? envAddress : null;
  const envLegacyReservoirAddress = envAddress && isContractPrincipal(envAddress) ? envAddress : null;

  let source: ServerIdentitySource = 'env';
  let privateKey = normalizePrivateKeyHex(envKeyRaw);
  if (!privateKey) {
    const storedKey = normalizePrivateKeyHex(getMeta('server_private_key') ?? '');
    if (storedKey) {
      privateKey = storedKey;
      source = 'db';
    }
  }
  if (!privateKey) {
    privateKey = Buffer.from(secp256k1.utils.randomPrivateKey()).toString('hex');
    source = 'generated';
  }

  const derivedSignerAddress = deriveStxAddressFromPrivateKey(privateKey, config.chainId);

  const storedAddress = normalizePrincipal(getMeta('server_stx_address') ?? '');
  const storedStandardAddress = storedAddress && isStandardPrincipal(storedAddress) ? storedAddress : null;
  const storedLegacyReservoirAddress = storedAddress && isContractPrincipal(storedAddress)
    ? storedAddress
    : null;

  const signerAddress = envStandardAddress ?? storedStandardAddress ?? derivedSignerAddress;
  if (!isStandardPrincipal(signerAddress)) {
    throw new Error('unable to resolve a valid signer STX principal');
  }

  // Signer principals must match the configured private key.
  if (signerAddress !== derivedSignerAddress) {
    throw new Error(
      `server signer address (${signerAddress}) does not match configured signing key-derived address (${derivedSignerAddress})`,
    );
  }

  const legacyReservoirAddress = envLegacyReservoirAddress ?? storedLegacyReservoirAddress ?? null;

  // Keep identity durable for container restarts.
  setMeta('server_private_key', privateKey);
  setMeta('server_stx_address', signerAddress);
  return { privateKey, signerAddress, legacyReservoirAddress, source };
}

async function main(): Promise<void> {
  const baseConfig = loadConfig();
  const config = { ...baseConfig };
  await mkdir(dirname(config.dbFile), { recursive: true });

  const store = new SqliteMessageStore(config.dbFile);
  await store.init();
  console.log('mailslot: database ready');

  // Inline reservoir shares the same SQLite DB as the message store
  const { default: Database } = await import('better-sqlite3');
  const reservoirDb = new Database(config.dbFile);
  reservoirDb.pragma('journal_mode = WAL');
  reservoirDb.pragma('synchronous = NORMAL');

  const identity = resolveServerIdentity(config, reservoirDb);
  config.serverPrivateKey = identity.privateKey;
  config.serverStxAddress = identity.signerAddress;

  const envReservoir = normalizeContractPrincipal(config.reservoirContractId);
  config.reservoirContractId = envReservoir ?? identity.legacyReservoirAddress ?? '';

  if (identity.source === 'generated') {
    console.warn(
      `mailslot: generated server key and persisted it to DB meta (signer: ${config.serverStxAddress})`,
    );
  } else if (identity.source === 'db') {
    console.warn(
      `mailslot: loaded server key from DB meta (signer: ${config.serverStxAddress})`,
    );
  }
  if (!envReservoir && identity.legacyReservoirAddress) {
    console.warn(
      `mailslot: using legacy MAILSLOT_SERVER_STX_ADDRESS contract principal as reservoir (${identity.legacyReservoirAddress}); set MAILSLOT_RESERVOIR_CONTRACT_ID explicitly`,
    );
  }
  console.log(`mailslot: signer address=${config.serverStxAddress}`);

  if (!config.sfContractId && config.reservoirContractId) {
    const discovered = await fetchSfContractFromReservoir(config.reservoirContractId, config.chainId);
    if (discovered) {
      config.sfContractId = discovered;
      console.log(`mailslot: discovered SF contract from reservoir: ${discovered}`);
    }
  }
  if (!config.sfContractId) {
    console.warn('mailslot: MAILSLOT_SF_CONTRACT_ID not set and could not be discovered — outgoing payments disabled');
  }
  if (!config.reservoirContractId) {
    console.warn('mailslot: reservoir contract not configured — tap onboarding disabled');
  }

  const runtimeSettings = new RuntimeSettingsStore(reservoirDb, runtimeSettingsFromConfig(config));

  const reservoir = new ReservoirService({
    db: reservoirDb,
    settings: runtimeSettings,
    serverAddress: config.reservoirContractId || config.serverStxAddress,
    signerAddress: config.serverStxAddress,
    reservoirContractId: config.reservoirContractId,
    serverPrivateKey: config.serverPrivateKey,
    contractId: config.sfContractId,
    chainId: config.chainId,
  });

  const server = createMailServer(config, store, reservoir, runtimeSettings);

  server.listen(config.port, config.host, () => {
    console.log(`mailslot: listening on ${config.host}:${config.port}`);
    console.log(`mailslot: network=${config.chainId === 1 ? 'mainnet' : 'testnet'}, contract=${config.sfContractId || '(none)'}`);
  });
}

main().catch(err => {
  console.error('fatal:', err);
  process.exit(1);
});
