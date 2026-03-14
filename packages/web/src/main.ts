import { secp256k1 } from '@noble/curves/secp256k1';
import { cbc } from '@noble/ciphers/aes.js';
import { hmac } from '@noble/hashes/hmac';
import { sha256 } from '@noble/hashes/sha256';
import { sha512 } from '@noble/hashes/sha512';
import { concatBytes } from '@noble/hashes/utils';
import {
  openContractCall,
  request as stacksRequest,
  getStacksProvider,
} from '@stacks/connect';
import {
  principalCV,
  noneCV,
  someCV,
  tupleCV,
  uintCV,
  stringAsciiCV,
  bufferCV,
  hexToCV,
  Pc,
  PostConditionMode,
  serializeCVBytes,
  ClarityType,
} from '@stacks/transactions';
import type { ClarityValue } from '@stacks/transactions';

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

const SF_CONTRACT = 'SP3QFYVTMS0PRJT3K3GMDW9DGR33TDHENSDWVNQMR.sm-stackflow';
const RESERVOIR   = 'SP3QFYVTMS0PRJT3K3GMDW9DGR33TDHENSDWVNQMR.sm-reservoir';
const CHAIN_ID    = 1; // mainnet; updated from /status if available
const OPEN_TAP_MULTIPLIER = 10n;
const OPEN_TAP_NONCE  = 0n;
const TARGET_RECEIVE_CAPACITY_MULTIPLIER = 20n;
const LOW_RECEIVE_CAPACITY_MULTIPLIER = 5n;
const OPEN_BORROW_NONCE  = 1n;

// (no session object needed — we use getStacksProvider() after wallet detection)

// ─────────────────────────────────────────────────────────────────────────────
// Utility helpers
// ─────────────────────────────────────────────────────────────────────────────

function bytesToHex(b: Uint8Array): string {
  return Array.from(b).map(x => x.toString(16).padStart(2, '0')).join('');
}

function hexToBytes(h: string): Uint8Array {
  h = h.replace(/^0x/, '');
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  return out;
}

async function withTimeout<T>(promise: Promise<T>, ms: number, message: string): Promise<T> {
  let timeoutId: ReturnType<typeof setTimeout> | undefined;
  const timeoutPromise = new Promise<never>((_, reject) => {
    timeoutId = setTimeout(() => reject(new Error(message)), ms);
  });
  try {
    return await Promise.race([promise, timeoutPromise]);
  } finally {
    if (timeoutId) clearTimeout(timeoutId);
  }
}

function chainIdToNetworkName(chainId: number): 'mainnet' | 'testnet' {
  return chainId === 1 ? 'mainnet' : 'testnet';
}

function chainIdToHiroApi(chainId: number): string {
  return chainId === 1 ? 'https://api.mainnet.hiro.so' : 'https://api.testnet.hiro.so';
}

function getRuntimeMessagePrice(): bigint {
  const raw = serverStatus.messagePriceSats;
  if (typeof raw === 'string' && /^\d+$/.test(raw.trim())) return BigInt(raw);
  return 1000n;
}

function getOpenTapAmount(): bigint {
  return getRuntimeMessagePrice() * OPEN_TAP_MULTIPLIER;
}

function getTargetReceiveLiquidity(): bigint {
  return getRuntimeMessagePrice() * TARGET_RECEIVE_CAPACITY_MULTIPLIER;
}

function getLowReceiveLiquidityThreshold(): bigint {
  return getRuntimeMessagePrice() * LOW_RECEIVE_CAPACITY_MULTIPLIER;
}

function getRemainingReceives(liquidity: bigint): bigint {
  const price = getRuntimeMessagePrice();
  if (price <= 0n) return 0n;
  return liquidity / price;
}

function getCapacityRefreshAmount(liquidity: bigint): bigint {
  const target = getTargetReceiveLiquidity();
  return liquidity >= target ? 0n : target - liquidity;
}

function describeReceiveCapacity(liquidity: bigint): { tone: 'good' | 'low'; message: string } {
  const remainingReceives = getRemainingReceives(liquidity);
  const threshold = getLowReceiveLiquidityThreshold();
  const target = getTargetReceiveLiquidity();
  if (liquidity <= threshold) {
    return {
      tone: 'low',
      message: `Receive capacity is low: about ${remainingReceives} more message(s). Refreshing restores it to ${getRemainingReceives(target)} messages.`,
    };
  }
  return {
    tone: 'good',
    message: `Receive capacity covers about ${remainingReceives} message(s).`,
  };
}

function extractSignature(resp: unknown): string | null {
  return (resp as { result?: { signature?: string }; signature?: string })?.result?.signature
    ?? (resp as { signature?: string })?.signature
    ?? null;
}

function extractPublicKey(resp: unknown): string | null {
  return (resp as { result?: { publicKey?: string }; publicKey?: string })?.result?.publicKey
    ?? (resp as { publicKey?: string })?.publicKey
    ?? null;
}

function extractAddresses(
  resp: unknown,
): Array<{ address: string; publicKey?: string }> {
  return (
    (resp as { result?: { addresses?: Array<{ address: string; publicKey?: string }> } })?.result?.addresses
    ?? (resp as { addresses?: Array<{ address: string; publicKey?: string }> })?.addresses
    ?? []
  );
}

function extractSupportedMethods(resp: unknown): string[] {
  return (
    (resp as { result?: { methods?: Array<{ name?: string }> } })?.result?.methods?.map(m => m.name ?? '')
      .filter(Boolean)
    ?? []
  );
}

function extractEncryptedMessage(resp: unknown): EncryptedMail | null {
  return (
    (resp as { result?: { encryptedMessage?: EncryptedMail } })?.result?.encryptedMessage
    ?? (resp as { encryptedMessage?: EncryptedMail })?.encryptedMessage
    ?? null
  );
}

function extractDecryptedMessage(resp: unknown): string | null {
  return (
    (resp as { result?: { message?: string } })?.result?.message
    ?? (resp as { message?: string })?.message
    ?? null
  );
}

function extractDecryptedMailslotMessage(resp: unknown): Partial<DecryptedMailPayload> | null {
  return (
    (resp as { result?: { mailslotMessage?: Partial<DecryptedMailPayload> } })?.result?.mailslotMessage
    ?? (resp as { mailslotMessage?: Partial<DecryptedMailPayload> })?.mailslotMessage
    ?? null
  );
}

function getLeatherProvider(): { request(method: string, params?: unknown): Promise<unknown> } | null {
  return (window as { LeatherProvider?: { request(method: string, params?: unknown): Promise<unknown> } })
    .LeatherProvider ?? null;
}

function isContractPrincipal(value: string): boolean {
  return /^S[PT][0-9A-Z]{39}\.[a-zA-Z][a-zA-Z0-9-]{0,39}$/.test(value);
}

function getRuntimeSfContract(): string {
  const sf = typeof serverStatus.sfContract === 'string' ? serverStatus.sfContract.trim() : '';
  return sf || SF_CONTRACT;
}

function getRuntimeReservoirContract(): string {
  const reservoir = typeof serverStatus.reservoirContract === 'string'
    ? serverStatus.reservoirContract.trim()
    : '';
  if (isContractPrincipal(reservoir)) return reservoir;
  const addr = typeof serverStatus.serverAddress === 'string' ? serverStatus.serverAddress.trim() : '';
  if (isContractPrincipal(addr)) return addr;
  return RESERVOIR;
}

function getReservoirDeployerAddress(): string | null {
  const [deployer] = getRuntimeReservoirContract().split('.');
  return /^S[PT][0-9A-Z]{39}$/.test(deployer) ? deployer : null;
}

function connectedUserIsReservoirAdmin(): boolean {
  return walletAddress != null && walletAddress === getReservoirDeployerAddress();
}

function browserDecryptFallbackEnabled(): boolean {
  return serverStatus.enableBrowserDecryptKey === true;
}

function updateAdminSectionVisibility(): void {
  const section = document.getElementById('admin-section') as HTMLElement | null;
  if (!section) return;
  section.style.display = connectedUserIsReservoirAdmin() ? '' : 'none';
}

function updateBrowserDecryptFallbackVisibility(): void {
  const section = document.getElementById('decrypt-key-section') as HTMLElement | null;
  if (!section) return;
  section.style.display = browserDecryptFallbackEnabled() ? '' : 'none';
}

function extractRuntimeSettings(status: Record<string, unknown>): RuntimeSettingsPayload | null {
  const raw = status.runtimeSettings;
  if (!raw || typeof raw !== 'object') return null;
  const value = raw as Record<string, unknown>;
  if (
    value.messagePriceSats == null ||
    value.minFeeSats == null ||
    value.maxPendingPerSender == null ||
    value.maxPendingPerRecipient == null ||
    value.maxDeferredPerSender == null ||
    value.maxDeferredPerRecipient == null ||
    value.maxDeferredGlobal == null ||
    value.deferredMessageTtlMs == null ||
    value.maxBorrowPerTap == null
  ) {
    return null;
  }
  return {
    messagePriceSats: String(value.messagePriceSats),
    minFeeSats: String(value.minFeeSats),
    maxPendingPerSender: Number(value.maxPendingPerSender),
    maxPendingPerRecipient: Number(value.maxPendingPerRecipient),
    maxDeferredPerSender: Number(value.maxDeferredPerSender),
    maxDeferredPerRecipient: Number(value.maxDeferredPerRecipient),
    maxDeferredGlobal: Number(value.maxDeferredGlobal),
    deferredMessageTtlMs: Number(value.deferredMessageTtlMs),
    maxBorrowPerTap: String(value.maxBorrowPerTap),
  };
}

function populateAdminSettingsForm(settings: RuntimeSettingsPayload | null): void {
  if (!settings) return;
  (document.getElementById('admin-message-price-input') as HTMLInputElement | null)!.value = settings.messagePriceSats;
  (document.getElementById('admin-min-fee-input') as HTMLInputElement | null)!.value = settings.minFeeSats;
  (document.getElementById('admin-max-pending-sender-input') as HTMLInputElement | null)!.value = String(settings.maxPendingPerSender);
  (document.getElementById('admin-max-pending-recipient-input') as HTMLInputElement | null)!.value = String(settings.maxPendingPerRecipient);
  (document.getElementById('admin-max-deferred-sender-input') as HTMLInputElement | null)!.value = String(settings.maxDeferredPerSender);
  (document.getElementById('admin-max-deferred-recipient-input') as HTMLInputElement | null)!.value = String(settings.maxDeferredPerRecipient);
  (document.getElementById('admin-max-deferred-global-input') as HTMLInputElement | null)!.value = String(settings.maxDeferredGlobal);
  (document.getElementById('admin-deferred-ttl-input') as HTMLInputElement | null)!.value = String(settings.deferredMessageTtlMs);
  (document.getElementById('admin-max-borrow-per-tap-input') as HTMLInputElement | null)!.value = settings.maxBorrowPerTap;
}

function hasSupportedTokenResolved(): boolean {
  return Object.prototype.hasOwnProperty.call(serverStatus, 'supportedToken');
}

function getRuntimeSupportedToken(): string | null {
  const token = serverStatus.supportedToken;
  if (token == null) return null;
  if (typeof token !== 'string') {
    throw new Error('Invalid supported token in server status');
  }
  const normalized = token.trim();
  if (!normalized) return null;
  if (!isContractPrincipal(normalized)) {
    throw new Error(`Invalid supported token principal: ${normalized}`);
  }
  return normalized;
}

function getRuntimeSupportedTokenAssetName(): string | null {
  const raw = serverStatus.supportedTokenAssetName;
  if (raw == null) return null;
  if (typeof raw !== 'string') {
    throw new Error('Invalid supported token asset name in server status');
  }
  const normalized = raw.trim();
  if (!normalized) return null;
  return normalized;
}

function optionalPrincipalCvHex(value: string | null): string {
  const cv = value == null ? noneCV() : someCV(principalCV(value));
  return bytesToHex(serializeCVBytes(cv));
}

function parseFungibleTokenNameFromInterface(
  payload: Record<string, unknown>,
  contractId: string,
): string | null {
  const pickFromContainer = (container: unknown): string | null => {
    if (!container || typeof container !== 'object') return null;
    const tokens = (container as { fungible_tokens?: unknown }).fungible_tokens;
    if (!Array.isArray(tokens) || tokens.length === 0) return null;
    for (const token of tokens) {
      if (typeof token === 'string' && token.trim()) return token.trim();
      if (token && typeof token === 'object') {
        const obj = token as Record<string, unknown>;
        const name = typeof obj.name === 'string' ? obj.name.trim() : '';
        if (name) return name;
        const assetId = typeof obj.asset_identifier === 'string' ? obj.asset_identifier : '';
        if (assetId.startsWith(`${contractId}::`)) return assetId.slice(`${contractId}::`.length);
      }
    }
    return null;
  };
  return pickFromContainer(payload) ?? pickFromContainer(payload.abi);
}

async function fetchFungibleTokenName(
  tokenContract: string,
  chainId: number,
): Promise<string> {
  const [contractAddr, contractName] = tokenContract.split('.');
  const r = await fetch(
    `${chainIdToHiroApi(chainId)}/v2/contracts/interface/${contractAddr}/${contractName}`,
  );
  if (!r.ok) {
    throw new Error(`Failed to read token interface from ${tokenContract} (${r.status})`);
  }
  const payload = await r.json() as Record<string, unknown>;
  const name = parseFungibleTokenNameFromInterface(payload, tokenContract);
  if (!name) {
    throw new Error(`Could not determine fungible token asset name for ${tokenContract}`);
  }
  return name;
}

async function fetchReservoirSupportedToken(
  reservoirContract: string,
  chainId: number,
): Promise<string | null> {
  const [contractAddr, contractName] = reservoirContract.split('.');
  const r = await fetch(
    `${chainIdToHiroApi(chainId)}/v2/data_var/${contractAddr}/${contractName}/supported-token`,
  );
  if (!r.ok) {
    throw new Error(`Failed to read supported-token from reservoir (${r.status})`);
  }
  const payload = await r.json() as Record<string, unknown>;
  const directHex =
    (typeof payload.data === 'string' ? payload.data : null)
    ?? (typeof payload.result === 'string' ? payload.result : null)
    ?? (typeof payload.value === 'string' ? payload.value : null)
    ?? (typeof payload.hex === 'string' ? payload.hex : null);
  if (!directHex || !directHex.startsWith('0x')) {
    throw new Error('Unexpected supported-token response format');
  }

  const cv = hexToCV(directHex);
  if (cv.type === ClarityType.OptionalNone) return null;
  if (cv.type === ClarityType.OptionalSome) {
    const nested = cv.value;
    if (nested.type === ClarityType.PrincipalContract || nested.type === ClarityType.PrincipalStandard) {
      return nested.value;
    }
  }
  throw new Error('supported-token is not an optional principal');
}

async function ensureServerStatusLoaded(): Promise<void> {
  if (
    typeof serverStatus.sfContract === 'string' &&
    typeof serverStatus.serverAddress === 'string' &&
    typeof serverStatus.chainId === 'number'
  ) {
    return;
  }
  await loadStatus();
}

async function ensureSupportedTokenLoaded(): Promise<void> {
  await ensureServerStatusLoaded();
  if (hasSupportedTokenResolved()) return;
  const reservoir = getRuntimeReservoirContract();
  const chainId = (serverStatus.chainId as number | undefined) ?? CHAIN_ID;
  const supportedToken = await fetchReservoirSupportedToken(reservoir, chainId);
  serverStatus.supportedToken = supportedToken;
}

async function ensureSupportedTokenAssetNameLoaded(): Promise<void> {
  await ensureSupportedTokenLoaded();
  const tokenContract = getRuntimeSupportedToken();
  if (tokenContract == null) {
    serverStatus.supportedTokenAssetName = null;
    return;
  }
  const existing = getRuntimeSupportedTokenAssetName();
  if (existing) return;
  const chainId = (serverStatus.chainId as number | undefined) ?? CHAIN_ID;
  const tokenName = await fetchFungibleTokenName(tokenContract, chainId);
  serverStatus.supportedTokenAssetName = tokenName;
}

// ─────────────────────────────────────────────────────────────────────────────
// Canonical pipe key ordering (using @stacks/transactions serializeCV)
// ─────────────────────────────────────────────────────────────────────────────

interface PipeKey {
  token: string | null;
  'principal-1': string;
  'principal-2': string;
}

function canonicalPipeKey(token: string | null, a: string, b: string): PipeKey {
  const pa = serializeCVBytes(principalCV(a));
  const pb = serializeCVBytes(principalCV(b));
  for (let i = 0; i < Math.min(pa.length, pb.length); i++) {
    if (pa[i] < pb[i]) return { token, 'principal-1': a, 'principal-2': b };
    if (pa[i] > pb[i]) return { token, 'principal-1': b, 'principal-2': a };
  }
  return { token, 'principal-1': a, 'principal-2': b };
}

// ─────────────────────────────────────────────────────────────────────────────
// buildTransferCV — builds the SIP-018 transfer tuple as a ClarityValue
// ─────────────────────────────────────────────────────────────────────────────

interface BuildTransferCVParams {
  pipeKey: PipeKey;
  forPrincipal: string;
  myBalance: bigint;
  theirBalance: bigint;
  nonce: bigint;
  action: bigint;
  actor: string;
  hashedSecret?: string | null;
  validAfter?: bigint | null;
}

function buildTransferCV(params: BuildTransferCVParams): ClarityValue {
  const localIsP1 = params.pipeKey['principal-1'] === params.forPrincipal;
  const balance1  = localIsP1 ? params.myBalance : params.theirBalance;
  const balance2  = localIsP1 ? params.theirBalance : params.myBalance;
  return tupleCV({
    'principal-1':   principalCV(params.pipeKey['principal-1']),
    'principal-2':   principalCV(params.pipeKey['principal-2']),
    token:           params.pipeKey.token == null ? noneCV() : someCV(principalCV(params.pipeKey.token)),
    'balance-1':     uintCV(balance1),
    'balance-2':     uintCV(balance2),
    nonce:           uintCV(params.nonce),
    action:          uintCV(params.action),
    actor:           principalCV(params.actor),
    'hashed-secret': params.hashedSecret == null ? noneCV() : someCV(bufferCV(hexToBytes(params.hashedSecret))),
    'valid-after':   params.validAfter == null ? noneCV() : someCV(uintCV(params.validAfter)),
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// cvToWalletJson — converts ClarityValues to wallet JSON representation
// ─────────────────────────────────────────────────────────────────────────────

function cvToWalletJson(cv: ClarityValue): unknown {
  switch (cv.type) {
    case ClarityType.UInt:
      return { type: 'uint', value: String(cv.value) };
    case ClarityType.Int:
      return { type: 'int', value: String(cv.value) };
    case ClarityType.PrincipalStandard:
    case ClarityType.PrincipalContract:
      return { type: 'principal', value: cv.value };
    case ClarityType.StringASCII:
      return { type: 'string-ascii', value: cv.value };
    case ClarityType.StringUTF8:
      return { type: 'string-utf8', value: cv.value };
    case ClarityType.OptionalNone:
      return { type: 'none' };
    case ClarityType.OptionalSome:
      return { type: 'some', value: cvToWalletJson(cv.value) };
    case ClarityType.ResponseOk:
      return { type: 'ok', value: cvToWalletJson(cv.value) };
    case ClarityType.ResponseErr:
      return { type: 'err', value: cvToWalletJson(cv.value) };
    case ClarityType.Buffer:
      return { type: 'buffer', data: cv.value };
    case ClarityType.Tuple: {
      const data: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(cv.value as Record<string, ClarityValue>)) {
        data[k] = cvToWalletJson(v);
      }
      return { type: 'tuple', data };
    }
    case ClarityType.List: {
      return { type: 'list', list: cv.value.map(cvToWalletJson) };
    }
    case ClarityType.BoolTrue:
      return { type: 'bool', value: true };
    case ClarityType.BoolFalse:
      return { type: 'bool', value: false };
    default:
      return { type: 'unknown' };
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// ECIES encryption
// ─────────────────────────────────────────────────────────────────────────────

interface EncryptedMail {
  iv: string;
  ephemeralPK: string;
  cipherText: string;
  mac: string;
  wasString: boolean;
  cipherTextEncoding?: 'hex' | 'base64';
}

interface DecryptedMailPayload {
  v: 1;
  secret: string;
  subject?: string;
  body: string;
}

async function encryptMail(payload: unknown, recipientPubkeyHex: string): Promise<EncryptedMail> {
  const ephemeralPrivateKey = secp256k1.utils.randomPrivateKey();
  const ephemeralPublicKey = secp256k1.getPublicKey(ephemeralPrivateKey, true);
  const recipientPublicKey = hexToBytes(recipientPubkeyHex.replace(/^0x/i, ''));
  const sharedSecret = secp256k1.getSharedSecret(ephemeralPrivateKey, recipientPublicKey, true).slice(1);
  const keyMaterial = sha512(sharedSecret);
  const encryptionKey = keyMaterial.slice(0, 32);
  const hmacKey = keyMaterial.slice(32);
  const iv = secp256k1.utils.randomPrivateKey().slice(0, 16);
  const plaintext = new TextEncoder().encode(JSON.stringify(payload));
  const cipherText = cbc(encryptionKey, iv).encrypt(plaintext);
  const mac = hmac(sha256, hmacKey, concatBytes(iv, ephemeralPublicKey, cipherText));
  return {
    iv: bytesToHex(iv),
    ephemeralPK: bytesToHex(ephemeralPublicKey),
    cipherText: bytesToHex(cipherText),
    mac: bytesToHex(mac),
    wasString: true,
  };
}

async function decryptMail(payload: EncryptedMail, privateKeyHex: string): Promise<DecryptedMailPayload> {
  const privateKey = hexToBytes(privateKeyHex.replace(/^0x/i, ''));
  const ephemeralPK = hexToBytes(payload.ephemeralPK.replace(/^0x/i, ''));
  const iv = hexToBytes(payload.iv.replace(/^0x/i, ''));
  const cipherText =
    payload.cipherTextEncoding === 'base64'
      ? Uint8Array.from(atob(payload.cipherText), c => c.charCodeAt(0))
      : hexToBytes(payload.cipherText.replace(/^0x/i, ''));
  const expectedMac = hexToBytes(payload.mac.replace(/^0x/i, ''));

  const sharedSecret = secp256k1.getSharedSecret(privateKey, ephemeralPK, true).slice(1);
  const keyMaterial = sha512(sharedSecret);
  const encryptionKey = keyMaterial.slice(0, 32);
  const hmacKey = keyMaterial.slice(32);
  const actualMac = hmac(sha256, hmacKey, concatBytes(iv, ephemeralPK, cipherText));
  if (actualMac.length !== expectedMac.length || actualMac.some((byte, i) => byte !== expectedMac[i])) {
    throw new Error('decryption failed: wrong key or corrupted ciphertext');
  }

  const plaintext = cbc(encryptionKey, iv).decrypt(cipherText);
  const parsed = JSON.parse(new TextDecoder().decode(plaintext)) as DecryptedMailPayload;
  if (!parsed || parsed.v !== 1 || typeof parsed.secret !== 'string' || typeof parsed.body !== 'string') {
    throw new Error('Decrypted payload is not valid Mailslot mail');
  }
  return parsed;
}

// ─────────────────────────────────────────────────────────────────────────────
// Wallet state
// ─────────────────────────────────────────────────────────────────────────────

let walletAddress: string | null = null;
let walletPubkey: string | null  = null;
let serverStatus: Record<string, unknown> = {};
let pipeState = { myBalance: 0n, serverBalance: 0n, nonce: 0n };
let inboxDecryptPrivateKey: string | null = null;
let walletCryptoAvailable = false;
let lastInboxMessages: InboxMessage[] = [];
let inboxActionMessageId: string | null = null;
const openedInboxMessages: Record<string, DecryptedMailPayload> = {};
const inboxMessageErrors: Record<string, string> = {};

// Auth header cache for get-inbox (avoids wallet popup on every inbox load)
let cachedGetInboxAuth: string | null = null;
let cachedGetInboxAuthExpiry = 0;
let inboxSessionToken: string | null = null;
let inboxSessionExpiresAt = 0;

interface RuntimeSettingsPayload {
  messagePriceSats: string;
  minFeeSats: string;
  maxPendingPerSender: number;
  maxPendingPerRecipient: number;
  maxDeferredPerSender: number;
  maxDeferredPerRecipient: number;
  maxDeferredGlobal: number;
  deferredMessageTtlMs: number;
  maxBorrowPerTap: string;
}
const DECRYPT_KEY_STORAGE_KEY = 'mailslot.inboxDecryptPrivateKey';

// ─────────────────────────────────────────────────────────────────────────────
// App state machine
// States: no-wallet | checking | no-tap | tx-pending | ready
// ─────────────────────────────────────────────────────────────────────────────

function setAppState(state: 'no-wallet' | 'checking' | 'no-tap' | 'tx-pending' | 'ready'): void {
  (document.getElementById('panel-no-wallet')  as HTMLElement).style.display = state === 'no-wallet'  ? '' : 'none';
  (document.getElementById('panel-checking')   as HTMLElement).style.display = state === 'checking'   ? '' : 'none';
  (document.getElementById('panel-onboarding') as HTMLElement).style.display = state === 'no-tap'     ? '' : 'none';
  (document.getElementById('panel-tx-pending') as HTMLElement).style.display = state === 'tx-pending' ? '' : 'none';
  (document.getElementById('panel-main')       as HTMLElement).style.display = state === 'ready'      ? '' : 'none';
  (document.getElementById('main-nav')         as HTMLElement).style.display = state === 'ready'      ? '' : 'none';
}

function normalizePrivateKeyHex(value: string): string | null {
  const normalized = value.trim().replace(/^0x/, '').toLowerCase();
  if (!normalized) return null;
  if (/^[0-9a-f]{64}$/.test(normalized)) return normalized;
  // Stacks wallets often export 33-byte compressed private keys with a trailing `01`.
  if (/^[0-9a-f]{66}$/.test(normalized) && normalized.endsWith('01')) {
    return normalized.slice(0, 64);
  }
  return null;
}

function maskPrivateKey(value: string): string {
  return `${value.slice(0, 6)}...${value.slice(-4)}`;
}

function validateDecryptKeyForWallet(privateKeyHex: string): void {
  const derivedPubkey = bytesToHex(secp256k1.getPublicKey(hexToBytes(privateKeyHex), true));
  if (walletPubkey && derivedPubkey !== walletPubkey.toLowerCase()) {
    throw new Error('Decrypt key does not match the connected wallet public key');
  }
}

function updateDecryptKeyStatus(kind: 'info' | 'success' | 'warning' | 'error', message: string): void {
  const statusEl = document.getElementById('decrypt-key-status') as HTMLElement | null;
  if (!statusEl) return;
  const cls = kind === 'info'
    ? 'alert-info'
    : kind === 'success'
      ? 'alert-success'
      : kind === 'warning'
        ? 'alert-warning'
        : 'alert-error';
  statusEl.innerHTML = `<div class="alert ${cls}">${escHtml(message)}</div>`;
}

function updateDecryptCliHelp(): void {
  const card = document.getElementById('decrypt-cli-help') as HTMLElement | null;
  const commandsEl = document.getElementById('decrypt-cli-commands') as HTMLElement | null;
  if (!card || !commandsEl) return;

  const shouldShow = !walletCryptoAvailable;
  card.style.display = shouldShow ? '' : 'none';
  if (!shouldShow) return;

  const serverUrl = window.location.origin;
  commandsEl.textContent = [
    'Install:',
    'curl -fsSL https://raw.githubusercontent.com/warmidris/mailslot/main/scripts/install-cli.sh | sh',
    'export MAILSLOT_PRIVATE_KEY=<your-private-key>',
    '',
    'Open your inbox:',
    `MAILSLOT_SERVER_URL=${serverUrl} mailslot inbox`,
    '',
    'Read a specific message:',
    `MAILSLOT_SERVER_URL=${serverUrl} mailslot read <message-id>`,
  ].join('\n');
}

function cliReadCommand(messageId: string): string {
  return `MAILSLOT_SERVER_URL=${window.location.origin} mailslot read ${messageId}`;
}

function updateDecryptKeyUI(): void {
  updateBrowserDecryptFallbackVisibility();
  const input = document.getElementById('decrypt-key-input') as HTMLInputElement | null;
  const saveBtn = document.getElementById('save-decrypt-key-btn') as HTMLButtonElement | null;
  const clearBtn = document.getElementById('clear-decrypt-key-btn') as HTMLButtonElement | null;
  if (!input || !saveBtn || !clearBtn) return;

  if (!browserDecryptFallbackEnabled()) {
    input.value = '';
    saveBtn.disabled = true;
    clearBtn.disabled = true;
    updateDecryptKeyStatus('info', walletCryptoAvailable
      ? 'Wallet-native decrypt is available.'
      : 'Browser private-key decrypt is disabled on this server.');
    updateDecryptCliHelp();
    return;
  }

  clearBtn.disabled = !inboxDecryptPrivateKey;
  saveBtn.disabled = false;
  if (inboxDecryptPrivateKey) {
    input.value = '';
    saveBtn.textContent = 'Replace Decrypt Key';
    updateDecryptKeyStatus('success', `Decrypt key loaded: ${maskPrivateKey(inboxDecryptPrivateKey)}`);
  } else if (walletCryptoAvailable) {
    saveBtn.textContent = 'Load Decrypt Key';
    updateDecryptKeyStatus('info', 'Leather wallet decrypt is available. Local key entry is optional fallback.');
  } else {
    saveBtn.textContent = 'Load Decrypt Key';
    updateDecryptKeyStatus('info', 'Load the local decrypt key to claim and open encrypted messages in the browser.');
  }
  updateDecryptCliHelp();
}

function saveDecryptKey(): void {
  if (!browserDecryptFallbackEnabled()) {
    updateDecryptKeyStatus('warning', 'Browser private-key decrypt is disabled on this server.');
    return;
  }
  const input = document.getElementById('decrypt-key-input') as HTMLInputElement;
  const normalized = normalizePrivateKeyHex(input.value);
  if (!normalized) {
    updateDecryptKeyStatus('warning', 'Enter a 64-char hex private key or a 66-char Stacks private key ending in 01.');
    return;
  }

  try {
    validateDecryptKeyForWallet(normalized);
    inboxDecryptPrivateKey = normalized;
    sessionStorage.setItem(DECRYPT_KEY_STORAGE_KEY, normalized);
    input.value = '';
    updateDecryptKeyUI();
    if (lastInboxMessages.length) renderInboxMessages(lastInboxMessages);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    updateDecryptKeyStatus('error', message);
  }
}

function clearDecryptKey(): void {
  inboxDecryptPrivateKey = null;
  sessionStorage.removeItem(DECRYPT_KEY_STORAGE_KEY);
  updateDecryptKeyUI();
  if (lastInboxMessages.length) renderInboxMessages(lastInboxMessages);
}

function restoreDecryptKeyFromSession(): void {
  if (!browserDecryptFallbackEnabled()) {
    sessionStorage.removeItem(DECRYPT_KEY_STORAGE_KEY);
    inboxDecryptPrivateKey = null;
    updateDecryptKeyUI();
    return;
  }
  const stored = sessionStorage.getItem(DECRYPT_KEY_STORAGE_KEY);
  if (!stored) {
    updateDecryptKeyUI();
    return;
  }
  const normalized = normalizePrivateKeyHex(stored);
  if (!normalized) {
    sessionStorage.removeItem(DECRYPT_KEY_STORAGE_KEY);
    updateDecryptKeyUI();
    return;
  }
  try {
    validateDecryptKeyForWallet(normalized);
    inboxDecryptPrivateKey = normalized;
    updateDecryptKeyUI();
  } catch {
    inboxDecryptPrivateKey = null;
    sessionStorage.removeItem(DECRYPT_KEY_STORAGE_KEY);
    updateDecryptKeyStatus('warning', 'Stored decrypt key did not match the connected wallet and was cleared.');
  }
}

async function refreshWalletCryptoAvailability(): Promise<void> {
  const provider = getLeatherProvider();
  if (!provider) {
    walletCryptoAvailable = false;
    updateDecryptKeyUI();
    return;
  }

  try {
    const resp = await provider.request('supportedMethods');
    const methods = extractSupportedMethods(resp);
    walletCryptoAvailable =
      methods.includes('stx_encryptMessage') && methods.includes('stx_decryptMessage');
  } catch {
    walletCryptoAvailable = false;
  }

  updateDecryptKeyUI();
  if (lastInboxMessages.length) renderInboxMessages(lastInboxMessages);
}

// ─────────────────────────────────────────────────────────────────────────────
// Connect wallet
// ─────────────────────────────────────────────────────────────────────────────

async function connectWallet(): Promise<void> {
  const btns = document.querySelectorAll<HTMLButtonElement>('#connect-wallet-btn, #connect-wallet-main');
  btns.forEach(b => { b.disabled = true; b.textContent = 'Connecting…'; });

  try {
    let accts: Array<{ address: string; publicKey?: string }> = [];

    // Preferred path: Stacks Connect handles wallet selection and compatibility.
    try {
      const addrsResp = await withTimeout(
        stacksRequest({ forceWalletSelect: true }, 'getAddresses'),
        120_000,
        'Timed out waiting for wallet connection. Open your wallet extension and approve the request.',
      );
      accts = extractAddresses(addrsResp);
    } catch (err) {
      try {
        const addrsResp = await withTimeout(
          stacksRequest({ forceWalletSelect: true }, 'stx_getAddresses'),
          120_000,
          'Timed out waiting for wallet connection. Open your wallet extension and approve the request.',
        );
        accts = extractAddresses(addrsResp);
      } catch {
        const provider = getStacksProvider();
        if (!provider) {
          throw err;
        }
        const addrsResp = await withTimeout(
          provider.request('stx_getAddresses'),
          120_000,
          'Timed out waiting for wallet connection. Open your wallet extension and approve the request.',
        );
        accts = extractAddresses(addrsResp);
      }
    }

    if (!accts.length) {
      const provider = getStacksProvider();
      if (!provider) {
        (document.getElementById('wallet-error') as HTMLElement).innerHTML =
          '<div class="alert alert-warning">No Stacks wallet detected. Install <a href="https://leather.io" target="_blank" style="color:inherit">Leather</a> or <a href="https://xverse.app" target="_blank" style="color:inherit">Xverse</a> and refresh.</div>';
        btns.forEach(b => { b.disabled = false; b.textContent = 'Connect Wallet'; });
        return;
      }
    }

    if (!accts.length) {
      (document.getElementById('wallet-error') as HTMLElement).innerHTML =
        '<div class="alert alert-error">Wallet connected, but no addresses were returned.</div>';
      throw new Error('Wallet returned no addresses.');
    }
    const mainnetAcct = accts.find(a => a.address?.startsWith('SP'))
      ?? accts.find(a => a.address?.startsWith('ST'))
      ?? accts[0];

    if (!mainnetAcct?.address) throw new Error('Wallet returned no address.');

    walletAddress = mainnetAcct.address;
    walletPubkey  = typeof mainnetAcct.publicKey === 'string'
      ? mainnetAcct.publicKey.replace(/^0x/, '').toLowerCase()
      : null;

    updateWalletUI();
    await ensureServerStatusLoaded().catch(() => {});
    restoreDecryptKeyFromSession();
    await refreshWalletCryptoAvailability();
    await onWalletConnected();
  } catch (e) {
    const msg = typeof e === 'string' ? e : ((e as Error)?.message || (e as { reason?: string })?.reason || JSON.stringify(e) || 'Unknown error');
    (document.getElementById('wallet-error') as HTMLElement).innerHTML =
      `<div class="alert alert-error">Connection failed: ${escHtml(msg)}</div>`;
    btns.forEach(b => { b.disabled = false; b.textContent = 'Connect Wallet'; });
  }
}

function disconnectWallet(): void {
  walletAddress = null;
  walletPubkey  = null;
  walletCryptoAvailable = false;
  pipeState     = { myBalance: 0n, serverBalance: 0n, nonce: 0n };
  lastInboxMessages = [];
  inboxActionMessageId = null;
  cachedGetInboxAuth = null;
  cachedGetInboxAuthExpiry = 0;
  inboxSessionToken = null;
  inboxSessionExpiresAt = 0;
  for (const key of Object.keys(openedInboxMessages)) delete openedInboxMessages[key];
  for (const key of Object.keys(inboxMessageErrors)) delete inboxMessageErrors[key];
  updateWalletUI();
  updateAdminSectionVisibility();
  clearDecryptKey();
  setAppState('no-wallet');
}

function updateWalletUI(): void {
  const chip       = document.getElementById('wallet-chip') as HTMLElement;
  const connectBtn = document.getElementById('connect-wallet-btn') as HTMLButtonElement;
  if (walletAddress) {
    chip.style.display = 'flex';
    connectBtn.style.display = 'none';
    (document.getElementById('wallet-addr-chip') as HTMLElement).textContent =
      walletAddress.slice(0, 8) + '…' + walletAddress.slice(-4);
  } else {
    chip.style.display = 'none';
    connectBtn.style.display = '';
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// After wallet connects: check tap, route to state
// ─────────────────────────────────────────────────────────────────────────────

async function onWalletConnected(): Promise<void> {
  setAppState('checking');
  (document.getElementById('checking-label') as HTMLElement).textContent = 'Checking payment channel…';

  try {
    await withTimeout(ensureServerStatusLoaded(), 15_000, 'Server status timeout');
  } catch {
    // Continue with defaults if status is temporarily unavailable.
  }

  const tap = await withTimeout(
    resolveTapState(walletAddress!),
    20_000,
    'On-chain tap query timeout',
  ).catch(() => null);

  if (!tap) {
    (document.getElementById('onboarding-addr') as HTMLElement).textContent = walletAddress!;
    setAppState('no-tap');
  } else {
    pipeState = { myBalance: tap.userBalance, serverBalance: tap.reservoirBalance, nonce: tap.nonce };
    updateIdentityUI();
    setAppState('ready');
    showTab('inbox');
    loadStatus();
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Wallet auth (SIP-018 structured data)
// ─────────────────────────────────────────────────────────────────────────────

async function buildWalletAuthHeader(action: string, messageId?: string): Promise<string> {
  // Return cached auth for get-inbox (valid for 4 minutes)
  if (action === 'get-inbox' && cachedGetInboxAuth && Date.now() < cachedGetInboxAuthExpiry) {
    return cachedGetInboxAuth;
  }

  const ts         = Date.now();
  const chainId    = (serverStatus.chainId as number | undefined)    ?? CHAIN_ID;
  const authDomain = (serverStatus.authDomain as string | undefined) ?? 'Mailslot';
  const sfVersion  = (serverStatus.sfVersion as string | undefined)  ?? '0.6.0';
  const audience   = (serverStatus.authAudience as string | undefined)
    ?? (serverStatus.reservoirContract as string | undefined)
    ?? (serverStatus.serverAddress as string | undefined)
    ?? 'Mailslot';

  const msgFields: Record<string, { type: string; value: string }> = {
    action:    { type: 'string-ascii', value: action },
    address:   { type: 'principal',   value: walletAddress! },
    timestamp: { type: 'uint',        value: String(ts) },
    audience:  { type: 'string-ascii', value: audience },
    ...(messageId ? { messageId: { type: 'string-ascii', value: messageId } } : {}),
  };

  const domainCV = tupleCV({
    'chain-id': uintCV(chainId),
    name: stringAsciiCV(authDomain),
    version: stringAsciiCV(sfVersion),
  });
  const messageCV = tupleCV({
    action: stringAsciiCV(action),
    address: principalCV(walletAddress!),
    timestamp: uintCV(BigInt(ts)),
    audience: stringAsciiCV(audience),
    ...(messageId ? { messageId: stringAsciiCV(messageId) } : {}),
  });

  const { signature, publicKey } = await withTimeout(
    signStructuredMessageWithWallet(messageCV, domainCV, chainId),
    120_000,
    'Timed out waiting for wallet signature. Open your wallet extension and approve the SIP-018 request.',
  );
  const pubkey = publicKey ?? walletPubkey;
  if (!signature) throw new Error('Wallet returned no signature');

  const authHeader = btoa(JSON.stringify({ type: 'sip018', pubkey, message: msgFields, signature }));

  if (action === 'get-inbox') {
    cachedGetInboxAuth = authHeader;
    cachedGetInboxAuthExpiry = Date.now() + 4 * 60 * 1000;
  }

  return authHeader;
}

// ─────────────────────────────────────────────────────────────────────────────
// SIP-018 signing for payment proofs — using stx_signStructuredMessage
// ─────────────────────────────────────────────────────────────────────────────

async function sip018SignWithWallet(contractId: string, transferCV: ClarityValue, chainId: number): Promise<string> {
  const domainCV = tupleCV({
    'chain-id': uintCV(chainId),
    name: stringAsciiCV(contractId),
    version: stringAsciiCV('0.6.0'),
  });
  const signed = await signStructuredMessageWithWallet(
    transferCV as ReturnType<typeof tupleCV>,
    domainCV,
    chainId,
  );
  return signed.signature;
}

async function signStructuredMessageWithWallet(
  messageCV: ReturnType<typeof tupleCV>,
  domainCV: ReturnType<typeof tupleCV>,
  chainId: number,
): Promise<{ signature: string; publicKey: string | null }> {
  const network = chainIdToNetworkName(chainId);
  let resp: unknown = null;
  let lastError: unknown = null;

  // Preferred path: @stacks/connect request() normalizes wallet-specific quirks.
  try {
    resp = await stacksRequest('stx_signStructuredMessage', {
      message: messageCV,
      domain: domainCV,
    });
    const sig = extractSignature(resp);
    if (sig) return { signature: sig, publicKey: extractPublicKey(resp) };
  } catch (err) {
    lastError = err;
  }

  const provider = getStacksProvider();
  if (!provider) {
    if (lastError) throw lastError;
    throw new Error('No Stacks wallet detected');
  }

  // Fallback path for providers that only expose raw request().
  try {
    resp = await provider.request('stx_signStructuredMessage', {
      network,
      message: messageCV,
      domain: domainCV,
    });
    const sig = extractSignature(resp);
    if (sig) return { signature: sig, publicKey: extractPublicKey(resp) };
  } catch (err) {
    lastError = err;
  }

  // Last resort: wallet-json format for older provider implementations.
  try {
    resp = await provider.request('stx_signStructuredMessage', {
      network,
      message: cvToWalletJson(messageCV),
      domain: cvToWalletJson(domainCV),
    });
    const sig = extractSignature(resp);
    if (sig) return { signature: sig, publicKey: extractPublicKey(resp) };
  } catch (err) {
    lastError = err;
  }

  if (lastError) {
    const msg = (lastError as Error)?.message ?? '';
    if (msg.includes('not supported') || msg.includes('structured')) {
      throw new Error("Your wallet doesn't support structured data signing (SIP-018). Try Leather v6+");
    }
    throw lastError;
  }
  throw new Error('Wallet returned no signature');
}

// ─────────────────────────────────────────────────────────────────────────────
// On-chain tap check — queries sm-stackflow via Hiro read-only API
// ─────────────────────────────────────────────────────────────────────────────

interface TapState {
  userBalance: bigint;
  reservoirBalance: bigint;
  settledUserBalance: bigint | null;
  settledReservoirBalance: bigint | null;
  pendingUserBalance: bigint | null;
  pendingReservoirBalance: bigint | null;
  nonce: bigint;
  pipeKey: PipeKey;
}

interface PendingLeg {
  amount: bigint;
  burnHeight: bigint | null;
}

interface TrackedTapResponse {
  ok?: boolean;
  tap?: {
    contractId?: string;
    token?: string | null;
    pipeKey?: PipeKey;
    serverBalance?: string;
    myBalance?: string;
    sendCapacity?: string;
    receiveLiquidity?: string;
    settledServerBalance?: string;
    settledMyBalance?: string;
    pendingServerBalance?: string;
    pendingMyBalance?: string;
    nonce?: string;
  } | null;
}

interface LiquidityParamsResponse {
  reservoirSignature?: string;
  borrowFee?: string;
}

function cvPrincipalHex(addr: string): string {
  return bytesToHex(serializeCVBytes(principalCV(addr)));
}

function cvTupleHex(fields: Record<string, string>): string {
  const sorted = Object.keys(fields).sort();
  const u32h = (n: number) => n.toString(16).padStart(8, '0');
  const u8h  = (n: number) => n.toString(16).padStart(2, '0');
  let h = '0c' + u32h(sorted.length);
  for (const name of sorted) {
    const nb = new TextEncoder().encode(name);
    h += u8h(nb.length) + Array.from(nb).map(b => b.toString(16).padStart(2, '0')).join('') + fields[name];
  }
  return h;
}

function parseUintCv(value: ClarityValue | undefined): bigint | null {
  if (!value) return null;
  if (value.type === ClarityType.UInt) return BigInt(value.value);
  if (value.type === ClarityType.ResponseOk) return parseUintCv(value.value);
  return null;
}

function parsePendingLegCv(value: ClarityValue | undefined): PendingLeg {
  if (!value) return { amount: 0n, burnHeight: null };
  if (value.type === ClarityType.OptionalNone) return { amount: 0n, burnHeight: null };
  if (value.type !== ClarityType.OptionalSome) return { amount: 0n, burnHeight: null };
  const inner = value.value;
  if (inner.type !== ClarityType.Tuple) return { amount: 0n, burnHeight: null };
  const tuple = inner.value as Record<string, ClarityValue>;
  return {
    amount: parseUintCv(tuple.amount) ?? 0n,
    burnHeight: parseUintCv(tuple['burn-height']),
  };
}

function parsePipeResult(result: string): { balance1: bigint; balance2: bigint; pending1: bigint; pending2: bigint; pendingLeg1: PendingLeg; pendingLeg2: PendingLeg; nonce: bigint } | null {
  if (!result) return null;
  if (result === '0x09') return null; // (none)

  if (result.startsWith('0x')) {
    try {
      let cv = hexToCV(result);
      if (cv.type === ClarityType.ResponseOk) cv = cv.value;
      if (cv.type === ClarityType.OptionalNone) return null;
      if (cv.type === ClarityType.OptionalSome) cv = cv.value;
      if (cv.type !== ClarityType.Tuple) return null;
      const tuple = cv.value as Record<string, ClarityValue>;
      const balance1 = parseUintCv(tuple['balance-1']);
      const balance2 = parseUintCv(tuple['balance-2']);
      const pendingLeg1 = parsePendingLegCv(tuple['pending-1']);
      const pendingLeg2 = parsePendingLegCv(tuple['pending-2']);
      const nonce = parseUintCv(tuple.nonce);
      if (balance1 == null || balance2 == null || nonce == null) return null;
      return { balance1, balance2, pending1: pendingLeg1.amount, pending2: pendingLeg2.amount, pendingLeg1, pendingLeg2, nonce };
    } catch {
      return null;
    }
  }

  // Fallback for older/plain repr responses.
  const b1m = result.match(/balance-1 u(\d+)/);
  const b2m = result.match(/balance-2 u(\d+)/);
  const p1m = result.match(/pending-1 \((?:some )?\(tuple \(amount u(\d+)\)/);
  const p2m = result.match(/pending-2 \((?:some )?\(tuple \(amount u(\d+)\)/);
  const ncm = result.match(/nonce u(\d+)/);
  if (!b1m || !b2m || !ncm) return null;
  return {
    balance1: BigInt(b1m[1]),
    balance2: BigInt(b2m[1]),
    pending1: p1m ? BigInt(p1m[1]) : 0n,
    pending2: p2m ? BigInt(p2m[1]) : 0n,
    pendingLeg1: { amount: p1m ? BigInt(p1m[1]) : 0n, burnHeight: null },
    pendingLeg2: { amount: p2m ? BigInt(p2m[1]) : 0n, burnHeight: null },
    nonce: BigInt(ncm[1]),
  };
}

async function fetchCurrentBurnBlockHeight(chainId: number): Promise<bigint | null> {
  try {
    const response = await fetch(`${chainIdToHiroApi(chainId)}/v2/info`);
    if (!response.ok) return null;
    const payload = await response.json() as Record<string, unknown>;
    const raw = payload.burn_block_height ?? payload.burnBlockHeight;
    if (typeof raw === 'number' || typeof raw === 'string' || typeof raw === 'bigint') {
      return BigInt(raw);
    }
    return null;
  } catch {
    return null;
  }
}

async function queryOnChainTap(userAddr: string): Promise<TapState | null> {
  try {
    await ensureSupportedTokenLoaded();
    const reservoir = getRuntimeReservoirContract();
    const sfContract = getRuntimeSfContract();
    const supportedToken = getRuntimeSupportedToken();
    const pipeKey = canonicalPipeKey(supportedToken, userAddr, reservoir);
    const legacyArgHex  = '0x' + cvTupleHex({
      'principal-1': cvPrincipalHex(pipeKey['principal-1']),
      'principal-2': cvPrincipalHex(pipeKey['principal-2']),
      token: optionalPrincipalCvHex(supportedToken),
    });
    const tokenArgHex = '0x' + optionalPrincipalCvHex(supportedToken);
    const withArgHex = '0x' + bytesToHex(serializeCVBytes(principalCV(reservoir)));
    const [contractAddr, contractName] = sfContract.split('.');
    const chainId = (serverStatus.chainId as number | undefined) ?? CHAIN_ID;
    const endpoint = `${chainIdToHiroApi(chainId)}/v2/contracts/call-read/${contractAddr}/${contractName}/get-pipe`;
    const callRead = async (argumentsHex: string[]): Promise<{ okay?: boolean; result?: string }> => {
      const r = await fetch(endpoint, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ sender: userAddr, arguments: argumentsHex }),
      });
      if (!r.ok) return {};
      return await r.json() as { okay?: boolean; result?: string };
    };

    // Current StackFlow signature: get-pipe(token, with)
    let data = await callRead([tokenArgHex, withArgHex]);
    // Fallback for older deployments that expected a single pipe-key tuple argument.
    if (!data.okay) data = await callRead([legacyArgHex]);
    if (!data.okay || !data.result) return null;

    const parsed = parsePipeResult(data.result);
    if (!parsed) return null;
    const currentBurnHeight = await fetchCurrentBurnBlockHeight(chainId);
    const matureAmount = (leg: PendingLeg): { settledAdd: bigint; pending: bigint } => {
      if (leg.amount <= 0n) return { settledAdd: 0n, pending: 0n };
      if (currentBurnHeight != null && leg.burnHeight != null && currentBurnHeight >= leg.burnHeight) {
        return { settledAdd: leg.amount, pending: 0n };
      }
      return { settledAdd: 0n, pending: leg.amount };
    };

    const userIsP1 = pipeKey['principal-1'] === userAddr;
    const userPending = matureAmount(userIsP1 ? parsed.pendingLeg1 : parsed.pendingLeg2);
    const reservoirPending = matureAmount(userIsP1 ? parsed.pendingLeg2 : parsed.pendingLeg1);
    return {
      userBalance:      userIsP1 ? parsed.balance1 + parsed.pending1 : parsed.balance2 + parsed.pending2,
      reservoirBalance: userIsP1 ? parsed.balance2 + parsed.pending2 : parsed.balance1 + parsed.pending1,
      settledUserBalance: (userIsP1 ? parsed.balance1 : parsed.balance2) + userPending.settledAdd,
      settledReservoirBalance: (userIsP1 ? parsed.balance2 : parsed.balance1) + reservoirPending.settledAdd,
      pendingUserBalance: userPending.pending,
      pendingReservoirBalance: reservoirPending.pending,
      nonce: parsed.nonce,
      pipeKey,
    };
  } catch { return null; }
}

async function queryTrackedTapState(userAddr: string): Promise<TapState | null> {
  if (!walletAddress || walletAddress !== userAddr) return null;
  try {
    const response = await apiFetch('/tap/state', {
      headers: await buildInboxRequestHeaders('get-inbox'),
    });
    captureInboxSession(response);
    if (!response.ok) return null;
    const data = await response.json() as TrackedTapResponse;
    if (!data.tap?.pipeKey || data.tap.myBalance == null || data.tap.serverBalance == null || data.tap.nonce == null) {
      return null;
    }
    return {
      userBalance: BigInt(data.tap.sendCapacity ?? data.tap.myBalance),
      reservoirBalance: BigInt(data.tap.receiveLiquidity ?? data.tap.serverBalance),
      settledUserBalance: data.tap.settledMyBalance != null ? BigInt(data.tap.settledMyBalance) : null,
      settledReservoirBalance: data.tap.settledServerBalance != null ? BigInt(data.tap.settledServerBalance) : null,
      pendingUserBalance: data.tap.pendingMyBalance != null ? BigInt(data.tap.pendingMyBalance) : null,
      pendingReservoirBalance: data.tap.pendingServerBalance != null ? BigInt(data.tap.pendingServerBalance) : null,
      nonce: BigInt(data.tap.nonce),
      pipeKey: data.tap.pipeKey,
    };
  } catch {
    return null;
  }
}

async function resolveTapState(userAddr: string): Promise<TapState | null> {
  return await queryTrackedTapState(userAddr) ?? await queryOnChainTap(userAddr);
}

async function refreshCurrentTapState(): Promise<void> {
  if (!walletAddress) return;
  const tap = await resolveTapState(walletAddress);
  if (!tap) return;
  pipeState = { myBalance: tap.userBalance, serverBalance: tap.reservoirBalance, nonce: tap.nonce };
  updateIdentityUI();
}

async function addFundsToTap(): Promise<void> {
  const btn = document.getElementById('add-funds-btn') as HTMLButtonElement;
  const statusEl = document.getElementById('liquidity-status') as HTMLElement;
  btn.disabled = true;
  btn.innerHTML = '<span class="spinner"></span> Adding…';
  statusEl.innerHTML = '';

  try {
    if (!walletAddress) throw new Error('Wallet not connected');
    await ensureSupportedTokenAssetNameLoaded();
    const chainId = (serverStatus.chainId as number | undefined) ?? CHAIN_ID;
    const sfContract = getRuntimeSfContract();
    const reservoir = getRuntimeReservoirContract();
    const supportedToken = getRuntimeSupportedToken();
    const tokenAssetName = supportedToken == null ? null : getRuntimeSupportedTokenAssetName();
    const amount = readPositiveAmountInput('add-funds-amount-input', 'Add funds amount');
    const tap = await queryOnChainTap(walletAddress);
    if (!tap) throw new Error('No on-chain tap found. Open your mailbox first.');
    const nextMyBalance = tap.userBalance + amount;
    const nextReservoirBalance = tap.reservoirBalance;
    const nextNonce = tap.nonce + 1n;

    statusEl.innerHTML = '<div class="alert alert-warning">Waiting for wallet signature (deposit state)…</div>';
    const mySignature = await withTimeout(
      sip018SignWithWallet(
        sfContract,
        buildTransferCV({
          pipeKey: tap.pipeKey,
          forPrincipal: walletAddress,
          myBalance: nextMyBalance,
          theirBalance: nextReservoirBalance,
          nonce: nextNonce,
          action: 2n,
          actor: walletAddress,
          hashedSecret: null,
          validAfter: null,
        }),
        chainId,
      ),
      120_000,
      'Timed out waiting for wallet signature. Open your wallet extension and approve the SIP-018 request.',
    );

    statusEl.innerHTML = '<div class="alert alert-warning">Preparing reservoir signature…</div>';
    const paramsRes = await apiFetch('/tap/add-funds-params', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        user: walletAddress,
        token: supportedToken,
        amount: amount.toString(),
        myBalance: nextMyBalance.toString(),
        reservoirBalance: nextReservoirBalance.toString(),
        nonce: nextNonce.toString(),
        mySignature,
      }),
    });
    const params = await paramsRes.json().catch(() => ({})) as LiquidityParamsResponse & { error?: string; message?: string };
    if (!paramsRes.ok || !params.reservoirSignature) {
      throw new Error(params.message || params.error || `Failed to prepare add-funds params (${paramsRes.status})`);
    }

    const tokenContractId = supportedToken as `${string}.${string}` | null;
    const postConditions = supportedToken == null
      ? [Pc.principal(walletAddress).willSendEq(amount).ustx()]
      : [Pc.principal(walletAddress).willSendEq(amount).ft(tokenContractId!, tokenAssetName!)];

    statusEl.innerHTML = '<div class="alert alert-warning">Waiting for wallet transaction approval…</div>';
    const txId = await withTimeout(
      new Promise<string>((resolve, reject) => {
        openContractCall({
          contractAddress: reservoir.split('.')[0],
          contractName: reservoir.split('.')[1],
          functionName: 'add-funds',
          functionArgs: [
            principalCV(sfContract),
            uintCV(amount),
            supportedToken == null ? noneCV() : someCV(principalCV(supportedToken)),
            uintCV(nextMyBalance),
            uintCV(nextReservoirBalance),
            bufferCV(hexToBytes(mySignature)),
            bufferCV(hexToBytes(params.reservoirSignature!)),
            uintCV(nextNonce),
          ],
          network: chainIdToNetworkName(chainId),
          postConditionMode: PostConditionMode.Deny,
          postConditions,
          appDetails: { name: 'Mailslot', icon: window.location.origin + '/favicon.ico' },
          onFinish: (data: { txId?: string; txid?: string; tx_id?: string }) =>
            resolve(data.txId ?? data.txid ?? data.tx_id ?? ''),
          onCancel: () => reject(new Error('Transaction cancelled')),
        });
      }),
      180_000,
      'Timed out waiting for wallet transaction approval',
    );
    if (!txId) throw new Error('No transaction ID returned from wallet');

    statusEl.innerHTML = `<div class="alert alert-warning">Transaction submitted. Waiting for confirmation…<br><a href="${escHtml(formatExplorerTxUrl(txId, chainId))}" target="_blank" rel="noopener" class="mono" style="color:inherit">${escHtml(txId)}</a></div>`;
    await waitForStacksTx(txId, chainId, 'add funds');
    await syncTapStateAfterOnChainAction({
      token: supportedToken,
      myBalance: nextMyBalance,
      reservoirBalance: nextReservoirBalance,
      nonce: nextNonce,
      action: 2n,
      actor: walletAddress,
      mySignature,
      reservoirSignature: params.reservoirSignature!,
    });
    await loadStatus();
    statusEl.innerHTML = `<div class="alert alert-success">Funds added successfully.<br><a href="${escHtml(formatExplorerTxUrl(txId, chainId))}" target="_blank" rel="noopener" class="mono" style="color:inherit">${escHtml(txId)}</a></div>`;
    (document.getElementById('add-funds-amount-input') as HTMLInputElement).value = '';
  } catch (e) {
    const msg = typeof e === 'string' ? e : ((e as Error)?.message || (e as { reason?: string })?.reason || JSON.stringify(e) || 'Unknown error');
    statusEl.innerHTML = `<div class="alert alert-error">${escHtml(msg)}</div>`;
  } finally {
    btn.disabled = false;
    btn.textContent = 'Add Funds';
  }
}

async function borrowMoreLiquidity(
  amount: bigint,
  options: { buttonId?: string; buttonText?: string; spinnerText?: string; successText?: string } = {},
): Promise<void> {
  const btn = document.getElementById(options.buttonId ?? 'refresh-capacity-btn') as HTMLButtonElement | null;
  const statusEl = document.getElementById('liquidity-status') as HTMLElement;
  if (btn) {
    btn.disabled = true;
    btn.innerHTML = `<span class="spinner"></span> ${options.spinnerText ?? 'Borrowing…'}`;
  }
  statusEl.innerHTML = '';

  try {
    if (!walletAddress) throw new Error('Wallet not connected');
    await ensureSupportedTokenAssetNameLoaded();
    const chainId = (serverStatus.chainId as number | undefined) ?? CHAIN_ID;
    const sfContract = getRuntimeSfContract();
    const reservoir = getRuntimeReservoirContract();
    const supportedToken = getRuntimeSupportedToken();
    const tokenAssetName = supportedToken == null ? null : getRuntimeSupportedTokenAssetName();
    const tap = await resolveTapState(walletAddress);
    if (!tap) throw new Error('No tap found. Open your mailbox first.');
    if (amount <= 0n) {
      statusEl.innerHTML = '<div class="alert alert-info">Receive capacity is already at or above target.</div>';
      return;
    }
    const nextMyBalance = tap.userBalance;
    const nextReservoirBalance = tap.reservoirBalance + amount;
    const nextNonce = tap.nonce + 1n;

    statusEl.innerHTML = '<div class="alert alert-warning">Waiting for wallet signature (borrow state)…</div>';
    const mySignature = await withTimeout(
      sip018SignWithWallet(
        sfContract,
        buildTransferCV({
          pipeKey: tap.pipeKey,
          forPrincipal: walletAddress,
          myBalance: nextMyBalance,
          theirBalance: nextReservoirBalance,
          nonce: nextNonce,
          action: 2n,
          actor: reservoir,
          hashedSecret: null,
          validAfter: null,
        }),
        chainId,
      ),
      120_000,
      'Timed out waiting for wallet signature. Open your wallet extension and approve the SIP-018 request.',
    );

    statusEl.innerHTML = '<div class="alert alert-warning">Preparing borrow parameters…</div>';
    const paramsRes = await apiFetch('/tap/borrow-more-params', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        borrower: walletAddress,
        token: supportedToken,
        borrowAmount: amount.toString(),
        myBalance: nextMyBalance.toString(),
        reservoirBalance: nextReservoirBalance.toString(),
        borrowNonce: nextNonce.toString(),
        mySignature,
      }),
    });
    const params = await paramsRes.json().catch(() => ({})) as LiquidityParamsResponse & { error?: string; message?: string };
    if (!paramsRes.ok || !params.reservoirSignature || !params.borrowFee) {
      throw new Error(params.message || params.error || `Failed to prepare borrow params (${paramsRes.status})`);
    }
    const borrowFee = BigInt(params.borrowFee);

    const tokenContractId = supportedToken as `${string}.${string}` | null;
    const postConditions = supportedToken == null ? [
      Pc.principal(walletAddress).willSendEq(borrowFee).ustx(),
      Pc.principal(reservoir).willSendEq(amount).ustx(),
    ] : [
      Pc.principal(walletAddress).willSendEq(borrowFee).ft(tokenContractId!, tokenAssetName!),
      Pc.principal(reservoir).willSendEq(amount).ft(tokenContractId!, tokenAssetName!),
    ];

    statusEl.innerHTML = `<div class="alert alert-warning">Waiting for wallet transaction approval…<br>Borrow fee: ${escHtml(formatPaymentAmount(borrowFee))}</div>`;
    const txId = await withTimeout(
      new Promise<string>((resolve, reject) => {
        openContractCall({
          contractAddress: reservoir.split('.')[0],
          contractName: reservoir.split('.')[1],
          functionName: 'borrow-liquidity',
          functionArgs: [
            principalCV(sfContract),
            uintCV(amount),
            uintCV(borrowFee),
            supportedToken == null ? noneCV() : someCV(principalCV(supportedToken)),
            uintCV(nextMyBalance),
            uintCV(nextReservoirBalance),
            bufferCV(hexToBytes(mySignature)),
            bufferCV(hexToBytes(params.reservoirSignature!)),
            uintCV(nextNonce),
          ],
          network: chainIdToNetworkName(chainId),
          postConditionMode: PostConditionMode.Deny,
          postConditions,
          appDetails: { name: 'Mailslot', icon: window.location.origin + '/favicon.ico' },
          onFinish: (data: { txId?: string; txid?: string; tx_id?: string }) =>
            resolve(data.txId ?? data.txid ?? data.tx_id ?? ''),
          onCancel: () => reject(new Error('Transaction cancelled')),
        });
      }),
      180_000,
      'Timed out waiting for wallet transaction approval',
    );
    if (!txId) throw new Error('No transaction ID returned from wallet');

    statusEl.innerHTML = `<div class="alert alert-warning">Transaction submitted. Waiting for confirmation…<br><a href="${escHtml(formatExplorerTxUrl(txId, chainId))}" target="_blank" rel="noopener" class="mono" style="color:inherit">${escHtml(txId)}</a></div>`;
    await waitForStacksTx(txId, chainId, 'borrow liquidity');
    await syncTapStateAfterOnChainAction({
      token: supportedToken,
      myBalance: nextMyBalance,
      reservoirBalance: nextReservoirBalance,
      nonce: nextNonce,
      action: 2n,
      actor: reservoir,
      mySignature,
      reservoirSignature: params.reservoirSignature!,
    });
    await loadStatus();
    statusEl.innerHTML = `<div class="alert alert-success">${escHtml(options.successText ?? 'Receive liquidity increased successfully.')}<br><a href="${escHtml(formatExplorerTxUrl(txId, chainId))}" target="_blank" rel="noopener" class="mono" style="color:inherit">${escHtml(txId)}</a></div>`;
  } catch (e) {
    const msg = typeof e === 'string' ? e : ((e as Error)?.message || (e as { reason?: string })?.reason || JSON.stringify(e) || 'Unknown error');
    statusEl.innerHTML = `<div class="alert alert-error">${escHtml(msg)}</div>`;
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.textContent = options.buttonText ?? 'Refresh Capacity';
    }
  }
}

async function refreshReceiveCapacity(): Promise<void> {
  const tap = walletAddress ? await resolveTapState(walletAddress) : null;
  const currentLiquidity = tap?.reservoirBalance ?? pipeState.serverBalance;
  const refreshAmount = getCapacityRefreshAmount(currentLiquidity);
  await borrowMoreLiquidity(refreshAmount, {
    buttonId: 'refresh-capacity-btn',
    buttonText: 'Refresh Capacity',
    spinnerText: 'Refreshing…',
    successText: 'Receive capacity refreshed successfully.',
  });
}

function formatExplorerTxUrl(txId: string, chainId: number): string {
  const chain = chainId === 1 ? 'mainnet' : 'testnet';
  return `https://explorer.hiro.so/txid/${txId}?chain=${chain}`;
}

async function waitForStacksTx(txId: string, chainId: number, label: string): Promise<void> {
  const base = chainIdToHiroApi(chainId);
  const startedAt = Date.now();
  while (Date.now() - startedAt < 180_000) {
    const response = await fetch(`${base}/extended/v1/tx/0x${txId}`);
    if (response.ok) {
      const payload = await response.json() as { tx_status?: string };
      const status = payload.tx_status ?? '';
      if (status === 'success') return;
      if (status.includes('abort') || status.includes('failed')) {
        throw new Error(`${label} transaction failed (${status})`);
      }
    }
    await new Promise(resolve => setTimeout(resolve, 4_000));
  }
  throw new Error(`Timed out waiting for ${label} transaction confirmation`);
}

function readPositiveAmountInput(id: string, label: string): bigint {
  const raw = (document.getElementById(id) as HTMLInputElement).value.trim();
  if (!/^\d+$/.test(raw)) {
    throw new Error(`${label} must be a positive integer amount`);
  }
  const amount = BigInt(raw);
  if (amount <= 0n) {
    throw new Error(`${label} must be greater than zero`);
  }
  return amount;
}

async function syncTapStateAfterOnChainAction(args: {
  token: string | null;
  myBalance: bigint;
  reservoirBalance: bigint;
  nonce: bigint;
  action: bigint;
  actor: string;
  mySignature: string;
  reservoirSignature: string;
}): Promise<void> {
  const response = await apiFetch('/tap/sync-state', {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      ...(await buildInboxRequestHeaders('get-inbox')),
    },
    body: JSON.stringify({
      user: walletAddress,
      token: args.token,
      myBalance: args.myBalance.toString(),
      reservoirBalance: args.reservoirBalance.toString(),
      nonce: args.nonce.toString(),
      action: args.action.toString(),
      actor: args.actor,
      mySignature: args.mySignature,
      reservoirSignature: args.reservoirSignature,
    }),
  });
  captureInboxSession(response);
  if (!response.ok) {
    const error = await response.json().catch(() => ({})) as { error?: string; message?: string };
    throw new Error(error.message || error.error || `Tap sync failed (${response.status})`);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Open mailbox — calls sm-reservoir::create-tap-with-borrowed-liquidity
// ─────────────────────────────────────────────────────────────────────────────

async function openMailbox(): Promise<void> {
  const btn     = document.getElementById('open-mailbox-btn') as HTMLButtonElement;
  const errorEl = document.getElementById('open-mailbox-error') as HTMLElement;
  btn.disabled = true;
  btn.innerHTML = '<span class="spinner"></span> Opening…';
  errorEl.innerHTML = '';

  try {
    if (!walletAddress) throw new Error('Wallet not connected');
    await ensureSupportedTokenAssetNameLoaded();
    const chainId = (serverStatus.chainId as number | undefined) ?? CHAIN_ID;
    const sfContract = getRuntimeSfContract();
    const reservoir = getRuntimeReservoirContract();
    const openTapAmount = getOpenTapAmount();
    const openBorrowAmount = getTargetReceiveLiquidity();
    const supportedToken = getRuntimeSupportedToken();
    const supportedTokenAssetName = supportedToken == null ? null : getRuntimeSupportedTokenAssetName();
    if (!isContractPrincipal(reservoir)) {
      throw new Error('Server reservoir principal is not configured');
    }
    if (supportedToken != null && !supportedTokenAssetName) {
      throw new Error(`Could not resolve fungible token asset name for ${supportedToken}`);
    }
    const setProgress = (msg: string): void => {
      errorEl.innerHTML = `<div class="alert alert-warning">${escHtml(msg)}</div>`;
    };

    // Borrower signs the post-borrow deposit state (action=2, hashed-secret=none).
    setProgress('Waiting for wallet signature (borrow params)… check your wallet popup/extension.');
    const pipeKey = canonicalPipeKey(supportedToken, walletAddress, reservoir);
    const borrowStateCV = buildTransferCV({
      pipeKey,
      forPrincipal: walletAddress,
      myBalance: openTapAmount,
      theirBalance: openBorrowAmount,
      nonce: OPEN_BORROW_NONCE,
      action: 2n,
      actor: reservoir,
      hashedSecret: null,
      validAfter: null,
    });
    const mySignature = await withTimeout(
      sip018SignWithWallet(sfContract, borrowStateCV, chainId),
      120_000,
      'Timed out waiting for wallet signature. Open your wallet extension and approve the SIP-018 request.',
    );

    // Request validated params + reservoir signature from server.
    setProgress('Preparing borrow parameters with server…');
    const paramsRes = await withTimeout(
      apiFetch('/tap/borrow-params', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          borrower: walletAddress,
          token: supportedToken,
          tapAmount: openTapAmount.toString(),
          tapNonce: OPEN_TAP_NONCE.toString(),
          borrowAmount: openBorrowAmount.toString(),
          myBalance: openTapAmount.toString(),
          reservoirBalance: openBorrowAmount.toString(),
          borrowNonce: OPEN_BORROW_NONCE.toString(),
          mySignature,
        }),
      }),
      25_000,
      'Timed out while preparing borrow parameters',
    );
    if (!paramsRes.ok) {
      const err = await paramsRes.json().catch(() => ({})) as { error?: string; message?: string };
      throw new Error(err.message || err.error || `Failed to prepare borrowed-liquidity params (${paramsRes.status})`);
    }
    const params = await paramsRes.json() as { reservoirSignature?: string; borrowFee?: string };
    const reservoirSignature = params.reservoirSignature;
    if (!reservoirSignature) throw new Error('Server did not return reservoir signature');
    if (!params.borrowFee) throw new Error('Server did not return borrow fee');
    const finalBorrowFee = BigInt(params.borrowFee);
    const tokenContractId = supportedToken as `${string}.${string}` | null;
    const postConditions = supportedToken == null ? [
      Pc.principal(walletAddress!).willSendEq(openTapAmount + finalBorrowFee).ustx(),
      Pc.principal(reservoir).willSendEq(openBorrowAmount).ustx(),
    ] : [
      Pc.principal(walletAddress!).willSendEq(openTapAmount + finalBorrowFee).ft(tokenContractId!, supportedTokenAssetName!),
      Pc.principal(reservoir).willSendEq(openBorrowAmount).ft(tokenContractId!, supportedTokenAssetName!),
    ];

    setProgress('Waiting for wallet transaction confirmation…');
    const txId = await withTimeout(
      new Promise<string>((resolve, reject) => {
        openContractCall({
          contractAddress: reservoir.split('.')[0],
          contractName:    reservoir.split('.')[1],
          functionName:    'create-tap-with-borrowed-liquidity',
          functionArgs: [
            principalCV(sfContract),
            supportedToken == null ? noneCV() : someCV(principalCV(supportedToken)),
            uintCV(openTapAmount),
            uintCV(OPEN_TAP_NONCE),
            uintCV(openBorrowAmount),
            uintCV(finalBorrowFee),
            uintCV(openTapAmount),
            uintCV(openBorrowAmount),
            bufferCV(hexToBytes(mySignature)),
            bufferCV(hexToBytes(reservoirSignature)),
            uintCV(OPEN_BORROW_NONCE),
          ],
          network:         chainIdToNetworkName(chainId),
          postConditionMode: PostConditionMode.Deny,
          postConditions,
          appDetails: { name: 'Mailslot', icon: window.location.origin + '/favicon.ico' },
          onFinish:  (data: { txId?: string; txid?: string; tx_id?: string }) =>
            resolve(data.txId ?? data.txid ?? data.tx_id ?? ''),
          onCancel:  () => reject(new Error('Transaction cancelled')),
        });
      }),
      180_000,
      'Timed out waiting for wallet transaction approval',
    );

    if (!txId) throw new Error('No transaction ID returned from wallet');

    const chain = chainId === 1 ? 'mainnet' : 'testnet';
    (document.getElementById('tx-explorer-link') as HTMLAnchorElement).href        = `https://explorer.hiro.so/txid/${txId}?chain=${chain}`;
    (document.getElementById('tx-explorer-link') as HTMLElement).textContent = txId.slice(0, 12) + '…' + txId.slice(-8);
    (document.getElementById('tx-status-msg') as HTMLElement).innerHTML = '';
    setAppState('tx-pending');

  } catch (e) {
    const rawMsg = typeof e === 'string' ? e : ((e as Error)?.message || (e as { reason?: string })?.reason || JSON.stringify(e) || 'Unknown error');
    const msg = /Post-condition check failure.*SentEq 0/i.test(rawMsg)
      ? `${rawMsg}\n\nLikely cause: the reservoir signer is not registered as a StackFlow agent. In Status -> Reservoir Admin, call set-agent with the signer address.`
      : rawMsg;
    errorEl.innerHTML = `<div class="alert alert-error">${escHtml(msg).replace(/\n/g, '<br>')}</div>`;
    btn.disabled = false;
    btn.innerHTML = 'Open Mailbox';
  }
}

async function checkTapAfterTx(): Promise<void> {
  const btn      = document.getElementById('check-tap-btn') as HTMLButtonElement;
  const statusEl = document.getElementById('tx-status-msg') as HTMLElement;
  btn.disabled = true;
  btn.innerHTML = '<span class="spinner"></span> Checking…';

  const tap = await resolveTapState(walletAddress!);
  if (tap) {
    pipeState = { myBalance: tap.userBalance, serverBalance: tap.reservoirBalance, nonce: tap.nonce };
    updateIdentityUI();
    setAppState('ready');
    showTab('inbox');
    loadInbox();
    loadStatus();
  } else {
    btn.disabled = false;
    btn.textContent = 'Check Again';
    statusEl.innerHTML = '<div class="alert alert-warning">Channel not found yet — the transaction may still be confirming. Try again in a moment.</div>';
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// API helper
// ─────────────────────────────────────────────────────────────────────────────

async function apiFetch(path: string, opts: RequestInit = {}): Promise<Response> {
  const timeoutMs = 20_000;
  if (opts.signal) return fetch(window.location.origin + path, opts);
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(window.location.origin + path, { ...opts, signal: controller.signal });
  } finally {
    clearTimeout(timeoutId);
  }
}

function captureInboxSession(response: Response): void {
  const token = response.headers.get('x-mailslot-session');
  const expiresAtRaw = response.headers.get('x-mailslot-session-expires-at');
  const expiresAt = expiresAtRaw ? Number(expiresAtRaw) : 0;
  if (token && Number.isFinite(expiresAt) && expiresAt > Date.now()) {
    inboxSessionToken = token;
    inboxSessionExpiresAt = expiresAt;
  }
}

async function buildInboxRequestHeaders(
  action: 'get-inbox' | 'claim-message' | 'get-message',
  messageId?: string,
  extraHeaders: Record<string, string> = {},
): Promise<Record<string, string>> {
  if (inboxSessionToken && Date.now() < inboxSessionExpiresAt) {
    return { ...extraHeaders, 'x-mailslot-session': inboxSessionToken };
  }
  return { ...extraHeaders, 'x-mailslot-auth': await buildWalletAuthHeader(action, messageId) };
}

// ─────────────────────────────────────────────────────────────────────────────
// Inbox tab
// ─────────────────────────────────────────────────────────────────────────────

async function loadInbox(): Promise<void> {
  const listEl   = document.getElementById('inbox-list') as HTMLElement;
  const statusEl = document.getElementById('inbox-status') as HTMLElement;
  const claimed  = (document.getElementById('show-claimed-cb') as HTMLInputElement).checked;

  statusEl.innerHTML = inboxSessionToken && Date.now() < inboxSessionExpiresAt
    ? '<span class="spinner"></span> Loading inbox…'
    : '<span class="spinner"></span> Waiting for wallet signature…';
  listEl.innerHTML   = '';

  try {
    statusEl.innerHTML = '<span class="spinner"></span> Loading inbox…';
    const r    = await apiFetch(`/inbox?limit=50${claimed ? '&claimed=true' : ''}`, {
      headers: await buildInboxRequestHeaders('get-inbox'),
    });
    captureInboxSession(r);
    if (!r.ok) {
      const err = await r.json().catch(() => ({})) as { message?: string };
      statusEl.innerHTML = `<div class="alert alert-error">Error: ${escHtml(err.message || String(r.status))}</div>`;
      return;
    }
    const data = await r.json() as { messages?: InboxMessage[] };
    lastInboxMessages = data.messages || [];
    statusEl.innerHTML = '';
    renderInboxMessages(lastInboxMessages);
  } catch (e) {
    const msg = typeof e === 'string' ? e : ((e as Error)?.message || (e as { reason?: string })?.reason || JSON.stringify(e) || 'Unknown error');
    statusEl.innerHTML = `<div class="alert alert-error">Failed to load inbox: ${escHtml(msg)}</div>`;
  }
}

interface InboxMessage {
  id: string;
  from: string;
  sentAt: number;
  amount?: number | string;
  claimed?: boolean;
}

function setComposeRecipient(address: string, subject = ''): void {
  const toInput = document.getElementById('to-input') as HTMLInputElement;
  const subjectInput = document.getElementById('subject-input') as HTMLInputElement;
  const bodyInput = document.getElementById('body-input') as HTMLTextAreaElement;
  const sendStatus = document.getElementById('send-status') as HTMLElement;
  const recipientStatus = document.getElementById('recipient-status') as HTMLElement;
  const paymentPanel = document.getElementById('payment-panel') as HTMLElement;
  const sendBtn = document.getElementById('send-btn') as HTMLButtonElement;

  toInput.value = address;
  subjectInput.value = subject;
  recipientInfo = null;
  recipientStatus.textContent = '';
  paymentPanel.style.display = 'none';
  sendStatus.innerHTML = '';
  sendBtn.disabled = true;
  bodyInput.focus();
}

async function replyToMessage(messageId: string): Promise<void> {
  const message = lastInboxMessages.find(entry => entry.id === messageId);
  if (!message?.from) throw new Error('Reply target not found');
  const opened = openedInboxMessages[messageId];
  const subject = opened?.subject?.trim() ? `Re: ${opened.subject}` : '';
  setComposeRecipient(message.from, subject);
  showTab('compose');
  await fetchRecipientInfo(message.from);
}

interface PreviewMessageResponse {
  messageId: string;
  from: string;
  sentAt: number;
  amount: string;
  hashedSecret: string;
  encryptedPayload: EncryptedMail;
}

interface ClaimedMessageResponse {
  message: {
    id: string;
    paymentId: string;
    encryptedPayload: EncryptedMail;
  };
}

function requireInboxDecryptKey(): string {
  if (!browserDecryptFallbackEnabled()) {
    throw new Error('Browser private-key decrypt is disabled on this server. Use wallet-native decrypt instead.');
  }
  if (!inboxDecryptPrivateKey) {
    throw new Error('Load your inbox decrypt key first. The UI accepts 64-char hex or 66-char Stacks keys ending in 01.');
  }
  return inboxDecryptPrivateKey;
}

function parseWalletDecryptedMail(message: string): DecryptedMailPayload {
  const parsed = JSON.parse(message) as Partial<DecryptedMailPayload>;
  if (!parsed || parsed.v !== 1 || typeof parsed.secret !== 'string' || typeof parsed.body !== 'string') {
    throw new Error('Wallet returned an invalid Mailslot payload');
  }
  return parsed as DecryptedMailPayload;
}

async function encryptMailWithWallet(payload: unknown, recipientPubkeyHex: string): Promise<EncryptedMail> {
  const provider = getLeatherProvider();
  if (!provider) throw new Error('Leather provider not available');
  const resp = await provider.request('stx_encryptMessage', {
    message: JSON.stringify(payload),
    publicKey: recipientPubkeyHex,
  });
  const encrypted = extractEncryptedMessage(resp);
  if (!encrypted) throw new Error('Wallet did not return an encrypted payload');
  return encrypted;
}

async function decryptMailWithWallet(payload: EncryptedMail): Promise<DecryptedMailPayload> {
  const provider = getLeatherProvider();
  if (!provider) throw new Error('Leather provider not available');
  const resp = await provider.request('stx_decryptMessage', { encryptedMessage: payload });
  const parsed = extractDecryptedMailslotMessage(resp);
  if (parsed && parsed.v === 1 && typeof parsed.secret === 'string' && typeof parsed.body === 'string') {
    return parsed as DecryptedMailPayload;
  }
  const message = extractDecryptedMessage(resp);
  if (!message) throw new Error('Wallet did not return decrypted plaintext');
  return parseWalletDecryptedMail(message);
}

async function decryptInboxPayload(payload: EncryptedMail): Promise<DecryptedMailPayload> {
  if (walletCryptoAvailable) {
    try {
      return await decryptMailWithWallet(payload);
    } catch (error) {
      if (!inboxDecryptPrivateKey) throw error;
    }
  }

  if (!browserDecryptFallbackEnabled()) {
    throw new Error('Wallet-native decrypt is required on this server.');
  }
  const privateKey = requireInboxDecryptKey();
  return decryptMail(payload, privateKey);
}

function updateInboxMessage(messages: InboxMessage[], messageId: string, patch: Partial<InboxMessage>): InboxMessage[] {
  return messages.map(message => message.id === messageId ? { ...message, ...patch } : message);
}

function renderInboxMessages(messages: InboxMessage[]): void {
  const listEl   = document.getElementById('inbox-list') as HTMLElement;
  const countEl  = document.getElementById('inbox-count') as HTMLElement;
  const unclaimed = messages.filter(m => !m.claimed);

  countEl.textContent = messages.length
    ? `${unclaimed.length} unclaimed · ${messages.length} total`
    : '';

  if (!messages.length) {
    listEl.innerHTML = `
      <div class="empty-state">
        <div class="empty-state-icon">📭</div>
        <h3>No messages yet</h3>
        <p>Share your address so others can send you messages:</p>
        <div class="mono" style="margin-top:8px;font-size:12px;color:var(--accent)">${escHtml(walletAddress ?? '')}</div>
      </div>`;
    return;
  }

  listEl.innerHTML = '';
  for (const msg of messages) {
    const el = document.createElement('div');
    el.className = 'msg-item';

    const time  = new Date(msg.sentAt).toLocaleString();
    const badge = msg.claimed
      ? '<span class="badge badge-green">✓ Claimed</span>'
      : '<span class="badge badge-purple">Pending</span>';
    const decryptReady = Boolean(inboxDecryptPrivateKey) || walletCryptoAvailable;
    const isBusy = inboxActionMessageId === msg.id;
    const actionHtml = msg.claimed
      ? `<button class="btn btn-secondary btn-sm" data-action="open-message" data-message-id="${escHtml(msg.id)}" ${decryptReady ? '' : 'disabled'}>${isBusy ? '<span class="spinner"></span> Opening…' : 'Open'}</button>
         <button class="btn btn-secondary btn-sm" data-action="reply-message" data-message-id="${escHtml(msg.id)}">Reply</button>`
      : `<button class="btn btn-primary btn-sm" data-action="claim-message" data-message-id="${escHtml(msg.id)}" ${decryptReady ? '' : 'disabled'}>${isBusy ? '<span class="spinner"></span> Claiming…' : 'Claim & Open'}</button>`;
    const cliActionHtml = !walletCryptoAvailable
      ? `<button class="btn btn-secondary btn-sm" data-action="copy-cli-read" data-message-id="${escHtml(msg.id)}">Copy CLI Read</button>`
      : '';
    const decryptHint = walletCryptoAvailable
      ? '<span style="color:var(--muted)">Leather can decrypt this message with the connected wallet.</span>'
      : decryptReady
        ? '<span style="color:var(--muted)">Encrypted message ready to decrypt locally.</span>'
        : browserDecryptFallbackEnabled()
          ? '<span style="color:var(--yellow)">Load your inbox decrypt key to claim and open this message.</span>'
          : '<span style="color:var(--yellow)">Wallet-native decrypt is required on this server.</span>';
    const opened = openedInboxMessages[msg.id];
    const messageError = inboxMessageErrors[msg.id];
    const subject = opened?.subject?.trim() ? opened.subject : '(no subject)';

    el.innerHTML = `
      <div class="msg-header">
        <div>
          <div class="msg-from">From: ${escHtml(msg.from || '—')}</div>
          <div style="margin-top:4px;font-size:12px;color:var(--muted)">${time}</div>
        </div>
        <div class="msg-meta">
          ${badge}
          <span class="msg-amount">${escHtml(formatPaymentAmount(msg.amount || 0))}</span>
        </div>
      </div>
      <div style="margin-top:10px;display:flex;align-items:center;gap:6px;font-size:12px;color:var(--muted);flex-wrap:wrap">
        <span>🔒</span>
        ${decryptHint}
      </div>
      <div class="row" style="margin-top:10px">
        ${actionHtml}
        ${cliActionHtml}
      </div>
      ${messageError ? `<div class="alert alert-error" style="margin-top:10px">${escHtml(messageError)}</div>` : ''}
      ${opened ? `
        <div class="msg-body">
          <div style="font-size:11px;color:var(--muted);text-transform:uppercase;margin-bottom:6px">Subject</div>
          <div style="margin-bottom:12px">${escHtml(subject)}</div>
          <div style="font-size:11px;color:var(--muted);text-transform:uppercase;margin-bottom:6px">Body</div>
          <div>${escHtml(opened.body)}</div>
        </div>` : ''}`;

    listEl.appendChild(el);
  }
}

async function fetchPreviewMessage(messageId: string): Promise<PreviewMessageResponse> {
  const response = await apiFetch(`/inbox/${encodeURIComponent(messageId)}/preview`, {
    headers: await buildInboxRequestHeaders('get-message', messageId),
  });
  captureInboxSession(response);
  const data = await response.json().catch(() => ({})) as Record<string, unknown>;
  if (!response.ok) throw new Error(String(data.message ?? data.error ?? `Preview failed: ${response.status}`));
  return data as unknown as PreviewMessageResponse;
}

async function fetchClaimedMessage(messageId: string): Promise<ClaimedMessageResponse> {
  const response = await apiFetch(`/inbox/${encodeURIComponent(messageId)}`, {
    headers: await buildInboxRequestHeaders('get-message', messageId),
  });
  captureInboxSession(response);
  const data = await response.json().catch(() => ({})) as Record<string, unknown>;
  if (!response.ok) throw new Error(String(data.message ?? data.error ?? `Fetch failed: ${response.status}`));
  return data as unknown as ClaimedMessageResponse;
}

async function claimAndOpenMessage(messageId: string): Promise<void> {
  inboxActionMessageId = messageId;
  delete inboxMessageErrors[messageId];
  renderInboxMessages(lastInboxMessages);

  try {
    const preview = await fetchPreviewMessage(messageId);
    const decrypted = await decryptInboxPayload(preview.encryptedPayload);
    const expectedHash = bytesToHex(sha256(hexToBytes(decrypted.secret)));
    if (expectedHash !== preview.hashedSecret) {
      throw new Error('Decrypted secret does not match the payment hash commitment');
    }

    const response = await apiFetch(`/inbox/${encodeURIComponent(messageId)}/claim`, {
      method: 'POST',
      headers: await buildInboxRequestHeaders('claim-message', messageId, {
        'content-type': 'application/json',
      }),
      body: JSON.stringify({ secret: decrypted.secret }),
    });
    captureInboxSession(response);
    const data = await response.json().catch(() => ({})) as Record<string, unknown>;
    if (!response.ok) throw new Error(String(data.message ?? data.error ?? `Claim failed: ${response.status}`));

    openedInboxMessages[messageId] = decrypted;
    lastInboxMessages = updateInboxMessage(lastInboxMessages, messageId, { claimed: true });
    await refreshCurrentTapState();
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    inboxMessageErrors[messageId] = message;
  } finally {
    inboxActionMessageId = null;
    renderInboxMessages(lastInboxMessages);
  }
}

async function openClaimedMessage(messageId: string): Promise<void> {
  inboxActionMessageId = messageId;
  delete inboxMessageErrors[messageId];
  renderInboxMessages(lastInboxMessages);

  try {
    const claimed = await fetchClaimedMessage(messageId);
    openedInboxMessages[messageId] = await decryptInboxPayload(claimed.message.encryptedPayload);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    inboxMessageErrors[messageId] = message;
  } finally {
    inboxActionMessageId = null;
    renderInboxMessages(lastInboxMessages);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Compose tab
// ─────────────────────────────────────────────────────────────────────────────

interface RecipientInfo {
  recipientPublicKey: string;
  serverAddress: string;
  amount: string | number;
}

let recipientInfo: RecipientInfo | null = null;

function getPaymentUnitLabel(): string {
  return getRuntimeSupportedTokenAssetName() ?? 'microstx';
}

function formatPaymentAmount(amount: string | number | bigint): string {
  const value = typeof amount === 'bigint' ? amount : BigInt(String(amount));
  return `${value.toLocaleString()} ${getPaymentUnitLabel()}`;
}

async function lookupRecipientPubkey(addr: string): Promise<string | null> {
  try {
    const url = `https://api.mainnet.hiro.so/extended/v1/address/${encodeURIComponent(addr)}/transactions?limit=5`;
    const r   = await fetch(url, { headers: { Accept: 'application/json' } });
    if (!r.ok) return null;
    const data = await r.json() as { results?: Array<{ sender_address: string; sender_public_key?: string }> };
    for (const tx of (data.results || [])) {
      if (tx.sender_address !== addr) continue;
      const pk = tx.sender_public_key;
      if (typeof pk === 'string') {
        const hex = pk.replace(/^0x/, '');
        if (/^0[23][0-9a-f]{64}$/i.test(hex)) return hex;
      }
    }
    return null;
  } catch { return null; }
}

async function fetchRecipientPaymentInfo(addr: string): Promise<RecipientInfo | null> {
  const r = await apiFetch(`/payment-info/${encodeURIComponent(addr)}`);
  const data = await r.json().catch(() => ({})) as {
    recipientPublicKey?: string;
    serverAddress?: string;
    amount?: string | number;
  };
  if (r.status === 404) return null;
  if (!r.ok) {
    throw new Error(String((data as { message?: string; error?: string }).message ?? (data as { error?: string }).error ?? `payment-info failed: ${r.status}`));
  }
  if (!data.recipientPublicKey || !data.serverAddress || data.amount == null) {
    throw new Error('payment-info response missing required fields');
  }
  return {
    recipientPublicKey: data.recipientPublicKey,
    serverAddress: data.serverAddress,
    amount: data.amount,
  };
}

async function fetchRecipientInfo(toAddr: string): Promise<void> {
  const el = document.getElementById('recipient-status') as HTMLElement;
  el.innerHTML = '<span class="spinner"></span> Looking up recipient…';

  const resetErr = (msg: string) => {
    el.innerHTML = `<span style="color:var(--red)">✗ ${escHtml(msg)}</span>`;
    recipientInfo = null;
    (document.getElementById('send-btn') as HTMLButtonElement).disabled = true;
    (document.getElementById('payment-panel') as HTMLElement).style.display = 'none';
  };

  try {
    await ensureSupportedTokenLoaded();
    const serverPaymentInfo = await fetchRecipientPaymentInfo(toAddr);
    if (serverPaymentInfo) {
      recipientInfo = serverPaymentInfo;
      el.innerHTML  = `<span style="color:var(--green)">✓ Recipient is registered with this Mailslot server</span>`;
    } else {
      const recipientPublicKey = await lookupRecipientPubkey(toAddr);
      if (!recipientPublicKey) {
        resetErr('Recipient has not registered with this server and has no discoverable outbound Stacks public key yet.');
        return;
      }

      const price      = (serverStatus.messagePriceSats as string | number | undefined) ?? '1000';
      const serverAddr = (serverStatus.serverAddress as string | undefined) ?? '';
      recipientInfo = { recipientPublicKey, serverAddress: serverAddr, amount: price };
      el.innerHTML  = `<span style="color:var(--green)">✓ Recipient public key recovered from chain history</span>`;
    }

    (document.getElementById('payment-panel') as HTMLElement).style.display = '';
    (document.getElementById('pay-price') as HTMLElement).textContent   = formatPaymentAmount(recipientInfo.amount);
    (document.getElementById('pay-balance') as HTMLElement).textContent = formatPaymentAmount(pipeState.myBalance);
    (document.getElementById('pay-nonce') as HTMLElement).textContent   = `${pipeState.nonce}`;

    const tap = await resolveTapState(walletAddress!);
    if (tap) {
      pipeState = { myBalance: tap.userBalance, serverBalance: tap.reservoirBalance, nonce: tap.nonce };
      (document.getElementById('pay-balance') as HTMLElement).textContent = formatPaymentAmount(pipeState.myBalance);
      (document.getElementById('pay-nonce') as HTMLElement).textContent   = `${pipeState.nonce}`;
      const receiveSummary = describeReceiveCapacity(pipeState.serverBalance);
      (document.getElementById('tap-status') as HTMLElement).innerHTML =
        `<span style="color:var(--green)">✓ Channel open — ${escHtml(formatPaymentAmount(pipeState.myBalance))} available to send</span><br>` +
        `<span style="color:${receiveSummary.tone === 'low' ? 'var(--amber)' : 'var(--muted)'}">${escHtml(receiveSummary.message)}</span>`;
      (document.getElementById('send-btn') as HTMLButtonElement).disabled = pipeState.myBalance < BigInt(String(recipientInfo.amount));
    } else {
      (document.getElementById('tap-status') as HTMLElement).innerHTML =
        `<span style="color:var(--red)">✗ No channel found on-chain</span>`;
      (document.getElementById('send-btn') as HTMLButtonElement).disabled = true;
    }

  } catch (e) {
    resetErr(typeof e === 'string' ? e : ((e as Error)?.message || (e as { reason?: string })?.reason || JSON.stringify(e) || 'Unknown error'));
  }
}

async function sendMessage(): Promise<void> {
  const toAddr   = (document.getElementById('to-input') as HTMLInputElement).value.trim();
  const subject  = (document.getElementById('subject-input') as HTMLInputElement).value.trim();
  const body     = (document.getElementById('body-input') as HTMLTextAreaElement).value.trim();
  const statusEl = document.getElementById('send-status') as HTMLElement;
  const sendBtn  = document.getElementById('send-btn') as HTMLButtonElement;

  if (!toAddr || !body) {
    statusEl.innerHTML = '<div class="alert alert-warning">Please fill in To and Message fields.</div>';
    return;
  }
  if (!recipientInfo) {
    statusEl.innerHTML = '<div class="alert alert-warning">Please wait for recipient info to load.</div>';
    return;
  }

  sendBtn.disabled = true;
  sendBtn.innerHTML = '<span class="spinner"></span> Sending…';
  statusEl.innerHTML = '';

  try {
    await ensureSupportedTokenLoaded();
    const chainId    = (serverStatus.chainId as number | undefined) ?? CHAIN_ID;
    const sfContract = getRuntimeSfContract();
    const serverAddr = recipientInfo.serverAddress;
    const senderAddr = walletAddress!;
    const supportedToken = getRuntimeSupportedToken();

    // Random secret + hash
    const secretBytes     = crypto.getRandomValues(new Uint8Array(32));
    const secretHex       = bytesToHex(secretBytes);
    const hashedSecretHex = bytesToHex(sha256(secretBytes));

    // Encrypt payload
    const mailPayload = { v: 1 as const, secret: secretHex, subject: subject || undefined, body };
    const encryptedPayload = walletCryptoAvailable
      ? await encryptMailWithWallet(mailPayload, recipientInfo.recipientPublicKey)
      : await encryptMail(mailPayload, recipientInfo.recipientPublicKey);

    // Update pipe state
    const price            = BigInt(recipientInfo.amount || '1000');
    if (pipeState.myBalance < price) {
      throw new Error(`Insufficient channel balance. Need ${formatPaymentAmount(price)}, have ${formatPaymentAmount(pipeState.myBalance)}.`);
    }
    const newServerBalance = pipeState.serverBalance + price;
    const newMyBalance     = pipeState.myBalance - price;
    const newNonce         = pipeState.nonce + 1n;

    // Build canonical pipe key (sender ↔ server, token follows reservoir supported-token)
    const pipeKey = canonicalPipeKey(supportedToken, senderAddr, serverAddr);

    // Build SIP-018 transfer CV
    const transferCV = buildTransferCV({
      pipeKey,
      forPrincipal: serverAddr,
      myBalance:    newServerBalance,
      theirBalance: newMyBalance,
      nonce:        newNonce,
      action:       1n,
      actor:        senderAddr,
      hashedSecret: hashedSecretHex,
      validAfter:   null,
    });

    // Sign with wallet
    const sig = await sip018SignWithWallet(sfContract, transferCV, chainId);

    // Build proof object
    const proof = {
      contractId:    sfContract,
      pipeKey,
      forPrincipal:  serverAddr,
      withPrincipal: senderAddr,
      myBalance:     newServerBalance.toString(),
      theirBalance:  newMyBalance.toString(),
      nonce:         newNonce.toString(),
      action:        '1',
      actor:         senderAddr,
      hashedSecret:  hashedSecretHex,
      theirSignature: sig,
    };

    const r = await apiFetch(`/messages/${encodeURIComponent(toAddr)}`, {
      method:  'POST',
      headers: {
        'content-type':        'application/json',
        'x-mailslot-payment': btoa(JSON.stringify(proof)),
      },
      body: JSON.stringify({ from: senderAddr, fromPublicKey: walletPubkey, encryptedPayload }),
    });

    const data = await r.json().catch(() => ({})) as {
      messageId?: string;
      message?: string;
      error?: string;
      deferred?: boolean;
      reason?: string;
    };
    if (!r.ok) throw new Error(data.message || data.error || `Send failed: ${r.status}`);

    // Commit state
    pipeState = { myBalance: newMyBalance, serverBalance: newServerBalance, nonce: newNonce };
    updateIdentityUI();
    (document.getElementById('pay-balance') as HTMLElement).textContent = formatPaymentAmount(pipeState.myBalance);
    (document.getElementById('pay-nonce') as HTMLElement).textContent   = `${pipeState.nonce}`;

    statusEl.innerHTML = data.deferred
      ? `
      <div class="alert alert-warning">
        Message accepted and queued.<br>
        Recipient still needs tap capacity before it can be claimed.<br>
        <span class="mono" style="font-size:11px">ID: ${escHtml(data.messageId || '—')} · ${escHtml(data.reason || 'deferred')}</span>
      </div>`
      : `
      <div class="alert alert-success">
        ✓ Message sent!<br>
        <span class="mono" style="font-size:11px">ID: ${escHtml(data.messageId || '—')}</span>
      </div>`;

    (document.getElementById('body-input') as HTMLTextAreaElement).value    = '';
    (document.getElementById('subject-input') as HTMLInputElement).value = '';

  } catch (e) {
    const msg = typeof e === 'string' ? e : ((e as Error)?.message || (e as { reason?: string })?.reason || JSON.stringify(e) || 'Unknown error');
    statusEl.innerHTML = `<div class="alert alert-error">✗ ${escHtml(msg)}</div>`;
  } finally {
    sendBtn.disabled = false;
    sendBtn.textContent = 'Send Message';
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Status tab
// ─────────────────────────────────────────────────────────────────────────────

async function loadStatus(): Promise<void> {
  const dot   = document.getElementById('health-dot') as HTMLElement;
  const label = document.getElementById('health-label') as HTMLElement;
  try {
    const r    = await apiFetch('/status');
    const data = await r.json() as Record<string, unknown>;
    try {
      const reservoir = (
        typeof data.reservoirContract === 'string' && isContractPrincipal(data.reservoirContract)
          ? data.reservoirContract
          : (typeof data.serverAddress === 'string' && isContractPrincipal(data.serverAddress) ? data.serverAddress : RESERVOIR)
      );
      const chainId = typeof data.chainId === 'number' ? data.chainId : CHAIN_ID;
      const supportedToken = await fetchReservoirSupportedToken(reservoir, chainId);
      data.supportedToken = supportedToken;
      if (supportedToken == null) {
        data.supportedTokenAssetName = null;
      } else {
        data.supportedTokenAssetName = await fetchFungibleTokenName(supportedToken, chainId);
      }
    } catch {
      // Keep status usable even if token lookup temporarily fails.
    }
    serverStatus = data;
    updateAdminSectionVisibility();
    updateDecryptKeyUI();
    populateAdminSettingsForm(extractRuntimeSettings(data));
    dot.className    = data.ok ? 'dot green' : 'dot red';
    label.textContent = data.ok ? 'Mailslot Server — Online' : 'Server returned error';
    (document.getElementById('s-addr') as HTMLElement).textContent     = String(data.serverAddress || '—');
    (document.getElementById('s-contract') as HTMLElement).textContent = String(data.sfContract    || '—');
    (document.getElementById('s-price') as HTMLElement).textContent    = data.messagePriceSats
      ? formatPaymentAmount(String(data.messagePriceSats)) : '—';
    (document.getElementById('s-network') as HTMLElement).textContent  = data.network
      ? String(data.network).charAt(0).toUpperCase() + String(data.network).slice(1) : '—';
    const adminAgentInput = document.getElementById('admin-agent-input') as HTMLInputElement | null;
    if (adminAgentInput && !adminAgentInput.value.trim()) {
      const candidate = typeof data.signerAddress === 'string'
        ? data.signerAddress.trim()
        : (typeof data.serverAddress === 'string' ? data.serverAddress.trim() : '');
      if (candidate) adminAgentInput.value = candidate;
    }
    await refreshCurrentTapState();
  } catch {
    dot.className    = 'dot red';
    label.textContent = 'Cannot reach server';
  }
}

async function refreshStatusPanel(): Promise<void> {
  const btn = document.getElementById('refresh-status-btn') as HTMLButtonElement | null;
  if (btn) {
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner"></span> Refreshing…';
  }
  try {
    await loadStatus();
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.textContent = 'Refresh';
    }
  }
}

function updateCapacityBanner(): void {
  const bannerEl = document.getElementById('capacity-banner') as HTMLElement | null;
  const statusAlertEl = document.getElementById('status-capacity-alert') as HTMLElement | null;
  if (!bannerEl || !statusAlertEl) return;

  if (!(pipeState.nonce > 0n || pipeState.myBalance > 0n || pipeState.serverBalance > 0n)) {
    bannerEl.style.display = 'none';
    bannerEl.innerHTML = '';
    statusAlertEl.innerHTML = '';
    return;
  }

  const summary = describeReceiveCapacity(pipeState.serverBalance);
  const target = getTargetReceiveLiquidity();
  const refreshAmount = getCapacityRefreshAmount(pipeState.serverBalance);
  const buttonDisabled = refreshAmount <= 0n ? 'disabled' : '';
  const buttonLabel = refreshAmount > 0n
    ? `Refresh Capacity (${formatPaymentAmount(refreshAmount)})`
    : 'Capacity Full';

  if (summary.tone === 'low') {
    bannerEl.style.display = '';
    bannerEl.innerHTML = `
      <div class="alert alert-warning" style="display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap">
        <div>${escHtml(summary.message)}</div>
        <button class="btn btn-primary btn-sm" id="capacity-banner-refresh-btn" ${buttonDisabled}>${escHtml(buttonLabel)}</button>
      </div>`;
  } else {
    bannerEl.style.display = 'none';
    bannerEl.innerHTML = '';
  }

  statusAlertEl.innerHTML = `
    <div class="alert ${summary.tone === 'low' ? 'alert-warning' : 'alert-info'}" style="display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap">
      <div>
        ${escHtml(summary.message)}
        <div style="font-size:12px;color:var(--muted);margin-top:4px">
          Target receive capacity: ${escHtml(formatPaymentAmount(target))} (${getRemainingReceives(target)} message(s)).
        </div>
      </div>
      <button class="btn btn-secondary btn-sm" id="status-capacity-refresh-btn" ${buttonDisabled}>${escHtml(buttonLabel)}</button>
    </div>`;
}

function updateIdentityUI(): void {
  const addr = walletAddress || '—';
  const pub  = walletPubkey  || '—';
  const el   = document.getElementById('status-wallet-addr');
  const pk   = document.getElementById('status-wallet-pubkey');
  const ia   = document.getElementById('inbox-addr');
  if (el) el.textContent = addr;
  if (pk) pk.textContent = pub;
  if (ia) ia.textContent = addr;
  updateAdminSectionVisibility();
  updateCapacityBanner();

  const tapEl = document.getElementById('status-tap-info');
  if (!tapEl) return;
  if (pipeState.nonce > 0n || pipeState.myBalance > 0n) {
    const sendTarget = getOpenTapAmount();
    const receiveTarget = getTargetReceiveLiquidity();
    const remainingReceives = getRemainingReceives(pipeState.serverBalance);
    tapEl.innerHTML = `
      <div style="font-size:11px;color:var(--muted);margin-top:4px;margin-bottom:8px">
        Send capacity is the balance you can spend toward the reservoir. Receive liquidity is the reservoir balance it can forward to you when others send mail. Effective liquidity shown below includes pending channel balance when available.
      </div>
      <div style="font-size:11px;color:var(--muted);margin-top:2px;margin-bottom:8px">
        Mailbox policy: open with ${escHtml(formatPaymentAmount(sendTarget))} send capacity and target ${escHtml(formatPaymentAmount(receiveTarget))} receive liquidity. Current receive headroom is about ${remainingReceives} message(s).
      </div>
      ${serverStatus.runtimeSettings && typeof (serverStatus.runtimeSettings as { maxBorrowPerTap?: unknown }).maxBorrowPerTap === 'string' ? `
      <div style="font-size:11px;color:var(--muted);margin-top:2px;margin-bottom:8px">
        Current receive-liquidity cap per tap: ${escHtml(formatPaymentAmount(String((serverStatus.runtimeSettings as { maxBorrowPerTap: string }).maxBorrowPerTap)))}
      </div>` : ''}
      <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:8px;margin-top:4px">
        <div>
          <div style="font-size:11px;color:var(--muted);text-transform:uppercase;margin-bottom:2px">Send capacity</div>
          <div style="font-size:15px;color:var(--text)">${escHtml(formatPaymentAmount(pipeState.myBalance))}</div>
        </div>
        <div>
          <div style="font-size:11px;color:var(--muted);text-transform:uppercase;margin-bottom:2px">Receive liquidity</div>
          <div style="font-size:15px;color:var(--text)">${escHtml(formatPaymentAmount(pipeState.serverBalance))}</div>
        </div>
        <div>
          <div style="font-size:11px;color:var(--muted);text-transform:uppercase;margin-bottom:2px">Nonce</div>
          <div style="font-size:15px;color:var(--text)">${pipeState.nonce}</div>
        </div>
      </div>`;
  } else {
    tapEl.textContent = 'No channel state loaded.';
  }
}

async function setBorrowRate(): Promise<void> {
  const input = document.getElementById('admin-borrow-rate-input') as HTMLInputElement;
  const btn = document.getElementById('admin-set-rate-btn') as HTMLButtonElement;
  const statusEl = document.getElementById('admin-rate-status') as HTMLElement;

  if (!walletAddress) {
    statusEl.innerHTML = '<div class="alert alert-warning">Connect wallet first.</div>';
    return;
  }
  if (!connectedUserIsReservoirAdmin()) {
    statusEl.innerHTML = '<div class="alert alert-warning">Only the reservoir deployer can use this control.</div>';
    return;
  }

  const raw = input.value.trim();
  if (!/^\d+$/.test(raw)) {
    statusEl.innerHTML = '<div class="alert alert-warning">Enter a non-negative integer borrow rate in basis points.</div>';
    return;
  }
  const rate = BigInt(raw);

  btn.disabled = true;
  btn.innerHTML = '<span class="spinner"></span> Submitting…';
  statusEl.innerHTML = '';

  try {
    await ensureServerStatusLoaded();
    const chainId = (serverStatus.chainId as number | undefined) ?? CHAIN_ID;
    const reservoir = getRuntimeReservoirContract();
    const txId = await withTimeout(
      new Promise<string>((resolve, reject) => {
        openContractCall({
          contractAddress: reservoir.split('.')[0],
          contractName: reservoir.split('.')[1],
          functionName: 'set-borrow-rate',
          functionArgs: [uintCV(rate)],
          network: chainIdToNetworkName(chainId),
          postConditionMode: PostConditionMode.Allow,
          appDetails: { name: 'Mailslot', icon: window.location.origin + '/favicon.ico' },
          onFinish: (data: { txId?: string; txid?: string; tx_id?: string }) =>
            resolve(data.txId ?? data.txid ?? data.tx_id ?? ''),
          onCancel: () => reject(new Error('Transaction cancelled')),
        });
      }),
      180_000,
      'Timed out waiting for wallet transaction approval',
    );

    if (!txId) throw new Error('No transaction ID returned from wallet');
    const chain = chainId === 1 ? 'mainnet' : 'testnet';
    statusEl.innerHTML = `
      <div class="alert alert-success">
        Borrow rate update submitted.<br>
        <a href="https://explorer.hiro.so/txid/${txId}?chain=${chain}" target="_blank" rel="noopener" class="mono" style="color:inherit">
          ${escHtml(txId)}
        </a>
      </div>`;
  } catch (e) {
    const msg = typeof e === 'string' ? e : ((e as Error)?.message || (e as { reason?: string })?.reason || JSON.stringify(e) || 'Unknown error');
    statusEl.innerHTML = `<div class="alert alert-error">${escHtml(msg)}</div>`;
  } finally {
    btn.disabled = false;
    btn.textContent = 'Set Borrow Rate';
  }
}

async function setReservoirAgent(): Promise<void> {
  const input = document.getElementById('admin-agent-input') as HTMLInputElement;
  const btn = document.getElementById('admin-set-agent-btn') as HTMLButtonElement;
  const statusEl = document.getElementById('admin-agent-status') as HTMLElement;

  if (!walletAddress) {
    statusEl.innerHTML = '<div class="alert alert-warning">Connect wallet first.</div>';
    return;
  }
  if (!connectedUserIsReservoirAdmin()) {
    statusEl.innerHTML = '<div class="alert alert-warning">Only the reservoir deployer can use this control.</div>';
    return;
  }

  const agent = input.value.trim();
  if (!/^S[PT][0-9A-Z]{39}$/.test(agent)) {
    statusEl.innerHTML = '<div class="alert alert-warning">Enter a valid standard STX address for the agent.</div>';
    return;
  }

  btn.disabled = true;
  btn.innerHTML = '<span class="spinner"></span> Submitting…';
  statusEl.innerHTML = '';

  try {
    await ensureServerStatusLoaded();
    const chainId = (serverStatus.chainId as number | undefined) ?? CHAIN_ID;
    const reservoir = getRuntimeReservoirContract();
    const sfContract = getRuntimeSfContract();
    const txId = await withTimeout(
      new Promise<string>((resolve, reject) => {
        openContractCall({
          contractAddress: reservoir.split('.')[0],
          contractName: reservoir.split('.')[1],
          functionName: 'set-agent',
          functionArgs: [principalCV(sfContract), principalCV(agent)],
          network: chainIdToNetworkName(chainId),
          postConditionMode: PostConditionMode.Allow,
          appDetails: { name: 'Mailslot', icon: window.location.origin + '/favicon.ico' },
          onFinish: (data: { txId?: string; txid?: string; tx_id?: string }) =>
            resolve(data.txId ?? data.txid ?? data.tx_id ?? ''),
          onCancel: () => reject(new Error('Transaction cancelled')),
        });
      }),
      180_000,
      'Timed out waiting for wallet transaction approval',
    );

    if (!txId) throw new Error('No transaction ID returned from wallet');
    const chain = chainId === 1 ? 'mainnet' : 'testnet';
    statusEl.innerHTML = `
      <div class="alert alert-success">
        Reservoir agent update submitted.<br>
        <a href="https://explorer.hiro.so/txid/${txId}?chain=${chain}" target="_blank" rel="noopener" class="mono" style="color:inherit">
          ${escHtml(txId)}
        </a>
      </div>`;
  } catch (e) {
    const msg = typeof e === 'string' ? e : ((e as Error)?.message || (e as { reason?: string })?.reason || JSON.stringify(e) || 'Unknown error');
    statusEl.innerHTML = `<div class="alert alert-error">${escHtml(msg)}</div>`;
  } finally {
    btn.disabled = false;
    btn.textContent = 'Set Reservoir Agent';
  }
}

async function saveAdminRuntimeSettings(): Promise<void> {
  const btn = document.getElementById('admin-save-settings-btn') as HTMLButtonElement;
  const statusEl = document.getElementById('admin-settings-status') as HTMLElement;

  if (!walletAddress) {
    statusEl.innerHTML = '<div class="alert alert-warning">Connect wallet first.</div>';
    return;
  }
  if (!connectedUserIsReservoirAdmin()) {
    statusEl.innerHTML = '<div class="alert alert-warning">Only the reservoir deployer can use this control.</div>';
    return;
  }

  const readInt = (id: string, label: string): number => {
    const raw = (document.getElementById(id) as HTMLInputElement).value.trim();
    if (!/^\d+$/.test(raw)) throw new Error(`${label} must be a non-negative integer`);
    return Number(raw);
  };
  const readUintString = (id: string, label: string): string => {
    const raw = (document.getElementById(id) as HTMLInputElement).value.trim();
    if (!/^\d+$/.test(raw)) throw new Error(`${label} must be a non-negative integer`);
    return raw;
  };

  let payload: RuntimeSettingsPayload;
  try {
    payload = {
      messagePriceSats: readUintString('admin-message-price-input', 'Message Price'),
      minFeeSats: readUintString('admin-min-fee-input', 'Minimum Fee'),
      maxPendingPerSender: readInt('admin-max-pending-sender-input', 'Max Pending / Sender'),
      maxPendingPerRecipient: readInt('admin-max-pending-recipient-input', 'Max Pending / Recipient'),
      maxDeferredPerSender: readInt('admin-max-deferred-sender-input', 'Max Deferred / Sender'),
      maxDeferredPerRecipient: readInt('admin-max-deferred-recipient-input', 'Max Deferred / Recipient'),
      maxDeferredGlobal: readInt('admin-max-deferred-global-input', 'Max Deferred / Global'),
      deferredMessageTtlMs: readInt('admin-deferred-ttl-input', 'Deferred TTL'),
      maxBorrowPerTap: readUintString('admin-max-borrow-per-tap-input', 'Max Borrow / Tap'),
    };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    statusEl.innerHTML = `<div class="alert alert-warning">${escHtml(message)}</div>`;
    return;
  }

  btn.disabled = true;
  btn.innerHTML = '<span class="spinner"></span> Saving…';
  statusEl.innerHTML = '';

  try {
    const response = await apiFetch('/admin/settings', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'x-mailslot-auth': await buildWalletAuthHeader('admin-settings'),
      },
      body: JSON.stringify(payload),
    });
    const data = await response.json().catch(() => ({})) as Record<string, unknown>;
    if (!response.ok) {
      throw new Error(String(data.message ?? data.error ?? `Save failed: ${response.status}`));
    }
    const settings = extractRuntimeSettings({ runtimeSettings: data.settings });
    if (settings) {
      serverStatus.runtimeSettings = settings;
      serverStatus.messagePriceSats = settings.messagePriceSats;
      serverStatus.minFeeSats = settings.minFeeSats;
      populateAdminSettingsForm(settings);
    }
    await loadStatus();
    statusEl.innerHTML = '<div class="alert alert-success">Runtime settings saved.</div>';
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    statusEl.innerHTML = `<div class="alert alert-error">${escHtml(message)}</div>`;
  } finally {
    btn.disabled = false;
    btn.textContent = 'Save Mailslot Settings';
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tab switching
// ─────────────────────────────────────────────────────────────────────────────

function showTab(name: string): void {
  document.querySelectorAll<HTMLElement>('.tab-btn').forEach(b =>
    b.classList.toggle('active', (b as HTMLElement & { dataset: { tab?: string } }).dataset.tab === name));
  document.querySelectorAll<HTMLElement>('#panel-main .tab-panel').forEach(p =>
    p.classList.toggle('active', p.id === `tab-${name}`));
  if (name === 'inbox')  loadInbox();
  if (name === 'status') loadStatus();
}

// ─────────────────────────────────────────────────────────────────────────────
// Utility
// ─────────────────────────────────────────────────────────────────────────────

function escHtml(s: string): string {
  return String(s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

async function copyToClipboard(text: string): Promise<boolean> {
  const clipboard = globalThis.navigator?.clipboard;
  if (clipboard?.writeText) {
    try {
      await clipboard.writeText(text);
      return true;
    } catch {
      // Fall back for non-secure origins or restricted clipboard permissions.
    }
  }

  const ta = document.createElement('textarea');
  ta.value = text;
  ta.style.cssText = 'position:fixed;opacity:0;pointer-events:none';
  document.body.appendChild(ta);
  ta.focus();
  ta.select();
  ta.setSelectionRange(0, ta.value.length);
  try {
    return document.execCommand('copy');
  } finally {
    document.body.removeChild(ta);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Event wiring
// ─────────────────────────────────────────────────────────────────────────────

function bindEvent<K extends keyof HTMLElementEventMap>(
  id: string,
  event: K,
  handler: (ev: HTMLElementEventMap[K]) => void | Promise<void>,
): void {
  const el = document.getElementById(id);
  if (!el) return;
  el.addEventListener(event, handler as EventListener);
}

bindEvent('connect-wallet-btn', 'click', connectWallet);
bindEvent('connect-wallet-main', 'click', connectWallet);
bindEvent('disconnect-btn', 'click', disconnectWallet);
bindEvent('open-mailbox-btn', 'click', openMailbox);
bindEvent('check-tap-btn', 'click', checkTapAfterTx);
bindEvent('add-funds-btn', 'click', addFundsToTap);
bindEvent('refresh-capacity-btn', 'click', () => refreshReceiveCapacity());

document.querySelectorAll<HTMLButtonElement>('.tab-btn').forEach(btn => {
  btn.addEventListener('click', () => showTab(btn.dataset.tab ?? ''));
});

bindEvent('refresh-inbox-btn', 'click', loadInbox);
bindEvent('show-claimed-cb', 'change', loadInbox);
bindEvent('save-decrypt-key-btn', 'click', saveDecryptKey);
bindEvent('clear-decrypt-key-btn', 'click', clearDecryptKey);
bindEvent('send-btn', 'click', sendMessage);
bindEvent('admin-set-agent-btn', 'click', setReservoirAgent);
bindEvent('admin-set-rate-btn', 'click', setBorrowRate);
bindEvent('admin-save-settings-btn', 'click', saveAdminRuntimeSettings);
document.addEventListener('click', async (event) => {
  const target = event.target as HTMLElement | null;
  const button = target?.closest<HTMLButtonElement>('#capacity-banner-refresh-btn, #status-capacity-refresh-btn');
  if (!button) return;
  await refreshReceiveCapacity();
});
bindEvent('inbox-list', 'click', async (event) => {
  const target = event.target as HTMLElement | null;
  const button = target?.closest<HTMLButtonElement>('button[data-action][data-message-id]');
  if (!button) return;

  const action = button.dataset.action;
  const messageId = button.dataset.messageId;
  if (!action || !messageId) return;

  if (action === 'claim-message') {
    await claimAndOpenMessage(messageId);
    return;
  }
  if (action === 'open-message') {
    await openClaimedMessage(messageId);
    return;
  }
  if (action === 'reply-message') {
    await replyToMessage(messageId);
    return;
  }
  if (action === 'copy-cli-read') {
    const ok = await copyToClipboard(cliReadCommand(messageId));
    const original = button.textContent ?? 'Copy CLI Read';
    button.textContent = ok ? 'Copied!' : 'Copy failed';
    setTimeout(() => { button.textContent = original; }, 1500);
  }
});

bindEvent('copy-inbox-addr-btn', 'click', async () => {
  const btn = document.getElementById('copy-inbox-addr-btn') as HTMLButtonElement;
  const ok = await copyToClipboard(walletAddress || '');
  btn.textContent = ok ? 'Copied!' : 'Copy failed';
  setTimeout(() => { btn.textContent = 'Copy'; }, 1500);
});

bindEvent('copy-status-addr-btn', 'click', async () => {
  const btn = document.getElementById('copy-status-addr-btn') as HTMLButtonElement;
  const ok = await copyToClipboard(walletAddress || '');
  btn.textContent = ok ? 'Copied!' : 'Copy failed';
  setTimeout(() => { btn.textContent = 'Copy'; }, 1500);
});
bindEvent('refresh-status-btn', 'click', refreshStatusPanel);

// Auto-fetch recipient info when a valid address is typed
let toDebounceTimer: ReturnType<typeof setTimeout> | null = null;
bindEvent('to-input', 'input', (e) => {
  const val = (e.target as HTMLInputElement).value.trim();
  recipientInfo = null;
  (document.getElementById('send-btn') as HTMLButtonElement).disabled = true;
  (document.getElementById('payment-panel') as HTMLElement).style.display = 'none';
  (document.getElementById('recipient-status') as HTMLElement).textContent = '';
  if (toDebounceTimer) clearTimeout(toDebounceTimer);
  if (val.startsWith('S') && val.length >= 30) {
    toDebounceTimer = setTimeout(() => fetchRecipientInfo(val), 500);
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// Bootstrap
// ─────────────────────────────────────────────────────────────────────────────

updateDecryptKeyUI();
setAppState('no-wallet');
