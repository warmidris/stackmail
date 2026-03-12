import { afterEach, describe, expect, it, vi } from 'vitest';
import { secp256k1 } from '@noble/curves/secp256k1';
import { principalCV, serializeCVBytes, someCV, uintCV } from '@stacks/transactions';
import { ReservoirService } from './reservoir.js';
import { buildTransferMessage, sip018Sign, type TransferState } from './sip018.js';
import { pubkeyToStxAddress } from './auth.js';

function privKeyHex(): string {
  return Buffer.from(secp256k1.utils.randomPrivateKey()).toString('hex');
}

function stxAddressFromPrivkey(privateKeyHex: string): string {
  const pub = secp256k1.getPublicKey(privateKeyHex, true);
  return pubkeyToStxAddress(Buffer.from(pub).toString('hex'));
}

function serializePrincipalForSort(principal: string): Buffer {
  return Buffer.from(serializeCVBytes(principalCV(principal)));
}

function canonicalPipePrincipals(a: string, b: string): { 'principal-1': string; 'principal-2': string } {
  const sa = serializePrincipalForSort(a);
  const sb = serializePrincipalForSort(b);
  for (let i = 0; i < Math.min(sa.length, sb.length); i++) {
    if (sa[i] < sb[i]) return { 'principal-1': a, 'principal-2': b };
    if (sa[i] > sb[i]) return { 'principal-1': b, 'principal-2': a };
  }
  return { 'principal-1': a, 'principal-2': b };
}

function pipeId(contractId: string, p1: string, p2: string): string {
  return `${contractId}|stx|${p1}|${p2}`;
}

describe('ReservoirService', () => {
  const realFetch = globalThis.fetch;

  afterEach(() => {
    if (realFetch) {
      vi.stubGlobal('fetch', realFetch);
    } else {
      vi.unstubAllGlobals();
    }
  });

  it('rejects payment verification when key is missing', async () => {
    const { default: Database } = await import('better-sqlite3');
    const db = new Database(':memory:');
    const serverPriv = privKeyHex();
    const serverAddress = stxAddressFromPrivkey(serverPriv);
    const service = new ReservoirService({
      db,
      serverAddress,
      serverPrivateKey: '',
      contractId: `${serverAddress}.stackflow-test`,
      chainId: 1,
      minFeeSats: '100',
      messagePriceSats: '500',
    });

    await expect(service.verifyIncomingPayment(JSON.stringify({
      hashedSecret: 'aa'.repeat(32),
      amount: '1000',
      actor: serverAddress,
    }))).rejects.toMatchObject({
      reason: 'payment-verification-disabled',
    });
  });

  it('persists latest signatures and nonce for a pipe', async () => {
    const { default: Database } = await import('better-sqlite3');
    const db = new Database(':memory:');
    const serverPriv = privKeyHex();
    const senderPriv = privKeyHex();
    const serverAddress = stxAddressFromPrivkey(serverPriv);
    const senderAddress = stxAddressFromPrivkey(senderPriv);
    const contractId = `${serverAddress}.stackflow-test`;
    const service = new ReservoirService({
      db,
      serverAddress,
      serverPrivateKey: serverPriv,
      contractId,
      chainId: 1,
      minFeeSats: '100',
      messagePriceSats: '500',
    });

    const principals = canonicalPipePrincipals(serverAddress, senderAddress);
    const incomingPipeKey = {
      'principal-1': principals['principal-1'],
      'principal-2': principals['principal-2'],
      token: null as string | null,
    };
    const incomingSecret = '11'.repeat(32);
    const incomingState: TransferState = {
      pipeKey: incomingPipeKey,
      forPrincipal: serverAddress,
      myBalance: '1000',
      theirBalance: '0',
      nonce: '1',
      action: '1',
      actor: senderAddress,
      hashedSecret: incomingSecret,
      validAfter: null,
    };
    const incomingSig = await sip018Sign(
      contractId,
      buildTransferMessage(incomingState),
      senderPriv,
      1,
    );

    const somePipeHex = '0x' + Buffer.from(serializeCVBytes(someCV(uintCV(0)))).toString('hex');
    vi.stubGlobal('fetch', vi.fn(async () => ({
      ok: true,
      json: async () => ({ okay: true, result: somePipeHex }),
    })) as unknown as typeof fetch);

    const verified = await service.verifyIncomingPayment(JSON.stringify({
      contractId,
      ...incomingState,
      withPrincipal: senderAddress,
      theirSignature: incomingSig,
    }));
    expect(verified.senderAddress).toBe(senderAddress);
    expect(verified.hashedSecret).toBe(incomingSecret);

    const outgoingSecret = '22'.repeat(32);
    const pending = await service.createOutgoingPayment({
      hashedSecret: outgoingSecret,
      incomingAmount: '700',
      recipientAddr: senderAddress,
      contractId,
    });
    expect(pending).not.toBeNull();

    const row = db.prepare(`
      SELECT nonce, last_action, last_actor, last_hashed_secret,
             last_server_signature, last_counterparty_signature
      FROM reservoir_pipes WHERE pipe_id = ?
    `).get(pipeId(contractId, incomingPipeKey['principal-1'], incomingPipeKey['principal-2'])) as Record<string, unknown>;

    expect(row['nonce']).toBe('2');
    expect(row['last_action']).toBe('1');
    expect(row['last_actor']).toBe(serverAddress);
    expect(row['last_hashed_secret']).toBe(outgoingSecret);
    expect(typeof row['last_server_signature']).toBe('string');
    expect(row['last_counterparty_signature']).toBe(incomingSig);
  });

  it('rejects non-canonical pipe principal order', async () => {
    const { default: Database } = await import('better-sqlite3');
    const db = new Database(':memory:');
    const serverPriv = privKeyHex();
    const senderPriv = privKeyHex();
    const serverAddress = stxAddressFromPrivkey(serverPriv);
    const senderAddress = stxAddressFromPrivkey(senderPriv);
    const contractId = `${serverAddress}.stackflow-test`;
    const service = new ReservoirService({
      db,
      serverAddress,
      serverPrivateKey: serverPriv,
      contractId,
      chainId: 1,
      minFeeSats: '100',
      messagePriceSats: '500',
    });

    const canonical = canonicalPipePrincipals(serverAddress, senderAddress);
    const nonCanonical = {
      'principal-1': canonical['principal-2'],
      'principal-2': canonical['principal-1'],
      token: null as string | null,
    };
    const state: TransferState = {
      pipeKey: nonCanonical,
      forPrincipal: serverAddress,
      myBalance: '1000',
      theirBalance: '0',
      nonce: '1',
      action: '1',
      actor: senderAddress,
      hashedSecret: '33'.repeat(32),
      validAfter: null,
    };
    const sig = await sip018Sign(contractId, buildTransferMessage(state), senderPriv, 1);

    await expect(service.verifyIncomingPayment(JSON.stringify({
      contractId,
      ...state,
      withPrincipal: senderAddress,
      theirSignature: sig,
    }))).rejects.toMatchObject({
      reason: 'non-canonical-pipe-key',
    });
  });
});
