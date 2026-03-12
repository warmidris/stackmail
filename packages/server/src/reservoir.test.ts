import { afterEach, describe, expect, it, vi } from 'vitest';
import { secp256k1 } from '@noble/curves/secp256k1';
import { noneCV, principalCV, responseOkCV, serializeCVBytes, someCV, tupleCV, uintCV } from '@stacks/transactions';
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

function encodeSomePipe(args: {
  balance1: bigint;
  balance2: bigint;
  pending1?: bigint;
  pending2?: bigint;
  nonce: bigint;
}): string {
  const pendingTuple = (amount?: bigint) => amount != null
    ? someCV(tupleCV({
        amount: uintCV(amount),
        'burn-height': uintCV(123n),
      }))
    : noneCV();

  return '0x' + Buffer.from(serializeCVBytes(responseOkCV(someCV(tupleCV({
    'balance-1': uintCV(args.balance1),
    'balance-2': uintCV(args.balance2),
    closer: noneCV(),
    'expires-at': uintCV(340282366920938463463374607431768211455n),
    nonce: uintCV(args.nonce),
    'pending-1': pendingTuple(args.pending1),
    'pending-2': pendingTuple(args.pending2),
  }))))).toString('hex');
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

    vi.stubGlobal('fetch', vi.fn(async () => ({
      ok: true,
      json: async () => ({ okay: true, result: encodeSomePipe({
        balance1: principals['principal-1'] === serverAddress ? 0n : 1000n,
        balance2: principals['principal-1'] === serverAddress ? 1000n : 0n,
        nonce: 0n,
      }) }),
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

  it('persists the initial pipe state when mailbox open params are created', async () => {
    const { default: Database } = await import('better-sqlite3');
    const db = new Database(':memory:');
    const serverPriv = privKeyHex();
    const borrowerPriv = privKeyHex();
    const signerAddress = stxAddressFromPrivkey(serverPriv);
    const borrowerAddress = stxAddressFromPrivkey(borrowerPriv);
    const reservoirContractId = `${signerAddress}.sm-reservoir`;
    const contractId = `${signerAddress}.sm-stackflow`;
    const service = new ReservoirService({
      db,
      serverAddress: reservoirContractId,
      signerAddress,
      reservoirContractId,
      serverPrivateKey: serverPriv,
      contractId,
      chainId: 1,
      minFeeSats: '100',
      messagePriceSats: '500',
    });

    const principals = canonicalPipePrincipals(borrowerAddress, reservoirContractId);
    const borrowState: TransferState = {
      pipeKey: {
        'principal-1': principals['principal-1'],
        'principal-2': principals['principal-2'],
        token: null,
      },
      forPrincipal: borrowerAddress,
      myBalance: '10000',
      theirBalance: '10000',
      nonce: '1',
      action: '2',
      actor: reservoirContractId,
      hashedSecret: null,
      validAfter: null,
    };
    const borrowerSig = await sip018Sign(contractId, buildTransferMessage(borrowState), borrowerPriv, 1);

    vi.stubGlobal('fetch', vi.fn(async () => ({
      ok: true,
      json: async () => ({ okay: true, result: '0x0100000000000000000000000000000000' }),
    })) as unknown as typeof fetch);

    const result = await service.createTapWithBorrowedLiquidityParams({
      borrower: borrowerAddress,
      token: null,
      tapAmount: '10000',
      tapNonce: '0',
      borrowAmount: '10000',
      myBalance: '10000',
      reservoirBalance: '10000',
      borrowNonce: '1',
      mySignature: borrowerSig,
    });
    expect(typeof result.reservoirSignature).toBe('string');

    const row = db.prepare(`
      SELECT server_balance, counterparty_balance, nonce, last_action,
             last_server_signature, last_counterparty_signature
      FROM reservoir_pipes WHERE pipe_id = ?
    `).get(pipeId(contractId, principals['principal-1'], principals['principal-2'])) as Record<string, unknown> | undefined;

    expect(row).toBeDefined();
    expect(row?.server_balance).toBe('10000');
    expect(row?.counterparty_balance).toBe('10000');
    expect(row?.nonce).toBe('1');
    expect(row?.last_action).toBe('2');
    expect(row?.last_server_signature).toBe(result.reservoirSignature);
    expect(row?.last_counterparty_signature).toBe(borrowerSig);
  });

  it('derives first incoming amount from on-chain balances including pending deposits', async () => {
    const { default: Database } = await import('better-sqlite3');
    const db = new Database(':memory:');
    const serverPriv = privKeyHex();
    const senderPriv = privKeyHex();
    const serverAddress = stxAddressFromPrivkey(serverPriv);
    const senderAddress = stxAddressFromPrivkey(senderPriv);
    const contractId = `${serverAddress}.sm-stackflow`;
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
    const incomingState: TransferState = {
      pipeKey: {
        'principal-1': principals['principal-1'],
        'principal-2': principals['principal-2'],
        token: null,
      },
      forPrincipal: serverAddress,
      myBalance: '11000',
      theirBalance: '49999000',
      nonce: '2',
      action: '1',
      actor: senderAddress,
      hashedSecret: '44'.repeat(32),
      validAfter: null,
    };
    const incomingSig = await sip018Sign(contractId, buildTransferMessage(incomingState), senderPriv, 1);
    const serverIsPrincipal1 = principals['principal-1'] === serverAddress;

    vi.stubGlobal('fetch', vi.fn(async () => ({
      ok: true,
      json: async () => ({ okay: true, result: encodeSomePipe({
        balance1: serverIsPrincipal1 ? 0n : 50000000n,
        balance2: serverIsPrincipal1 ? 50000000n : 0n,
        pending1: serverIsPrincipal1 ? 10000n : undefined,
        pending2: serverIsPrincipal1 ? undefined : 10000n,
        nonce: 1n,
      }) }),
    })) as unknown as typeof fetch);

    const verified = await service.verifyIncomingPayment(JSON.stringify({
      contractId,
      ...incomingState,
      withPrincipal: senderAddress,
      theirSignature: incomingSig,
    }));

    expect(verified.incomingAmount).toBe('1000');

    const row = db.prepare(`
      SELECT server_balance, counterparty_balance, nonce
      FROM reservoir_pipes WHERE pipe_id = ?
    `).get(pipeId(contractId, principals['principal-1'], principals['principal-2'])) as Record<string, unknown>;

    expect(row.server_balance).toBe('11000');
    expect(row.counterparty_balance).toBe('49999000');
    expect(row.nonce).toBe('2');
  });

  it('rejects a first incoming proof whose total drops pending borrowed liquidity', async () => {
    const { default: Database } = await import('better-sqlite3');
    const db = new Database(':memory:');
    const serverPriv = privKeyHex();
    const senderPriv = privKeyHex();
    const serverAddress = stxAddressFromPrivkey(serverPriv);
    const senderAddress = stxAddressFromPrivkey(senderPriv);
    const contractId = `${serverAddress}.sm-stackflow`;
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
    const invalidState: TransferState = {
      pipeKey: {
        'principal-1': principals['principal-1'],
        'principal-2': principals['principal-2'],
        token: null,
      },
      forPrincipal: serverAddress,
      myBalance: '1000',
      theirBalance: '49999000',
      nonce: '1',
      action: '1',
      actor: senderAddress,
      hashedSecret: '55'.repeat(32),
      validAfter: null,
    };
    const invalidSig = await sip018Sign(contractId, buildTransferMessage(invalidState), senderPriv, 1);
    const serverIsPrincipal1 = principals['principal-1'] === serverAddress;

    vi.stubGlobal('fetch', vi.fn(async () => ({
      ok: true,
      json: async () => ({ okay: true, result: encodeSomePipe({
        balance1: serverIsPrincipal1 ? 0n : 50000000n,
        balance2: serverIsPrincipal1 ? 50000000n : 0n,
        pending1: serverIsPrincipal1 ? 10000n : undefined,
        pending2: serverIsPrincipal1 ? undefined : 10000n,
        nonce: 1n,
      }) }),
    })) as unknown as typeof fetch);

    await expect(service.verifyIncomingPayment(JSON.stringify({
      contractId,
      ...invalidState,
      withPrincipal: senderAddress,
      theirSignature: invalidSig,
    }))).rejects.toMatchObject({
      reason: 'invalid-nonce',
    });

    const nextInvalidState: TransferState = {
      ...invalidState,
      myBalance: '1000',
      theirBalance: '49999000',
      nonce: '2',
    };
    const nextInvalidSig = await sip018Sign(contractId, buildTransferMessage(nextInvalidState), senderPriv, 1);

    await expect(service.verifyIncomingPayment(JSON.stringify({
      contractId,
      ...nextInvalidState,
      withPrincipal: senderAddress,
      theirSignature: nextInvalidSig,
    }))).rejects.toMatchObject({
      reason: 'invalid-total-balance',
    });
  });

  it('rejects a tracked incoming proof whose total does not match the latest tracked state', async () => {
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
    db.prepare(`
      INSERT INTO reservoir_pipes (
        pipe_id, contract_id, pipe_key_json, server_balance, counterparty_balance, nonce, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, unixepoch('now') * 1000)
    `).run(
      pipeId(contractId, principals['principal-1'], principals['principal-2']),
      contractId,
      JSON.stringify({
        'principal-1': principals['principal-1'],
        'principal-2': principals['principal-2'],
        token: null,
      }),
      '1000',
      '9000',
      '1',
    );

    const invalidState: TransferState = {
      pipeKey: {
        'principal-1': principals['principal-1'],
        'principal-2': principals['principal-2'],
        token: null,
      },
      forPrincipal: serverAddress,
      myBalance: '1500',
      theirBalance: '8000',
      nonce: '2',
      action: '1',
      actor: senderAddress,
      hashedSecret: '66'.repeat(32),
      validAfter: null,
    };
    const invalidSig = await sip018Sign(contractId, buildTransferMessage(invalidState), senderPriv, 1);

    await expect(service.verifyIncomingPayment(JSON.stringify({
      contractId,
      ...invalidState,
      withPrincipal: senderAddress,
      theirSignature: invalidSig,
    }))).rejects.toMatchObject({
      reason: 'invalid-total-balance',
    });
  });
});
