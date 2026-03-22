import { afterEach, describe, expect, it, vi } from 'vitest';
import { secp256k1 } from '@noble/curves/secp256k1';
import { noneCV, principalCV, responseOkCV, serializeCVBytes, someCV, tupleCV, uintCV } from '@stacks/transactions';
import { ReservoirService } from './reservoir.js';
import { buildTransferMessage, sip018Sign, type TransferState } from './sip018.js';
import { pubkeyToStxAddress } from './auth.js';
import { RuntimeSettingsStore } from './settings.js';
import { runtimeSettingsFromConfig } from './types.js';

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

function makeSettingsStore(db: import('better-sqlite3').Database) {
  return new RuntimeSettingsStore(db, runtimeSettingsFromConfig({
    messagePriceSats: '500',
    minFeeSats: '100',
    maxPendingPerSender: 5,
    maxPendingPerRecipient: 20,
    maxDeferredPerSender: 5,
    maxDeferredPerRecipient: 20,
    maxDeferredGlobal: 200,
    deferredMessageTtlMs: 86_400_000,
    maxBorrowPerTap: '100000',
    receiveCapacityMultiplier: 20,
    rebalanceThresholdPct: 150,
    refreshCapacityCooldownMs: 86_400_000,
  }));
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
      settings: makeSettingsStore(db),
      serverAddress,
      serverPrivateKey: '',
      contractId: `${serverAddress}.stackflow-test`,
      chainId: 1,
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
      settings: makeSettingsStore(db),
      serverAddress,
      serverPrivateKey: serverPriv,
      contractId,
      chainId: 1,
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

    const rows = db.prepare(`
      SELECT nonce, action, actor, hashed_secret, server_signature, counterparty_signature
      FROM reservoir_pending_states WHERE pipe_id = ?
      ORDER BY CAST(nonce AS INTEGER) ASC
    `).all(pipeId(contractId, incomingPipeKey['principal-1'], incomingPipeKey['principal-2'])) as Record<string, unknown>[];

    expect(rows).toHaveLength(2);
    expect(rows[0]['nonce']).toBe('1');
    expect(rows[0]['counterparty_signature']).toBe(incomingSig);
    expect(rows[1]['nonce']).toBe('2');
    expect(rows[1]['action']).toBe('1');
    expect(rows[1]['actor']).toBe(serverAddress);
    expect(rows[1]['hashed_secret']).toBe(outgoingSecret);
    expect(typeof rows[1]['server_signature']).toBe('string');
  });

  it('records completed incoming payments with an active tap status when no tracked pipe row exists yet', async () => {
    const { default: Database } = await import('better-sqlite3');
    const db = new Database(':memory:');
    const serverPriv = privKeyHex();
    const senderPriv = privKeyHex();
    const serverAddress = stxAddressFromPrivkey(serverPriv);
    const senderAddress = stxAddressFromPrivkey(senderPriv);
    const contractId = `${serverAddress}.stackflow-test`;
    const service = new ReservoirService({
      db,
      settings: makeSettingsStore(db),
      serverAddress,
      serverPrivateKey: serverPriv,
      contractId,
      chainId: 1,
    });

    const principals = canonicalPipePrincipals(serverAddress, senderAddress);
    const proof = Buffer.from(JSON.stringify({
      contractId,
      pipeKey: {
        'principal-1': principals['principal-1'],
        'principal-2': principals['principal-2'],
        token: null,
      },
      forPrincipal: serverAddress,
      withPrincipal: senderAddress,
      myBalance: '1500',
      theirBalance: '8500',
      nonce: '3',
      action: '1',
      actor: senderAddress,
      hashedSecret: 'aa'.repeat(32),
      theirSignature: 'bb'.repeat(65),
    })).toString('base64url');

    await service.recordCompletedIncomingPayment({
      paymentProof: proof,
      secret: 'cc'.repeat(32),
    });

    const row = db.prepare(`
      SELECT server_balance, counterparty_balance, nonce, tap_status, enforceable_secret
      FROM reservoir_pipes
      WHERE pipe_id = ?
    `).get(pipeId(contractId, principals['principal-1'], principals['principal-2'])) as Record<string, unknown>;

    expect(row.server_balance).toBe('1500');
    expect(row.counterparty_balance).toBe('8500');
    expect(row.nonce).toBe('3');
    expect(row.tap_status).toBe('active');
    expect(row.enforceable_secret).toBe('cc'.repeat(32));
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
      settings: makeSettingsStore(db),
      serverAddress,
      serverPrivateKey: serverPriv,
      contractId,
      chainId: 1,
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
      settings: makeSettingsStore(db),
      serverAddress: reservoirContractId,
      signerAddress,
      reservoirContractId,
      serverPrivateKey: serverPriv,
      contractId,
      chainId: 1,
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
      settings: makeSettingsStore(db),
      serverAddress,
      serverPrivateKey: serverPriv,
      contractId,
      chainId: 1,
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
      FROM reservoir_pending_states WHERE pipe_id = ?
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
      settings: makeSettingsStore(db),
      serverAddress,
      serverPrivateKey: serverPriv,
      contractId,
      chainId: 1,
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
      settings: makeSettingsStore(db),
      serverAddress,
      serverPrivateKey: serverPriv,
      contractId,
      chainId: 1,
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

  it('creates refresh-liquidity params from the latest tracked pipe state', async () => {
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
      settings: makeSettingsStore(db),
      serverAddress: reservoirContractId,
      signerAddress,
      reservoirContractId,
      serverPrivateKey: serverPriv,
      contractId,
      chainId: 1,
    });

    const principals = canonicalPipePrincipals(borrowerAddress, reservoirContractId);
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
      '6000',
      '14000',
      '8',
    );

    vi.stubGlobal('fetch', vi.fn(async () => ({
      ok: true,
      json: async () => ({ okay: true, result: '0x0100000000000000000000000000000000' }),
    })) as unknown as typeof fetch);

    const refreshState: TransferState = {
      pipeKey: {
        'principal-1': principals['principal-1'],
        'principal-2': principals['principal-2'],
        token: null,
      },
      forPrincipal: borrowerAddress,
      myBalance: '14000',
      theirBalance: '10000',
      nonce: '9',
      action: '2',
      actor: reservoirContractId,
      hashedSecret: null,
      validAfter: null,
    };
    const borrowerSig = await sip018Sign(contractId, buildTransferMessage(refreshState), borrowerPriv, 1);

    const result = await service.createBorrowLiquidityParams({
      borrower: borrowerAddress,
      token: null,
      borrowAmount: '4000',
      myBalance: '14000',
      reservoirBalance: '10000',
      borrowNonce: '9',
      mySignature: borrowerSig,
    });

    expect(result.borrowFee).toBe('0');
    expect(typeof result.reservoirSignature).toBe('string');
  });

  it('recovers a missing tracked tap from on-chain state before creating refresh params', async () => {
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
      settings: makeSettingsStore(db),
      serverAddress: reservoirContractId,
      signerAddress,
      reservoirContractId,
      serverPrivateKey: serverPriv,
      contractId,
      chainId: 1,
    });

    const principals = canonicalPipePrincipals(borrowerAddress, reservoirContractId);
    vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.includes('/v2/info')) {
        return {
          ok: true,
          json: async () => ({ burn_block_height: 999 }),
        } as Response;
      }
      if (url.includes('/get-borrow-fee')) {
        return {
          ok: true,
          json: async () => ({ okay: true, result: '0x0100000000000000000000000000000000' }),
        } as Response;
      }
      return {
        ok: true,
        json: async () => ({ okay: true, result: encodeSomePipe({
          balance1: principals['principal-1'] === reservoirContractId ? 6000n : 14000n,
          balance2: principals['principal-1'] === reservoirContractId ? 14000n : 6000n,
          nonce: 8n,
        }) }),
      } as Response;
    }) as unknown as typeof fetch);

    const refreshState: TransferState = {
      pipeKey: {
        'principal-1': principals['principal-1'],
        'principal-2': principals['principal-2'],
        token: null,
      },
      forPrincipal: borrowerAddress,
      myBalance: '14000',
      theirBalance: '10000',
      nonce: '9',
      action: '2',
      actor: reservoirContractId,
      hashedSecret: null,
      validAfter: null,
    };
    const borrowerSig = await sip018Sign(contractId, buildTransferMessage(refreshState), borrowerPriv, 1);

    const result = await service.createBorrowLiquidityParams({
      borrower: borrowerAddress,
      token: null,
      borrowAmount: '4000',
      myBalance: '14000',
      reservoirBalance: '10000',
      borrowNonce: '9',
      mySignature: borrowerSig,
    });

    expect(result.borrowFee).toBe('0');
    expect(typeof result.reservoirSignature).toBe('string');

    const recovered = await service.getTrackedTapState(borrowerAddress);
    expect(recovered?.serverBalance).toBe('6000');
    expect(recovered?.counterpartyBalance).toBe('14000');
    expect(recovered?.nonce).toBe('8');
  });

  it('creates add-funds params from the latest optimistic tap state', async () => {
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
      settings: makeSettingsStore(db),
      serverAddress: reservoirContractId,
      signerAddress,
      reservoirContractId,
      serverPrivateKey: serverPriv,
      contractId,
      chainId: 1,
    });

    const principals = canonicalPipePrincipals(borrowerAddress, reservoirContractId);
    const currentPipeId = pipeId(contractId, principals['principal-1'], principals['principal-2']);
    const pipeKey = {
      'principal-1': principals['principal-1'],
      'principal-2': principals['principal-2'],
      token: null,
    };
    db.prepare(`
      INSERT INTO reservoir_pipes (
        pipe_id, contract_id, pipe_key_json, server_balance, counterparty_balance, nonce, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, unixepoch('now') * 1000)
    `).run(
      currentPipeId,
      contractId,
      JSON.stringify(pipeKey),
      '29000',
      '2500',
      '19',
    );
    db.prepare(`
      INSERT INTO reservoir_pending_states (
        pipe_id, nonce, contract_id, pipe_key_json, server_balance, counterparty_balance, action, actor, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, unixepoch('now') * 1000)
    `).run(
      currentPipeId,
      '21',
      contractId,
      JSON.stringify(pipeKey),
      '31000',
      '500',
      '1',
      borrowerAddress,
    );

    vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.includes('/v2/info')) {
        return {
          ok: true,
          json: async () => ({ burn_block_height: 999 }),
        } as Response;
      }
      return {
        ok: true,
        json: async () => ({ okay: true, result: encodeSomePipe({
          balance1: principals['principal-1'] === reservoirContractId ? 29000n : 2500n,
          balance2: principals['principal-1'] === reservoirContractId ? 2500n : 29000n,
          nonce: 19n,
        }) }),
      } as Response;
    }) as unknown as typeof fetch);

    const depositState: TransferState = {
      pipeKey,
      forPrincipal: borrowerAddress,
      myBalance: '2000',
      theirBalance: '31000',
      nonce: '22',
      action: '2',
      actor: borrowerAddress,
      hashedSecret: null,
      validAfter: null,
    };
    const borrowerSig = await sip018Sign(contractId, buildTransferMessage(depositState), borrowerPriv, 1);

    const result = await service.createAddFundsParams({
      user: borrowerAddress,
      token: null,
      amount: '1500',
      myBalance: '2000',
      reservoirBalance: '31000',
      nonce: '22',
      mySignature: borrowerSig,
    });

    expect(typeof result.reservoirSignature).toBe('string');
  });

  it('creates withdraw params from the current on-chain tap and advances the tracked nonce', async () => {
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
      settings: makeSettingsStore(db),
      serverAddress: reservoirContractId,
      signerAddress,
      reservoirContractId,
      serverPrivateKey: serverPriv,
      contractId,
      chainId: 1,
    });

    const principals = canonicalPipePrincipals(borrowerAddress, reservoirContractId);
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
      '10000',
      '14000',
      '8',
    );

    vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.includes('/v2/info')) {
        return {
          ok: true,
          json: async () => ({ burn_block_height: 999 }),
        } as Response;
      }
      return {
        ok: true,
        json: async () => ({ okay: true, result: encodeSomePipe({
          balance1: principals['principal-1'] === reservoirContractId ? 10000n : 14000n,
          balance2: principals['principal-1'] === reservoirContractId ? 14000n : 10000n,
          nonce: 8n,
        }) }),
      } as Response;
    }) as unknown as typeof fetch);

    const withdrawState: TransferState = {
      pipeKey: {
        'principal-1': principals['principal-1'],
        'principal-2': principals['principal-2'],
        token: null,
      },
      forPrincipal: borrowerAddress,
      myBalance: '14000',
      theirBalance: '9000',
      nonce: '9',
      action: '3',
      actor: borrowerAddress,
      hashedSecret: null,
      validAfter: null,
    };
    const borrowerSig = await sip018Sign(contractId, buildTransferMessage(withdrawState), borrowerPriv, 1);

    const result = await service.createWithdrawFundsParams({
      user: borrowerAddress,
      token: null,
      amount: '1000',
      myBalance: '14000',
      reservoirBalance: '9000',
      nonce: '9',
      mySignature: borrowerSig,
    });

    expect(typeof result.reservoirSignature).toBe('string');

    const latest = await service.getTrackedTapState(borrowerAddress);
    expect(latest?.nonce).toBe('9');
    expect(latest?.counterpartyBalance).toBe('14000');
    expect(latest?.serverBalance).toBe('9000');

    const pendingAction = db.prepare(`
      SELECT action, amount, nonce, counterparty_balance, server_balance
      FROM reservoir_pending_tap_actions
      WHERE pipe_id = ?
    `).get(pipeId(contractId, principals['principal-1'], principals['principal-2'])) as Record<string, unknown>;
    expect(pendingAction.action).toBe('3');
    expect(pendingAction.amount).toBe('1000');
    expect(pendingAction.nonce).toBe('9');
    expect(pendingAction.counterparty_balance).toBe('14000');
    expect(pendingAction.server_balance).toBe('9000');
  });

  it('returns a rebalance request when receive liquidity is above the configured target', async () => {
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
      settings: makeSettingsStore(db),
      serverAddress: reservoirContractId,
      signerAddress,
      reservoirContractId,
      serverPrivateKey: serverPriv,
      contractId,
      chainId: 1,
    });

    const principals = canonicalPipePrincipals(borrowerAddress, reservoirContractId);
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
      '16000',
      '14000',
      '8',
    );

    vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.includes('/v2/info')) {
        return { ok: true, json: async () => ({ burn_block_height: 999 }) } as Response;
      }
      return {
        ok: true,
        json: async () => ({ okay: true, result: encodeSomePipe({
          balance1: principals['principal-1'] === reservoirContractId ? 16000n : 14000n,
          balance2: principals['principal-1'] === reservoirContractId ? 14000n : 16000n,
          nonce: 8n,
        }) }),
      } as Response;
    }) as unknown as typeof fetch);

    const rebalance = await service.getTapRebalanceRequest(borrowerAddress);
    expect(rebalance).toEqual({
      token: null,
      amount: '6000',
      myBalance: '14000',
      reservoirBalance: '10000',
      nonce: '9',
    });
  });

  it('does not request a rebalance until receive liquidity reaches the configured threshold', async () => {
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
      settings: makeSettingsStore(db),
      serverAddress: reservoirContractId,
      signerAddress,
      reservoirContractId,
      serverPrivateKey: serverPriv,
      contractId,
      chainId: 1,
    });

    const principals = canonicalPipePrincipals(borrowerAddress, reservoirContractId);
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
      '14000',
      '14000',
      '8',
    );

    vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.includes('/v2/info')) {
        return { ok: true, json: async () => ({ burn_block_height: 999 }) } as Response;
      }
      return {
        ok: true,
        json: async () => ({ okay: true, result: encodeSomePipe({
          balance1: principals['principal-1'] === reservoirContractId ? 14000n : 14000n,
          balance2: principals['principal-1'] === reservoirContractId ? 14000n : 14000n,
          nonce: 8n,
        }) }),
      } as Response;
    }) as unknown as typeof fetch);

    const rebalance = await service.getTapRebalanceRequest(borrowerAddress);
    expect(rebalance).toBeNull();
  });

  it('returns a rebalance request from the latest optimistic tap state once the threshold is crossed', async () => {
    const { default: Database } = await import('better-sqlite3');
    const db = new Database(':memory:');
    const serverPriv = privKeyHex();
    const borrowerPriv = privKeyHex();
    const signerAddress = stxAddressFromPrivkey(serverPriv);
    const borrowerAddress = stxAddressFromPrivkey(borrowerPriv);
    const reservoirContractId = `${signerAddress}.sm-reservoir`;
    const contractId = `${signerAddress}.sm-stackflow`;
    const settings = new RuntimeSettingsStore(db, runtimeSettingsFromConfig({
      messagePriceSats: '1000',
      minFeeSats: '100',
      maxPendingPerSender: 5,
      maxPendingPerRecipient: 20,
      maxDeferredPerSender: 5,
      maxDeferredPerRecipient: 20,
      maxDeferredGlobal: 200,
      deferredMessageTtlMs: 86_400_000,
      maxBorrowPerTap: '100000',
      receiveCapacityMultiplier: 10,
      rebalanceThresholdPct: 150,
      refreshCapacityCooldownMs: 86_400_000,
    }));
    const service = new ReservoirService({
      db,
      settings,
      serverAddress: reservoirContractId,
      signerAddress,
      reservoirContractId,
      serverPrivateKey: serverPriv,
      contractId,
      chainId: 1,
    });

    const principals = canonicalPipePrincipals(borrowerAddress, reservoirContractId);
    const pendingPipeId = pipeId(contractId, principals['principal-1'], principals['principal-2']);
    const pipeKeyJson = JSON.stringify({
      'principal-1': principals['principal-1'],
      'principal-2': principals['principal-2'],
      token: null,
    });
    db.prepare(`
      INSERT INTO reservoir_pipes (
        pipe_id, contract_id, pipe_key_json, server_balance, counterparty_balance, nonce, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, unixepoch('now') * 1000)
    `).run(
      pendingPipeId,
      contractId,
      pipeKeyJson,
      '14000',
      '20000',
      '8',
    );
    db.prepare(`
      INSERT INTO reservoir_pending_states (
        pipe_id, nonce, contract_id, pipe_key_json, server_balance, counterparty_balance, action, actor, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, unixepoch('now') * 1000)
    `).run(
      pendingPipeId,
      '10',
      contractId,
      pipeKeyJson,
      '16000',
      '18000',
      '1',
      borrowerAddress,
    );

    vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.includes('/v2/info')) {
        return { ok: true, json: async () => ({ burn_block_height: 999 }) } as Response;
      }
      return {
        ok: true,
        json: async () => ({ okay: true, result: encodeSomePipe({
          balance1: principals['principal-1'] === reservoirContractId ? 14000n : 20000n,
          balance2: principals['principal-1'] === reservoirContractId ? 20000n : 14000n,
          nonce: 8n,
        }) }),
      } as Response;
    }) as unknown as typeof fetch);

    const rebalance = await service.getTapRebalanceRequest(borrowerAddress);
    expect(rebalance).toEqual({
      token: null,
      amount: '6000',
      myBalance: '18000',
      reservoirBalance: '10000',
      nonce: '11',
    });
  });

  it('accepts a rebalance withdraw signature from the latest optimistic tap state', async () => {
    const { default: Database } = await import('better-sqlite3');
    const db = new Database(':memory:');
    const serverPriv = privKeyHex();
    const borrowerPriv = privKeyHex();
    const signerAddress = stxAddressFromPrivkey(serverPriv);
    const borrowerAddress = stxAddressFromPrivkey(borrowerPriv);
    const reservoirContractId = `${signerAddress}.sm-reservoir`;
    const contractId = `${signerAddress}.sm-stackflow`;
    const settings = new RuntimeSettingsStore(db, runtimeSettingsFromConfig({
      messagePriceSats: '1000',
      minFeeSats: '100',
      maxPendingPerSender: 5,
      maxPendingPerRecipient: 20,
      maxDeferredPerSender: 5,
      maxDeferredPerRecipient: 20,
      maxDeferredGlobal: 200,
      deferredMessageTtlMs: 86_400_000,
      maxBorrowPerTap: '100000',
      receiveCapacityMultiplier: 10,
      rebalanceThresholdPct: 150,
      refreshCapacityCooldownMs: 86_400_000,
    }));
    const service = new ReservoirService({
      db,
      settings,
      serverAddress: reservoirContractId,
      signerAddress,
      reservoirContractId,
      serverPrivateKey: serverPriv,
      contractId,
      chainId: 1,
    });

    const principals = canonicalPipePrincipals(borrowerAddress, reservoirContractId);
    const pendingPipeId = pipeId(contractId, principals['principal-1'], principals['principal-2']);
    const pipeKey = {
      'principal-1': principals['principal-1'],
      'principal-2': principals['principal-2'],
      token: null,
    };
    db.prepare(`
      INSERT INTO reservoir_pipes (
        pipe_id, contract_id, pipe_key_json, server_balance, counterparty_balance, nonce, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, unixepoch('now') * 1000)
    `).run(
      pendingPipeId,
      contractId,
      JSON.stringify(pipeKey),
      '14000',
      '20000',
      '8',
    );
    db.prepare(`
      INSERT INTO reservoir_pending_states (
        pipe_id, nonce, contract_id, pipe_key_json, server_balance, counterparty_balance, action, actor, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, unixepoch('now') * 1000)
    `).run(
      pendingPipeId,
      '10',
      contractId,
      JSON.stringify(pipeKey),
      '16000',
      '18000',
      '1',
      borrowerAddress,
    );

    vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.includes('/v2/info')) {
        return { ok: true, json: async () => ({ burn_block_height: 999 }) } as Response;
      }
      return {
        ok: true,
        json: async () => ({ okay: true, result: encodeSomePipe({
          balance1: principals['principal-1'] === reservoirContractId ? 14000n : 20000n,
          balance2: principals['principal-1'] === reservoirContractId ? 20000n : 14000n,
          nonce: 8n,
        }) }),
      } as Response;
    }) as unknown as typeof fetch);

    const withdrawState: TransferState = {
      pipeKey,
      forPrincipal: borrowerAddress,
      myBalance: '18000',
      theirBalance: '10000',
      nonce: '11',
      action: '3',
      actor: borrowerAddress,
      hashedSecret: null,
      validAfter: null,
    };
    const borrowerSig = await sip018Sign(contractId, buildTransferMessage(withdrawState), borrowerPriv, 1);

    const result = await service.createWithdrawFundsParams({
      user: borrowerAddress,
      token: null,
      amount: '6000',
      myBalance: '18000',
      reservoirBalance: '10000',
      nonce: '11',
      mySignature: borrowerSig,
    });

    expect(typeof result.reservoirSignature).toBe('string');

    const latest = await service.getTrackedTapState(borrowerAddress);
    expect(latest?.nonce).toBe('11');
    expect(latest?.counterpartyBalance).toBe('18000');
    expect(latest?.serverBalance).toBe('10000');
  });

  it('rejects withdraw signatures with incorrect balances', async () => {
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
      settings: makeSettingsStore(db),
      serverAddress: reservoirContractId,
      signerAddress,
      reservoirContractId,
      serverPrivateKey: serverPriv,
      contractId,
      chainId: 1,
    });

    const principals = canonicalPipePrincipals(borrowerAddress, reservoirContractId);
    vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.includes('/v2/info')) {
        return { ok: true, json: async () => ({ burn_block_height: 999 }) } as Response;
      }
      return {
        ok: true,
        json: async () => ({ okay: true, result: encodeSomePipe({
          balance1: principals['principal-1'] === reservoirContractId ? 10000n : 14000n,
          balance2: principals['principal-1'] === reservoirContractId ? 14000n : 10000n,
          nonce: 8n,
        }) }),
      } as Response;
    }) as unknown as typeof fetch);

    const invalidState: TransferState = {
      pipeKey: {
        'principal-1': principals['principal-1'],
        'principal-2': principals['principal-2'],
        token: null,
      },
      forPrincipal: borrowerAddress,
      myBalance: '13500',
      theirBalance: '9500',
      nonce: '9',
      action: '3',
      actor: borrowerAddress,
      hashedSecret: null,
      validAfter: null,
    };
    const borrowerSig = await sip018Sign(contractId, buildTransferMessage(invalidState), borrowerPriv, 1);

    await expect(service.createWithdrawFundsParams({
      user: borrowerAddress,
      token: null,
      amount: '1000',
      myBalance: '13500',
      reservoirBalance: '9500',
      nonce: '9',
      mySignature: borrowerSig,
    })).rejects.toMatchObject({
      reason: 'invalid-my-balance',
    });
  });

  it('syncs a close action into a closed tap record and preserves reopen nonces', async () => {
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
      settings: makeSettingsStore(db),
      serverAddress: reservoirContractId,
      signerAddress,
      reservoirContractId,
      serverPrivateKey: serverPriv,
      contractId,
      chainId: 1,
    });

    const principals = canonicalPipePrincipals(borrowerAddress, reservoirContractId);
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
      '10000',
      '14000',
      '8',
    );

    let callCount = 0;
    vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.includes('/v2/info')) {
        return {
          ok: true,
          json: async () => ({ burn_block_height: 999 }),
        } as Response;
      }
      callCount += 1;
      if (callCount === 1) {
        return {
          ok: true,
          json: async () => ({ okay: true, result: encodeSomePipe({
            balance1: principals['principal-1'] === reservoirContractId ? 10000n : 14000n,
            balance2: principals['principal-1'] === reservoirContractId ? 14000n : 10000n,
            nonce: 8n,
          }) }),
        } as Response;
      }
      return {
        ok: true,
        json: async () => ({ okay: true, result: encodeSomePipe({
          balance1: 0n,
          balance2: 0n,
          nonce: 9n,
        }) }),
      } as Response;
    }) as unknown as typeof fetch);

    const closeState: TransferState = {
      pipeKey: {
        'principal-1': principals['principal-1'],
        'principal-2': principals['principal-2'],
        token: null,
      },
      forPrincipal: borrowerAddress,
      myBalance: '14000',
      theirBalance: '10000',
      nonce: '9',
      action: '0',
      actor: borrowerAddress,
      hashedSecret: null,
      validAfter: null,
    };
    const borrowerSig = await sip018Sign(contractId, buildTransferMessage(closeState), borrowerPriv, 1);
    const signed = await service.createCloseTapParams({
      user: borrowerAddress,
      token: null,
      myBalance: '14000',
      reservoirBalance: '10000',
      nonce: '9',
      mySignature: borrowerSig,
    });

    await service.syncTapState({
      counterparty: borrowerAddress,
      token: null,
      userBalance: '14000',
      reservoirBalance: '10000',
      nonce: '9',
      action: '0',
      actor: borrowerAddress,
      counterpartySignature: borrowerSig,
      serverSignature: signed.reservoirSignature,
    });

    const row = db.prepare('SELECT server_balance, counterparty_balance, nonce, tap_status FROM reservoir_pipes WHERE pipe_id = ?')
      .get(pipeId(contractId, principals['principal-1'], principals['principal-2'])) as Record<string, unknown>;
    expect(row.server_balance).toBe('0');
    expect(row.counterparty_balance).toBe('0');
    expect(row.nonce).toBe('9');
    expect(row.tap_status).toBe('closed');

    const lifecycle = await service.getTapLifecycleState(borrowerAddress);
    expect(lifecycle.status).toBe('closed');
    expect(lifecycle.nextTapNonce).toBe('9');
    expect(lifecycle.nextBorrowNonce).toBe('10');
  });

  it('requires reopened taps to continue from the previous closed nonce', async () => {
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
      settings: makeSettingsStore(db),
      serverAddress: reservoirContractId,
      signerAddress,
      reservoirContractId,
      serverPrivateKey: serverPriv,
      contractId,
      chainId: 1,
    });

    const principals = canonicalPipePrincipals(borrowerAddress, reservoirContractId);
    db.prepare(`
      INSERT INTO reservoir_pipes (
        pipe_id, contract_id, pipe_key_json, server_balance, counterparty_balance, nonce, tap_status, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, unixepoch('now') * 1000)
    `).run(
      pipeId(contractId, principals['principal-1'], principals['principal-2']),
      contractId,
      JSON.stringify({
        'principal-1': principals['principal-1'],
        'principal-2': principals['principal-2'],
        token: null,
      }),
      '0',
      '0',
      '9',
      'closed',
    );

    vi.stubGlobal('fetch', vi.fn(async () => ({
      ok: true,
      json: async () => ({ okay: true, result: '0x0100000000000000000000000000000000' }),
    })) as unknown as typeof fetch);

    const reopenState: TransferState = {
      pipeKey: {
        'principal-1': principals['principal-1'],
        'principal-2': principals['principal-2'],
        token: null,
      },
      forPrincipal: borrowerAddress,
      myBalance: '10000',
      theirBalance: '10000',
      nonce: '10',
      action: '2',
      actor: reservoirContractId,
      hashedSecret: null,
      validAfter: null,
    };
    const borrowerSig = await sip018Sign(contractId, buildTransferMessage(reopenState), borrowerPriv, 1);

    await expect(service.createTapWithBorrowedLiquidityParams({
      borrower: borrowerAddress,
      token: null,
      tapAmount: '10000',
      tapNonce: '0',
      borrowAmount: '10000',
      myBalance: '10000',
      reservoirBalance: '10000',
      borrowNonce: '1',
      mySignature: borrowerSig,
    })).rejects.toMatchObject({
      reason: 'invalid-tap-nonce',
    });

    const result = await service.createTapWithBorrowedLiquidityParams({
      borrower: borrowerAddress,
      token: null,
      tapAmount: '10000',
      tapNonce: '9',
      borrowAmount: '10000',
      myBalance: '10000',
      reservoirBalance: '10000',
      borrowNonce: '10',
      mySignature: borrowerSig,
    });
    expect(typeof result.reservoirSignature).toBe('string');
  });

  it('rate-limits refresh signing per borrower during the cooldown window', async () => {
    const { default: Database } = await import('better-sqlite3');
    const db = new Database(':memory:');
    const serverPriv = privKeyHex();
    const borrowerPriv = privKeyHex();
    const signerAddress = stxAddressFromPrivkey(serverPriv);
    const borrowerAddress = stxAddressFromPrivkey(borrowerPriv);
    const reservoirContractId = `${signerAddress}.sm-reservoir`;
    const contractId = `${signerAddress}.sm-stackflow`;
    const settings = new RuntimeSettingsStore(db, runtimeSettingsFromConfig({
      messagePriceSats: '500',
      minFeeSats: '100',
      maxPendingPerSender: 5,
      maxPendingPerRecipient: 20,
      maxDeferredPerSender: 5,
      maxDeferredPerRecipient: 20,
      maxDeferredGlobal: 200,
      deferredMessageTtlMs: 86_400_000,
      maxBorrowPerTap: '100000',
      receiveCapacityMultiplier: 20,
      rebalanceThresholdPct: 150,
      refreshCapacityCooldownMs: 86_400_000,
    }));
    const service = new ReservoirService({
      db,
      settings,
      serverAddress: reservoirContractId,
      signerAddress,
      reservoirContractId,
      serverPrivateKey: serverPriv,
      contractId,
      chainId: 1,
    });

    const principals = canonicalPipePrincipals(borrowerAddress, reservoirContractId);
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
      '6000',
      '14000',
      '8',
    );

    vi.stubGlobal('fetch', vi.fn(async () => ({
      ok: true,
      json: async () => ({ okay: true, result: '0x0100000000000000000000000000000000' }),
    })) as unknown as typeof fetch);

    const refreshState: TransferState = {
      pipeKey: {
        'principal-1': principals['principal-1'],
        'principal-2': principals['principal-2'],
        token: null,
      },
      forPrincipal: borrowerAddress,
      myBalance: '14000',
      theirBalance: '10000',
      nonce: '9',
      action: '2',
      actor: reservoirContractId,
      hashedSecret: null,
      validAfter: null,
    };
    const borrowerSig = await sip018Sign(contractId, buildTransferMessage(refreshState), borrowerPriv, 1);
    const nowSpy = vi.spyOn(Date, 'now').mockReturnValue(1_710_000_000_000);

    await expect(service.createBorrowLiquidityParams({
      borrower: borrowerAddress,
      token: null,
      borrowAmount: '4000',
      myBalance: '14000',
      reservoirBalance: '10000',
      borrowNonce: '9',
      mySignature: borrowerSig,
    })).resolves.toMatchObject({
      borrowFee: '0',
    });

    await expect(service.createBorrowLiquidityParams({
      borrower: borrowerAddress,
      token: null,
      borrowAmount: '4000',
      myBalance: '14000',
      reservoirBalance: '10000',
      borrowNonce: '9',
      mySignature: borrowerSig,
    })).rejects.toMatchObject({
      reason: 'refresh-cooldown-active',
      statusCode: 429,
    });

    nowSpy.mockRestore();
  });

  it('refuses to sign a refresh when receive liquidity is already above the default target', async () => {
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
      settings: makeSettingsStore(db),
      serverAddress: reservoirContractId,
      signerAddress,
      reservoirContractId,
      serverPrivateKey: serverPriv,
      contractId,
      chainId: 1,
    });

    const principals = canonicalPipePrincipals(borrowerAddress, reservoirContractId);
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
      '11000',
      '9000',
      '8',
    );

    const refreshState: TransferState = {
      pipeKey: {
        'principal-1': principals['principal-1'],
        'principal-2': principals['principal-2'],
        token: null,
      },
      forPrincipal: borrowerAddress,
      myBalance: '9000',
      theirBalance: '12000',
      nonce: '9',
      action: '2',
      actor: reservoirContractId,
      hashedSecret: null,
      validAfter: null,
    };
    const borrowerSig = await sip018Sign(contractId, buildTransferMessage(refreshState), borrowerPriv, 1);

    await expect(service.createBorrowLiquidityParams({
      borrower: borrowerAddress,
      token: null,
      borrowAmount: '1000',
      myBalance: '9000',
      reservoirBalance: '12000',
      borrowNonce: '9',
      mySignature: borrowerSig,
    })).rejects.toMatchObject({
      reason: 'capacity-already-sufficient',
    });
  });
});
