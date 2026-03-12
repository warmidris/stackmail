#!/usr/bin/env node

import fs from 'node:fs';
import { createRequire } from 'node:module';
import { execFileSync } from 'node:child_process';

import { createNetwork } from '@stacks/network';
import {
  AnchorMode,
  PostConditionMode,
  broadcastTransaction,
  bufferCV,
  cvToValue,
  fetchNonce,
  getAddressFromPrivateKey,
  hexToCV,
  makeContractCall,
  principalCV,
  serializeCVBytes,
  someCV,
  uintCV,
} from '@stacks/transactions';

const require = createRequire(import.meta.url);
const { generateWallet } = require('/Users/brice/obybot/work/stackflow/node_modules/@stacks/wallet-sdk/dist/index.js');
const { buildTransferMessage, sip018Sign } =
  await import('/Users/brice/obybot/work/stackmail/packages/server/dist/sip018.js');

const CONFIG = {
  api: 'https://api.mainnet.hiro.so',
  network: 'mainnet',
  contractAddress: 'SP3QFYVTMS0PRJT3K3GMDW9DGR33TDHENSDWVNQMR',
  reservoirContractName: 'sm-reservoir',
  stackflowContractId: 'SP3QFYVTMS0PRJT3K3GMDW9DGR33TDHENSDWVNQMR.sm-stackflow',
  tokenContractId: 'SP3QFYVTMS0PRJT3K3GMDW9DGR33TDHENSDWVNQMR.sm-test-token',
  borrowAmount: 10_000n,
  mnemonicPath: '/Users/brice/obybot/identity/aibtc/mnemonic.txt',
  dbPath: '/Users/brice/obybot/work/stackmail/data/stackmail.db',
};

const network = createNetwork({
  network: CONFIG.network,
  client: { baseUrl: CONFIG.api },
});

function hexArg(cv) {
  return '0x' + Buffer.from(serializeCVBytes(cv)).toString('hex');
}

function readMetaValue(key) {
  return execFileSync('sqlite3', ['-readonly', CONFIG.dbPath, `select value from meta where key='${key}';`], {
    encoding: 'utf8',
  }).trim();
}

async function broadcastAndWait(transaction, label) {
  const result = await broadcastTransaction({ transaction, network });
  if ('reason' in result) {
    throw new Error(`${label}: broadcast failed (${result.reason || 'unknown'})`);
  }
  console.log(`[repair] ${label}: broadcast ${result.txid}`);
  for (;;) {
    const resp = await fetch(`${CONFIG.api}/extended/v1/tx/0x${result.txid}`);
    const payload = await resp.json();
    if (payload.tx_status === 'success') {
      console.log(`[repair] ${label}: confirmed ${result.txid}`);
      return result.txid;
    }
    if (payload.tx_status && payload.tx_status !== 'pending') {
      throw new Error(`${label}: failed (${payload.tx_status})`);
    }
    await new Promise((resolve) => setTimeout(resolve, 5000));
  }
}

async function getWallet() {
  const mnemonic = fs.readFileSync(CONFIG.mnemonicPath, 'utf8').trim();
  const wallet = await generateWallet({ secretKey: mnemonic, password: '' });
  const txKey = wallet.accounts[0].stxPrivateKey;
  const signKey = txKey.replace(/01$/, '');
  const address = getAddressFromPrivateKey(txKey, CONFIG.network);
  return { txKey, signKey, address };
}

async function readPipeState(owner, reservoirContractId) {
  const resp = await fetch(`${CONFIG.api}/v2/contracts/call-read/${CONFIG.contractAddress}/sm-stackflow/get-pipe`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      sender: owner,
      arguments: [
        hexArg(someCV(principalCV(CONFIG.tokenContractId))),
        hexArg(principalCV(reservoirContractId)),
      ],
    }),
  });
  if (!resp.ok) {
    throw new Error(`get-pipe failed (${resp.status})`);
  }
  const payload = await resp.json();
  if (!payload.okay || typeof payload.result !== 'string') {
    throw new Error('get-pipe read-only call failed');
  }
  return cvToValue(hexToCV(payload.result));
}

async function getBorrowFee(owner, reservoirContractId) {
  const [addr, name] = reservoirContractId.split('.');
  const resp = await fetch(`${CONFIG.api}/v2/contracts/call-read/${addr}/${name}/get-borrow-fee`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      sender: owner,
      arguments: [hexArg(uintCV(CONFIG.borrowAmount))],
    }),
  });
  if (!resp.ok) {
    throw new Error(`get-borrow-fee failed (${resp.status})`);
  }
  const payload = await resp.json();
  if (!payload.okay || typeof payload.result !== 'string') {
    throw new Error('get-borrow-fee read-only call failed');
  }
  const value = cvToValue(hexToCV(payload.result));
  return BigInt(value.value ?? value);
}

async function main() {
  const { txKey, signKey, address } = await getWallet();
  const serverSignerAddress = readMetaValue('server_stx_address');
  const serverSignerKey = readMetaValue('server_private_key');
  const reservoirContractId = `${CONFIG.contractAddress}.${CONFIG.reservoirContractName}`;

  let nonce = await fetchNonce({
    address,
    network: CONFIG.network,
    client: { baseUrl: CONFIG.api },
  });

  const setAgentTx = await makeContractCall({
    network,
    senderKey: txKey,
    contractAddress: CONFIG.contractAddress,
    contractName: CONFIG.reservoirContractName,
    functionName: 'set-agent',
    functionArgs: [
      principalCV(CONFIG.stackflowContractId),
      principalCV(serverSignerAddress),
    ],
    nonce,
    anchorMode: AnchorMode.Any,
    postConditionMode: PostConditionMode.Allow,
    validateWithAbi: false,
  });
  const setAgentTxid = await broadcastAndWait(setAgentTx, 'set-agent');
  nonce += 1n;

  const pipe = await readPipeState(address, reservoirContractId);
  const pipeValue = (pipe && typeof pipe === 'object' && 'value' in pipe) ? pipe.value : null;
  const userBalance = BigInt(pipeValue?.['balance-1']?.value ?? '0');
  const pipeNonce = BigInt(pipeValue?.nonce?.value ?? '0');
  if (userBalance <= 0n) {
    throw new Error(`unexpected user balance: ${userBalance}`);
  }
  if (pipeNonce !== 0n) {
    throw new Error(`expected nonce 0 before first borrow, got ${pipeNonce}`);
  }

  const borrowFee = await getBorrowFee(address, reservoirContractId);
  const pipeKey = {
    'principal-1': address,
    'principal-2': reservoirContractId,
    token: CONFIG.tokenContractId,
  };
  const borrowNonce = pipeNonce + 1n;

  const userMessage = buildTransferMessage({
    pipeKey,
    forPrincipal: address,
    myBalance: userBalance.toString(),
    theirBalance: CONFIG.borrowAmount.toString(),
    nonce: borrowNonce.toString(),
    action: '2',
    actor: reservoirContractId,
    hashedSecret: null,
    validAfter: null,
  });
  const reservoirMessage = buildTransferMessage({
    pipeKey,
    forPrincipal: reservoirContractId,
    myBalance: CONFIG.borrowAmount.toString(),
    theirBalance: userBalance.toString(),
    nonce: borrowNonce.toString(),
    action: '2',
    actor: reservoirContractId,
    hashedSecret: null,
    validAfter: null,
  });

  const userSignature = await sip018Sign(CONFIG.stackflowContractId, userMessage, signKey, 1);
  const reservoirSignature = await sip018Sign(CONFIG.stackflowContractId, reservoirMessage, serverSignerKey, 1);

  const borrowTx = await makeContractCall({
    network,
    senderKey: txKey,
    contractAddress: CONFIG.contractAddress,
    contractName: CONFIG.reservoirContractName,
    functionName: 'borrow-liquidity',
    functionArgs: [
      principalCV(CONFIG.stackflowContractId),
      uintCV(CONFIG.borrowAmount),
      uintCV(borrowFee),
      someCV(principalCV(CONFIG.tokenContractId)),
      uintCV(userBalance),
      uintCV(CONFIG.borrowAmount),
      bufferCV(Buffer.from(userSignature.replace(/^0x/, ''), 'hex')),
      bufferCV(Buffer.from(reservoirSignature.replace(/^0x/, ''), 'hex')),
      uintCV(borrowNonce),
    ],
    nonce,
    anchorMode: AnchorMode.Any,
    postConditionMode: PostConditionMode.Allow,
    validateWithAbi: false,
  });
  const borrowTxid = await broadcastAndWait(borrowTx, 'borrow-liquidity');

  console.log(JSON.stringify({
    address,
    signerAddress: serverSignerAddress,
    reservoirContractId,
    stackflowContractId: CONFIG.stackflowContractId,
    borrowAmount: CONFIG.borrowAmount.toString(),
    borrowFee: borrowFee.toString(),
    txids: {
      setAgentTxid,
      borrowTxid,
    },
  }, null, 2));
}

main().catch((error) => {
  console.error('[repair] fatal:', error);
  process.exit(1);
});
