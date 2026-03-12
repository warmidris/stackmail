#!/usr/bin/env node

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFileSync } from 'node:child_process';
import { createRequire } from 'node:module';

import {
  AnchorMode,
  PostConditionMode,
  broadcastTransaction,
  bufferCV,
  ClarityVersion,
  fetchNonce,
  getAddressFromPrivateKey,
  hexToCV,
  makeContractCall,
  makeContractDeploy,
  noneCV,
  principalCV,
  serializeCVBytes,
  someCV,
  uintCV,
  cvToValue,
} from '@stacks/transactions';
import { createNetwork } from '@stacks/network';

const require = createRequire(import.meta.url);
const { generateWallet } = require('/Users/brice/obybot/work/stackflow/node_modules/@stacks/wallet-sdk/dist/index.js');
const { buildTransferMessage, sip018Sign } =
  await import('/Users/brice/obybot/work/stackmail/packages/server/dist/sip018.js');

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const STACKS_API_URL = process.env.STACKS_API_URL?.trim() || 'https://api.mainnet.hiro.so';
const STACKS_NETWORK = process.env.STACKS_NETWORK?.trim() || 'mainnet';
const NETWORK = createNetwork({
  network: STACKS_NETWORK,
  client: { baseUrl: STACKS_API_URL },
});
const CHAIN_ID = 1;

const DEFAULTS = {
  sfContractId: 'SP3QFYVTMS0PRJT3K3GMDW9DGR33TDHENSDWVNQMR.sm-stackflow',
  tokenContractId: 'SP3QFYVTMS0PRJT3K3GMDW9DGR33TDHENSDWVNQMR.sm-test-token',
  reservoirContractName: 'sm-reservoir-2',
  initialBorrowRate: 1n,
  liquidityAmount: 1_000_000n,
  tapAmount: 10_000n,
  borrowAmount: 10_000n,
  mnemonicPath: '/Users/brice/obybot/identity/aibtc/mnemonic.txt',
  dbPath: '/Users/brice/obybot/work/stackmail/data/stackmail.db',
  envPath: '/Users/brice/obybot/work/stackmail/.env',
};

function normalizePrivateKey(input) {
  return input.trim().replace(/^0x/, '').toLowerCase();
}

function loadDeployerPrivateKey() {
  const fromEnv = process.env.DEPLOYER_PRIVATE_KEY?.trim();
  if (fromEnv) {
    return normalizePrivateKey(fromEnv);
  }
  const mnemonic = fs.readFileSync(DEFAULTS.mnemonicPath, 'utf8').trim();
  return generateWallet({ secretKey: mnemonic, password: '' })
    .then((wallet) => normalizePrivateKey(wallet.accounts[0].stxPrivateKey));
}

function readMetaValue(key) {
  return execFileSync(
    'sqlite3',
    ['-readonly', DEFAULTS.dbPath, `select value from meta where key='${key}';`],
    { encoding: 'utf8' },
  ).trim();
}

function hexArg(cv) {
  return '0x' + Buffer.from(serializeCVBytes(cv)).toString('hex');
}

async function contractExists(contractId) {
  const [addr, name] = contractId.split('.');
  const resp = await fetch(`${STACKS_API_URL}/extended/v1/contract/${addr}/${name}`);
  return resp.ok;
}

async function waitForTx(txid, label) {
  for (;;) {
    const resp = await fetch(`${STACKS_API_URL}/extended/v1/tx/${txid}`);
    if (!resp.ok) {
      throw new Error(`${label}: failed to fetch tx status (${resp.status})`);
    }
    const payload = await resp.json();
    if (payload.tx_status === 'success') {
      console.log(`[recover] ${label}: confirmed ${txid}`);
      return payload;
    }
    if (payload.tx_status === 'abort_by_response' || payload.tx_status === 'abort_by_post_condition' || payload.tx_status === 'dropped_replace_by_fee') {
      throw new Error(`${label}: failed ${txid} (${payload.tx_status})`);
    }
    if (payload.tx_status === 'pending') {
      console.log(`[recover] ${label}: pending ${txid}`);
      await new Promise((resolve) => setTimeout(resolve, 5000));
      continue;
    }
    await new Promise((resolve) => setTimeout(resolve, 5000));
  }
}

async function broadcastAndWait(transaction, label) {
  const result = await broadcastTransaction({ transaction, network: NETWORK });
  if ('reason' in result) {
    throw new Error(`${label}: broadcast failed (${result.reason || 'unknown'})`);
  }
  console.log(`[recover] ${label}: broadcast ${result.txid}`);
  await waitForTx(result.txid, label);
  return result.txid;
}

async function fetchBorrowFee(reservoirContractId, sender, amount) {
  const [addr, name] = reservoirContractId.split('.');
  const resp = await fetch(`${STACKS_API_URL}/v2/contracts/call-read/${addr}/${name}/get-borrow-fee`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      sender,
      arguments: [hexArg(uintCV(amount))],
    }),
  });
  if (!resp.ok) {
    throw new Error(`failed to read borrow fee (${resp.status})`);
  }
  const payload = await resp.json();
  if (!payload.okay || typeof payload.result !== 'string') {
    throw new Error('borrow fee read-only call failed');
  }
  const value = cvToValue(hexToCV(payload.result));
  return BigInt(value.value ?? value);
}

function replaceEnvValue(contents, key, value) {
  const line = `${key}=${value}`;
  const pattern = new RegExp(`^${key}=.*$`, 'm');
  if (pattern.test(contents)) {
    return contents.replace(pattern, line);
  }
  return contents.trimEnd() + `\n${line}\n`;
}

async function updateEnvFile(reservoirContractId) {
  const current = fs.readFileSync(DEFAULTS.envPath, 'utf8');
  const next = replaceEnvValue(
    replaceEnvValue(current, 'STACKMAIL_RESERVOIR_CONTRACT_ID', reservoirContractId),
    'STACKMAIL_SF_CONTRACT_ID',
    DEFAULTS.sfContractId,
  );
  fs.writeFileSync(DEFAULTS.envPath, next);
}

function loadReservoirCode() {
  return fs.readFileSync(
    path.resolve(__dirname, '../../stackflow/contracts/reservoir.clar'),
    'utf8',
  );
}

async function main() {
  const deployerTxKey = await loadDeployerPrivateKey();
  const deployerSignKey = deployerTxKey.replace(/01$/, '');
  const deployerAddress = getAddressFromPrivateKey(deployerTxKey, NETWORK);
  const serverSignerKey = normalizePrivateKey(readMetaValue('server_private_key'));
  const serverSignerAddress = readMetaValue('server_stx_address');

  const reservoirContractId = `${deployerAddress}.${DEFAULTS.reservoirContractName}`;
  if (await contractExists(reservoirContractId)) {
    throw new Error(`contract already exists: ${reservoirContractId}`);
  }

  console.log(`[recover] deployer=${deployerAddress}`);
  console.log(`[recover] signer=${serverSignerAddress}`);
  console.log(`[recover] new reservoir=${reservoirContractId}`);

  let nonce = await fetchNonce({
    address: deployerAddress,
    network: STACKS_NETWORK,
    client: { baseUrl: STACKS_API_URL },
  });

  const deployTx = await makeContractDeploy({
    contractName: DEFAULTS.reservoirContractName,
    codeBody: loadReservoirCode(),
    senderKey: deployerTxKey,
    nonce,
    network: NETWORK,
    clarityVersion: ClarityVersion.Clarity4,
    anchorMode: AnchorMode.Any,
  });
  const deployTxid = await broadcastAndWait(deployTx, 'deploy reservoir');
  nonce += 1n;

  const initTx = await makeContractCall({
    network: NETWORK,
    senderKey: deployerTxKey,
    contractAddress: deployerAddress,
    contractName: DEFAULTS.reservoirContractName,
    functionName: 'init',
    functionArgs: [
      principalCV(DEFAULTS.sfContractId),
      someCV(principalCV(DEFAULTS.tokenContractId)),
      uintCV(DEFAULTS.initialBorrowRate),
    ],
    nonce,
    anchorMode: AnchorMode.Any,
    postConditionMode: PostConditionMode.Allow,
    validateWithAbi: false,
  });
  const initTxid = await broadcastAndWait(initTx, 'init reservoir');
  nonce += 1n;

  const setAgentTx = await makeContractCall({
    network: NETWORK,
    senderKey: deployerTxKey,
    contractAddress: deployerAddress,
    contractName: DEFAULTS.reservoirContractName,
    functionName: 'set-agent',
    functionArgs: [
      principalCV(DEFAULTS.sfContractId),
      principalCV(serverSignerAddress),
    ],
    nonce,
    anchorMode: AnchorMode.Any,
    postConditionMode: PostConditionMode.Allow,
    validateWithAbi: false,
  });
  const setAgentTxid = await broadcastAndWait(setAgentTx, 'set reservoir agent');
  nonce += 1n;

  const addLiquidityTx = await makeContractCall({
    network: NETWORK,
    senderKey: deployerTxKey,
    contractAddress: deployerAddress,
    contractName: DEFAULTS.reservoirContractName,
    functionName: 'add-liquidity',
    functionArgs: [
      someCV(principalCV(DEFAULTS.tokenContractId)),
      uintCV(DEFAULTS.liquidityAmount),
    ],
    nonce,
    anchorMode: AnchorMode.Any,
    postConditionMode: PostConditionMode.Allow,
    validateWithAbi: false,
  });
  const addLiquidityTxid = await broadcastAndWait(addLiquidityTx, 'fund reservoir');
  nonce += 1n;

  const borrowFee = await fetchBorrowFee(reservoirContractId, deployerAddress, DEFAULTS.borrowAmount);
  const pipeKey = {
    'principal-1': deployerAddress,
    'principal-2': reservoirContractId,
    token: DEFAULTS.tokenContractId,
  };

  const userMessage = buildTransferMessage({
    pipeKey,
    forPrincipal: deployerAddress,
    myBalance: DEFAULTS.tapAmount.toString(),
    theirBalance: DEFAULTS.borrowAmount.toString(),
    nonce: '1',
    action: '2',
    actor: reservoirContractId,
    hashedSecret: null,
    validAfter: null,
  });
  const reservoirMessage = buildTransferMessage({
    pipeKey,
    forPrincipal: reservoirContractId,
    myBalance: DEFAULTS.borrowAmount.toString(),
    theirBalance: DEFAULTS.tapAmount.toString(),
    nonce: '1',
    action: '2',
    actor: reservoirContractId,
    hashedSecret: null,
    validAfter: null,
  });

  const userSignature = await sip018Sign(
    DEFAULTS.sfContractId,
    userMessage,
    deployerSignKey,
    CHAIN_ID,
  );
  const reservoirSignature = await sip018Sign(
    DEFAULTS.sfContractId,
    reservoirMessage,
    serverSignerKey,
    CHAIN_ID,
  );

  const openMailboxTx = await makeContractCall({
    network: NETWORK,
    senderKey: deployerTxKey,
    contractAddress: deployerAddress,
    contractName: DEFAULTS.reservoirContractName,
    functionName: 'create-tap-with-borrowed-liquidity',
    functionArgs: [
      principalCV(DEFAULTS.sfContractId),
      someCV(principalCV(DEFAULTS.tokenContractId)),
      uintCV(DEFAULTS.tapAmount),
      uintCV(0),
      uintCV(DEFAULTS.borrowAmount),
      uintCV(borrowFee),
      uintCV(DEFAULTS.tapAmount),
      uintCV(DEFAULTS.borrowAmount),
      bufferCV(Buffer.from(userSignature.replace(/^0x/, ''), 'hex')),
      bufferCV(Buffer.from(reservoirSignature.replace(/^0x/, ''), 'hex')),
      uintCV(1),
    ],
    nonce,
    anchorMode: AnchorMode.Any,
    postConditionMode: PostConditionMode.Allow,
    validateWithAbi: false,
  });
  const openMailboxTxid = await broadcastAndWait(openMailboxTx, 'open mailbox');

  await updateEnvFile(reservoirContractId);

  console.log('\n[recover] complete');
  console.log(JSON.stringify({
    deployerAddress,
    signerAddress: serverSignerAddress,
    sfContractId: DEFAULTS.sfContractId,
    tokenContractId: DEFAULTS.tokenContractId,
    reservoirContractId,
    borrowFee: borrowFee.toString(),
    txids: {
      deployTxid,
      initTxid,
      setAgentTxid,
      addLiquidityTxid,
      openMailboxTxid,
    },
  }, null, 2));
}

main().catch((error) => {
  console.error('[recover] fatal:', error);
  process.exit(1);
});
