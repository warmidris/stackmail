/**
 * Stackmail demo — two-agent send/receive flow
 *
 * Shows the full interaction:
 *   1. Both agents register mailboxes
 *   2. Agent A sends messages to Agent B (with SIP-018 payment proofs)
 *   3. Agent B reads and claims messages (decrypts and reveals HTLC secret)
 *
 * On-chain model: agents open taps via sm-reservoir (not directly on sm-stackflow).
 * The pipe counterparty is the RESERVOIR CONTRACT, not the server's personal wallet.
 *
 * Run: node scripts/demo.mjs
 * Requires server: node packages/server/dist/index.js
 */

import { createHash, randomBytes } from 'node:crypto';
import { secp256k1 } from '/agent/work/stackmail/node_modules/@noble/curves/secp256k1.js';

const { buildTransferMessage, sip018Sign } =
  await import('/agent/work/stackmail/packages/server/dist/sip018.js');
const { encryptMail, decryptMail, hashSecret } =
  await import('/agent/work/stackmail/packages/crypto/dist/index.js');

// ─── Constants ────────────────────────────────────────────────────────────────

const SERVER      = process.env.STACKMAIL_SERVER_URL ?? 'http://127.0.0.1:8800';
// The reservoir contract is the on-chain counterparty for all agent taps.
// Agents call create-tap on sm-reservoir (not fund-pipe on sm-stackflow directly).
const RESERVOIR   = process.env.STACKMAIL_RESERVOIR_CONTRACT_ID ?? 'SP3QFYVTMS0PRJT3K3GMDW9DGR33TDHENSDWVNQMR.sm-reservoir';
const SF_CONTRACT = process.env.STACKMAIL_SF_CONTRACT_ID ?? 'SP3QFYVTMS0PRJT3K3GMDW9DGR33TDHENSDWVNQMR.sm-stackflow';
const TOKEN       = process.env.STACKMAIL_TOKEN_CONTRACT_ID ?? 'SP3QFYVTMS0PRJT3K3GMDW9DGR33TDHENSDWVNQMR.sm-test-token';
const CHAIN_ID    = Number.parseInt(process.env.STACKMAIL_CHAIN_ID ?? '1', 10);
const MSG_PRICE   = 1000n;

// ─── Address helpers ──────────────────────────────────────────────────────────

const C32 = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

function c32encode(data) {
  let n = BigInt('0x' + Buffer.from(data).toString('hex'));
  const chars = [];
  while (n > 0n) { chars.push(C32[Number(n % 32n)]); n /= 32n; }
  for (const b of data) { if (b === 0) chars.push('0'); else break; }
  return chars.reverse().join('');
}

function c32DecodeFixed(encoded, expectedBytes) {
  const result = Buffer.alloc(expectedBytes, 0);
  let carry = 0, carryBits = 0, byteIdx = expectedBytes - 1;
  for (let i = encoded.length - 1; i >= 0 && byteIdx >= 0; i--) {
    const val = C32.indexOf(encoded[i].toUpperCase());
    if (val < 0) throw new Error('bad c32 char: ' + encoded[i]);
    carry |= (val << carryBits); carryBits += 5;
    if (carryBits >= 8) { result[byteIdx--] = carry & 0xff; carry >>= 8; carryBits -= 8; }
  }
  return result;
}

function parseStxAddress(addr) {
  const a = addr.includes('.') ? addr.slice(0, addr.indexOf('.')) : addr;
  const version = C32.indexOf(a[1].toUpperCase());
  const decoded = c32DecodeFixed(a.slice(2), 24);
  return { version, hash160: decoded.subarray(0, 20) };
}

function stxAddress(pubkeyHex) {
  const pub = Buffer.from(pubkeyHex, 'hex');
  const sha = createHash('sha256').update(pub).digest();
  const h160 = createHash('ripemd160').update(sha).digest();
  const v = 22;
  const payload = Buffer.concat([Buffer.from([v]), h160]);
  const h1 = createHash('sha256').update(payload).digest();
  const checksum = createHash('sha256').update(h1).digest().subarray(0, 4);
  return 'S' + C32[v] + c32encode(Buffer.concat([h160, checksum]));
}

function genKeypair() {
  const priv = randomBytes(32);
  const pub = secp256k1.getPublicKey(priv, true);
  const privHex = Buffer.from(priv).toString('hex');
  const pubHex  = Buffer.from(pub).toString('hex');
  return { privHex, pubHex, addr: stxAddress(pubHex) };
}

// ─── Canonical pipe key ───────────────────────────────────────────────────────
// Matches Clarity's to-consensus-buff? ordering:
//   Standard principal: 0x05 <ver> <hash160>           (starts with 0x05)
//   Contract principal: 0x06 <ver> <hash160> <n> <name> (starts with 0x06)
// ⟹ 0x05 < 0x06, so standard address is ALWAYS principal-1 vs a contract principal.

function toConsensusBuff(addr) {
  const dotIdx = addr.indexOf('.');
  if (dotIdx < 0) {
    const { version, hash160 } = parseStxAddress(addr);
    return Buffer.concat([Buffer.from([0x05, version]), hash160]);
  } else {
    const { version, hash160 } = parseStxAddress(addr.slice(0, dotIdx));
    const nameBytes = Buffer.from(addr.slice(dotIdx + 1), 'ascii');
    return Buffer.concat([Buffer.from([0x06, version]), hash160, Buffer.from([nameBytes.length]), nameBytes]);
  }
}

function canonicalPipeKey(token, addr1, addr2) {
  const p1 = toConsensusBuff(addr1);
  const p2 = toConsensusBuff(addr2);
  return Buffer.compare(p1, p2) < 0
    ? { token, 'principal-1': addr1, 'principal-2': addr2 }
    : { token, 'principal-1': addr2, 'principal-2': addr1 };
}

// ─── Auth header ──────────────────────────────────────────────────────────────

function buildAuthHeader(privHex, pubHex, addr, action, messageId) {
  const payload = { action, address: addr, timestamp: Date.now(), ...(messageId ? { messageId } : {}) };
  const hash = createHash('sha256').update(JSON.stringify(payload)).digest();
  const sig = secp256k1.sign(hash, Buffer.from(privHex, 'hex'), { lowS: true });
  return Buffer.from(JSON.stringify({
    pubkey: pubHex,
    payload,
    signature: Buffer.from(sig.toCompactRawBytes()).toString('hex'),
  })).toString('base64');
}

// ─── API helper ───────────────────────────────────────────────────────────────

async function api(method, path, body, headers = {}) {
  const opts = { method, headers: { ...headers } };
  if (body) { opts.headers['content-type'] = 'application/json'; opts.body = JSON.stringify(body); }
  const r = await fetch(`${SERVER}${path}`, opts);
  const text = await r.text();
  let data; try { data = JSON.parse(text); } catch { data = text; }
  return { status: r.status, ok: r.ok, data };
}

// ─── Stackmail client functions ───────────────────────────────────────────────

/** Register mailbox (stores agent's pubkey with server for senders to look up). */
async function registerMailbox(kp) {
  const auth = buildAuthHeader(kp.privHex, kp.pubHex, kp.addr, 'get-inbox');
  const r = await api('GET', '/inbox', null, { 'x-stackmail-auth': auth });
  if (r.status !== 200 && r.status !== 404) throw new Error(`register failed: ${r.status} ${JSON.stringify(r.data)}`);
  console.log(`  Registered: ${kp.addr}`);
}

/** Look up recipient's pubkey and price. Recipient must have registered first. */
async function getPaymentInfo(addr) {
  const r = await api('GET', `/payment-info/${addr}`);
  if (!r.ok) throw new Error(`payment-info failed: ${r.status} ${JSON.stringify(r.data)}`);
  return r.data;
}

/**
 * Send a message to a recipient.
 *
 * pipeState tracks your off-chain balance with the reservoir:
 *   { serverBalance: bigint, myBalance: bigint, nonce: bigint }
 *
 * On-chain: this corresponds to the state of your tap on sm-stackflow
 * (opened via sm-reservoir::create-tap).
 */
async function sendMessage(senderKp, toAddr, subject, body, pipeState) {
  // 1. Get recipient's public key
  const payInfo = await getPaymentInfo(toAddr);
  if (payInfo.serverAddress !== RESERVOIR) {
    throw new Error(`Server address mismatch: expected ${RESERVOIR}, got ${payInfo.serverAddress}`);
  }

  // 2. Generate HTLC secret and encrypt message
  const secretHex      = randomBytes(32).toString('hex');
  const hashedSecretHex = hashSecret(secretHex);
  const encPayload     = encryptMail(
    { v: 1, secret: secretHex, subject, body },
    payInfo.recipientPublicKey,
  );

  // 3. Compute new channel balances (agent's tap with reservoir)
  const newServerBalance = pipeState.serverBalance + MSG_PRICE;
  const newMyBalance     = pipeState.myBalance - MSG_PRICE;
  const nextNonce        = pipeState.nonce + 1n;

  // 4. Build canonical pipe key: agent (standard) is principal-1, reservoir (contract) is principal-2
  const pipeKey = canonicalPipeKey(TOKEN, senderKp.addr, RESERVOIR);

  // 5. Sign state update from sender's perspective
  const state = {
    pipeKey,
    forPrincipal: senderKp.addr,   // sender is signing (they're principal-1)
    myBalance:    newMyBalance.toString(),
    theirBalance: newServerBalance.toString(),
    nonce:        nextNonce.toString(),
    action: '1', actor: senderKp.addr,
    hashedSecret: hashedSecretHex,
    validAfter: null,
  };
  const sig = await sip018Sign(SF_CONTRACT, buildTransferMessage(state), senderKp.privHex, CHAIN_ID);

  // 6. Encode proof for server (from reservoir's perspective)
  const proof = {
    contractId:    SF_CONTRACT,
    pipeKey,
    forPrincipal:  RESERVOIR,       // payment is TO the reservoir
    withPrincipal: senderKp.addr,
    myBalance:     newServerBalance.toString(),
    theirBalance:  newMyBalance.toString(),
    nonce:         nextNonce.toString(),
    action: '1', actor: senderKp.addr,
    hashedSecret:  hashedSecretHex,
    theirSignature: sig,
    validAfter: null,
  };
  const proofHeader = Buffer.from(JSON.stringify(proof)).toString('base64url');

  // 7. POST to server
  const r = await api(
    'POST', `/messages/${toAddr}`,
    { from: senderKp.addr, encryptedPayload: encPayload },
    { 'x-stackmail-payment': proofHeader },
  );
  if (!r.ok) throw new Error(`sendMessage failed: ${r.status} ${JSON.stringify(r.data)}`);

  return {
    messageId: r.data.messageId,
    newPipeState: { serverBalance: newServerBalance, myBalance: newMyBalance, nonce: nextNonce },
  };
}

/** Get inbox (message headers only). */
async function getInbox(kp, includeClaimed = false) {
  const auth = buildAuthHeader(kp.privHex, kp.pubHex, kp.addr, 'get-inbox');
  const r = await api('GET', `/inbox${includeClaimed ? '?claimed=true' : ''}`, null, { 'x-stackmail-auth': auth });
  if (!r.ok) throw new Error(`getInbox failed: ${r.status} ${JSON.stringify(r.data)}`);
  return r.data.messages ?? [];
}

/** Claim a message: decrypt it, verify secret, reveal to server. */
async function claimMessage(kp, messageId) {
  // Preview
  const auth1 = buildAuthHeader(kp.privHex, kp.pubHex, kp.addr, 'get-message', messageId);
  const prev = await api('GET', `/inbox/${messageId}/preview`, null, { 'x-stackmail-auth': auth1 });
  if (!prev.ok) throw new Error(`preview failed: ${prev.status} ${JSON.stringify(prev.data)}`);

  // Decrypt
  const dec = decryptMail(prev.data.encryptedPayload, kp.privHex);

  // Verify secret hash matches the payment commitment
  const expected = prev.data.hashedSecret.replace(/^0x/, '');
  const computed = hashSecret(dec.secret);
  if (computed !== expected) throw new Error('secret hash mismatch!');

  // Claim
  const auth2 = buildAuthHeader(kp.privHex, kp.pubHex, kp.addr, 'claim-message', messageId);
  const claim = await api('POST', `/inbox/${messageId}/claim`, { secret: dec.secret }, { 'x-stackmail-auth': auth2 });
  if (!claim.ok) throw new Error(`claim failed: ${claim.status} ${JSON.stringify(claim.data)}`);

  return { id: messageId, from: prev.data.from, subject: dec.subject, body: dec.body, amount: prev.data.amount };
}

// ─── Demo ─────────────────────────────────────────────────────────────────────

async function demo() {
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log('  Stackmail Demo — reservoir model');
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');
  console.log('Contracts:');
  console.log(`  sm-test-token : ${TOKEN}`);
  console.log(`  sm-stackflow  : ${SF_CONTRACT}`);
  console.log(`  sm-reservoir  : ${RESERVOIR}`);
  console.log(`  (server URL)  : ${SERVER}\n`);

  const alice = genKeypair();
  const bob   = genKeypair();
  console.log('Agents:');
  console.log('  Alice:', alice.addr, '← sender');
  console.log('  Bob:  ', bob.addr, '← receiver\n');

  // ── Step 1: Register both mailboxes ────────────────────────────────────────
  console.log('Step 1: Register mailboxes');
  await registerMailbox(alice);
  await registerMailbox(bob);
  console.log();

  // ── Step 2: Alice sends Bob a message ─────────────────────────────────────
  // pipeState reflects the state of Alice's tap on sm-stackflow (opened via sm-reservoir::create-tap).
  // For the demo we simulate a funded tap of 100,000 TEST.
  // In production: read the actual on-chain pipe state after calling create-tap.
  console.log('Step 2: Alice sends Bob a message');
  console.log('  (simulating a funded tap: 100,000 TEST, nonce 0)');
  let alicePipe = { serverBalance: 0n, myBalance: 100_000n, nonce: 0n };

  const { messageId, newPipeState } = await sendMessage(
    alice, bob.addr,
    'Hello from Alice!',
    'Welcome to Stackmail. This message is secured by a StackFlow payment channel tap on mainnet.',
    alicePipe,
  );
  alicePipe = newPipeState;
  console.log('  Sent! Message ID:', messageId);
  console.log('  Alice tap state:', {
    serverBalance: alicePipe.serverBalance.toString(),
    myBalance:     alicePipe.myBalance.toString(),
    nonce:         alicePipe.nonce.toString(),
  }, '\n');

  // ── Step 3: Bob checks inbox ───────────────────────────────────────────────
  console.log('Step 3: Bob checks inbox');
  const inbox = await getInbox(bob);
  console.log(`  ${inbox.length} message(s)`);
  inbox.forEach(m => console.log(`  [${m.id.slice(0,8)}...] from: ${m.from.slice(0,20)}... amount: ${m.amount} claimed: ${m.claimed}`));
  console.log();

  // ── Step 4: Bob claims message ─────────────────────────────────────────────
  console.log('Step 4: Bob claims message');
  const claimed = await claimMessage(bob, messageId);
  console.log('  Subject:', claimed.subject);
  console.log('  Body:   ', claimed.body);
  console.log('  Amount: ', claimed.amount, '\n');

  // ── Step 5: Alice sends two more messages ──────────────────────────────────
  console.log('Step 5: Alice sends two more messages');
  const { messageId: msg2, newPipeState: p2 } = await sendMessage(
    alice, bob.addr, 'Second message', 'State channels are amazing.', alicePipe,
  );
  alicePipe = p2;
  const { messageId: msg3, newPipeState: p3 } = await sendMessage(
    alice, bob.addr, 'Third message', 'Three messages, one tap, instant finality.', alicePipe,
  );
  alicePipe = p3;
  console.log('  Sent messages:', msg2.slice(0,8) + '...', msg3.slice(0,8) + '...');
  console.log('  Alice tap after 3 messages:', {
    serverBalance: alicePipe.serverBalance.toString(),
    myBalance:     alicePipe.myBalance.toString(),
    nonce:         alicePipe.nonce.toString(),
  }, '\n');

  // ── Step 6: Bob reads all new messages at once ─────────────────────────────
  console.log('Step 6: Bob reads all unclaimed messages');
  const allNew = (await getInbox(bob)).filter(m => !m.claimed);
  console.log(`  ${allNew.length} unclaimed message(s)`);
  for (const entry of allNew) {
    const msg = await claimMessage(bob, entry.id);
    console.log(`  > "${msg.subject}": ${msg.body.slice(0, 50)}...`);
  }

  console.log('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log('  Demo complete! All messages sent and claimed.');
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

  console.log('On-chain setup required for real use:');
  console.log('  Alice calls sm-reservoir::create-tap(sm-stackflow, some sm-test-token, amount, u0)');
  console.log('  This opens a pipe on sm-stackflow between Alice and sm-reservoir.');
  console.log('  The pipeState above must match the actual on-chain funded amounts.');
}

demo().catch(e => { console.error('Demo failed:', e.message); process.exit(1); });
