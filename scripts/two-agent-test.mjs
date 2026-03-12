/**
 * Stackmail Two-Agent Realistic Test
 *
 * Simulates two independent agents (Alice and Bob) communicating through the
 * Stackmail server using real StackFlow payment-channel proofs.
 *
 * ─── On-chain model ────────────────────────────────────────────────────────
 *
 * Agents open "taps" via sm-reservoir::create-tap, which creates pipes on
 * sm-stackflow between the agent and the RESERVOIR CONTRACT. The reservoir
 * contract is the server's on-chain identity.
 *
 *   Alice's tap pipe: Alice <-> sm-reservoir
 *   principal-1: Alice  (standard principal, 0x05 type byte — always less than
 *   principal-2: sm-reservoir (contract principal, 0x06 type byte)
 *
 * The server validates SIP-018 signatures and tracks pipe state locally.
 * Settlement on-chain (reveal-preimage) can be done separately once messages
 * are confirmed.
 *
 * ─── What this test does ───────────────────────────────────────────────────
 *
 * 1. Optionally read Alice's on-chain pipe state from sm-stackflow (if tap exists)
 * 2. Alice agent registers mailbox
 * 3. Bob agent registers mailbox
 * 4. Alice sends 5 messages to Bob with real SIP-018 HTLC proofs
 * 5. Bob reads inbox and claims all messages (decrypt + reveal secret)
 * 6. Verify all messages claimed; print final channel state
 *
 * ─── Running the test ──────────────────────────────────────────────────────
 *
 * Default (ephemeral Alice — no on-chain tap required):
 *   node scripts/two-agent-test.mjs
 *
 * With a real on-chain tap (Alice must have called sm-reservoir::create-tap):
 *   ALICE_PRIVKEY=<hex> node scripts/two-agent-test.mjs
 *
 * SECURITY: ALICE_PRIVKEY should be a DEDICATED TEST KEY, not your main wallet.
 * Generate a throwaway key: node -e "const {randomBytes}=require('crypto');
 *   const {secp256k1}=require('@noble/curves/secp256k1');
 *   const priv=randomBytes(32); const pub=secp256k1.getPublicKey(priv,true);
 *   console.log('priv:', priv.toString('hex'));"
 */

import { createHash, randomBytes } from 'node:crypto';
import { secp256k1 } from '/agent/work/stackmail/node_modules/@noble/curves/secp256k1.js';

const { buildTransferMessage, sip018Sign } =
  await import('/agent/work/stackmail/packages/server/dist/sip018.js');
const { encryptMail, decryptMail, hashSecret } =
  await import('/agent/work/stackmail/packages/crypto/dist/index.js');

// ─── Constants ────────────────────────────────────────────────────────────────

const SERVER      = process.env.STACKMAIL_SERVER_URL ?? 'http://127.0.0.1:8800';
const RESERVOIR   = process.env.STACKMAIL_RESERVOIR_CONTRACT_ID ?? 'SP3QFYVTMS0PRJT3K3GMDW9DGR33TDHENSDWVNQMR.sm-reservoir';
const SF_CONTRACT = process.env.STACKMAIL_SF_CONTRACT_ID ?? 'SP3QFYVTMS0PRJT3K3GMDW9DGR33TDHENSDWVNQMR.sm-stackflow';
const TOKEN       = process.env.STACKMAIL_TOKEN_CONTRACT_ID ?? 'SP3QFYVTMS0PRJT3K3GMDW9DGR33TDHENSDWVNQMR.sm-test-token';
const CHAIN_ID    = Number.parseInt(process.env.STACKMAIL_CHAIN_ID ?? '1', 10);
const HIRO_API    = CHAIN_ID === 1 ? 'https://api.mainnet.hiro.so' : 'https://api.testnet.hiro.so';
const EXPLORER_CHAIN = CHAIN_ID === 1 ? 'mainnet' : 'testnet';
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
  const v = 22;  // mainnet P2PKH version
  const payload = Buffer.concat([Buffer.from([v]), h160]);
  const h1 = createHash('sha256').update(payload).digest();
  const checksum = createHash('sha256').update(h1).digest().subarray(0, 4);
  return 'S' + C32[v] + c32encode(Buffer.concat([h160, checksum]));
}

function keypairFromPrivkey(privHex) {
  const pub = secp256k1.getPublicKey(Buffer.from(privHex, 'hex'), true);
  const pubHex = Buffer.from(pub).toString('hex');
  return { privHex, pubHex, addr: stxAddress(pubHex) };
}

function genKeypair() {
  const priv = randomBytes(32);
  const pub = secp256k1.getPublicKey(priv, true);
  return {
    privHex: Buffer.from(priv).toString('hex'),
    pubHex:  Buffer.from(pub).toString('hex'),
    addr:    stxAddress(Buffer.from(pub).toString('hex')),
  };
}

// ─── Canonical pipe key ───────────────────────────────────────────────────────
// Matches Clarity's to-consensus-buff? ordering:
//   Standard:  0x05 <version> <hash160>              — type byte 0x05
//   Contract:  0x06 <version> <hash160> <len> <name> — type byte 0x06
// ⟹ 0x05 < 0x06: standard addresses are always principal-1 vs contract principals.

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

// ─── On-chain pipe state reader ───────────────────────────────────────────────

function cvPrincipal(addr) {
  const dotIdx = addr.indexOf('.');
  if (dotIdx < 0) {
    const { version, hash160 } = parseStxAddress(addr);
    return Buffer.concat([Buffer.from([0x05, version]), hash160]).toString('hex');
  } else {
    const { version, hash160 } = parseStxAddress(addr.slice(0, dotIdx));
    const name = Buffer.from(addr.slice(dotIdx + 1), 'ascii');
    return Buffer.concat([Buffer.from([0x06, version]), hash160, Buffer.from([name.length]), name]).toString('hex');
  }
}

function cvTuple(fields) {
  const sorted = Object.keys(fields).sort();
  const u32 = (n) => { const b = Buffer.alloc(4); b.writeUInt32BE(n, 0); return b.toString('hex'); };
  const u8  = (n) => Buffer.from([n]).toString('hex');
  let hex = '0c' + u32(sorted.length);
  for (const name of sorted) {
    const nb = Buffer.from(name, 'utf-8');
    hex += u8(nb.length) + nb.toString('hex') + fields[name];
  }
  return hex;
}

function clarityEncodePipeKey(pipeKey) {
  const tokenCV = pipeKey.token ? ('0a' + cvPrincipal(pipeKey.token)) : '09';
  return '0x' + cvTuple({
    'principal-1': cvPrincipal(pipeKey['principal-1']),
    'principal-2': cvPrincipal(pipeKey['principal-2']),
    'token': tokenCV,
  });
}

async function readOnChainPipeState(aliceAddr) {
  const pipeKey = canonicalPipeKey(TOKEN, aliceAddr, RESERVOIR);
  try {
    const resp = await fetch(
      `${HIRO_API}/v2/contracts/call-read/${SF_CONTRACT.split('.')[0]}/${SF_CONTRACT.split('.')[1]}/get-pipe`,
      {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ sender: aliceAddr, arguments: [clarityEncodePipeKey(pipeKey)] }),
      }
    );
    if (!resp.ok) return null;
    const data = await resp.json();
    if (!data.okay) return null;
    const repr = data.result;
    if (repr === 'none' || !repr) return null;
    const b1Match = repr.match(/balance-1 u(\d+)/);
    const b2Match = repr.match(/balance-2 u(\d+)/);
    const nonceMatch = repr.match(/nonce u(\d+)/);
    if (!b1Match || !b2Match || !nonceMatch) return null;
    return {
      balance1: BigInt(b1Match[1]),
      balance2: BigInt(b2Match[1]),
      nonce:    BigInt(nonceMatch[1]),
      pipeKey,
    };
  } catch {
    return null;
  }
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
  if (!r.ok && method !== 'GET') throw new Error(`${method} ${path} → ${r.status}: ${JSON.stringify(data)}`);
  return { status: r.status, ok: r.ok, data };
}

// ─── Stackmail operations ─────────────────────────────────────────────────────

async function registerMailbox(kp) {
  const auth = buildAuthHeader(kp.privHex, kp.pubHex, kp.addr, 'get-inbox');
  const r = await api('GET', '/inbox', null, { 'x-stackmail-auth': auth });
  if (r.status !== 200 && r.status !== 404) {
    throw new Error(`register failed: ${r.status} ${JSON.stringify(r.data)}`);
  }
}

async function getPaymentInfo(addr) {
  const r = await api('GET', `/payment-info/${addr}`);
  if (!r.ok) throw new Error(`payment-info: ${r.status} ${JSON.stringify(r.data)}`);
  return r.data;
}

async function sendMessage(senderKp, toAddr, subject, body, pipeState) {
  const payInfo = await getPaymentInfo(toAddr);

  const secretHex       = randomBytes(32).toString('hex');
  const hashedSecretHex = hashSecret(secretHex);
  const encPayload      = encryptMail(
    { v: 1, secret: secretHex, subject, body },
    payInfo.recipientPublicKey,
  );

  const newServerBalance = pipeState.serverBalance + MSG_PRICE;
  const newMyBalance     = pipeState.myBalance - MSG_PRICE;
  const nextNonce        = pipeState.nonce + 1n;

  const pipeKey = canonicalPipeKey(TOKEN, senderKp.addr, RESERVOIR);

  // Sign as the sender: myBalance = sender's new balance, theirBalance = server's new balance
  const state = {
    pipeKey,
    forPrincipal: senderKp.addr,    // "my" perspective: I am the sender
    myBalance:    newMyBalance.toString(),
    theirBalance: newServerBalance.toString(),
    nonce:        nextNonce.toString(),
    action: '1', actor: senderKp.addr,
    hashedSecret: hashedSecretHex,
    validAfter: null,
  };
  const sig = await sip018Sign(SF_CONTRACT, buildTransferMessage(state), senderKp.privHex, CHAIN_ID);

  // Payment proof sent to server: from server's perspective (forPrincipal = RESERVOIR)
  const proof = {
    contractId:    SF_CONTRACT,
    pipeKey,
    forPrincipal:  RESERVOIR,
    withPrincipal: senderKp.addr,
    myBalance:     newServerBalance.toString(),   // server's new balance
    theirBalance:  newMyBalance.toString(),        // sender's new balance
    nonce:         nextNonce.toString(),
    action: '1', actor: senderKp.addr,
    hashedSecret:  hashedSecretHex,
    theirSignature: sig,
    validAfter: null,
  };
  const proofHeader = Buffer.from(JSON.stringify(proof)).toString('base64url');

  const r = await api(
    'POST', `/messages/${toAddr}`,
    { from: senderKp.addr, encryptedPayload: encPayload },
    { 'x-stackmail-payment': proofHeader },
  );

  return {
    messageId: r.data.messageId,
    newPipeState: { serverBalance: newServerBalance, myBalance: newMyBalance, nonce: nextNonce },
  };
}

async function getInbox(kp, includeClaimed = false) {
  const auth = buildAuthHeader(kp.privHex, kp.pubHex, kp.addr, 'get-inbox');
  const r = await api('GET', `/inbox${includeClaimed ? '?claimed=true' : ''}`, null, { 'x-stackmail-auth': auth });
  return r.data.messages ?? [];
}

async function claimMessage(kp, messageId) {
  const auth1 = buildAuthHeader(kp.privHex, kp.pubHex, kp.addr, 'get-message', messageId);
  const prev = await api('GET', `/inbox/${messageId}/preview`, null, { 'x-stackmail-auth': auth1 });
  if (!prev.ok) throw new Error(`preview: ${prev.status} ${JSON.stringify(prev.data)}`);

  const dec = decryptMail(prev.data.encryptedPayload, kp.privHex);
  const expected = prev.data.hashedSecret.replace(/^0x/, '');
  if (hashSecret(dec.secret) !== expected) throw new Error('secret hash mismatch');

  const auth2 = buildAuthHeader(kp.privHex, kp.pubHex, kp.addr, 'claim-message', messageId);
  const claim = await api('POST', `/inbox/${messageId}/claim`, { secret: dec.secret }, { 'x-stackmail-auth': auth2 });

  return { id: messageId, from: prev.data.from, subject: dec.subject, body: dec.body, amount: prev.data.amount };
}

// ─── Main ─────────────────────────────────────────────────────────────────────

async function main() {
  console.log('════════════════════════════════════════════════════════════');
  console.log('  Stackmail — Two-Agent Realistic Test');
  console.log('════════════════════════════════════════════════════════════\n');

  // ── Agents ──────────────────────────────────────────────────────────────────

  // Alice = sender agent.
  // If ALICE_PRIVKEY env is set (hex, dedicated test key), use it — allows testing
  // against a real on-chain tap.  Otherwise generate an ephemeral keypair.
  const alicePrivkey = process.env.ALICE_PRIVKEY;
  const alice = alicePrivkey ? keypairFromPrivkey(alicePrivkey) : genKeypair();
  const usingRealTap = !!alicePrivkey;

  // Bob = fresh ephemeral keypair (recipient, no on-chain tap needed to receive)
  const bob = genKeypair();

  console.log('Agent Alice (sender):');
  console.log('  STX address:', alice.addr);
  console.log('  Tap mode:   ', usingRealTap ? 'real on-chain tap (ALICE_PRIVKEY set)' : 'ephemeral (no on-chain tap)');
  console.log('\nAgent Bob (recipient):');
  console.log('  STX address:', bob.addr);
  console.log('\nReservoir (server identity):', RESERVOIR, '\n');

  // ── Step 1: Check on-chain tap state (informational) ─────────────────────────
  console.log('Step 1: Checking on-chain tap state...');
  const onChainState = await readOnChainPipeState(alice.addr);

  let pipeState;
  if (onChainState) {
    console.log('  On-chain pipe found:');
    console.log('    balance-1 (Alice):     ', onChainState.balance1.toString(), 'µTOKEN');
    console.log('    balance-2 (Reservoir): ', onChainState.balance2.toString(), 'µTOKEN');
    console.log('    nonce:                 ', onChainState.nonce.toString());
    pipeState = {
      myBalance:     onChainState.balance1,
      serverBalance: onChainState.balance2,
      nonce:         onChainState.nonce,
    };
  } else {
    const reason = usingRealTap
      ? 'could not read pipe (API error or tap not yet created)'
      : 'ephemeral Alice — no on-chain tap';
    console.log('  No on-chain pipe:', reason);
    // Assume a tap of 50 TEST was funded for capacity calculation
    pipeState = { myBalance: 50_000_000n, serverBalance: 0n, nonce: 0n };
  }

  const messagesCapacity = pipeState.myBalance / MSG_PRICE;
  console.log('\n  Starting pipe state (Alice perspective):');
  console.log('    myBalance:    ', pipeState.myBalance.toString(), 'µTOKEN');
  console.log('    serverBalance:', pipeState.serverBalance.toString(), 'µTOKEN');
  console.log('    nonce:        ', pipeState.nonce.toString());
  console.log('  Capacity:       ', messagesCapacity.toString(), 'messages\n');

  // ── Step 2: Register mailboxes ────────────────────────────────────────────────
  console.log('Step 2: Both agents register mailboxes...');
  await registerMailbox(alice);
  console.log('  Alice registered:', alice.addr);
  await registerMailbox(bob);
  console.log('  Bob registered:  ', bob.addr, '\n');

  // ── Step 3: Alice sends 5 messages to Bob ─────────────────────────────────────
  const messages = [
    { subject: 'Hello from Alice',  body: 'First message via a real StackFlow HTLC proof.' },
    { subject: 'Micropayments',     body: 'Each message costs 1000 µTOKEN, deducted from Alice\'s tap balance.' },
    { subject: 'ECIES encryption',  body: 'Only you can read this — encrypted with your secp256k1 public key.' },
    { subject: 'HTLC payment',      body: 'The secret in this envelope unlocks payment from the reservoir to you.' },
    { subject: 'Final message',     body: 'Five messages, five micropayments, all using SIP-018 signed proofs.' },
  ];

  console.log('Step 3: Alice sends', messages.length, 'messages to Bob...');
  const sentIds = [];
  for (const [i, { subject, body }] of messages.entries()) {
    const { messageId, newPipeState } = await sendMessage(alice, bob.addr, subject, body, pipeState);
    pipeState = newPipeState;
    sentIds.push(messageId);
    console.log(`  [${i + 1}/${messages.length}] sent: ${messageId.slice(0, 8)}... | nonce: ${pipeState.nonce} | Alice: ${pipeState.myBalance} µTOKEN`);
  }
  console.log('\n  Alice pipe state after sending:');
  console.log('    myBalance:    ', pipeState.myBalance.toString(), 'µTOKEN');
  console.log('    serverBalance:', pipeState.serverBalance.toString(), 'µTOKEN');
  console.log('    nonce:        ', pipeState.nonce.toString(), '\n');

  // ── Step 4: Bob reads inbox ───────────────────────────────────────────────────
  console.log('Step 4: Bob checks inbox...');
  const inbox = await getInbox(bob);
  console.log('  Total messages:', inbox.length);
  console.log('  Unclaimed:     ', inbox.filter(m => !m.claimed).length, '\n');

  // ── Step 5: Bob claims all messages ──────────────────────────────────────────
  console.log('Step 5: Bob claims all messages...');
  const unclaimed = inbox.filter(m => !m.claimed);
  const results = [];
  for (const [i, entry] of unclaimed.entries()) {
    const msg = await claimMessage(bob, entry.id);
    results.push(msg);
    console.log(`  [${i + 1}/${unclaimed.length}] "${msg.subject}"`);
    console.log(`        amount: ${msg.amount} µTOKEN | from: ${msg.from.slice(0, 20)}...`);
    console.log(`        body:   "${msg.body.slice(0, 60)}"`);
  }

  // ── Step 6: Final verification ────────────────────────────────────────────────
  console.log('\nStep 6: Final verification...');
  const finalInbox = await getInbox(bob, true);
  const allClaimed = finalInbox.every(m => m.claimed);

  console.log('  Total in Bob\'s inbox:', finalInbox.length);
  console.log('  All claimed:         ', allClaimed ? '✓ yes' : '✗ no');
  console.log('  Total value claimed: ', (BigInt(finalInbox.length) * MSG_PRICE).toString(), 'µTOKEN');

  if (!allClaimed || finalInbox.length !== messages.length) {
    throw new Error(`Expected ${messages.length} claimed messages, got ${finalInbox.filter(m=>m.claimed).length}`);
  }

  console.log('\n════════════════════════════════════════════════════════════');
  console.log('  ✅  TWO-AGENT TEST PASSED');
  console.log('════════════════════════════════════════════════════════════\n');
  console.log('Summary:');
  console.log('  Messages sent/claimed:', messages.length);
  console.log('  Price per message:    ', MSG_PRICE.toString(), 'µTOKEN (0.001 TEST)');
  console.log('  Total paid:           ', (MSG_PRICE * BigInt(messages.length)).toString(), 'µTOKEN');
  console.log('  Alice remaining:      ', pipeState.myBalance.toString(), 'µTOKEN');

  if (usingRealTap) {
    console.log('\n  On-chain state to verify (sm-stackflow::get-pipe):');
    console.log('    balance-1 (Alice):    ', pipeState.myBalance.toString(), 'µTOKEN');
    console.log('    balance-2 (Reservoir):', pipeState.serverBalance.toString(), 'µTOKEN');
    console.log('    nonce:                ', pipeState.nonce.toString());
    console.log('\n  To close tap: sm-reservoir::force-cancel-tap (144-block dispute window)');
    console.log(`  Explorer: https://explorer.hiro.so/address/${SF_CONTRACT}?chain=${EXPLORER_CHAIN}`);
  }
}

main().catch(e => {
  console.error('\n✗ TEST FAILED:', e.message);
  console.error(e.stack);
  process.exit(1);
});
