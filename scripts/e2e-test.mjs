/**
 * Stackmail end-to-end test (two synthetic agents, real server, mainnet contracts)
 *
 * Tests the server's off-chain logic with valid SIP-018 signatures.
 * Agents interact through the sm-reservoir contract (hub-and-spoke model).
 *
 * Deployed contracts (SP3QFYVTMS0PRJT3K3GMDW9DGR33TDHENSDWVNQMR):
 *   sm-test-token  – TEST SIP-010 token
 *   sm-stackflow   – StackFlow v0.6.0 payment channels
 *   sm-reservoir   – reservoir hub (the server's on-chain identity)
 *
 * Server URL: http://127.0.0.1:8800
 * Reservoir (server's on-chain address): SP3QFYVTMS0PRJT3K3GMDW9DGR33TDHENSDWVNQMR.sm-reservoir
 *
 * On-chain setup (one-time, done before this test):
 *   Alice calls `create-tap` on sm-reservoir to open a pipe:
 *     Alice <-> sm-reservoir on sm-stackflow
 */

import { createHash, randomBytes } from 'node:crypto';
import { secp256k1 } from '/agent/work/stackmail/node_modules/@noble/curves/secp256k1.js';

const { buildTransferMessage, sip018Sign, sip018Verify } =
  await import('/agent/work/stackmail/packages/server/dist/sip018.js');
const { encryptMail, decryptMail, hashSecret, verifySecretHash } =
  await import('/agent/work/stackmail/packages/crypto/dist/index.js');

const SERVER = process.env.STACKMAIL_SERVER_URL ?? 'http://127.0.0.1:8800';
// The reservoir contract IS the server's on-chain identity — pipes are opened to it
const RESERVOIR = process.env.STACKMAIL_RESERVOIR_CONTRACT_ID ?? 'SP3QFYVTMS0PRJT3K3GMDW9DGR33TDHENSDWVNQMR.sm-reservoir';
const SF_CONTRACT = process.env.STACKMAIL_SF_CONTRACT_ID ?? 'SP3QFYVTMS0PRJT3K3GMDW9DGR33TDHENSDWVNQMR.sm-stackflow';
const TOKEN = process.env.STACKMAIL_TOKEN_CONTRACT_ID ?? 'SP3QFYVTMS0PRJT3K3GMDW9DGR33TDHENSDWVNQMR.sm-test-token';
const CHAIN_ID = Number.parseInt(process.env.STACKMAIL_CHAIN_ID ?? '1', 10);
const MESSAGE_PRICE = 1000n;

// ── c32 address helpers ───────────────────────────────────────────────────────
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
    if (val < 0) throw new Error('bad c32 char ' + encoded[i]);
    carry |= (val << carryBits); carryBits += 5;
    if (carryBits >= 8) { result[byteIdx--] = carry & 0xff; carry >>= 8; carryBits -= 8; }
  }
  return result;
}

function parseStxAddress(addr) {
  const a = addr.includes('.') ? addr.slice(0, addr.indexOf('.')) : addr;
  if (a[0] !== 'S') throw new Error('Invalid STX address: ' + a);
  const version = C32.indexOf(a[1].toUpperCase());
  const decoded = c32DecodeFixed(a.slice(2), 24);
  return { version, hash160: decoded.subarray(0, 20) };
}

function stxAddress(pubkeyHex) {
  const pub = Buffer.from(pubkeyHex, 'hex');
  const sha = createHash('sha256').update(pub).digest();
  const h160 = createHash('ripemd160').update(sha).digest();
  const version = 22; // mainnet SP
  const payload = Buffer.concat([Buffer.from([version]), h160]);
  const h1 = createHash('sha256').update(payload).digest();
  const checksum = createHash('sha256').update(h1).digest().subarray(0, 4);
  return 'S' + C32[version] + c32encode(Buffer.concat([h160, checksum]));
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

// ── Canonical pipe key ────────────────────────────────────────────────────────
// Uses Clarity's to-consensus-buff? ordering:
//   Standard principal: 0x05 <version> <hash160>        (22 bytes)
//   Contract principal: 0x06 <version> <hash160> <len> <name>  (22+1+n bytes)
// Since 0x05 < 0x06, standard principals are always principal-1 vs contract principals.

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

// ── Auth header ───────────────────────────────────────────────────────────────
function sha256(data) { return createHash('sha256').update(data).digest(); }

function buildAuthHeader(privHex, pubHex, addr, action, messageId) {
  const payload = { action, address: addr, timestamp: Date.now(), ...(messageId ? { messageId } : {}) };
  const hash = sha256(Buffer.from(JSON.stringify(payload)));
  const sig = secp256k1.sign(hash, Buffer.from(privHex, 'hex'), { lowS: true });
  return Buffer.from(JSON.stringify({
    pubkey: pubHex, payload,
    signature: Buffer.from(sig.toCompactRawBytes()).toString('hex'),
  })).toString('base64');
}

// ── API helper ────────────────────────────────────────────────────────────────
async function api(method, path, body, headers = {}) {
  const opts = { method, headers: { ...headers } };
  if (body) { opts.headers['content-type'] = 'application/json'; opts.body = JSON.stringify(body); }
  const r = await fetch(`${SERVER}${path}`, opts);
  const text = await r.text();
  let data; try { data = JSON.parse(text); } catch { data = text; }
  return { status: r.status, ok: r.ok, data };
}

function assert(condition, msg) {
  if (!condition) throw new Error('ASSERTION FAILED: ' + msg);
}

// ── Main test ─────────────────────────────────────────────────────────────────
async function run() {
  console.log('═══════════════════════════════════════════════════════');
  console.log('  Stackmail E2E Test — reservoir model');
  console.log('═══════════════════════════════════════════════════════\n');

  const alice = genKeypair();
  const bob   = genKeypair();

  console.log(`Alice:     ${alice.addr}`);
  console.log(`Bob:       ${bob.addr}`);
  console.log(`Reservoir: ${RESERVOIR}\n`);

  // ─── 1. Health ──────────────────────────────────────────────────────────────
  console.log('1. Health check...');
  const health = await api('GET', '/health');
  assert(health.ok, 'health check failed: ' + JSON.stringify(health.data));
  console.log('   ✓', health.data, '\n');

  // ─── 2. Bob registers mailbox ───────────────────────────────────────────────
  console.log('2. Bob registers mailbox with server (stores pubkey)...');
  const bobAuth = buildAuthHeader(bob.privHex, bob.pubHex, bob.addr, 'get-inbox');
  const bobInbox = await api('GET', '/inbox', null, { 'x-stackmail-auth': bobAuth });
  console.log(`   GET /inbox → ${bobInbox.status}`);
  assert(bobInbox.status === 200 || bobInbox.status === 404, `unexpected status ${bobInbox.status}: ${JSON.stringify(bobInbox.data)}`);

  // ─── 3. Fetch Bob's payment info ────────────────────────────────────────────
  console.log('\n3. Alice fetches Bob\'s payment info...');
  const payInfo = await api('GET', `/payment-info/${bob.addr}`);
  assert(payInfo.ok, `payment-info failed: ${JSON.stringify(payInfo.data)}`);
  assert(payInfo.data.recipientPublicKey, 'missing recipientPublicKey');
  assert(payInfo.data.serverAddress === RESERVOIR, `server address mismatch: got ${payInfo.data.serverAddress}, want ${RESERVOIR}`);
  const bobPubkey = payInfo.data.recipientPublicKey;
  console.log('   ✓ recipientPublicKey:', bobPubkey.slice(0, 20) + '...');
  console.log('   ✓ serverAddress (reservoir):', payInfo.data.serverAddress);
  console.log('   ✓ price:', payInfo.data.amount, '\n');

  // ─── 4. Generate HTLC secret and encrypt ────────────────────────────────────
  console.log('4. Alice generates HTLC secret and encrypts message for Bob...');
  const secretHex     = randomBytes(32).toString('hex');
  const hashedSecret  = hashSecret(secretHex);  // sha256(secret_bytes) hex, no 0x prefix
  const encPayload    = encryptMail(
    { v: 1, secret: secretHex, subject: 'Hello from Alice', body: 'First message via Stackmail reservoir model 🚀' },
    bobPubkey,
  );
  console.log('   ✓ hashedSecret:', hashedSecret.slice(0, 20) + '...');
  console.log('   ✓ encryptedPayload.epk:', encPayload.epk.slice(0, 20) + '...\n');

  // ─── 5. Build SIP-018 payment proof ─────────────────────────────────────────
  console.log('5. Alice builds SIP-018 payment proof (Alice → Reservoir)...');
  // Pipe: Alice (standard principal) <-> Reservoir (contract principal)
  // Since 0x05 < 0x06, Alice is always principal-1, Reservoir is always principal-2.
  const pipeKey = canonicalPipeKey(TOKEN, alice.addr, RESERVOIR);
  console.log('   pipe-key principal-1:', pipeKey['principal-1'], '(Alice)');
  console.log('   pipe-key principal-2:', pipeKey['principal-2'], '(Reservoir)');
  assert(pipeKey['principal-1'] === alice.addr, 'Alice should be principal-1 (standard < contract)');
  assert(pipeKey['principal-2'] === RESERVOIR,  'Reservoir should be principal-2');

  // Simulate a channel: Alice funded 100,000 TEST; server starts at 0
  const aliceFunded      = 100_000n;
  const reservoirNewBal  = MESSAGE_PRICE;    // server gains price
  const aliceNewBal      = aliceFunded - MESSAGE_PRICE;  // alice loses price
  const nonce            = 1;

  // Alice signs from her own perspective (she is principal-1)
  const aliceState = {
    pipeKey,
    forPrincipal: alice.addr,     // Alice is signing (she's principal-1)
    myBalance:    aliceNewBal.toString(),
    theirBalance: reservoirNewBal.toString(),
    nonce:        nonce.toString(),
    action:       '1',            // ACTION_TRANSFER
    actor:        alice.addr,
    hashedSecret,
    validAfter:   null,
  };
  const aliceSig = await sip018Sign(SF_CONTRACT, buildTransferMessage(aliceState), alice.privHex, CHAIN_ID);
  console.log('   ✓ Alice signature:', aliceSig.slice(0, 30) + '...');

  // Self-check: verify signature from server's perspective
  const serverState = {
    pipeKey,
    forPrincipal: RESERVOIR,      // Reservoir is principal-2
    myBalance:    reservoirNewBal.toString(),
    theirBalance: aliceNewBal.toString(),
    nonce:        nonce.toString(),
    action:       '1',
    actor:        alice.addr,
    hashedSecret,
    validAfter:   null,
  };
  const verified = await sip018Verify(SF_CONTRACT, buildTransferMessage(serverState), aliceSig, alice.addr, CHAIN_ID);
  assert(verified, 'SIP-018 self-check failed');
  console.log('   ✓ SIP-018 signature verified\n');

  // ─── 6. Alice sends message to Bob ──────────────────────────────────────────
  console.log('6. Alice sends message to Bob...');
  const proof = {
    contractId:    SF_CONTRACT,
    pipeKey,
    forPrincipal:  RESERVOIR,     // From reservoir's perspective: forPrincipal = reservoir
    withPrincipal: alice.addr,
    myBalance:     reservoirNewBal.toString(),
    theirBalance:  aliceNewBal.toString(),
    nonce:         nonce.toString(),
    action:        '1',
    actor:         alice.addr,
    hashedSecret,
    theirSignature: aliceSig,
    validAfter:    null,
  };
  const proofHeader = Buffer.from(JSON.stringify(proof)).toString('base64url');

  const sendResp = await api(
    'POST',
    `/messages/${bob.addr}`,
    { from: alice.addr, encryptedPayload: encPayload },
    { 'x-stackmail-payment': proofHeader },
  );
  if (!sendResp.ok) {
    console.error('   Send failed:', sendResp.status, JSON.stringify(sendResp.data));
    process.exit(1);
  }
  const { messageId } = sendResp.data;
  assert(messageId, 'no messageId in response');
  console.log('   ✓ Message sent! ID:', messageId, '\n');

  // ─── 7. Bob polls inbox ─────────────────────────────────────────────────────
  console.log('7. Bob polls inbox...');
  const bobAuth2 = buildAuthHeader(bob.privHex, bob.pubHex, bob.addr, 'get-inbox');
  const inbox = await api('GET', '/inbox', null, { 'x-stackmail-auth': bobAuth2 });
  assert(inbox.ok, `inbox failed: ${JSON.stringify(inbox.data)}`);
  const messages = inbox.data.messages ?? [];
  assert(messages.length > 0, 'inbox is empty');
  const msg = messages.find(m => m.id === messageId);
  assert(msg, 'message not found in inbox');
  console.log(`   ✓ ${messages.length} message(s) in inbox`);
  console.log('   ✓ Found message:', msg.id, '| amount:', msg.amount, '\n');

  // ─── 8. Bob previews message ────────────────────────────────────────────────
  console.log('8. Bob previews message (gets encrypted payload)...');
  const bobAuth3 = buildAuthHeader(bob.privHex, bob.pubHex, bob.addr, 'get-message', messageId);
  const preview = await api('GET', `/inbox/${messageId}/preview`, null, { 'x-stackmail-auth': bobAuth3 });
  assert(preview.ok, `preview failed: ${JSON.stringify(preview.data)}`);
  assert(preview.data.encryptedPayload, 'no encryptedPayload');
  console.log('   ✓ from:', preview.data.from);
  console.log('   ✓ amount:', preview.data.amount);

  // Bob decrypts with his private key
  const decrypted = decryptMail(preview.data.encryptedPayload, bob.privHex);
  assert(decrypted.v === 1, 'bad payload version');
  assert(decrypted.secret === secretHex, 'decrypted secret mismatch');
  assert(verifySecretHash(decrypted.secret, preview.data.hashedSecret), 'secret hash mismatch');
  console.log('   ✓ Decrypted subject:', decrypted.subject);
  console.log('   ✓ Decrypted body:', decrypted.body);
  console.log('   ✓ Secret verified against payment commitment\n');

  // ─── 9. Bob claims ──────────────────────────────────────────────────────────
  console.log('9. Bob claims message (reveals secret to unlock payment)...');
  const bobAuth4 = buildAuthHeader(bob.privHex, bob.pubHex, bob.addr, 'claim-message', messageId);
  const claim = await api(
    'POST',
    `/inbox/${messageId}/claim`,
    { secret: decrypted.secret },
    { 'x-stackmail-auth': bobAuth4 },
  );
  assert(claim.ok, `claim failed: ${JSON.stringify(claim.data)}`);
  const claimedMsg = claim.data.message;
  assert(claimedMsg, 'no message in claim response');
  console.log('   ✓ Claimed! From:', claimedMsg.from);
  console.log('   ✓ Amount:', claimedMsg.amount, '\n');

  // ─── 10. Verify claimed status ──────────────────────────────────────────────
  console.log('10. Verifying message is marked claimed...');
  const bobAuth5 = buildAuthHeader(bob.privHex, bob.pubHex, bob.addr, 'get-inbox');
  const inbox2 = await api('GET', '/inbox?claimed=true', null, { 'x-stackmail-auth': bobAuth5 });
  const claimedEntry = (inbox2.data.messages ?? []).find(m => m.id === messageId);
  assert(claimedEntry?.claimed === true, 'message should be claimed');
  console.log('   ✓ claimed flag:', claimedEntry.claimed);

  console.log('\n╔════════════════════════════════════════════╗');
  console.log('║  ✅  E2E TEST PASSED (reservoir model)     ║');
  console.log('╚════════════════════════════════════════════╝\n');

  console.log('Deployment summary:');
  console.log(`  sm-test-token : ${TOKEN}`);
  console.log(`  sm-stackflow  : ${SF_CONTRACT}`);
  console.log(`  sm-reservoir  : ${RESERVOIR}`);
  console.log(`  Server URL    : ${SERVER}`);
  console.log('  Alice →', alice.addr);
  console.log('  Bob   →', bob.addr);
}

run().catch(e => { console.error('\n✗ E2E TEST FAILED:', e.message); process.exit(1); });
