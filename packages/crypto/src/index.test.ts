import { describe, it, expect } from 'vitest';
import { createECDH, randomBytes } from 'node:crypto';
import { encryptMail, decryptMail, hashSecret, verifySecretHash, type MailPayload } from './index.js';

function generateTestKeypair() {
  const ecdh = createECDH('secp256k1');
  ecdh.generateKeys();
  return {
    privkeyHex: ecdh.getPrivateKey('hex'),
    pubkeyHex: ecdh.getPublicKey('hex', 'compressed'),
  };
}

describe('encryptMail / decryptMail', () => {
  it('round-trips a full payload', () => {
    const { privkeyHex, pubkeyHex } = generateTestKeypair();
    const payload: MailPayload = {
      v: 1,
      secret: randomBytes(32).toString('hex'),
      subject: 'Test subject',
      body: 'Hello, world!',
    };
    expect(decryptMail(encryptMail(payload, pubkeyHex), privkeyHex)).toEqual(payload);
  });

  it('round-trips a payload without subject', () => {
    const { privkeyHex, pubkeyHex } = generateTestKeypair();
    const payload: MailPayload = { v: 1, secret: 'a'.repeat(64), body: 'body only' };
    expect(decryptMail(encryptMail(payload, pubkeyHex), privkeyHex)).toEqual(payload);
  });

  it('produces different ciphertext each time (random IV + ephemeral key)', () => {
    const { pubkeyHex } = generateTestKeypair();
    const payload: MailPayload = { v: 1, secret: 'a'.repeat(64), body: 'same message' };
    const enc1 = encryptMail(payload, pubkeyHex);
    const enc2 = encryptMail(payload, pubkeyHex);
    expect(enc1.iv).not.toBe(enc2.iv);
    expect(enc1.epk).not.toBe(enc2.epk);
    expect(enc1.data).not.toBe(enc2.data);
  });

  it('rejects decryption with wrong private key', () => {
    const { pubkeyHex } = generateTestKeypair();
    const { privkeyHex: wrongPrivkey } = generateTestKeypair();
    const payload: MailPayload = { v: 1, secret: 'a'.repeat(64), body: 'secret' };
    expect(() => decryptMail(encryptMail(payload, pubkeyHex), wrongPrivkey)).toThrow('decryption failed');
  });

  it('rejects corrupted ciphertext', () => {
    const { privkeyHex, pubkeyHex } = generateTestKeypair();
    const payload: MailPayload = { v: 1, secret: 'a'.repeat(64), body: 'data' };
    const encrypted = encryptMail(payload, pubkeyHex);
    const dataBytes = Buffer.from(encrypted.data, 'hex');
    dataBytes[10] ^= 0xff;
    expect(() => decryptMail({ ...encrypted, data: dataBytes.toString('hex') }, privkeyHex)).toThrow();
  });

  it('accepts pubkey with 0x prefix', () => {
    const { privkeyHex, pubkeyHex } = generateTestKeypair();
    const payload: MailPayload = { v: 1, secret: 'a'.repeat(64), body: 'test' };
    expect(decryptMail(encryptMail(payload, '0x' + pubkeyHex), privkeyHex)).toEqual(payload);
  });

  it('accepts privkey with 0x prefix', () => {
    const { privkeyHex, pubkeyHex } = generateTestKeypair();
    const payload: MailPayload = { v: 1, secret: 'a'.repeat(64), body: 'test' };
    expect(decryptMail(encryptMail(payload, pubkeyHex), '0x' + privkeyHex)).toEqual(payload);
  });

  it('throws on non-33-byte recipient pubkey', () => {
    expect(() =>
      encryptMail({ v: 1, secret: 'a'.repeat(64), body: '' }, 'deadbeef')
    ).toThrow('33 bytes');
  });

  it('throws on non-32-byte private key', () => {
    const { pubkeyHex } = generateTestKeypair();
    const payload: MailPayload = { v: 1, secret: 'a'.repeat(64), body: '' };
    expect(() => decryptMail(encryptMail(payload, pubkeyHex), 'deadbeef')).toThrow('32 bytes');
  });
});

describe('hashSecret / verifySecretHash', () => {
  it('hashSecret is deterministic', () => {
    const hex = randomBytes(32).toString('hex');
    expect(hashSecret(hex)).toBe(hashSecret(hex));
  });

  it('hashSecret differs for different inputs', () => {
    const a = randomBytes(32).toString('hex');
    const b = randomBytes(32).toString('hex');
    expect(hashSecret(a)).not.toBe(hashSecret(b));
  });

  it('verifySecretHash passes when hash matches', () => {
    const hex = randomBytes(32).toString('hex');
    expect(verifySecretHash(hex, hashSecret(hex))).toBe(true);
  });

  it('verifySecretHash fails with wrong secret', () => {
    const hex = randomBytes(32).toString('hex');
    const wrong = randomBytes(32).toString('hex');
    expect(verifySecretHash(wrong, hashSecret(hex))).toBe(false);
  });

  it('verifySecretHash is case-insensitive on hashedSecret', () => {
    const hex = randomBytes(32).toString('hex');
    expect(verifySecretHash(hex, hashSecret(hex).toUpperCase())).toBe(true);
  });

  it('verifySecretHash accepts 0x prefix on hashedSecret', () => {
    const hex = randomBytes(32).toString('hex');
    expect(verifySecretHash(hex, '0x' + hashSecret(hex))).toBe(true);
  });
});
