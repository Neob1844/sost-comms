/**
 * Wrong-key rejection tests — verify that encrypted envelopes
 * cannot be decrypted with incorrect keys.
 *
 * These tests use the X25519 + HKDF + ChaCha20-Poly1305 stack
 * that the e2e modules will use. Since those modules are being
 * built in parallel, we use Node.js crypto directly here.
 */

import { describe, it, expect } from "vitest";
import * as crypto from "crypto";

import { generateX25519KeyPair, deriveSharedSecret } from "../../src/crypto/x25519";
import { deriveChannelKeys } from "../../src/e2e/channel_keys";
import { generateKeyPair, publicKeyHex, signMessage } from "../../src/crypto/ed25519";

// ---------------------------------------------------------------------------
// Helpers — ChaCha20-Poly1305 encrypt/decrypt
// ---------------------------------------------------------------------------

function encrypt(key: Buffer, plaintext: string): { nonce: string; ciphertext: string; tag: string } {
  const nonce = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("chacha20-poly1305", key, nonce, { authTagLength: 16 });
  const enc = Buffer.concat([cipher.update(plaintext, "utf-8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    nonce: nonce.toString("hex"),
    ciphertext: enc.toString("hex"),
    tag: tag.toString("hex"),
  };
}

function decrypt(key: Buffer, nonceHex: string, ciphertextHex: string, tagHex: string): string {
  const decipher = crypto.createDecipheriv(
    "chacha20-poly1305",
    key,
    Buffer.from(nonceHex, "hex"),
    { authTagLength: 16 },
  );
  decipher.setAuthTag(Buffer.from(tagHex, "hex"));
  const dec = Buffer.concat([
    decipher.update(Buffer.from(ciphertextHex, "hex")),
    decipher.final(),
  ]);
  return dec.toString("utf-8");
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("Wrong key rejection", () => {
  const dealId = "deal_wrongkey_test";

  // 1
  it("encrypt with key A, decrypt with key B fails", () => {
    const aliceX = generateX25519KeyPair();
    const bobX = generateX25519KeyPair();
    const eveX = generateX25519KeyPair();

    // Alice and Bob derive shared secret
    const sharedAB = deriveSharedSecret(aliceX.privateKey, bobX.publicKey);
    const keysAlice = deriveChannelKeys(sharedAB, dealId, true);

    // Eve derives a different shared secret with Bob
    const sharedEB = deriveSharedSecret(eveX.privateKey, bobX.publicKey);
    const keysEve = deriveChannelKeys(sharedEB, dealId, true);

    // Alice encrypts
    const plaintext = "gold_amount=0.05";
    const encrypted = encrypt(keysAlice.sendKey, plaintext);

    // Eve tries to decrypt with her key — should fail
    expect(() => {
      decrypt(keysEve.sendKey, encrypted.nonce, encrypted.ciphertext, encrypted.tag);
    }).toThrow();
  });

  // 2
  it("encrypt for recipient A, try decrypt as recipient B fails", () => {
    const aliceX = generateX25519KeyPair();
    const bobX = generateX25519KeyPair();
    const carolX = generateX25519KeyPair();

    // Alice-Bob channel
    const sharedAB = deriveSharedSecret(aliceX.privateKey, bobX.publicKey);
    const keysAliceToBob = deriveChannelKeys(sharedAB, dealId, true);

    // Alice-Carol channel (different shared secret)
    const sharedAC = deriveSharedSecret(aliceX.privateKey, carolX.publicKey);
    const keysCarol = deriveChannelKeys(sharedAC, dealId, false);

    // Alice encrypts for Bob
    const plaintext = "settlement_tx=0xabc";
    const encrypted = encrypt(keysAliceToBob.sendKey, plaintext);

    // Carol tries to decrypt — should fail
    expect(() => {
      decrypt(keysCarol.recvKey, encrypted.nonce, encrypted.ciphertext, encrypted.tag);
    }).toThrow();
  });

  // 3
  it("modified envelope header invalidates signature", () => {
    const kp = generateKeyPair();
    const pubHex = publicKeyHex(kp.publicKey);

    // Build a header and sign it
    const header = {
      ciphertext: crypto.randomBytes(64).toString("hex"),
      deal_id: dealId,
      msg_type: "trade_offer",
      nonce: crypto.randomBytes(12).toString("hex"),
      receiver_id: crypto.randomBytes(32).toString("hex"),
      sender_id: pubHex,
      seq_no: 0,
      session_id: crypto.randomBytes(16).toString("hex"),
      tag: crypto.randomBytes(16).toString("hex"),
      timestamp: Math.floor(Date.now() / 1000),
      version: 1,
    };

    const headerStr = JSON.stringify(header);
    const signature = signMessage(headerStr, kp.privateKey);

    // Tamper with the deal_id
    const tampered = { ...header, deal_id: "deal_tampered" };
    const tamperedStr = JSON.stringify(tampered);

    // Verify original works
    const hashOrig = crypto.createHash("sha256").update(headerStr).digest();
    const validOrig = crypto.verify(null, hashOrig, kp.publicKey, Buffer.from(signature, "hex"));
    expect(validOrig).toBe(true);

    // Verify tampered fails
    const hashTamp = crypto.createHash("sha256").update(tamperedStr).digest();
    const validTamp = crypto.verify(null, hashTamp, kp.publicKey, Buffer.from(signature, "hex"));
    expect(validTamp).toBe(false);
  });

  // 4
  it("correct key succeeds", () => {
    const aliceX = generateX25519KeyPair();
    const bobX = generateX25519KeyPair();

    // Both derive the same shared secret
    const sharedA = deriveSharedSecret(aliceX.privateKey, bobX.publicKey);
    const sharedB = deriveSharedSecret(bobX.privateKey, aliceX.publicKey);
    expect(sharedA.equals(sharedB)).toBe(true);

    const keysAlice = deriveChannelKeys(sharedA, dealId, true);
    const keysBob = deriveChannelKeys(sharedB, dealId, false);

    // Alice encrypts with her sendKey
    const plaintext = "deal_confirmed=true";
    const encrypted = encrypt(keysAlice.sendKey, plaintext);

    // Bob decrypts with his recvKey (should be same as Alice's sendKey)
    expect(keysAlice.sendKey.equals(keysBob.recvKey)).toBe(true);
    const decrypted = decrypt(keysBob.recvKey, encrypted.nonce, encrypted.ciphertext, encrypted.tag);
    expect(decrypted).toBe(plaintext);
  });
});
