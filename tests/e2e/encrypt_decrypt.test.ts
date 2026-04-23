import { describe, it, expect } from "vitest";

import { generateKeyPair, publicKeyHex } from "../../src/crypto/ed25519";
import { generateX25519KeyPair, deriveSharedSecret } from "../../src/crypto/x25519";
import { deriveChannelKeys } from "../../src/e2e/channel_keys";
import { encryptMessage, EncryptedEnvelope } from "../../src/e2e/encrypt";
import { decryptMessage } from "../../src/e2e/decrypt";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function setupChannel() {
  const aliceSig = generateKeyPair();
  const bobSig = generateKeyPair();
  const aliceEnc = generateX25519KeyPair();
  const bobEnc = generateX25519KeyPair();

  const shared = deriveSharedSecret(aliceEnc.privateKey, bobEnc.publicKey);
  const aliceKeys = deriveChannelKeys(shared, "deal-001", true);
  const bobKeys = deriveChannelKeys(shared, "deal-001", false);

  const meta = {
    deal_id: "deal-001",
    sender_id: publicKeyHex(aliceSig.publicKey),
    receiver_id: publicKeyHex(bobSig.publicKey),
    msg_type: "trade_offer",
  };

  return { aliceSig, bobSig, aliceKeys, bobKeys, meta };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("AEAD encrypt/decrypt", () => {
  it("encrypt then decrypt returns original plaintext", () => {
    const { aliceSig, bobSig, aliceKeys, bobKeys, meta } = setupChannel();
    const plaintext = JSON.stringify({ price: "0.0005", amount: "100" });

    const envelope = encryptMessage(plaintext, aliceKeys, 1, aliceSig.privateKey, meta);
    const result = decryptMessage(envelope, bobKeys, aliceSig.publicKey);

    expect(result.plaintext).toBe(plaintext);
    expect(result.verified).toBe(true);
  });

  it("wrong key fails decrypt", () => {
    const { aliceSig, aliceKeys, meta } = setupChannel();
    const plaintext = '{"data":"secret"}';

    const envelope = encryptMessage(plaintext, aliceKeys, 1, aliceSig.privateKey, meta);

    // Use unrelated channel keys to try decrypting
    const wrongEnc = generateX25519KeyPair();
    const wrongShared = deriveSharedSecret(wrongEnc.privateKey, generateX25519KeyPair().publicKey);
    const wrongKeys = deriveChannelKeys(wrongShared, "deal-001", false);

    expect(() => decryptMessage(envelope, wrongKeys, aliceSig.publicKey)).toThrow();
  });

  it("modified ciphertext fails auth tag", () => {
    const { aliceSig, aliceKeys, bobKeys, meta } = setupChannel();
    const envelope = encryptMessage('{"x":1}', aliceKeys, 1, aliceSig.privateKey, meta);

    // Tamper with ciphertext
    const tampered: EncryptedEnvelope = {
      ...envelope,
      ciphertext: "ff" + envelope.ciphertext.slice(2),
    };

    expect(() => decryptMessage(tampered, bobKeys, aliceSig.publicKey)).toThrow();
  });

  it("modified tag fails", () => {
    const { aliceSig, aliceKeys, bobKeys, meta } = setupChannel();
    const envelope = encryptMessage('{"x":1}', aliceKeys, 1, aliceSig.privateKey, meta);

    const tampered: EncryptedEnvelope = {
      ...envelope,
      tag: "ff".repeat(16),
    };

    expect(() => decryptMessage(tampered, bobKeys, aliceSig.publicKey)).toThrow();
  });

  it("different nonce produces different ciphertext", () => {
    const { aliceSig, aliceKeys, meta } = setupChannel();
    const plaintext = '{"same":"data"}';

    const e1 = encryptMessage(plaintext, aliceKeys, 1, aliceSig.privateKey, meta);
    const e2 = encryptMessage(plaintext, aliceKeys, 2, aliceSig.privateKey, meta);

    expect(e1.nonce).not.toBe(e2.nonce);
    expect(e1.ciphertext).not.toBe(e2.ciphertext);
  });

  it("seq_no is tracked correctly in envelope", () => {
    const { aliceSig, aliceKeys, meta } = setupChannel();

    const e1 = encryptMessage("{}", aliceKeys, 42, aliceSig.privateKey, meta);
    expect(e1.seq_no).toBe(42);
    expect(e1.version).toBe(1);
  });

  it("signature verifies on envelope header", () => {
    const { aliceSig, aliceKeys, bobKeys, meta } = setupChannel();
    const envelope = encryptMessage('{"test":true}', aliceKeys, 1, aliceSig.privateKey, meta);

    const result = decryptMessage(envelope, bobKeys, aliceSig.publicKey);
    expect(result.verified).toBe(true);
  });

  it("wrong sender key fails signature verification", () => {
    const { aliceSig, aliceKeys, bobKeys, meta } = setupChannel();
    const envelope = encryptMessage('{"test":true}', aliceKeys, 1, aliceSig.privateKey, meta);

    // Verify with a different public key — signature should not match
    const impostor = generateKeyPair();
    const result = decryptMessage(envelope, bobKeys, impostor.publicKey);
    expect(result.verified).toBe(false);
    // Plaintext still decrypts (AEAD key is correct), but signature fails
    expect(result.plaintext).toBe('{"test":true}');
  });

  it("large payload works", () => {
    const { aliceSig, aliceKeys, bobKeys, meta } = setupChannel();
    const largePayload = JSON.stringify({ data: "x".repeat(100_000) });

    const envelope = encryptMessage(largePayload, aliceKeys, 1, aliceSig.privateKey, meta);
    const result = decryptMessage(envelope, bobKeys, aliceSig.publicKey);

    expect(result.plaintext).toBe(largePayload);
    expect(result.verified).toBe(true);
  });

  it("empty payload works", () => {
    const { aliceSig, aliceKeys, bobKeys, meta } = setupChannel();

    const envelope = encryptMessage("", aliceKeys, 1, aliceSig.privateKey, meta);
    const result = decryptMessage(envelope, bobKeys, aliceSig.publicKey);

    expect(result.plaintext).toBe("");
    expect(result.verified).toBe(true);
  });
});
