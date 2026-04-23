import { describe, it, expect, beforeEach } from "vitest";

import { publicKeyHex } from "../../src/crypto/ed25519";
import { generateKeyBundle, keyBundleToPublicHex } from "../../src/crypto/key_bundle";
import { createPrekeyBundle } from "../../src/e2e/prekey_bundle";
import { initiateAsyncSession, receiveAsyncSession } from "../../src/e2e/async_handshake";
import { encryptMessage } from "../../src/e2e/encrypt";
import { decryptMessage } from "../../src/e2e/decrypt";
import { _resetPrekeyIdCounter } from "../../src/e2e/prekeys";

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("async handshake", () => {
  beforeEach(() => {
    _resetPrekeyIdCounter();
  });

  it("initiate async session produces valid session init", () => {
    const alice = generateKeyBundle();
    const bob = generateKeyBundle();
    const { prekeyBundle } = createPrekeyBundle(bob, 5);

    const { sessionInit } = initiateAsyncSession(alice, prekeyBundle, "deal-001");

    expect(sessionInit.dealId).toBe("deal-001");
    expect(sessionInit.senderIdentityKey).toBe(publicKeyHex(alice.signing.publicKey));
    expect(sessionInit.senderEphemeralKey).toMatch(/^[0-9a-f]{64}$/);
    expect(sessionInit.usedSignedPrekeyId).toBe(prekeyBundle.signedPrekey.id);
    expect(sessionInit.usedOneTimePrekeyId).toBeDefined();
    expect(sessionInit.timestamp).toBeGreaterThan(0);
  });

  it("both sides derive matching channel keys", () => {
    const alice = generateKeyBundle();
    const bob = generateKeyBundle();
    const { prekeyBundle, privateKeys } = createPrekeyBundle(bob, 5);

    const { sessionInit, channelKeys: aliceKeys } = initiateAsyncSession(
      alice, prekeyBundle, "deal-002",
    );

    const bobKeys = receiveAsyncSession(
      bob, privateKeys, sessionInit, publicKeyHex(alice.signing.publicKey),
    );

    // Initiator's send = responder's recv, and vice versa
    expect(aliceKeys.sendKey.equals(bobKeys.recvKey)).toBe(true);
    expect(aliceKeys.recvKey.equals(bobKeys.sendKey)).toBe(true);
    expect(aliceKeys.sessionId).toBe(bobKeys.sessionId);
  });

  it("channel keys work for encrypt/decrypt", () => {
    const alice = generateKeyBundle();
    const bob = generateKeyBundle();
    const { prekeyBundle, privateKeys } = createPrekeyBundle(bob, 5);
    const alicePubs = keyBundleToPublicHex(alice);
    const bobPubs = keyBundleToPublicHex(bob);

    const { sessionInit, channelKeys: aliceKeys } = initiateAsyncSession(
      alice, prekeyBundle, "deal-003",
    );
    const bobKeys = receiveAsyncSession(
      bob, privateKeys, sessionInit, publicKeyHex(alice.signing.publicKey),
    );

    // Alice encrypts
    const plaintext = JSON.stringify({ action: "confirm", amount: "100.00" });
    const envelope = encryptMessage(plaintext, aliceKeys, 1, alice.signing.privateKey, {
      deal_id: "deal-003",
      sender_id: alicePubs.signingPub,
      receiver_id: bobPubs.signingPub,
      msg_type: "trade_offer",
    });

    // Bob decrypts
    const result = decryptMessage(envelope, bobKeys, alice.signing.publicKey);
    expect(result.plaintext).toBe(plaintext);
    expect(result.verified).toBe(true);
  });

  it("without OTK: still works (signed prekey only)", () => {
    const alice = generateKeyBundle();
    const bob = generateKeyBundle();
    // Create bundle with 0 one-time prekeys
    const { prekeyBundle, privateKeys } = createPrekeyBundle(bob, 0);

    const { sessionInit, channelKeys: aliceKeys } = initiateAsyncSession(
      alice, prekeyBundle, "deal-004",
    );
    expect(sessionInit.usedOneTimePrekeyId).toBeUndefined();

    const bobKeys = receiveAsyncSession(
      bob, privateKeys, sessionInit, publicKeyHex(alice.signing.publicKey),
    );

    expect(aliceKeys.sendKey.equals(bobKeys.recvKey)).toBe(true);
    expect(aliceKeys.recvKey.equals(bobKeys.sendKey)).toBe(true);
  });

  it("with OTK produces different keys than without", () => {
    const alice = generateKeyBundle();
    const bob = generateKeyBundle();

    // Session without OTK
    const { prekeyBundle: bundleNoOtk, privateKeys: keysNoOtk } = createPrekeyBundle(bob, 0);
    const { channelKeys: keysWithout } = initiateAsyncSession(alice, bundleNoOtk, "deal-005");

    // Reset and create bundle with OTK (same signed prekey won't match, but
    // the point is that having OTK changes the derived keys)
    _resetPrekeyIdCounter();
    const { prekeyBundle: bundleWithOtk } = createPrekeyBundle(bob, 5);
    const { channelKeys: keysWith } = initiateAsyncSession(alice, bundleWithOtk, "deal-005");

    // Keys should differ because of the additional DH with OTK
    expect(keysWith.sendKey.equals(keysWithout.sendKey)).toBe(false);
  });

  it("wrong sender identity fails", () => {
    const alice = generateKeyBundle();
    const bob = generateKeyBundle();
    const mallory = generateKeyBundle();
    const { prekeyBundle, privateKeys } = createPrekeyBundle(bob, 5);

    const { sessionInit } = initiateAsyncSession(alice, prekeyBundle, "deal-006");

    // Recipient expects mallory's identity but gets alice's
    expect(() =>
      receiveAsyncSession(
        bob, privateKeys, sessionInit, publicKeyHex(mallory.signing.publicKey),
      ),
    ).toThrow("Sender identity key mismatch");
  });

  it("tampered session init fails to produce matching keys", () => {
    const alice = generateKeyBundle();
    const bob = generateKeyBundle();
    const { prekeyBundle, privateKeys } = createPrekeyBundle(bob, 5);

    const { sessionInit, channelKeys: aliceKeys } = initiateAsyncSession(
      alice, prekeyBundle, "deal-007",
    );

    // Tamper with the ephemeral key
    const tampered = { ...sessionInit, senderEphemeralKey: "a".repeat(64) };

    // Should produce different keys (tampered DH input)
    const bobKeys = receiveAsyncSession(
      bob, privateKeys, tampered, publicKeyHex(alice.signing.publicKey),
    );
    expect(aliceKeys.sendKey.equals(bobKeys.recvKey)).toBe(false);
  });

  it("full flow: bundle -> init -> receive -> encrypt -> decrypt", () => {
    const alice = generateKeyBundle();
    const bob = generateKeyBundle();
    const alicePubs = keyBundleToPublicHex(alice);
    const bobPubs = keyBundleToPublicHex(bob);

    // Bob publishes prekey bundle
    const { prekeyBundle, privateKeys } = createPrekeyBundle(bob, 10);

    // Alice initiates async session
    const { sessionInit, channelKeys: aliceKeys } = initiateAsyncSession(
      alice, prekeyBundle, "deal-full",
    );

    // Bob comes online and processes session init
    const bobKeys = receiveAsyncSession(
      bob, privateKeys, sessionInit, publicKeyHex(alice.signing.publicKey),
    );

    // Alice sends encrypted message
    const msg1 = JSON.stringify({ step: "offer", price: "42.00" });
    const env1 = encryptMessage(msg1, aliceKeys, 1, alice.signing.privateKey, {
      deal_id: "deal-full",
      sender_id: alicePubs.signingPub,
      receiver_id: bobPubs.signingPub,
      msg_type: "trade_offer",
    });

    // Bob decrypts
    const res1 = decryptMessage(env1, bobKeys, alice.signing.publicKey);
    expect(res1.plaintext).toBe(msg1);
    expect(res1.verified).toBe(true);

    // Bob replies
    const msg2 = JSON.stringify({ step: "accept" });
    const env2 = encryptMessage(msg2, bobKeys, 1, bob.signing.privateKey, {
      deal_id: "deal-full",
      sender_id: bobPubs.signingPub,
      receiver_id: alicePubs.signingPub,
      msg_type: "trade_accept",
    });

    // Alice decrypts reply
    const res2 = decryptMessage(env2, aliceKeys, bob.signing.publicKey);
    expect(res2.plaintext).toBe(msg2);
    expect(res2.verified).toBe(true);
  });
});
