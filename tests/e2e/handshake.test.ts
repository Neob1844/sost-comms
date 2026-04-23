import { describe, it, expect } from "vitest";

import { publicKeyHex } from "../../src/crypto/ed25519";
import { generateKeyBundle, keyBundleToPublicHex } from "../../src/crypto/key_bundle";
import {
  createHandshakeOffer,
  acceptHandshake,
  completeHandshake,
} from "../../src/e2e/handshake";
import { encryptMessage } from "../../src/e2e/encrypt";
import { decryptMessage } from "../../src/e2e/decrypt";

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("deal channel handshake", () => {
  it("handshake offer/accept produces matching channel keys", () => {
    const alice = generateKeyBundle();
    const bob = generateKeyBundle();

    const offer = createHandshakeOffer(alice, "deal-100");
    const { accept, channelKeys: bobKeys } = acceptHandshake(bob, offer);
    const aliceKeys = completeHandshake(alice, offer, accept);

    // Both sides derive the same underlying key material (just swapped)
    expect(aliceKeys.sendKey.equals(bobKeys.recvKey)).toBe(true);
    expect(aliceKeys.recvKey.equals(bobKeys.sendKey)).toBe(true);
  });

  it("both sides derive same sessionId", () => {
    const alice = generateKeyBundle();
    const bob = generateKeyBundle();

    const offer = createHandshakeOffer(alice, "deal-200");
    const { accept, channelKeys: bobKeys } = acceptHandshake(bob, offer);
    const aliceKeys = completeHandshake(alice, offer, accept);

    expect(aliceKeys.sessionId).toBe(bobKeys.sessionId);
    expect(aliceKeys.sessionId).toMatch(/^[0-9a-f]{32}$/);
  });

  it("sessionId is deterministic for same keys and deal", () => {
    const alice = generateKeyBundle();
    const bob = generateKeyBundle();

    const offer1 = createHandshakeOffer(alice, "deal-300");
    const { accept: accept1, channelKeys: bobKeys1 } = acceptHandshake(bob, offer1);
    const aliceKeys1 = completeHandshake(alice, offer1, accept1);

    const offer2 = createHandshakeOffer(alice, "deal-300");
    const { accept: accept2, channelKeys: bobKeys2 } = acceptHandshake(bob, offer2);
    const aliceKeys2 = completeHandshake(alice, offer2, accept2);

    expect(aliceKeys1.sessionId).toBe(aliceKeys2.sessionId);
  });

  it("different deals produce different keys", () => {
    const alice = generateKeyBundle();
    const bob = generateKeyBundle();

    const offer1 = createHandshakeOffer(alice, "deal-AAA");
    const { accept: accept1, channelKeys: bobKeys1 } = acceptHandshake(bob, offer1);
    const aliceKeys1 = completeHandshake(alice, offer1, accept1);

    const offer2 = createHandshakeOffer(alice, "deal-BBB");
    const { accept: accept2, channelKeys: bobKeys2 } = acceptHandshake(bob, offer2);
    const aliceKeys2 = completeHandshake(alice, offer2, accept2);

    expect(aliceKeys1.sendKey.equals(aliceKeys2.sendKey)).toBe(false);
    expect(aliceKeys1.sessionId).not.toBe(aliceKeys2.sessionId);
  });

  it("complete roundtrip: handshake → encrypt → decrypt", () => {
    const alice = generateKeyBundle();
    const bob = generateKeyBundle();

    // Handshake
    const offer = createHandshakeOffer(alice, "deal-e2e");
    const { accept, channelKeys: bobKeys } = acceptHandshake(bob, offer);
    const aliceKeys = completeHandshake(alice, offer, accept);

    const alicePubs = keyBundleToPublicHex(alice);
    const bobPubs = keyBundleToPublicHex(bob);

    // Alice encrypts a message to Bob
    const plaintext = JSON.stringify({ action: "confirm", amount: "50.00" });
    const envelope = encryptMessage(plaintext, aliceKeys, 1, alice.signing.privateKey, {
      deal_id: "deal-e2e",
      sender_id: alicePubs.signingPub,
      receiver_id: bobPubs.signingPub,
      msg_type: "trade_offer",
    });

    // Bob decrypts
    const result = decryptMessage(envelope, bobKeys, alice.signing.publicKey);
    expect(result.plaintext).toBe(plaintext);
    expect(result.verified).toBe(true);

    // Bob encrypts a reply to Alice
    const reply = JSON.stringify({ action: "accept" });
    const replyEnvelope = encryptMessage(reply, bobKeys, 1, bob.signing.privateKey, {
      deal_id: "deal-e2e",
      sender_id: bobPubs.signingPub,
      receiver_id: alicePubs.signingPub,
      msg_type: "trade_accept",
    });

    // Alice decrypts the reply
    const replyResult = decryptMessage(replyEnvelope, aliceKeys, bob.signing.publicKey);
    expect(replyResult.plaintext).toBe(reply);
    expect(replyResult.verified).toBe(true);
  });

  it("handshake offer contains correct public keys", () => {
    const alice = generateKeyBundle();
    const pubs = keyBundleToPublicHex(alice);

    const offer = createHandshakeOffer(alice, "deal-check");
    expect(offer.initiator_signing_pub).toBe(pubs.signingPub);
    expect(offer.initiator_encryption_pub).toBe(pubs.encryptionPub);
    expect(offer.deal_id).toBe("deal-check");
    expect(offer.timestamp).toBeGreaterThan(0);
  });
});
