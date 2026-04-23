/**
 * Signed prekey verification tests — verify that signed prekeys
 * can be validated and that tampered/wrong-key prekeys are rejected.
 */

import { describe, it, expect } from "vitest";
import * as crypto from "crypto";

import {
  generateKeyPair,
  publicKeyHex,
  signCanonicalHash,
  verifyCanonicalHash,
} from "../../src/crypto/ed25519";
import {
  generateX25519KeyPair,
  x25519PublicKeyHex,
} from "../../src/crypto/x25519";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

interface SignedPrekey {
  prekey_pub: string;       // X25519 public key hex
  signature: string;        // ED25519 signature over prekey
  created_at: number;
  rotation_interval: number; // seconds
}

/**
 * Create a signed prekey: sign the X25519 public key with the ED25519 identity key.
 */
function createSignedPrekey(
  identityPriv: crypto.KeyObject,
  rotationInterval: number = 604800,
): SignedPrekey {
  const prekeyPair = generateX25519KeyPair();
  const prekeyPubHex = x25519PublicKeyHex(prekeyPair.publicKey);

  // Sign the hash of the prekey public key
  const hash = crypto.createHash("sha256").update(prekeyPubHex).digest("hex");
  const signature = signCanonicalHash(hash, identityPriv);

  return {
    prekey_pub: prekeyPubHex,
    signature,
    created_at: Math.floor(Date.now() / 1000),
    rotation_interval: rotationInterval,
  };
}

/**
 * Verify a signed prekey against an identity public key.
 */
function verifySignedPrekey(
  prekey: SignedPrekey,
  identityPub: crypto.KeyObject,
): boolean {
  const hash = crypto.createHash("sha256").update(prekey.prekey_pub).digest("hex");
  return verifyCanonicalHash(hash, prekey.signature, identityPub);
}

/**
 * Check if a prekey needs rotation based on its creation time.
 */
function isPrekeyExpired(prekey: SignedPrekey): boolean {
  const now = Math.floor(Date.now() / 1000);
  return now > prekey.created_at + prekey.rotation_interval;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("Signed prekey verification", () => {
  // 1
  it("valid signed prekey verifies", () => {
    const identity = generateKeyPair();
    const prekey = createSignedPrekey(identity.privateKey);

    const valid = verifySignedPrekey(prekey, identity.publicKey);
    expect(valid).toBe(true);
  });

  // 2
  it("tampered prekey fails verification", () => {
    const identity = generateKeyPair();
    const prekey = createSignedPrekey(identity.privateKey);

    // Tamper with the prekey public key
    const tampered = { ...prekey };
    tampered.prekey_pub = crypto.randomBytes(32).toString("hex");

    const valid = verifySignedPrekey(tampered, identity.publicKey);
    expect(valid).toBe(false);
  });

  // 3
  it("wrong signing key fails verification", () => {
    const identity = generateKeyPair();
    const wrongIdentity = generateKeyPair();
    const prekey = createSignedPrekey(identity.privateKey);

    // Verify with the wrong identity key
    const valid = verifySignedPrekey(prekey, wrongIdentity.publicKey);
    expect(valid).toBe(false);
  });

  // 4
  it("expired prekey detected by rotation check", () => {
    const identity = generateKeyPair();

    // Create a prekey with 0-second rotation interval
    const prekey = createSignedPrekey(identity.privateKey, 0);
    // Set created_at to the past to guarantee expiry
    prekey.created_at = prekey.created_at - 10;

    const expired = isPrekeyExpired(prekey);
    expect(expired).toBe(true);

    // Verify signature is still valid (expiry is a policy check, not crypto)
    const sigValid = verifySignedPrekey(prekey, identity.publicKey);
    expect(sigValid).toBe(true);
  });
});
