/**
 * SOST Comms — X25519 Key Exchange Module
 *
 * Uses Node.js built-in crypto (X25519 support since Node 15.x).
 * X25519 is a Diffie-Hellman key agreement scheme on Curve25519.
 */

import * as crypto from "crypto";

// ---------------------------------------------------------------------------
// Key generation
// ---------------------------------------------------------------------------

export interface X25519KeyPair {
  publicKey: crypto.KeyObject;
  privateKey: crypto.KeyObject;
}

/**
 * Generate a new X25519 key pair for key agreement.
 */
export function generateX25519KeyPair(): X25519KeyPair {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("x25519");
  return { publicKey, privateKey };
}

// ---------------------------------------------------------------------------
// Hex export
// ---------------------------------------------------------------------------

/**
 * Export the raw 32-byte X25519 public key as a hex string.
 */
export function x25519PublicKeyHex(key: crypto.KeyObject): string {
  const der = key.export({ type: "spki", format: "der" });
  // X25519 SPKI DER: prefix bytes then 32-byte raw key
  return der.subarray(der.length - 32).toString("hex");
}

/**
 * Export the raw 32-byte X25519 private key as a hex string.
 */
export function x25519PrivateKeyHex(key: crypto.KeyObject): string {
  const der = key.export({ type: "pkcs8", format: "der" });
  // X25519 PKCS8 DER: prefix bytes then 32-byte raw key
  return der.subarray(der.length - 32).toString("hex");
}

// ---------------------------------------------------------------------------
// Hex import
// ---------------------------------------------------------------------------

/** SPKI DER prefix for X25519 public keys (12 bytes) */
const X25519_SPKI_PREFIX = Buffer.from("302a300506032b656e032100", "hex");

/** PKCS8 DER prefix for X25519 private keys (16 bytes) */
const X25519_PKCS8_PREFIX = Buffer.from("302e020100300506032b656e04220420", "hex");

/**
 * Reconstruct an X25519 key pair from raw hex-encoded 32-byte keys.
 */
export function x25519KeyPairFromHex(pubHex: string, privHex: string): X25519KeyPair {
  if (!/^[0-9a-f]{64}$/i.test(pubHex)) {
    throw new Error(`Invalid X25519 public key hex: expected 64 hex chars, got ${pubHex.length}`);
  }
  if (!/^[0-9a-f]{64}$/i.test(privHex)) {
    throw new Error(`Invalid X25519 private key hex: expected 64 hex chars, got ${privHex.length}`);
  }

  const pubRaw = Buffer.from(pubHex, "hex");
  const privRaw = Buffer.from(privHex, "hex");

  const spkiDer = Buffer.concat([X25519_SPKI_PREFIX, pubRaw]);
  const pkcs8Der = Buffer.concat([X25519_PKCS8_PREFIX, privRaw]);

  const publicKey = crypto.createPublicKey({ key: spkiDer, format: "der", type: "spki" });
  const privateKey = crypto.createPrivateKey({ key: pkcs8Der, format: "der", type: "pkcs8" });

  return { publicKey, privateKey };
}

// ---------------------------------------------------------------------------
// Diffie-Hellman shared secret
// ---------------------------------------------------------------------------

/**
 * Derive a 32-byte shared secret using X25519 Diffie-Hellman.
 */
export function deriveSharedSecret(
  ourPrivate: crypto.KeyObject,
  theirPublic: crypto.KeyObject,
): Buffer {
  return crypto.diffieHellman({
    privateKey: ourPrivate,
    publicKey: theirPublic,
  });
}
