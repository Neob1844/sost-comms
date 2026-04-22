/**
 * SOST Comms — Ed25519 Signing Module
 *
 * Uses Node.js built-in crypto (Ed25519 support since Node 15.x).
 * Ed25519 is a deterministic signature scheme — no separate hash algorithm
 * is needed (pass null to crypto.sign/crypto.verify).
 */

import * as crypto from "crypto";

// ---------------------------------------------------------------------------
// Key generation
// ---------------------------------------------------------------------------

export interface KeyPair {
  publicKey: crypto.KeyObject;
  privateKey: crypto.KeyObject;
}

/**
 * Generate a new Ed25519 key pair.
 */
export function generateKeyPair(): KeyPair {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  return { publicKey, privateKey };
}

/**
 * Export the raw 32-byte public key as a hex string.
 */
export function publicKeyHex(key: crypto.KeyObject): string {
  // Export as DER (SPKI), then extract the last 32 bytes (the raw key)
  const der = key.export({ type: "spki", format: "der" });
  return der.subarray(der.length - 32).toString("hex");
}

/**
 * Export the raw 32-byte private key seed as a hex string.
 */
export function privateKeyHex(key: crypto.KeyObject): string {
  // PKCS8 DER for ed25519: the last 32 bytes are the seed
  const der = key.export({ type: "pkcs8", format: "der" });
  return der.subarray(der.length - 32).toString("hex");
}

// ---------------------------------------------------------------------------
// Sign / verify arbitrary messages (SHA-256 then Ed25519)
// ---------------------------------------------------------------------------

/**
 * Sign the SHA-256 hash of a message string.
 * Returns the signature as a hex string.
 */
export function signMessage(message: string, privateKey: crypto.KeyObject): string {
  const hash = crypto.createHash("sha256").update(message).digest();
  const sig = crypto.sign(null, hash, privateKey);
  return sig.toString("hex");
}

/**
 * Verify an Ed25519 signature over the SHA-256 hash of a message.
 */
export function verifyMessage(
  message: string,
  signature: string,
  publicKey: crypto.KeyObject,
): boolean {
  const hash = crypto.createHash("sha256").update(message).digest();
  return crypto.verify(null, hash, publicKey, Buffer.from(signature, "hex"));
}

// ---------------------------------------------------------------------------
// Sign / verify canonical hashes (already hex-encoded SHA-256)
// ---------------------------------------------------------------------------

/**
 * Sign a pre-computed canonical hash (hex string).
 * The hash is converted to bytes and signed directly with Ed25519.
 */
export function signCanonicalHash(hash: string, privateKey: crypto.KeyObject): string {
  const sig = crypto.sign(null, Buffer.from(hash, "hex"), privateKey);
  return sig.toString("hex");
}

/**
 * Verify an Ed25519 signature over a pre-computed canonical hash.
 */
export function verifyCanonicalHash(
  hash: string,
  signature: string,
  publicKey: crypto.KeyObject,
): boolean {
  return crypto.verify(
    null,
    Buffer.from(hash, "hex"),
    publicKey,
    Buffer.from(signature, "hex"),
  );
}

// ---------------------------------------------------------------------------
// Nonce replay protection
// ---------------------------------------------------------------------------

/**
 * Simple Set-based nonce registry to detect replay attacks.
 */
export class NonceRegistry {
  private readonly seen = new Set<string>();

  /** Returns true if the nonce has already been registered. */
  has(nonce: string): boolean {
    return this.seen.has(nonce);
  }

  /** Register a nonce. Returns false if it was already present (replay). */
  add(nonce: string): boolean {
    if (this.seen.has(nonce)) return false;
    this.seen.add(nonce);
    return true;
  }

  /** Number of tracked nonces. */
  get size(): number {
    return this.seen.size;
  }
}
