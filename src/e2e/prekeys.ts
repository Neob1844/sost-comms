/**
 * SOST Comms — Prekey Generation
 *
 * Signed prekeys and one-time prekeys for asynchronous session establishment.
 * Signed prekeys are medium-term X25519 keys signed by the identity Ed25519 key.
 * One-time prekeys are single-use X25519 keys that provide forward secrecy.
 */

import * as crypto from "crypto";
import { signMessage, verifyMessage } from "../crypto/ed25519";
import {
  generateX25519KeyPair,
  x25519PublicKeyHex,
} from "../crypto/x25519";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface SignedPrekey {
  publicKey: string;      // X25519 public hex
  signature: string;      // ED25519 signature over publicKey
  createdAt: number;
  id: number;             // rotating ID
}

export interface OneTimePrekey {
  publicKey: string;      // X25519 public hex
  id: number;
  used: boolean;
}

// ---------------------------------------------------------------------------
// ID counter (module-level, monotonic)
// ---------------------------------------------------------------------------

let nextPrekeyId = 1;

/**
 * Reset the prekey ID counter (for testing only).
 */
export function _resetPrekeyIdCounter(start: number = 1): void {
  nextPrekeyId = start;
}

// ---------------------------------------------------------------------------
// Signed prekey
// ---------------------------------------------------------------------------

/**
 * Generate a new signed prekey: an X25519 key pair signed by the Ed25519 identity key.
 */
export function generateSignedPrekey(
  signingKey: crypto.KeyObject,
): { signed: SignedPrekey; privateKey: crypto.KeyObject } {
  const kp = generateX25519KeyPair();
  const pubHex = x25519PublicKeyHex(kp.publicKey);
  const signature = signMessage(pubHex, signingKey);
  const id = nextPrekeyId++;

  return {
    signed: {
      publicKey: pubHex,
      signature,
      createdAt: Date.now(),
      id,
    },
    privateKey: kp.privateKey,
  };
}

/**
 * Verify a signed prekey's signature against a signing public key.
 */
export function verifySignedPrekey(
  signed: SignedPrekey,
  signingPublicKey: crypto.KeyObject,
): boolean {
  return verifyMessage(signed.publicKey, signed.signature, signingPublicKey);
}

// ---------------------------------------------------------------------------
// One-time prekeys
// ---------------------------------------------------------------------------

/**
 * Generate a batch of one-time prekeys.
 */
export function generateOneTimePrekeys(
  count: number,
): { prekeys: OneTimePrekey[]; privateKeys: Map<number, crypto.KeyObject> } {
  const prekeys: OneTimePrekey[] = [];
  const privateKeys = new Map<number, crypto.KeyObject>();

  for (let i = 0; i < count; i++) {
    const kp = generateX25519KeyPair();
    const id = nextPrekeyId++;
    prekeys.push({
      publicKey: x25519PublicKeyHex(kp.publicKey),
      id,
      used: false,
    });
    privateKeys.set(id, kp.privateKey);
  }

  return { prekeys, privateKeys };
}
