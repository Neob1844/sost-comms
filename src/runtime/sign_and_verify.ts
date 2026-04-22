/**
 * SOST Comms — Sign & Verify Runtime
 *
 * High-level functions to sign and verify any trade protocol message.
 * Detects message type from `msg.type`, computes the canonical hash,
 * and delegates to the Ed25519 crypto layer.
 */

import * as crypto from "crypto";

import { canonicalHash as offerHash, isExpired } from "../protocol/trade_offer";
import { canonicalHash as acceptHash } from "../protocol/trade_accept";
import { canonicalHash as cancelHash } from "../protocol/trade_cancel";
import { canonicalHash as noticeHash } from "../protocol/settlement_notice";
import { signCanonicalHash, verifyCanonicalHash, NonceRegistry } from "../crypto/ed25519";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface SignedMessage {
  message: any;
  signature: string;
  hash: string;
}

export interface VerifyResult {
  valid: boolean;
  reason?: string;
}

// ---------------------------------------------------------------------------
// Module-level nonce registry (shared across all verifications)
// ---------------------------------------------------------------------------

const globalNonceRegistry = new NonceRegistry();

/**
 * Get the global nonce registry (useful for testing / reset).
 */
export function getNonceRegistry(): NonceRegistry {
  return globalNonceRegistry;
}

// ---------------------------------------------------------------------------
// Canonical hash dispatch
// ---------------------------------------------------------------------------

type MessageType = "trade_offer" | "trade_accept" | "trade_cancel" | "settlement_notice";

function computeHash(msg: any): string {
  const t = msg.type as MessageType;
  switch (t) {
    case "trade_offer":
      return offerHash(msg);
    case "trade_accept":
      return acceptHash(msg);
    case "trade_cancel":
      return cancelHash(msg);
    case "settlement_notice":
      return noticeHash(msg);
    default:
      throw new Error(`Unknown message type: ${t}`);
  }
}

// ---------------------------------------------------------------------------
// Sign
// ---------------------------------------------------------------------------

/**
 * Sign a trade message (any protocol type).
 *
 * The message should be an unsigned object (without `signature` field).
 * Returns the signed envelope: { message, signature, hash }.
 */
export function signTradeMessage(msg: any, privateKey: crypto.KeyObject): SignedMessage {
  if (!msg || !msg.type) {
    throw new Error("Message must have a 'type' field");
  }

  const hash = computeHash(msg);
  const signature = signCanonicalHash(hash, privateKey);

  return { message: msg, signature, hash };
}

// ---------------------------------------------------------------------------
// Verify
// ---------------------------------------------------------------------------

/**
 * Verify a signed trade message.
 *
 * Checks:
 * 1. Signature validity against the provided public key.
 * 2. Nonce has not been seen before (replay protection).
 * 3. Expiry (for trade_offer messages).
 *
 * @param signed - The SignedMessage envelope (or an object with message, signature, hash).
 * @param publicKey - The Ed25519 public key of the alleged signer.
 * @param nonceRegistry - Optional nonce registry; uses global if omitted.
 */
export function verifyTradeMessage(
  signed: SignedMessage,
  publicKey: crypto.KeyObject,
  nonceRegistry?: NonceRegistry,
): VerifyResult {
  const registry = nonceRegistry || globalNonceRegistry;
  const msg = signed.message;

  if (!msg || !msg.type) {
    return { valid: false, reason: "missing_type" };
  }

  // Recompute hash to verify integrity
  let hash: string;
  try {
    hash = computeHash(msg);
  } catch {
    return { valid: false, reason: "unknown_type" };
  }

  // Verify Ed25519 signature
  const sigValid = verifyCanonicalHash(hash, signed.signature, publicKey);
  if (!sigValid) {
    return { valid: false, reason: "invalid_signature" };
  }

  // Check nonce replay
  const nonce = msg.nonce;
  if (nonce != null) {
    if (!registry.add(nonce)) {
      return { valid: false, reason: "replay_nonce" };
    }
  }

  // Check expiry for offers
  if (msg.type === "trade_offer") {
    if (isExpired(msg)) {
      return { valid: false, reason: "expired" };
    }
  }

  return { valid: true, reason: "ok" };
}
