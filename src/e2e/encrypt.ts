/**
 * SOST Comms — AEAD Encryption (ChaCha20-Poly1305)
 *
 * Encrypts trade protocol payloads for end-to-end confidentiality.
 * The envelope header (deal_id, sender/receiver, msg_type, seq_no, timestamp)
 * remains in cleartext for relay routing. An Ed25519 signature over the
 * header lets the relay verify authenticity without reading content.
 */

import * as crypto from "crypto";
import { signCanonicalHash } from "../crypto/ed25519";
import { ChannelKeys } from "./channel_keys";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface EncryptedEnvelope {
  version: 1;
  deal_id: string;
  session_id: string;
  sender_id: string;      // public signing key hex (for routing)
  receiver_id: string;    // public signing key hex
  msg_type: string;       // "trade_offer" etc (visible for routing)
  seq_no: number;
  timestamp: number;
  nonce: string;          // hex, 12 bytes
  ciphertext: string;     // hex, AEAD encrypted payload
  tag: string;            // hex, 16-byte auth tag
  signature: string;      // Ed25519 signature over envelope header
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Build a canonical header string for signing.
 * Covers all routing-visible fields so the relay can verify without decryption.
 */
function canonicalHeader(fields: {
  version: number;
  deal_id: string;
  session_id: string;
  sender_id: string;
  receiver_id: string;
  msg_type: string;
  seq_no: number;
  timestamp: number;
  nonce: string;
}): string {
  return [
    fields.version,
    fields.deal_id,
    fields.session_id,
    fields.sender_id,
    fields.receiver_id,
    fields.msg_type,
    fields.seq_no,
    fields.timestamp,
    fields.nonce,
  ].join("|");
}

/**
 * Build a 12-byte nonce from seq_no (first 4 bytes) + random (last 8 bytes).
 */
function buildNonce(seqNo: number): Buffer {
  const nonce = Buffer.alloc(12);
  nonce.writeUInt32BE(seqNo, 0);
  crypto.randomFillSync(nonce, 4, 8);
  return nonce;
}

// ---------------------------------------------------------------------------
// Encrypt
// ---------------------------------------------------------------------------

/**
 * Encrypt a plaintext JSON payload into an EncryptedEnvelope.
 *
 * @param plaintext        - JSON string to encrypt
 * @param channelKeys      - derived channel keys (sendKey used for encryption)
 * @param seqNo            - monotonic sequence number
 * @param senderSigningKey - Ed25519 private key for header signature
 * @param metadata         - routing metadata (deal_id, sender_id, receiver_id, msg_type)
 */
export function encryptMessage(
  plaintext: string,
  channelKeys: ChannelKeys,
  seqNo: number,
  senderSigningKey: crypto.KeyObject,
  metadata: {
    deal_id: string;
    sender_id: string;
    receiver_id: string;
    msg_type: string;
  },
): EncryptedEnvelope {
  const nonce = buildNonce(seqNo);
  const timestamp = Date.now();

  // Build header fields
  const headerFields = {
    version: 1 as const,
    deal_id: metadata.deal_id,
    session_id: channelKeys.sessionId,
    sender_id: metadata.sender_id,
    receiver_id: metadata.receiver_id,
    msg_type: metadata.msg_type,
    seq_no: seqNo,
    timestamp,
    nonce: nonce.toString("hex"),
  };

  // Sign the canonical header
  const headerStr = canonicalHeader(headerFields);
  const headerHash = crypto.createHash("sha256").update(headerStr).digest("hex");
  const signature = signCanonicalHash(headerHash, senderSigningKey);

  // Encrypt with ChaCha20-Poly1305
  const cipher = crypto.createCipheriv(
    "chacha20-poly1305" as any,
    channelKeys.sendKey,
    nonce,
    { authTagLength: 16 } as any,
  );

  // Use the canonical header as AAD so it's authenticated but not encrypted
  cipher.setAAD(Buffer.from(headerStr, "utf-8"));

  const encrypted = Buffer.concat([
    cipher.update(plaintext, "utf-8"),
    cipher.final(),
  ]);
  const tag = cipher.getAuthTag();

  return {
    ...headerFields,
    ciphertext: encrypted.toString("hex"),
    tag: tag.toString("hex"),
    signature,
  };
}

// Re-export canonicalHeader for decrypt module
export { canonicalHeader };
