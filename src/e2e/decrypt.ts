/**
 * SOST Comms — AEAD Decryption (ChaCha20-Poly1305)
 *
 * Decrypts an EncryptedEnvelope and verifies the Ed25519 header signature.
 */

import * as crypto from "crypto";
import { verifyCanonicalHash } from "../crypto/ed25519";
import { ChannelKeys } from "./channel_keys";
import { EncryptedEnvelope, canonicalHeader } from "./encrypt";

// ---------------------------------------------------------------------------
// Decrypt
// ---------------------------------------------------------------------------

/**
 * Decrypt an EncryptedEnvelope and verify the header signature.
 *
 * @param envelope       - the received encrypted envelope
 * @param channelKeys    - derived channel keys (recvKey used for decryption)
 * @param senderPublicKey - Ed25519 public key of the sender (to verify signature)
 * @returns plaintext string and whether the header signature verified
 * @throws on auth tag failure, wrong key, or corrupted ciphertext
 */
export function decryptMessage(
  envelope: EncryptedEnvelope,
  channelKeys: ChannelKeys,
  senderPublicKey: crypto.KeyObject,
): { plaintext: string; verified: boolean } {
  // Reconstruct the canonical header
  const headerStr = canonicalHeader({
    version: envelope.version,
    deal_id: envelope.deal_id,
    session_id: envelope.session_id,
    sender_id: envelope.sender_id,
    receiver_id: envelope.receiver_id,
    msg_type: envelope.msg_type,
    seq_no: envelope.seq_no,
    timestamp: envelope.timestamp,
    nonce: envelope.nonce,
  });

  // Verify the Ed25519 signature over the header
  const headerHash = crypto.createHash("sha256").update(headerStr).digest("hex");
  const verified = verifyCanonicalHash(headerHash, envelope.signature, senderPublicKey);

  // Decrypt with ChaCha20-Poly1305
  const nonce = Buffer.from(envelope.nonce, "hex");
  const ciphertext = Buffer.from(envelope.ciphertext, "hex");
  const tag = Buffer.from(envelope.tag, "hex");

  const decipher = crypto.createDecipheriv(
    "chacha20-poly1305" as any,
    channelKeys.recvKey,
    nonce,
    { authTagLength: 16 } as any,
  );

  decipher.setAAD(Buffer.from(headerStr, "utf-8"));
  decipher.setAuthTag(tag);

  const decrypted = Buffer.concat([
    decipher.update(ciphertext),
    decipher.final(),
  ]);

  return {
    plaintext: decrypted.toString("utf-8"),
    verified,
  };
}
