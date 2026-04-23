/**
 * SOST Comms — Channel Key Derivation
 *
 * Derives symmetric send/recv keys from a shared DH secret using HKDF-SHA256.
 * Each deal channel gets a unique pair of directional keys so that
 * the initiator's send key is the responder's recv key and vice versa.
 */

import * as crypto from "crypto";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface ChannelKeys {
  sendKey: Buffer;   // 32 bytes — used to encrypt outgoing messages
  recvKey: Buffer;   // 32 bytes — used to decrypt incoming messages
  dealId: string;
  sessionId: string;
}

// ---------------------------------------------------------------------------
// Labels
// ---------------------------------------------------------------------------

const LABEL_A = "sost-deal-key-a";
const LABEL_B = "sost-deal-key-b";

// ---------------------------------------------------------------------------
// Derivation
// ---------------------------------------------------------------------------

/**
 * Derive directional channel keys from a DH shared secret.
 *
 * @param sharedSecret - 32-byte X25519 shared secret
 * @param dealId       - unique deal identifier (used as HKDF salt context)
 * @param isInitiator  - true for the party that sent the handshake offer
 * @returns ChannelKeys with send/recv keys and session metadata
 */
export function deriveChannelKeys(
  sharedSecret: Buffer,
  dealId: string,
  isInitiator: boolean,
): ChannelKeys {
  const salt = Buffer.from(dealId, "utf-8");

  const keyA = crypto.hkdfSync("sha256", sharedSecret, salt, LABEL_A, 32);
  const keyB = crypto.hkdfSync("sha256", sharedSecret, salt, LABEL_B, 32);

  const keyABuf = Buffer.from(keyA);
  const keyBBuf = Buffer.from(keyB);

  // Session ID = first 16 bytes of SHA-256(sharedSecret || dealId)
  const sessionHash = crypto
    .createHash("sha256")
    .update(sharedSecret)
    .update(dealId)
    .digest();
  const sessionId = sessionHash.subarray(0, 16).toString("hex");

  return {
    sendKey: isInitiator ? keyABuf : keyBBuf,
    recvKey: isInitiator ? keyBBuf : keyABuf,
    dealId,
    sessionId,
  };
}
