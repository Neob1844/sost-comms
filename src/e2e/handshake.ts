/**
 * SOST Comms — Deal Channel Handshake
 *
 * Three-step handshake to establish an encrypted channel for a deal:
 * 1. Initiator creates a HandshakeOffer (shares ephemeral X25519 pub)
 * 2. Responder calls acceptHandshake → gets ChannelKeys + HandshakeAccept
 * 3. Initiator calls completeHandshake → gets matching ChannelKeys
 */

import * as crypto from "crypto";
import { publicKeyHex } from "../crypto/ed25519";
import {
  x25519PublicKeyHex,
  deriveSharedSecret,
} from "../crypto/x25519";
import { KeyBundle } from "../crypto/key_bundle";
import { deriveChannelKeys, ChannelKeys } from "./channel_keys";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface HandshakeOffer {
  deal_id: string;
  initiator_signing_pub: string;
  initiator_encryption_pub: string;  // ephemeral X25519 for this deal
  timestamp: number;
}

export interface HandshakeAccept {
  deal_id: string;
  responder_signing_pub: string;
  responder_encryption_pub: string;
  timestamp: number;
}

// ---------------------------------------------------------------------------
// Handshake functions
// ---------------------------------------------------------------------------

/**
 * Create a handshake offer for a new deal channel.
 * Uses the bundle's encryption key as the ephemeral key for this deal.
 */
export function createHandshakeOffer(bundle: KeyBundle, dealId: string): HandshakeOffer {
  return {
    deal_id: dealId,
    initiator_signing_pub: publicKeyHex(bundle.signing.publicKey),
    initiator_encryption_pub: x25519PublicKeyHex(bundle.encryption.publicKey),
    timestamp: Date.now(),
  };
}

/**
 * Accept a handshake offer: derive shared secret and channel keys.
 *
 * @param bundle - responder's key bundle
 * @param offer  - the initiator's handshake offer
 * @returns HandshakeAccept message and derived channel keys
 */
export function acceptHandshake(
  bundle: KeyBundle,
  offer: HandshakeOffer,
): { accept: HandshakeAccept; channelKeys: ChannelKeys } {
  // Reconstruct initiator's X25519 public key from hex
  const initiatorPub = importX25519PublicKey(offer.initiator_encryption_pub);

  // Derive shared secret: responder's private + initiator's public
  const sharedSecret = deriveSharedSecret(bundle.encryption.privateKey, initiatorPub);

  // Derive channel keys (responder is NOT the initiator)
  const channelKeys = deriveChannelKeys(sharedSecret, offer.deal_id, false);

  const accept: HandshakeAccept = {
    deal_id: offer.deal_id,
    responder_signing_pub: publicKeyHex(bundle.signing.publicKey),
    responder_encryption_pub: x25519PublicKeyHex(bundle.encryption.publicKey),
    timestamp: Date.now(),
  };

  return { accept, channelKeys };
}

/**
 * Complete the handshake on the initiator side after receiving the accept.
 *
 * @param bundle - initiator's key bundle
 * @param offer  - the original handshake offer (for deal_id)
 * @param accept - the responder's handshake accept
 * @returns derived channel keys
 */
export function completeHandshake(
  bundle: KeyBundle,
  offer: HandshakeOffer,
  accept: HandshakeAccept,
): ChannelKeys {
  // Reconstruct responder's X25519 public key
  const responderPub = importX25519PublicKey(accept.responder_encryption_pub);

  // Derive shared secret: initiator's private + responder's public
  const sharedSecret = deriveSharedSecret(bundle.encryption.privateKey, responderPub);

  // Derive channel keys (initiator IS the initiator)
  return deriveChannelKeys(sharedSecret, offer.deal_id, true);
}

// ---------------------------------------------------------------------------
// Helper: import X25519 public key from hex
// ---------------------------------------------------------------------------

/** SPKI DER prefix for X25519 public keys (12 bytes) */
const X25519_SPKI_PREFIX = Buffer.from("302a300506032b656e032100", "hex");

function importX25519PublicKey(pubHex: string): crypto.KeyObject {
  const pubRaw = Buffer.from(pubHex, "hex");
  const spkiDer = Buffer.concat([X25519_SPKI_PREFIX, pubRaw]);
  return crypto.createPublicKey({ key: spkiDer, format: "der", type: "spki" });
}
