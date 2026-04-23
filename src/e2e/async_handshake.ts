/**
 * SOST Comms — Asynchronous Session Establishment
 *
 * Allows a sender to initiate an encrypted channel with a recipient who
 * may be offline, using the recipient's published prekey bundle.
 *
 * Key agreement:
 *   DH1: sender_ephemeral x recipient_signed_prekey
 *   DH2: sender_ephemeral x recipient_one_time_prekey  (if available)
 *
 * The DH outputs are combined and fed through HKDF to derive channel keys.
 */

import * as crypto from "crypto";
import { publicKeyHex } from "../crypto/ed25519";
import {
  generateX25519KeyPair,
  x25519PublicKeyHex,
  deriveSharedSecret,
} from "../crypto/x25519";
import { KeyBundle } from "../crypto/key_bundle";
import { deriveChannelKeys, ChannelKeys } from "./channel_keys";
import { PrekeyBundle } from "./prekey_bundle";
import { verifySignedPrekey } from "./prekeys";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface AsyncSessionInit {
  dealId: string;
  senderIdentityKey: string;      // ED25519 pub hex
  senderEphemeralKey: string;     // X25519 pub hex (new ephemeral for this session)
  usedSignedPrekeyId: number;
  usedOneTimePrekeyId?: number;   // undefined if no OTK available
  timestamp: number;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** SPKI DER prefix for X25519 public keys (12 bytes) */
const X25519_SPKI_PREFIX = Buffer.from("302a300506032b656e032100", "hex");

function importX25519PublicKey(pubHex: string): crypto.KeyObject {
  const pubRaw = Buffer.from(pubHex, "hex");
  const spkiDer = Buffer.concat([X25519_SPKI_PREFIX, pubRaw]);
  return crypto.createPublicKey({ key: spkiDer, format: "der", type: "spki" });
}

/**
 * Combine DH outputs into a single master secret using SHA-256.
 */
function combineDHOutputs(dh1: Buffer, dh2?: Buffer): Buffer {
  const hash = crypto.createHash("sha256");
  hash.update(dh1);
  if (dh2) hash.update(dh2);
  return hash.digest();
}

// ---------------------------------------------------------------------------
// Initiate (sender side — recipient can be offline)
// ---------------------------------------------------------------------------

/**
 * Initiate an asynchronous session using the recipient's prekey bundle.
 *
 * @param senderBundle           - sender's key bundle
 * @param recipientPrekeyBundle  - recipient's published prekey bundle
 * @param dealId                 - unique deal identifier
 */
export function initiateAsyncSession(
  senderBundle: KeyBundle,
  recipientPrekeyBundle: PrekeyBundle,
  dealId: string,
): { sessionInit: AsyncSessionInit; channelKeys: ChannelKeys; ephemeralPrivate: crypto.KeyObject } {
  // Verify the recipient's signed prekey
  const recipientIdentityPub = importEd25519PublicKey(recipientPrekeyBundle.identityKey);
  if (!verifySignedPrekey(recipientPrekeyBundle.signedPrekey, recipientIdentityPub)) {
    throw new Error("Recipient's signed prekey signature verification failed");
  }

  // Generate ephemeral X25519 key pair for this session
  const ephemeral = generateX25519KeyPair();
  const ephemeralPubHex = x25519PublicKeyHex(ephemeral.publicKey);

  // DH1: sender_ephemeral x recipient_signed_prekey
  const recipientSignedPrekeyPub = importX25519PublicKey(
    recipientPrekeyBundle.signedPrekey.publicKey,
  );
  const dh1 = deriveSharedSecret(ephemeral.privateKey, recipientSignedPrekeyPub);

  // DH2: sender_ephemeral x recipient_one_time_prekey (if available)
  let dh2: Buffer | undefined;
  let usedOneTimePrekeyId: number | undefined;

  const unusedOtk = recipientPrekeyBundle.oneTimePrekeys.find((k) => !k.used);
  if (unusedOtk) {
    const otkPub = importX25519PublicKey(unusedOtk.publicKey);
    dh2 = deriveSharedSecret(ephemeral.privateKey, otkPub);
    usedOneTimePrekeyId = unusedOtk.id;
  }

  // Combine DH outputs into master secret
  const masterSecret = combineDHOutputs(dh1, dh2);

  // Derive channel keys (sender is initiator)
  const channelKeys = deriveChannelKeys(masterSecret, dealId, true);

  const sessionInit: AsyncSessionInit = {
    dealId,
    senderIdentityKey: publicKeyHex(senderBundle.signing.publicKey),
    senderEphemeralKey: ephemeralPubHex,
    usedSignedPrekeyId: recipientPrekeyBundle.signedPrekey.id,
    usedOneTimePrekeyId,
    timestamp: Date.now(),
  };

  return { sessionInit, channelKeys, ephemeralPrivate: ephemeral.privateKey };
}

// ---------------------------------------------------------------------------
// Receive (recipient side)
// ---------------------------------------------------------------------------

/**
 * Process an incoming async session init and derive matching channel keys.
 *
 * @param recipientBundle      - recipient's key bundle
 * @param recipientPrivateKeys - recipient's prekey private keys
 * @param sessionInit          - the sender's session init message
 * @param senderIdentityKey    - sender's ED25519 public key hex (for verification)
 */
export function receiveAsyncSession(
  recipientBundle: KeyBundle,
  recipientPrivateKeys: import("./prekey_bundle").PrekeyPrivateKeys,
  sessionInit: AsyncSessionInit,
  senderIdentityKey: string,
): ChannelKeys {
  // Verify sender identity matches
  if (sessionInit.senderIdentityKey !== senderIdentityKey) {
    throw new Error("Sender identity key mismatch");
  }

  // Reconstruct sender's ephemeral public key
  const senderEphemeralPub = importX25519PublicKey(sessionInit.senderEphemeralKey);

  // DH1: recipient_signed_prekey_private x sender_ephemeral
  const dh1 = deriveSharedSecret(recipientPrivateKeys.signedPrekeyPrivate, senderEphemeralPub);

  // DH2: recipient_one_time_prekey_private x sender_ephemeral (if OTK was used)
  let dh2: Buffer | undefined;
  if (sessionInit.usedOneTimePrekeyId !== undefined) {
    const otkPrivate = recipientPrivateKeys.oneTimePrivates.get(sessionInit.usedOneTimePrekeyId);
    if (!otkPrivate) {
      throw new Error(`One-time prekey ${sessionInit.usedOneTimePrekeyId} not found`);
    }
    dh2 = deriveSharedSecret(otkPrivate, senderEphemeralPub);
  }

  // Combine DH outputs into master secret
  const masterSecret = combineDHOutputs(dh1, dh2);

  // Derive channel keys (recipient is NOT the initiator)
  return deriveChannelKeys(masterSecret, sessionInit.dealId, false);
}

// ---------------------------------------------------------------------------
// Helper: import Ed25519 public key from hex
// ---------------------------------------------------------------------------

const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

function importEd25519PublicKey(pubHex: string): crypto.KeyObject {
  const pubRaw = Buffer.from(pubHex, "hex");
  const spkiDer = Buffer.concat([ED25519_SPKI_PREFIX, pubRaw]);
  return crypto.createPublicKey({ key: spkiDer, format: "der", type: "spki" });
}
