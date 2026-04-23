/**
 * Session bootstrap tests — full async session establishment through
 * prekey bundles and offline message delivery.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
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
  deriveSharedSecret,
} from "../../src/crypto/x25519";
import { deriveChannelKeys } from "../../src/e2e/channel_keys";
import { encryptMessage } from "../../src/e2e/encrypt";
import { decryptMessage } from "../../src/e2e/decrypt";
import { RelayNode } from "../../src/relay/relay_node";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

let tmpDir: string;

function makeTmpDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), "sost-bootstrap-"));
}

/** SPKI DER prefix for X25519 public keys */
const X25519_SPKI_PREFIX = Buffer.from("302a300506032b656e032100", "hex");

function importX25519PublicKey(pubHex: string): crypto.KeyObject {
  const pubRaw = Buffer.from(pubHex, "hex");
  const spkiDer = Buffer.concat([X25519_SPKI_PREFIX, pubRaw]);
  return crypto.createPublicKey({ key: spkiDer, format: "der", type: "spki" });
}

interface PrekeyBundle {
  identity_pub: string;       // ED25519 public key hex
  signed_prekey_pub: string;  // X25519 public key hex
  signed_prekey_sig: string;  // ED25519 signature over prekey
  otk_pub?: string;           // optional one-time X25519 key hex
}

function createPrekeyBundle(
  identityKp: { publicKey: crypto.KeyObject; privateKey: crypto.KeyObject },
  includeOtk: boolean = false,
): { bundle: PrekeyBundle; signedPrekeyPriv: crypto.KeyObject; otkPriv?: crypto.KeyObject } {
  const identityPubHex = publicKeyHex(identityKp.publicKey);

  const signedPrekey = generateX25519KeyPair();
  const signedPrekeyPubHex = x25519PublicKeyHex(signedPrekey.publicKey);
  const prekeyHash = crypto.createHash("sha256").update(signedPrekeyPubHex).digest("hex");
  const signature = signCanonicalHash(prekeyHash, identityKp.privateKey);

  const bundle: PrekeyBundle = {
    identity_pub: identityPubHex,
    signed_prekey_pub: signedPrekeyPubHex,
    signed_prekey_sig: signature,
  };

  let otkPriv: crypto.KeyObject | undefined;
  if (includeOtk) {
    const otk = generateX25519KeyPair();
    bundle.otk_pub = x25519PublicKeyHex(otk.publicKey);
    otkPriv = otk.privateKey;
  }

  return { bundle, signedPrekeyPriv: signedPrekey.privateKey, otkPriv };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("Session bootstrap", () => {
  let relay: RelayNode;

  beforeEach(() => {
    tmpDir = makeTmpDir();
    relay = new RelayNode({ dataDir: tmpDir });
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  // 1
  it("full bootstrap: publish → fetch → init session → encrypt → queue → fetch pending → decrypt", () => {
    // Recipient creates and publishes prekey bundle
    const recipientIdentity = generateKeyPair();
    const recipientIdHex = publicKeyHex(recipientIdentity.publicKey);
    const { bundle, signedPrekeyPriv } = createPrekeyBundle(recipientIdentity);

    relay.publishPrekeyBundle(recipientIdHex, bundle);

    // Sender fetches the bundle
    const fetched = relay.getPrekeyBundle(recipientIdHex);
    expect(fetched).not.toBeNull();
    expect(fetched.identity_pub).toBe(recipientIdHex);

    // Sender verifies signed prekey
    const prekeyHash = crypto.createHash("sha256")
      .update(fetched.signed_prekey_pub).digest("hex");
    const sigValid = verifyCanonicalHash(
      prekeyHash, fetched.signed_prekey_sig, recipientIdentity.publicKey,
    );
    expect(sigValid).toBe(true);

    // Sender creates ephemeral X25519, derives shared secret
    const senderEphemeral = generateX25519KeyPair();
    const recipientPrekeyPub = importX25519PublicKey(fetched.signed_prekey_pub);
    const sharedSecret = deriveSharedSecret(senderEphemeral.privateKey, recipientPrekeyPub);

    const dealId = "deal_bootstrap_" + crypto.randomBytes(4).toString("hex");
    const senderKeys = deriveChannelKeys(sharedSecret, dealId, true);

    // Sender encrypts a trade offer
    const senderIdentity = generateKeyPair();
    const senderIdHex = publicKeyHex(senderIdentity.publicKey);
    const plaintext = JSON.stringify({ type: "trade_offer", amount: 100, price: 2000 });

    const envelope = encryptMessage(plaintext, senderKeys, 0, senderIdentity.privateKey, {
      deal_id: dealId,
      sender_id: senderIdHex,
      receiver_id: recipientIdHex,
      msg_type: "trade_offer",
    });

    // Sender submits to relay with offline queuing
    const result = relay.submitEncryptedWithOffline(envelope, recipientIdHex);
    expect(result.accepted).toBe(true);
    expect(result.queued).toBe(true);

    // Time passes... recipient comes online and fetches pending
    const pending = relay.fetchPending(recipientIdHex);
    expect(pending).toHaveLength(1);

    // Recipient derives same shared secret (using their prekey private + sender's ephemeral pub)
    // In a real protocol the sender's ephemeral pub would be sent in the envelope header.
    // Here we derive directly since we have both sides.
    const recipientSharedSecret = deriveSharedSecret(
      signedPrekeyPriv,
      senderEphemeral.publicKey,
    );
    const recipientKeys = deriveChannelKeys(recipientSharedSecret, dealId, false);

    // Recipient decrypts
    const envelopeParsed = JSON.parse(pending[0].envelope_json);
    const decrypted = decryptMessage(envelopeParsed, recipientKeys, senderIdentity.publicKey);
    expect(decrypted.verified).toBe(true);

    const payload = JSON.parse(decrypted.plaintext);
    expect(payload.type).toBe("trade_offer");
    expect(payload.amount).toBe(100);

    // Recipient acknowledges
    relay.acknowledgeMessage(pending[0].id);
  });

  // 2
  it("session without OTK works", () => {
    const recipientIdentity = generateKeyPair();
    const recipientIdHex = publicKeyHex(recipientIdentity.publicKey);
    const { bundle, signedPrekeyPriv } = createPrekeyBundle(recipientIdentity, false);

    expect(bundle.otk_pub).toBeUndefined();

    relay.publishPrekeyBundle(recipientIdHex, bundle);
    const fetched = relay.getPrekeyBundle(recipientIdHex);

    // Derive keys using only signed prekey (no OTK)
    const senderEphemeral = generateX25519KeyPair();
    const recipientPrekeyPub = importX25519PublicKey(fetched.signed_prekey_pub);
    const sharedSecret = deriveSharedSecret(senderEphemeral.privateKey, recipientPrekeyPub);

    const dealId = "deal_no_otk";
    const senderKeys = deriveChannelKeys(sharedSecret, dealId, true);
    const recipientKeys = deriveChannelKeys(
      deriveSharedSecret(signedPrekeyPriv, senderEphemeral.publicKey), dealId, false,
    );

    // Keys match
    expect(senderKeys.sendKey.toString("hex")).toBe(recipientKeys.recvKey.toString("hex"));
    expect(senderKeys.recvKey.toString("hex")).toBe(recipientKeys.sendKey.toString("hex"));
  });

  // 3
  it("session with OTK produces different keys", () => {
    const recipientIdentity = generateKeyPair();
    const recipientIdHex = publicKeyHex(recipientIdentity.publicKey);

    // Without OTK
    const { bundle: bundleNoOtk, signedPrekeyPriv: privNoOtk } =
      createPrekeyBundle(recipientIdentity, false);

    // With OTK
    const { bundle: bundleOtk, signedPrekeyPriv: privOtk, otkPriv } =
      createPrekeyBundle(recipientIdentity, true);

    expect(bundleOtk.otk_pub).toBeDefined();

    const senderEphemeral = generateX25519KeyPair();

    // Derive without OTK
    const prekeyPubNoOtk = importX25519PublicKey(bundleNoOtk.signed_prekey_pub);
    const secretNoOtk = deriveSharedSecret(senderEphemeral.privateKey, prekeyPubNoOtk);

    // Derive with OTK: combine both DH results via HKDF
    const prekeyPubOtk = importX25519PublicKey(bundleOtk.signed_prekey_pub);
    const otkPub = importX25519PublicKey(bundleOtk.otk_pub!);
    const dh1 = deriveSharedSecret(senderEphemeral.privateKey, prekeyPubOtk);
    const dh2 = deriveSharedSecret(senderEphemeral.privateKey, otkPub);
    const combinedSecret = crypto.createHash("sha256")
      .update(Buffer.concat([dh1, dh2])).digest();

    const dealId = "deal_otk_test";
    const keysNoOtk = deriveChannelKeys(secretNoOtk, dealId, true);
    const keysOtk = deriveChannelKeys(combinedSecret, dealId, true);

    // Keys must differ because different shared secrets
    expect(keysNoOtk.sendKey.toString("hex")).not.toBe(keysOtk.sendKey.toString("hex"));
  });

  // 4
  it("relay stores prekey bundle correctly", () => {
    const identity = generateKeyPair();
    const idHex = publicKeyHex(identity.publicKey);
    const { bundle } = createPrekeyBundle(identity, true);

    relay.publishPrekeyBundle(idHex, bundle);

    const fetched = relay.getPrekeyBundle(idHex);
    expect(fetched).toEqual(bundle);
    expect(fetched.identity_pub).toBe(idHex);
    expect(fetched.signed_prekey_pub).toBeTruthy();
    expect(fetched.signed_prekey_sig).toBeTruthy();
    expect(fetched.otk_pub).toBeTruthy();
  });

  // 5
  it("relay cannot decrypt queued messages", () => {
    const recipientIdentity = generateKeyPair();
    const recipientIdHex = publicKeyHex(recipientIdentity.publicKey);
    const { bundle } = createPrekeyBundle(recipientIdentity);

    relay.publishPrekeyBundle(recipientIdHex, bundle);

    // Sender encrypts and queues
    const senderIdentity = generateKeyPair();
    const senderIdHex = publicKeyHex(senderIdentity.publicKey);
    const senderEphemeral = generateX25519KeyPair();
    const recipientPrekeyPub = importX25519PublicKey(bundle.signed_prekey_pub);
    const sharedSecret = deriveSharedSecret(senderEphemeral.privateKey, recipientPrekeyPub);

    const dealId = "deal_blind";
    const senderKeys = deriveChannelKeys(sharedSecret, dealId, true);
    const secretPayload = "CONFIDENTIAL: 50oz gold at $2100/oz";

    const envelope = encryptMessage(secretPayload, senderKeys, 0, senderIdentity.privateKey, {
      deal_id: dealId,
      sender_id: senderIdHex,
      receiver_id: recipientIdHex,
      msg_type: "trade_offer",
    });

    relay.submitEncryptedWithOffline(envelope, recipientIdHex);

    // Relay has the encrypted data but cannot read it
    const encrypted = relay.getEncryptedDealMessages(dealId);
    expect(encrypted).toHaveLength(1);

    const storedEnvelope = JSON.parse(encrypted[0].envelope_json);
    expect(storedEnvelope.ciphertext).toBeTruthy();
    expect(storedEnvelope.ciphertext).not.toContain(secretPayload);
    expect(encrypted[0].envelope_json).not.toContain(secretPayload);
  });
});
