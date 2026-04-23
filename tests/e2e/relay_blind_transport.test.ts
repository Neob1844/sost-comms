/**
 * Blind transport tests — relay accepts, stores, and returns
 * encrypted envelopes without ever decrypting them.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import * as crypto from "crypto";

import { generateKeyPair, publicKeyHex, signMessage } from "../../src/crypto/ed25519";
import { RelayNode } from "../../src/relay/relay_node";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

let tmpDir: string;

function makeTmpDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), "sost-enc-relay-"));
}

function makeEnvelope(
  senderPriv: crypto.KeyObject,
  senderPubHex: string,
  overrides: Record<string, any> = {},
) {
  const base: Record<string, any> = {
    version: 1,
    deal_id: "deal_" + crypto.randomBytes(8).toString("hex"),
    session_id: crypto.randomBytes(16).toString("hex"),
    sender_id: senderPubHex,
    receiver_id: crypto.randomBytes(32).toString("hex"),
    msg_type: "trade_offer",
    seq_no: 0,
    timestamp: Math.floor(Date.now() / 1000),
    nonce: crypto.randomBytes(12).toString("hex"),
    ciphertext: crypto.randomBytes(128).toString("hex"),
    tag: crypto.randomBytes(16).toString("hex"),
  };

  // Apply overrides before signing
  for (const [k, v] of Object.entries(overrides)) {
    if (v === undefined) {
      delete base[k];
    } else {
      base[k] = v;
    }
  }

  // Sign header (all fields except signature, sorted)
  const headerFields: Record<string, any> = {};
  const fieldNames = [
    "version", "deal_id", "session_id", "sender_id", "receiver_id",
    "msg_type", "seq_no", "timestamp", "nonce", "ciphertext", "tag",
  ];
  for (const f of fieldNames) {
    if (base[f] !== undefined) {
      headerFields[f] = base[f];
    }
  }
  const keys = Object.keys(headerFields).sort();
  const canonical: Record<string, any> = {};
  for (const k of keys) {
    canonical[k] = headerFields[k];
  }
  const headerStr = JSON.stringify(canonical);
  const signature = signMessage(headerStr, senderPriv);

  base.signature = signature;
  return base;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("Relay blind transport", () => {
  let relay: RelayNode;

  beforeEach(() => {
    tmpDir = makeTmpDir();
    relay = new RelayNode({ dataDir: tmpDir });
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  // 1
  it("accepts encrypted envelope with valid header", () => {
    const kp = generateKeyPair();
    const pubHex = publicKeyHex(kp.publicKey);
    const env = makeEnvelope(kp.privateKey, pubHex);

    const result = relay.submitEncrypted(env);
    expect(result.accepted).toBe(true);
    expect(result.deal_id).toBe(env.deal_id);
  });

  // 2
  it("rejects envelope missing required fields", () => {
    const kp = generateKeyPair();
    const pubHex = publicKeyHex(kp.publicKey);

    // Missing ciphertext
    const env = makeEnvelope(kp.privateKey, pubHex, { ciphertext: undefined });
    const result = relay.submitEncrypted(env);
    expect(result.accepted).toBe(false);
    expect(result.reason).toMatch(/missing_field/);
  });

  // 3
  it("stores encrypted envelope without decrypting", () => {
    const kp = generateKeyPair();
    const pubHex = publicKeyHex(kp.publicKey);
    const env = makeEnvelope(kp.privateKey, pubHex);

    relay.submitEncrypted(env);

    const stored = relay.getEncryptedDealMessages(env.deal_id);
    expect(stored).toHaveLength(1);

    // The stored envelope_json is the full envelope serialized
    const parsed = JSON.parse(stored[0].envelope_json);
    expect(parsed.ciphertext).toBe(env.ciphertext);
    expect(parsed.tag).toBe(env.tag);
  });

  // 4
  it("returns stored envelopes as-is", () => {
    const kp = generateKeyPair();
    const pubHex = publicKeyHex(kp.publicKey);
    const env = makeEnvelope(kp.privateKey, pubHex);

    relay.submitEncrypted(env);

    const stored = relay.getEncryptedDealMessages(env.deal_id);
    const parsed = JSON.parse(stored[0].envelope_json);

    // Every field from the original envelope must be present unchanged
    expect(parsed.version).toBe(env.version);
    expect(parsed.deal_id).toBe(env.deal_id);
    expect(parsed.session_id).toBe(env.session_id);
    expect(parsed.sender_id).toBe(env.sender_id);
    expect(parsed.receiver_id).toBe(env.receiver_id);
    expect(parsed.msg_type).toBe(env.msg_type);
    expect(parsed.seq_no).toBe(env.seq_no);
    expect(parsed.nonce).toBe(env.nonce);
    expect(parsed.ciphertext).toBe(env.ciphertext);
    expect(parsed.tag).toBe(env.tag);
    expect(parsed.signature).toBe(env.signature);
  });

  // 5
  it("relay cannot read ciphertext (stored data is still encrypted)", () => {
    const kp = generateKeyPair();
    const pubHex = publicKeyHex(kp.publicKey);

    // The "plaintext" that was encrypted — relay should never see this
    const secret = "TOP SECRET: gold price = $2000";
    // Ciphertext is random bytes, not the plaintext
    const fakeCiphertext = crypto.randomBytes(128).toString("hex");

    const env = makeEnvelope(kp.privateKey, pubHex, { ciphertext: fakeCiphertext });
    relay.submitEncrypted(env);

    const stored = relay.getEncryptedDealMessages(env.deal_id);
    const parsed = JSON.parse(stored[0].envelope_json);

    // Relay has the ciphertext, not the plaintext
    expect(parsed.ciphertext).toBe(fakeCiphertext);
    expect(parsed.ciphertext).not.toContain(secret);

    // The stored message also does not contain plaintext anywhere
    expect(stored[0].envelope_json).not.toContain(secret);
  });

  // 6
  it("multiple envelopes per deal stored correctly", () => {
    const kp = generateKeyPair();
    const pubHex = publicKeyHex(kp.publicKey);
    const dealId = "deal_multi_" + crypto.randomBytes(4).toString("hex");

    for (let i = 0; i < 5; i++) {
      const env = makeEnvelope(kp.privateKey, pubHex, {
        deal_id: dealId,
        seq_no: i,
        msg_type: i === 0 ? "trade_offer" : "trade_update",
      });
      const result = relay.submitEncrypted(env);
      expect(result.accepted).toBe(true);
    }

    const stored = relay.getEncryptedDealMessages(dealId);
    expect(stored).toHaveLength(5);

    // Verify ordering by seq_no
    const seqNos = stored.map(s => s.seq_no);
    expect(seqNos).toEqual([0, 1, 2, 3, 4]);
  });

  // 7
  it("verifies header signature (routing auth)", () => {
    const kp = generateKeyPair();
    const pubHex = publicKeyHex(kp.publicKey);
    const env = makeEnvelope(kp.privateKey, pubHex);

    // Valid signature works
    const result = relay.submitEncrypted(env);
    expect(result.accepted).toBe(true);
  });

  // 8
  it("rejects invalid header signature", () => {
    const kp = generateKeyPair();
    const pubHex = publicKeyHex(kp.publicKey);
    const env = makeEnvelope(kp.privateKey, pubHex);

    // Corrupt the signature
    env.signature = crypto.randomBytes(64).toString("hex");

    const result = relay.submitEncrypted(env);
    expect(result.accepted).toBe(false);
    expect(result.reason).toBe("invalid_header_signature");
  });
});
