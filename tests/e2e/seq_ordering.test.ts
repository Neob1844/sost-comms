/**
 * Sequence number ordering tests — verify the relay enforces
 * a sequence window to prevent replay and detect gaps.
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
  return fs.mkdtempSync(path.join(os.tmpdir(), "sost-seq-"));
}

function makeEnvelope(
  senderPriv: crypto.KeyObject,
  senderPubHex: string,
  dealId: string,
  seqNo: number,
) {
  const base: Record<string, any> = {
    version: 1,
    deal_id: dealId,
    session_id: crypto.randomBytes(16).toString("hex"),
    sender_id: senderPubHex,
    receiver_id: crypto.randomBytes(32).toString("hex"),
    msg_type: "trade_update",
    seq_no: seqNo,
    timestamp: Math.floor(Date.now() / 1000),
    nonce: crypto.randomBytes(12).toString("hex"),
    ciphertext: crypto.randomBytes(64).toString("hex"),
    tag: crypto.randomBytes(16).toString("hex"),
  };

  // Sign header
  const headerFields: Record<string, any> = {};
  const fieldNames = [
    "version", "deal_id", "session_id", "sender_id", "receiver_id",
    "msg_type", "seq_no", "timestamp", "nonce", "ciphertext", "tag",
  ];
  for (const f of fieldNames) {
    headerFields[f] = base[f];
  }
  const keys = Object.keys(headerFields).sort();
  const canonical: Record<string, any> = {};
  for (const k of keys) {
    canonical[k] = headerFields[k];
  }
  base.signature = signMessage(JSON.stringify(canonical), senderPriv);
  return base;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("Sequence number ordering", () => {
  let relay: RelayNode;
  const dealId = "deal_seq_" + crypto.randomBytes(4).toString("hex");

  beforeEach(() => {
    tmpDir = makeTmpDir();
    relay = new RelayNode({ dataDir: tmpDir });
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  // 1
  it("sequential messages accepted", () => {
    const kp = generateKeyPair();
    const pubHex = publicKeyHex(kp.publicKey);

    for (let i = 0; i < 10; i++) {
      const env = makeEnvelope(kp.privateKey, pubHex, dealId, i);
      const result = relay.submitEncrypted(env);
      expect(result.accepted).toBe(true);
    }

    const stored = relay.getEncryptedDealMessages(dealId);
    expect(stored).toHaveLength(10);
  });

  // 2
  it("gap within window accepted", () => {
    const kp = generateKeyPair();
    const pubHex = publicKeyHex(kp.publicKey);

    // Send seq 0, then jump to seq 50 (within 256 window)
    const env0 = makeEnvelope(kp.privateKey, pubHex, dealId, 0);
    expect(relay.submitEncrypted(env0).accepted).toBe(true);

    const env50 = makeEnvelope(kp.privateKey, pubHex, dealId, 50);
    expect(relay.submitEncrypted(env50).accepted).toBe(true);

    const stored = relay.getEncryptedDealMessages(dealId);
    expect(stored).toHaveLength(2);
  });

  // 3
  it("reversed order within window accepted", () => {
    const kp = generateKeyPair();
    const pubHex = publicKeyHex(kp.publicKey);

    // Send seq 5, then seq 3, then seq 1 — all within window
    const env5 = makeEnvelope(kp.privateKey, pubHex, dealId, 5);
    expect(relay.submitEncrypted(env5).accepted).toBe(true);

    const env3 = makeEnvelope(kp.privateKey, pubHex, dealId, 3);
    expect(relay.submitEncrypted(env3).accepted).toBe(true);

    const env1 = makeEnvelope(kp.privateKey, pubHex, dealId, 1);
    expect(relay.submitEncrypted(env1).accepted).toBe(true);

    const stored = relay.getEncryptedDealMessages(dealId);
    expect(stored).toHaveLength(3);
  });

  // 4
  it("seq_no beyond window rejected", () => {
    const kp = generateKeyPair();
    const pubHex = publicKeyHex(kp.publicKey);

    // Send seq 0
    const env0 = makeEnvelope(kp.privateKey, pubHex, dealId, 0);
    expect(relay.submitEncrypted(env0).accepted).toBe(true);

    // Jump to seq 300 — beyond the 256 window
    const envFar = makeEnvelope(kp.privateKey, pubHex, dealId, 300);
    const result = relay.submitEncrypted(envFar);
    expect(result.accepted).toBe(false);
    expect(result.reason).toBe("seq_beyond_window");
  });
});
