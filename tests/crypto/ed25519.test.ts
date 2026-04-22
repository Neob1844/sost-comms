import { describe, it, expect } from "vitest";

import {
  generateKeyPair,
  publicKeyHex,
  privateKeyHex,
  signMessage,
  verifyMessage,
  signCanonicalHash,
  verifyCanonicalHash,
  NonceRegistry,
} from "../../src/crypto/ed25519";

import { canonicalHash as offerCanonicalHash, createOffer } from "../../src/protocol/trade_offer";
import { canonicalHash as acceptCanonicalHash, createAccept } from "../../src/protocol/trade_accept";
import { canonicalHash as cancelCanonicalHash, createCancel } from "../../src/protocol/trade_cancel";
import {
  canonicalHash as noticeCanonicalHash,
  createNotice,
} from "../../src/protocol/settlement_notice";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function freshKeyPair() {
  return generateKeyPair();
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("ed25519 crypto module", () => {
  // 1. Key generation -------------------------------------------------------

  it("generateKeyPair returns valid KeyObjects", () => {
    const kp = freshKeyPair();
    expect(kp.publicKey.type).toBe("public");
    expect(kp.privateKey.type).toBe("private");
    expect(kp.publicKey.asymmetricKeyType).toBe("ed25519");
    expect(kp.privateKey.asymmetricKeyType).toBe("ed25519");
  });

  it("publicKeyHex / privateKeyHex return 64-char hex strings", () => {
    const kp = freshKeyPair();
    const pub = publicKeyHex(kp.publicKey);
    const priv = privateKeyHex(kp.privateKey);
    expect(pub).toMatch(/^[0-9a-f]{64}$/);
    expect(priv).toMatch(/^[0-9a-f]{64}$/);
  });

  // 2. signMessage / verifyMessage ------------------------------------------

  it("signMessage produces a hex string", () => {
    const kp = freshKeyPair();
    const sig = signMessage("hello", kp.privateKey);
    // Ed25519 signature is 64 bytes = 128 hex chars
    expect(sig).toMatch(/^[0-9a-f]{128}$/);
  });

  it("verifyMessage returns true for a valid signature", () => {
    const kp = freshKeyPair();
    const sig = signMessage("hello", kp.privateKey);
    expect(verifyMessage("hello", sig, kp.publicKey)).toBe(true);
  });

  it("verifyMessage returns false for wrong key", () => {
    const kp1 = freshKeyPair();
    const kp2 = freshKeyPair();
    const sig = signMessage("hello", kp1.privateKey);
    expect(verifyMessage("hello", sig, kp2.publicKey)).toBe(false);
  });

  it("verifyMessage returns false for altered message", () => {
    const kp = freshKeyPair();
    const sig = signMessage("hello", kp.privateKey);
    expect(verifyMessage("hell0", sig, kp.publicKey)).toBe(false);
  });

  // 3. signCanonicalHash / verifyCanonicalHash ------------------------------

  it("signCanonicalHash + verifyCanonicalHash roundtrip", () => {
    const kp = freshKeyPair();
    const hash = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";
    const sig = signCanonicalHash(hash, kp.privateKey);
    expect(verifyCanonicalHash(hash, sig, kp.publicKey)).toBe(true);
  });

  // 4. Deterministic & distinct signatures ----------------------------------

  it("different messages produce different signatures", () => {
    const kp = freshKeyPair();
    const sig1 = signMessage("alpha", kp.privateKey);
    const sig2 = signMessage("beta", kp.privateKey);
    expect(sig1).not.toBe(sig2);
  });

  it("ed25519 signatures are deterministic (same key+message = same sig)", () => {
    const kp = freshKeyPair();
    const sig1 = signMessage("deterministic", kp.privateKey);
    const sig2 = signMessage("deterministic", kp.privateKey);
    expect(sig1).toBe(sig2);
  });

  // 5. Protocol message signing ---------------------------------------------

  it("sign and verify trade_offer canonical hash", () => {
    const kp = freshKeyPair();
    const offer = createOffer({
      pair: "SOST/XAUT",
      side: "sell",
      amount_sost: "100.00000000",
      amount_gold: "0.050000000000000000",
      price: "0.0005",
      maker_sost_addr: "sost1abc",
      maker_eth_addr: "0xdef",
    });
    const hash = offerCanonicalHash(offer);
    const sig = signCanonicalHash(hash, kp.privateKey);
    expect(verifyCanonicalHash(hash, sig, kp.publicKey)).toBe(true);
  });

  it("sign and verify trade_accept canonical hash", () => {
    const kp = freshKeyPair();
    const accept = createAccept({
      offer_id: "abcdef0123456789",
      taker_sost_addr: "sost1xyz",
      taker_eth_addr: "0x999",
      fill_amount_sost: "50.00000000",
      fill_amount_gold: "0.025000000000000000",
    });
    const hash = acceptCanonicalHash(accept);
    const sig = signCanonicalHash(hash, kp.privateKey);
    expect(verifyCanonicalHash(hash, sig, kp.publicKey)).toBe(true);
  });

  it("sign and verify trade_cancel canonical hash", () => {
    const kp = freshKeyPair();
    const cancel = createCancel({
      target_id: "abcdef0123456789",
      target_type: "offer",
      cancelled_by: "sost1abc",
      reason: "changed my mind",
    });
    const hash = cancelCanonicalHash(cancel);
    const sig = signCanonicalHash(hash, kp.privateKey);
    expect(verifyCanonicalHash(hash, sig, kp.publicKey)).toBe(true);
  });

  it("sign and verify settlement_notice canonical hash", () => {
    const kp = freshKeyPair();
    const notice = createNotice({
      deal_id: "deal0000deadbeef",
      outcome: "settled",
      eth_tx_hash: "0xabc123",
      sost_txid: "txid456",
      detail: "both sides confirmed",
    });
    const hash = noticeCanonicalHash(notice);
    const sig = signCanonicalHash(hash, kp.privateKey);
    expect(verifyCanonicalHash(hash, sig, kp.publicKey)).toBe(true);
  });

  // 6. Tamper detection -----------------------------------------------------

  it("altered field after signing causes verification failure", () => {
    const kp = freshKeyPair();
    const offer = createOffer({
      pair: "SOST/XAUT",
      side: "buy",
      amount_sost: "200.00000000",
      amount_gold: "0.100000000000000000",
      price: "0.0005",
      maker_sost_addr: "sost1maker",
      maker_eth_addr: "0xmaker",
    });
    const originalHash = offerCanonicalHash(offer);
    const sig = signCanonicalHash(originalHash, kp.privateKey);

    // Tamper with the amount
    const tampered = { ...offer, amount_sost: "999.00000000" };
    const tamperedHash = offerCanonicalHash(tampered);
    expect(verifyCanonicalHash(tamperedHash, sig, kp.publicKey)).toBe(false);
  });

  it("wrong key pair causes verification failure", () => {
    const signer = freshKeyPair();
    const imposter = freshKeyPair();
    const offer = createOffer({
      pair: "SOST/PAXG",
      side: "sell",
      amount_sost: "10.00000000",
      amount_gold: "0.005000000000000000",
      price: "0.0005",
      maker_sost_addr: "sost1real",
      maker_eth_addr: "0xreal",
    });
    const hash = offerCanonicalHash(offer);
    const sig = signCanonicalHash(hash, signer.privateKey);
    expect(verifyCanonicalHash(hash, sig, imposter.publicKey)).toBe(false);
  });

  // 7. NonceRegistry --------------------------------------------------------

  it("NonceRegistry detects replay (same nonce used twice)", () => {
    const registry = new NonceRegistry();
    const nonce = "unique-nonce-abc123";

    expect(registry.has(nonce)).toBe(false);
    expect(registry.add(nonce)).toBe(true);   // first use succeeds
    expect(registry.has(nonce)).toBe(true);
    expect(registry.add(nonce)).toBe(false);  // replay detected
    expect(registry.size).toBe(1);
  });
});
