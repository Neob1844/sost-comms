import { describe, it, expect, beforeEach } from "vitest";

import { generateKeyPair } from "../../src/crypto/ed25519";
import { NonceRegistry } from "../../src/crypto/ed25519";
import { createOffer } from "../../src/protocol/trade_offer";
import { createAccept } from "../../src/protocol/trade_accept";
import { createCancel } from "../../src/protocol/trade_cancel";
import { createNotice } from "../../src/protocol/settlement_notice";
import { signTradeMessage, verifyTradeMessage, SignedMessage } from "../../src/runtime/sign_and_verify";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function freshKeyPair() {
  return generateKeyPair();
}

function sampleOffer() {
  return createOffer({
    pair: "SOST/XAUT",
    side: "sell",
    amount_sost: "100.00000000",
    amount_gold: "0.050000000000000000",
    price: "0.0005",
    maker_sost_addr: "sost1maker",
    maker_eth_addr: "0xmaker",
    ttl_seconds: 3600,
  });
}

function sampleAccept(offer_id: string) {
  return createAccept({
    offer_id,
    taker_sost_addr: "sost1taker",
    taker_eth_addr: "0xtaker",
    fill_amount_sost: "50.00000000",
    fill_amount_gold: "0.025000000000000000",
  });
}

function sampleCancel(target_id: string) {
  return createCancel({
    target_id,
    target_type: "offer",
    cancelled_by: "sost1maker",
    reason: "changed mind",
  });
}

function sampleNotice(deal_id: string) {
  return createNotice({
    deal_id,
    outcome: "settled",
    eth_tx_hash: "0xabc",
    sost_txid: "txid123",
    detail: "all good",
  });
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("sign_and_verify runtime", () => {
  let registry: NonceRegistry;

  beforeEach(() => {
    registry = new NonceRegistry();
  });

  // 1
  it("signTradeMessage produces valid SignedMessage for trade_offer", () => {
    const kp = freshKeyPair();
    const offer = sampleOffer();
    const signed = signTradeMessage(offer, kp.privateKey);

    expect(signed.signature).toMatch(/^[0-9a-f]{128}$/);
    expect(signed.hash).toMatch(/^[0-9a-f]{64}$/);
    expect(signed.message).toBe(offer);
  });

  // 2
  it("signTradeMessage produces valid SignedMessage for trade_accept", () => {
    const kp = freshKeyPair();
    const accept = sampleAccept("offer123");
    const signed = signTradeMessage(accept, kp.privateKey);

    expect(signed.signature).toMatch(/^[0-9a-f]{128}$/);
    expect(signed.hash).toMatch(/^[0-9a-f]{64}$/);
  });

  // 3
  it("signTradeMessage produces valid SignedMessage for trade_cancel", () => {
    const kp = freshKeyPair();
    const cancel = sampleCancel("offer123");
    const signed = signTradeMessage(cancel, kp.privateKey);

    expect(signed.signature).toMatch(/^[0-9a-f]{128}$/);
  });

  // 4
  it("signTradeMessage produces valid SignedMessage for settlement_notice", () => {
    const kp = freshKeyPair();
    const notice = sampleNotice("deal456");
    const signed = signTradeMessage(notice, kp.privateKey);

    expect(signed.signature).toMatch(/^[0-9a-f]{128}$/);
  });

  // 5
  it("verifyTradeMessage returns valid for correct signature", () => {
    const kp = freshKeyPair();
    const offer = sampleOffer();
    const signed = signTradeMessage(offer, kp.privateKey);

    const result = verifyTradeMessage(signed, kp.publicKey, registry);
    expect(result.valid).toBe(true);
    expect(result.reason).toBe("ok");
  });

  // 6
  it("verifyTradeMessage fails for wrong key", () => {
    const kp1 = freshKeyPair();
    const kp2 = freshKeyPair();
    const offer = sampleOffer();
    const signed = signTradeMessage(offer, kp1.privateKey);

    const result = verifyTradeMessage(signed, kp2.publicKey, registry);
    expect(result.valid).toBe(false);
    expect(result.reason).toBe("invalid_signature");
  });

  // 7
  it("verifyTradeMessage fails for tampered message", () => {
    const kp = freshKeyPair();
    const offer = sampleOffer();
    const signed = signTradeMessage(offer, kp.privateKey);

    // Tamper with the message
    const tampered: SignedMessage = {
      ...signed,
      message: { ...signed.message, amount_sost: "999.00000000" },
    };

    const result = verifyTradeMessage(tampered, kp.publicKey, registry);
    expect(result.valid).toBe(false);
    expect(result.reason).toBe("invalid_signature");
  });

  // 8
  it("verifyTradeMessage detects replay nonce", () => {
    const kp = freshKeyPair();
    const offer = sampleOffer();
    const signed = signTradeMessage(offer, kp.privateKey);

    // First verify should pass
    const result1 = verifyTradeMessage(signed, kp.publicKey, registry);
    expect(result1.valid).toBe(true);

    // Second verify with same nonce should fail
    const result2 = verifyTradeMessage(signed, kp.publicKey, registry);
    expect(result2.valid).toBe(false);
    expect(result2.reason).toBe("replay_nonce");
  });

  // 9
  it("verifyTradeMessage detects expired offer", () => {
    const kp = freshKeyPair();
    const offer = sampleOffer();

    // Set expires_at to the past
    (offer as any).expires_at = Math.floor(Date.now() / 1000) - 100;
    // Recompute nonce so it's unique
    const signed = signTradeMessage(offer, kp.privateKey);

    const result = verifyTradeMessage(signed, kp.publicKey, registry);
    expect(result.valid).toBe(false);
    expect(result.reason).toBe("expired");
  });

  // 10
  it("full flow: create offer → sign → verify → create accept → sign → verify", () => {
    const makerKp = freshKeyPair();
    const takerKp = freshKeyPair();

    // Maker creates and signs offer
    const offer = sampleOffer();
    const signedOffer = signTradeMessage(offer, makerKp.privateKey);
    const offerResult = verifyTradeMessage(signedOffer, makerKp.publicKey, registry);
    expect(offerResult.valid).toBe(true);

    // Taker creates and signs accept
    const accept = sampleAccept(offer.offer_id);
    const signedAccept = signTradeMessage(accept, takerKp.privateKey);
    const acceptResult = verifyTradeMessage(signedAccept, takerKp.publicKey, registry);
    expect(acceptResult.valid).toBe(true);
  });

  // 11
  it("signTradeMessage throws on missing type", () => {
    const kp = freshKeyPair();
    expect(() => signTradeMessage({}, kp.privateKey)).toThrow();
  });

  // 12
  it("verifyTradeMessage returns invalid for unknown type", () => {
    const kp = freshKeyPair();
    const signed: SignedMessage = {
      message: { type: "bogus" },
      signature: "00".repeat(64),
      hash: "00".repeat(32),
    };
    const result = verifyTradeMessage(signed, kp.publicKey, registry);
    expect(result.valid).toBe(false);
    expect(result.reason).toBe("unknown_type");
  });
});
