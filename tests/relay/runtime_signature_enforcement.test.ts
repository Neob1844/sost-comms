import { describe, it, expect, beforeEach, afterEach } from "vitest";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";

import { generateKeyPair, publicKeyHex } from "../../src/crypto/ed25519";
import { createOffer } from "../../src/protocol/trade_offer";
import { createAccept, deriveDealId } from "../../src/protocol/trade_accept";
import { createCancel } from "../../src/protocol/trade_cancel";
import { createNotice } from "../../src/protocol/settlement_notice";
import { signTradeMessage } from "../../src/runtime/sign_and_verify";
import { RelayNode } from "../../src/relay/relay_node";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

let tmpDir: string;

function makeTmpDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), "sost-sig-enforce-"));
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

function sampleAccept(offerId: string) {
  return createAccept({
    offer_id: offerId,
    taker_sost_addr: "sost1taker",
    taker_eth_addr: "0xtaker",
    fill_amount_sost: "50.00000000",
    fill_amount_gold: "0.025000000000000000",
  });
}

/** Set up offer + accept on the relay, returning the deal_id. */
function setupDeal(relay: RelayNode) {
  const makerKp = generateKeyPair();
  const takerKp = generateKeyPair();

  const offer = sampleOffer();
  const signedOffer = signTradeMessage(offer, makerKp.privateKey);
  relay.submit(offer, signedOffer.signature, makerKp.publicKey);

  const accept = sampleAccept(offer.offer_id);
  const signedAccept = signTradeMessage(accept, takerKp.privateKey);
  relay.submit(accept, signedAccept.signature, takerKp.publicKey);

  return { makerKp, takerKp, offer, accept, dealId: accept.deal_id };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("Runtime signature enforcement", () => {
  let relay: RelayNode;

  beforeEach(() => {
    tmpDir = makeTmpDir();
    relay = new RelayNode({ dataDir: tmpDir });
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  // 1
  it("rejects offer without signature", () => {
    const kp = generateKeyPair();
    const offer = sampleOffer();

    // Submit with undefined/empty signature — no signing step
    const result = relay.submit(offer, "", kp.publicKey);
    expect(result.accepted).toBe(false);
    expect(result.reason).toBe("invalid_signature");
  });

  // 2
  it("rejects offer with empty signature string", () => {
    const kp = generateKeyPair();
    const offer = sampleOffer();

    const result = relay.submit(offer, "  ", kp.publicKey);
    expect(result.accepted).toBe(false);
    expect(result.reason).toBe("invalid_signature");
  });

  // 3
  it("rejects accept with forged signature (valid ed25519 but wrong key)", () => {
    const makerKp = generateKeyPair();
    const takerKp = generateKeyPair();
    const forgerKp = generateKeyPair();

    const offer = sampleOffer();
    const signedOffer = signTradeMessage(offer, makerKp.privateKey);
    relay.submit(offer, signedOffer.signature, makerKp.publicKey);

    const accept = sampleAccept(offer.offer_id);
    // Sign with forger's key but present taker's public key
    const forgedSigned = signTradeMessage(accept, forgerKp.privateKey);
    const result = relay.submit(accept, forgedSigned.signature, takerKp.publicKey);

    expect(result.accepted).toBe(false);
    expect(result.reason).toBe("invalid_signature");
  });

  // 4
  it("rejects cancel with signature from non-party", () => {
    const { dealId } = setupDeal(relay);
    const outsiderKp = generateKeyPair();

    const cancel = createCancel({
      target_id: dealId,
      target_type: "deal",
      cancelled_by: "sost1outsider",
      reason: "hostile cancel",
    });
    // Sign with outsider's key but present a *different* outsider key as verifier
    const anotherKp = generateKeyPair();
    const signedCancel = signTradeMessage(cancel, outsiderKp.privateKey);
    const result = relay.submit(cancel, signedCancel.signature, anotherKp.publicKey);

    expect(result.accepted).toBe(false);
    expect(result.reason).toBe("invalid_signature");
  });

  // 5
  it("accepts settlement_notice with valid operator signature", () => {
    const { dealId } = setupDeal(relay);
    const operatorKp = generateKeyPair();

    const notice = createNotice({
      deal_id: dealId,
      outcome: "settled",
      eth_tx_hash: "0xabc",
      sost_txid: "txid123",
      detail: "settlement complete",
    });
    const signedNotice = signTradeMessage(notice, operatorKp.privateKey);
    const result = relay.submit(notice, signedNotice.signature, operatorKp.publicKey);

    expect(result.accepted).toBe(true);
    expect(result.deal_id).toBe(dealId);
  });

  // 6
  it("rejects tampered offer (amount_sost changed after signing)", () => {
    const kp = generateKeyPair();
    const offer = sampleOffer();
    const signed = signTradeMessage(offer, kp.privateKey);

    // Tamper with the message after signing
    const tampered = { ...offer, amount_sost: "999.00000000" };
    const result = relay.submit(tampered, signed.signature, kp.publicKey);

    expect(result.accepted).toBe(false);
    expect(result.reason).toBe("invalid_signature");
  });

  // 7
  it("rejects tampered accept (fill_amount changed after signing)", () => {
    const makerKp = generateKeyPair();
    const takerKp = generateKeyPair();

    const offer = sampleOffer();
    const signedOffer = signTradeMessage(offer, makerKp.privateKey);
    relay.submit(offer, signedOffer.signature, makerKp.publicKey);

    const accept = sampleAccept(offer.offer_id);
    const signedAccept = signTradeMessage(accept, takerKp.privateKey);

    // Tamper with fill amount
    const tampered = { ...accept, fill_amount_sost: "999.00000000" };
    const result = relay.submit(tampered, signedAccept.signature, takerKp.publicKey);

    expect(result.accepted).toBe(false);
    expect(result.reason).toBe("invalid_signature");
  });

  // 8
  it("valid chain: offer(signed) -> accept(signed) -> notice(signed) all accepted", () => {
    const makerKp = generateKeyPair();
    const takerKp = generateKeyPair();
    const operatorKp = generateKeyPair();

    // Step 1: offer
    const offer = sampleOffer();
    const signedOffer = signTradeMessage(offer, makerKp.privateKey);
    const r1 = relay.submit(offer, signedOffer.signature, makerKp.publicKey);
    expect(r1.accepted).toBe(true);

    // Step 2: accept
    const accept = sampleAccept(offer.offer_id);
    const signedAccept = signTradeMessage(accept, takerKp.privateKey);
    const r2 = relay.submit(accept, signedAccept.signature, takerKp.publicKey);
    expect(r2.accepted).toBe(true);
    expect(r2.deal_id).toBe(accept.deal_id);

    // Step 3: settlement notice
    const notice = createNotice({
      deal_id: accept.deal_id,
      outcome: "settled",
      eth_tx_hash: "0xfinal",
      sost_txid: "txidfinal",
      detail: "deal completed",
    });
    const signedNotice = signTradeMessage(notice, operatorKp.privateKey);
    const r3 = relay.submit(notice, signedNotice.signature, operatorKp.publicKey);
    expect(r3.accepted).toBe(true);
    expect(r3.deal_id).toBe(accept.deal_id);

    // Verify full history
    const history = relay.getDealHistory(accept.deal_id);
    expect(history).toHaveLength(3);
    expect(history.map(m => m.type)).toEqual([
      "trade_offer",
      "trade_accept",
      "settlement_notice",
    ]);
  });
});
