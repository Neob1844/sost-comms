import { describe, it, expect, beforeEach, afterEach } from "vitest";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";

import { generateKeyPair, NonceRegistry } from "../../src/crypto/ed25519";
import { signTradeMessage } from "../../src/runtime/sign_and_verify";
import { createOffer } from "../../src/protocol/trade_offer";
import { createAccept } from "../../src/protocol/trade_accept";
import { createCancel } from "../../src/protocol/trade_cancel";
import { createNotice } from "../../src/protocol/settlement_notice";
import { RelayNode } from "../../src/relay/relay_node";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

let tmpDir: string;

function makeTmpDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), "sost-relay-"));
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

function sampleCancel(targetId: string, targetType: "offer" | "deal") {
  return createCancel({
    target_id: targetId,
    target_type: targetType,
    cancelled_by: "sost1maker",
    reason: "changed mind",
  });
}

function sampleNotice(dealId: string) {
  return createNotice({
    deal_id: dealId,
    outcome: "settled",
    eth_tx_hash: "0xabc",
    sost_txid: "txid123",
    detail: "all good",
  });
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("RelayNode", () => {
  let relay: RelayNode;

  beforeEach(() => {
    tmpDir = makeTmpDir();
    relay = new RelayNode({ dataDir: tmpDir });
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  // 1
  it("submit offer creates pending entry", () => {
    const kp = generateKeyPair();
    const offer = sampleOffer();
    const signed = signTradeMessage(offer, kp.privateKey);

    const result = relay.submit(offer, signed.signature, kp.publicKey);
    expect(result.accepted).toBe(true);
    expect(result.deal_id).toBeUndefined();

    const offers = relay.getOffers();
    expect(offers).toHaveLength(1);
    expect(offers[0].message.offer_id).toBe(offer.offer_id);
  });

  // 2
  it("submit accept creates deal channel", () => {
    const makerKp = generateKeyPair();
    const takerKp = generateKeyPair();

    const offer = sampleOffer();
    const signedOffer = signTradeMessage(offer, makerKp.privateKey);
    relay.submit(offer, signedOffer.signature, makerKp.publicKey);

    const accept = sampleAccept(offer.offer_id);
    const signedAccept = signTradeMessage(accept, takerKp.privateKey);
    const result = relay.submit(accept, signedAccept.signature, takerKp.publicKey);

    expect(result.accepted).toBe(true);
    expect(result.deal_id).toBe(accept.deal_id);

    const deals = relay.listDeals();
    expect(deals).toHaveLength(1);
    expect(deals[0].deal_id).toBe(accept.deal_id);
  });

  // 3
  it("submit with bad signature rejected", () => {
    const kp1 = generateKeyPair();
    const kp2 = generateKeyPair();
    const offer = sampleOffer();
    const signed = signTradeMessage(offer, kp1.privateKey);

    // Submit with wrong public key
    const result = relay.submit(offer, signed.signature, kp2.publicKey);
    expect(result.accepted).toBe(false);
    expect(result.reason).toBe("invalid_signature");
  });

  // 4
  it("submit with replay nonce rejected", () => {
    const kp = generateKeyPair();
    const offer = sampleOffer();
    const signed = signTradeMessage(offer, kp.privateKey);

    relay.submit(offer, signed.signature, kp.publicKey);
    const result = relay.submit(offer, signed.signature, kp.publicKey);
    expect(result.accepted).toBe(false);
    expect(result.reason).toBe("replay_nonce");
  });

  // 5
  it("getDealHistory returns full history", () => {
    const makerKp = generateKeyPair();
    const takerKp = generateKeyPair();

    const offer = sampleOffer();
    const signedOffer = signTradeMessage(offer, makerKp.privateKey);
    relay.submit(offer, signedOffer.signature, makerKp.publicKey);

    const accept = sampleAccept(offer.offer_id);
    const signedAccept = signTradeMessage(accept, takerKp.privateKey);
    relay.submit(accept, signedAccept.signature, takerKp.publicKey);

    const history = relay.getDealHistory(accept.deal_id);
    expect(history).toHaveLength(2);
    expect(history[0].type).toBe("trade_offer");
    expect(history[1].type).toBe("trade_accept");
  });

  // 6
  it("listDeals shows active deals", () => {
    const makerKp = generateKeyPair();
    const takerKp = generateKeyPair();

    // Create two deals
    const offer1 = sampleOffer();
    const signed1 = signTradeMessage(offer1, makerKp.privateKey);
    relay.submit(offer1, signed1.signature, makerKp.publicKey);
    const accept1 = sampleAccept(offer1.offer_id);
    const sa1 = signTradeMessage(accept1, takerKp.privateKey);
    relay.submit(accept1, sa1.signature, takerKp.publicKey);

    const offer2 = sampleOffer();
    const signed2 = signTradeMessage(offer2, makerKp.privateKey);
    relay.submit(offer2, signed2.signature, makerKp.publicKey);
    const accept2 = sampleAccept(offer2.offer_id);
    const sa2 = signTradeMessage(accept2, takerKp.privateKey);
    relay.submit(accept2, sa2.signature, takerKp.publicKey);

    const deals = relay.listDeals();
    expect(deals).toHaveLength(2);
  });

  // 7
  it("submit cancel to existing deal", () => {
    const makerKp = generateKeyPair();
    const takerKp = generateKeyPair();

    const offer = sampleOffer();
    const signedOffer = signTradeMessage(offer, makerKp.privateKey);
    relay.submit(offer, signedOffer.signature, makerKp.publicKey);

    const accept = sampleAccept(offer.offer_id);
    const signedAccept = signTradeMessage(accept, takerKp.privateKey);
    relay.submit(accept, signedAccept.signature, takerKp.publicKey);

    const cancel = sampleCancel(accept.deal_id, "deal");
    const signedCancel = signTradeMessage(cancel, makerKp.privateKey);
    const result = relay.submit(cancel, signedCancel.signature, makerKp.publicKey);

    expect(result.accepted).toBe(true);
    expect(result.deal_id).toBe(accept.deal_id);

    const history = relay.getDealHistory(accept.deal_id);
    expect(history).toHaveLength(3);
    expect(history[2].type).toBe("trade_cancel");
  });

  // 8
  it("submit settlement_notice to existing deal", () => {
    const makerKp = generateKeyPair();
    const takerKp = generateKeyPair();
    const daemonKp = generateKeyPair();

    const offer = sampleOffer();
    const signedOffer = signTradeMessage(offer, makerKp.privateKey);
    relay.submit(offer, signedOffer.signature, makerKp.publicKey);

    const accept = sampleAccept(offer.offer_id);
    const signedAccept = signTradeMessage(accept, takerKp.privateKey);
    relay.submit(accept, signedAccept.signature, takerKp.publicKey);

    const notice = sampleNotice(accept.deal_id);
    const signedNotice = signTradeMessage(notice, daemonKp.privateKey);
    const result = relay.submit(notice, signedNotice.signature, daemonKp.publicKey);

    expect(result.accepted).toBe(true);
    expect(result.deal_id).toBe(accept.deal_id);
  });

  // 9
  it("submit to non-existent deal rejected (for cancel/notice)", () => {
    const kp = generateKeyPair();

    const cancel = sampleCancel("nonexistent_deal", "deal");
    const signedCancel = signTradeMessage(cancel, kp.privateKey);
    const result = relay.submit(cancel, signedCancel.signature, kp.publicKey);

    expect(result.accepted).toBe(false);
    expect(result.reason).toBe("deal_not_found");
  });

  // 10
  it("full E2E: offer -> accept -> cancel flow", () => {
    const makerKp = generateKeyPair();
    const takerKp = generateKeyPair();

    // Step 1: Maker submits offer
    const offer = sampleOffer();
    const signedOffer = signTradeMessage(offer, makerKp.privateKey);
    const offerResult = relay.submit(offer, signedOffer.signature, makerKp.publicKey);
    expect(offerResult.accepted).toBe(true);
    expect(relay.getOffers()).toHaveLength(1);

    // Step 2: Taker accepts offer — creates deal
    const accept = sampleAccept(offer.offer_id);
    const signedAccept = signTradeMessage(accept, takerKp.privateKey);
    const acceptResult = relay.submit(accept, signedAccept.signature, takerKp.publicKey);
    expect(acceptResult.accepted).toBe(true);
    expect(acceptResult.deal_id).toBe(accept.deal_id);
    expect(relay.getOffers()).toHaveLength(0);  // offer moved to deal
    expect(relay.listDeals()).toHaveLength(1);

    // Step 3: Maker cancels deal
    const cancel = sampleCancel(accept.deal_id, "deal");
    const signedCancel = signTradeMessage(cancel, makerKp.privateKey);
    const cancelResult = relay.submit(cancel, signedCancel.signature, makerKp.publicKey);
    expect(cancelResult.accepted).toBe(true);

    // Verify full history
    const history = relay.getDealHistory(accept.deal_id);
    expect(history).toHaveLength(3);
    expect(history.map(m => m.type)).toEqual(["trade_offer", "trade_accept", "trade_cancel"]);
  });
});
