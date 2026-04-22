import { describe, it, expect, beforeEach, afterEach } from "vitest";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";

import { generateKeyPair, NonceRegistry } from "../../src/crypto/ed25519";
import { signTradeMessage } from "../../src/runtime/sign_and_verify";
import { createPositionOffer } from "../../src/protocol/trade_offer";
import { createAccept } from "../../src/protocol/trade_accept";
import { createNotice } from "../../src/protocol/settlement_notice";
import { RelayNode } from "../../src/relay/relay_node";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

let tmpDir: string;

function makeTmpDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), "sost-relay-pos-"));
}

function samplePositionOffer(assetType: "POSITION_FULL" | "POSITION_REWARD_RIGHT" = "POSITION_FULL") {
  return createPositionOffer({
    asset_type: assetType,
    position_id: "pos_test_" + Math.random().toString(36).substring(2, 10),
    price_sost: "5000000",
    side: "sell",
    amount_sost: "5000000",
    maker_sost_addr: "sost1seller_alpha_test_001",
    maker_eth_addr: "0xSellerEth",
    ttl_seconds: 3600,
  });
}

function samplePositionAccept(
  offerId: string,
  assetType: "POSITION_FULL" | "POSITION_REWARD_RIGHT" = "POSITION_FULL",
  positionId?: string,
) {
  return createAccept({
    offer_id: offerId,
    taker_sost_addr: "sost1buyer_alpha_test_001",
    taker_eth_addr: "0xBuyerEth",
    fill_amount_sost: "5000000",
    fill_amount_gold: "0",
    asset_type: assetType,
    position_id: positionId,
  });
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("RelayNode — Position Trade", () => {
  let relay: RelayNode;

  beforeEach(() => {
    tmpDir = makeTmpDir();
    relay = new RelayNode({ dataDir: tmpDir });
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  // 1
  it("submit position offer to relay node — accepted", () => {
    const kp = generateKeyPair();
    const offer = samplePositionOffer("POSITION_FULL");
    const signed = signTradeMessage(offer, kp.privateKey);

    const result = relay.submit(offer, signed.signature, kp.publicKey);
    expect(result.accepted).toBe(true);

    const offers = relay.getOffers();
    expect(offers).toHaveLength(1);
    expect(offers[0].message.offer_id).toBe(offer.offer_id);
    expect(offers[0].message.asset_type).toBe("POSITION_FULL");
    expect(offers[0].message.position_id).toBeDefined();
  });

  // 2
  it("submit position accept — deal channel created", () => {
    const sellerKp = generateKeyPair();
    const buyerKp = generateKeyPair();

    const offer = samplePositionOffer("POSITION_FULL");
    const signedOffer = signTradeMessage(offer, sellerKp.privateKey);
    relay.submit(offer, signedOffer.signature, sellerKp.publicKey);

    const accept = samplePositionAccept(offer.offer_id, "POSITION_FULL", offer.position_id);
    const signedAccept = signTradeMessage(accept, buyerKp.privateKey);
    const result = relay.submit(accept, signedAccept.signature, buyerKp.publicKey);

    expect(result.accepted).toBe(true);
    expect(result.deal_id).toBe(accept.deal_id);

    const deals = relay.listDeals();
    expect(deals).toHaveLength(1);
    expect(deals[0].deal_id).toBe(accept.deal_id);
  });

  // 3
  it("get deal history shows offer + accept", () => {
    const sellerKp = generateKeyPair();
    const buyerKp = generateKeyPair();

    const offer = samplePositionOffer("POSITION_FULL");
    const signedOffer = signTradeMessage(offer, sellerKp.privateKey);
    relay.submit(offer, signedOffer.signature, sellerKp.publicKey);

    const accept = samplePositionAccept(offer.offer_id, "POSITION_FULL", offer.position_id);
    const signedAccept = signTradeMessage(accept, buyerKp.privateKey);
    relay.submit(accept, signedAccept.signature, buyerKp.publicKey);

    const history = relay.getDealHistory(accept.deal_id);
    expect(history).toHaveLength(2);
    expect(history[0].type).toBe("trade_offer");
    expect(history[1].type).toBe("trade_accept");
  });

  // 4
  it("submit settlement notice to deal — accepted", () => {
    const sellerKp = generateKeyPair();
    const buyerKp = generateKeyPair();
    const operatorKp = generateKeyPair();

    const offer = samplePositionOffer("POSITION_FULL");
    const signedOffer = signTradeMessage(offer, sellerKp.privateKey);
    relay.submit(offer, signedOffer.signature, sellerKp.publicKey);

    const accept = samplePositionAccept(offer.offer_id, "POSITION_FULL", offer.position_id);
    const signedAccept = signTradeMessage(accept, buyerKp.privateKey);
    relay.submit(accept, signedAccept.signature, buyerKp.publicKey);

    const notice = createNotice({
      deal_id: accept.deal_id,
      outcome: "settled",
      eth_tx_hash: "0xsettlement_tx",
      sost_txid: "sost_txid_001",
      settlement_ref: offer.position_id,
      detail: `POSITION_FULL transfer completed`,
    });
    const signedNotice = signTradeMessage(notice, operatorKp.privateKey);
    const result = relay.submit(notice, signedNotice.signature, operatorKp.publicKey);

    expect(result.accepted).toBe(true);
    expect(result.deal_id).toBe(accept.deal_id);
  });

  // 5
  it("full flow: offer -> accept -> notice -> all in channel", () => {
    const sellerKp = generateKeyPair();
    const buyerKp = generateKeyPair();
    const operatorKp = generateKeyPair();

    // Step 1: Offer
    const offer = samplePositionOffer("POSITION_FULL");
    const signedOffer = signTradeMessage(offer, sellerKp.privateKey);
    const offerResult = relay.submit(offer, signedOffer.signature, sellerKp.publicKey);
    expect(offerResult.accepted).toBe(true);
    expect(relay.getOffers()).toHaveLength(1);

    // Step 2: Accept
    const accept = samplePositionAccept(offer.offer_id, "POSITION_FULL", offer.position_id);
    const signedAccept = signTradeMessage(accept, buyerKp.privateKey);
    const acceptResult = relay.submit(accept, signedAccept.signature, buyerKp.publicKey);
    expect(acceptResult.accepted).toBe(true);
    expect(acceptResult.deal_id).toBe(accept.deal_id);
    expect(relay.getOffers()).toHaveLength(0);
    expect(relay.listDeals()).toHaveLength(1);

    // Step 3: Settlement notice
    const notice = createNotice({
      deal_id: accept.deal_id,
      outcome: "settled",
      eth_tx_hash: "0xfinal_tx",
      detail: "position transferred",
    });
    const signedNotice = signTradeMessage(notice, operatorKp.privateKey);
    const noticeResult = relay.submit(notice, signedNotice.signature, operatorKp.publicKey);
    expect(noticeResult.accepted).toBe(true);

    // Verify full channel
    const history = relay.getDealHistory(accept.deal_id);
    expect(history).toHaveLength(3);
    expect(history.map(m => m.type)).toEqual([
      "trade_offer",
      "trade_accept",
      "settlement_notice",
    ]);
  });

  // 6
  it("position fields preserved in stored messages", () => {
    const sellerKp = generateKeyPair();
    const buyerKp = generateKeyPair();

    const offer = samplePositionOffer("POSITION_REWARD_RIGHT");
    const signedOffer = signTradeMessage(offer, sellerKp.privateKey);
    relay.submit(offer, signedOffer.signature, sellerKp.publicKey);

    const accept = samplePositionAccept(
      offer.offer_id,
      "POSITION_REWARD_RIGHT",
      offer.position_id,
    );
    const signedAccept = signTradeMessage(accept, buyerKp.privateKey);
    relay.submit(accept, signedAccept.signature, buyerKp.publicKey);

    const history = relay.getDealHistory(accept.deal_id);
    expect(history).toHaveLength(2);

    // Verify offer position fields
    const storedOffer = history[0].message;
    expect(storedOffer.asset_type).toBe("POSITION_REWARD_RIGHT");
    expect(storedOffer.position_id).toBe(offer.position_id);
    expect(storedOffer.price_sost).toBe("5000000");

    // Verify accept position fields
    const storedAccept = history[1].message;
    expect(storedAccept.asset_type).toBe("POSITION_REWARD_RIGHT");
    expect(storedAccept.position_id).toBe(offer.position_id);
  });
});
