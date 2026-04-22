import { describe, it, expect, beforeEach, afterEach } from "vitest";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";

import { generateKeyPair, NonceRegistry } from "../../src/crypto/ed25519";
import { signTradeMessage } from "../../src/runtime/sign_and_verify";
import { createOffer } from "../../src/protocol/trade_offer";
import { createAccept } from "../../src/protocol/trade_accept";
import { createNotice } from "../../src/protocol/settlement_notice";
import { MessageStore, StoredMessage } from "../../src/relay/message_store";
import { DealChannel } from "../../src/relay/deal_channel";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

let tmpDir: string;

function makeTmpDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), "sost-channel-"));
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

describe("DealChannel", () => {
  let store: MessageStore;
  let registry: NonceRegistry;

  beforeEach(() => {
    tmpDir = makeTmpDir();
    store = new MessageStore(tmpDir);
    registry = new NonceRegistry();
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  // 1
  it("addMessage with valid signature accepted", () => {
    const kp = generateKeyPair();
    const offer = sampleOffer();
    const signed = signTradeMessage(offer, kp.privateKey);
    const channel = new DealChannel("deal_test", store, registry);

    const result = channel.addMessage(offer, signed.signature, kp.publicKey);
    expect(result.accepted).toBe(true);
  });

  // 2
  it("addMessage with invalid signature rejected", () => {
    const kp1 = generateKeyPair();
    const kp2 = generateKeyPair();
    const offer = sampleOffer();
    const signed = signTradeMessage(offer, kp1.privateKey);
    const channel = new DealChannel("deal_test", store, registry);

    // Verify with wrong key
    const result = channel.addMessage(offer, signed.signature, kp2.publicKey);
    expect(result.accepted).toBe(false);
    expect(result.reason).toBe("invalid_signature");
  });

  // 3
  it("addMessage with replay nonce rejected", () => {
    const kp = generateKeyPair();
    const offer = sampleOffer();
    const signed = signTradeMessage(offer, kp.privateKey);
    const channel = new DealChannel("deal_test", store, registry);

    // First submission passes
    const r1 = channel.addMessage(offer, signed.signature, kp.publicKey);
    expect(r1.accepted).toBe(true);

    // Second submission with same nonce fails
    const r2 = channel.addMessage(offer, signed.signature, kp.publicKey);
    expect(r2.accepted).toBe(false);
    expect(r2.reason).toBe("replay_nonce");
  });

  // 4
  it("getHistory returns ordered messages", () => {
    const kp = generateKeyPair();
    const channel = new DealChannel("deal_order", store, registry);

    const offer = sampleOffer();
    const signedOffer = signTradeMessage(offer, kp.privateKey);
    channel.addMessage(offer, signedOffer.signature, kp.publicKey);

    const accept = sampleAccept(offer.offer_id);
    const signedAccept = signTradeMessage(accept, kp.privateKey);
    channel.addMessage(accept, signedAccept.signature, kp.publicKey);

    const history = channel.getHistory();
    expect(history).toHaveLength(2);
    expect(history[0].type).toBe("trade_offer");
    expect(history[1].type).toBe("trade_accept");
  });

  // 5
  it("full flow: offer -> accept -> settlement_notice", () => {
    const makerKp = generateKeyPair();
    const takerKp = generateKeyPair();
    const daemonKp = generateKeyPair();

    const offer = sampleOffer();
    const accept = sampleAccept(offer.offer_id);
    const dealId = accept.deal_id;
    const notice = sampleNotice(dealId);

    const channel = new DealChannel(dealId, store, registry);

    // Offer
    const signedOffer = signTradeMessage(offer, makerKp.privateKey);
    expect(channel.addMessage(offer, signedOffer.signature, makerKp.publicKey).accepted).toBe(true);

    // Accept
    const signedAccept = signTradeMessage(accept, takerKp.privateKey);
    expect(channel.addMessage(accept, signedAccept.signature, takerKp.publicKey).accepted).toBe(true);

    // Settlement notice
    const signedNotice = signTradeMessage(notice, daemonKp.privateKey);
    expect(channel.addMessage(notice, signedNotice.signature, daemonKp.publicKey).accepted).toBe(true);

    const history = channel.getHistory();
    expect(history).toHaveLength(3);
    expect(history.map(m => m.type)).toEqual(["trade_offer", "trade_accept", "settlement_notice"]);
  });

  // 6
  it("getSummary returns correct info", () => {
    const kp = generateKeyPair();
    const channel = new DealChannel("deal_summary", store, registry);

    const offer = sampleOffer();
    const signed = signTradeMessage(offer, kp.privateKey);
    channel.addMessage(offer, signed.signature, kp.publicKey);

    const summary = channel.getSummary();
    expect(summary.deal_id).toBe("deal_summary");
    expect(summary.messages).toBe(1);
    expect(summary.last_type).toBe("trade_offer");
    expect(summary.last_at).toBeGreaterThan(0);
  });

  // 7
  it("getSummary on empty channel", () => {
    const channel = new DealChannel("deal_empty", store, registry);
    const summary = channel.getSummary();
    expect(summary.messages).toBe(0);
    expect(summary.last_type).toBe("");
    expect(summary.last_at).toBe(0);
  });

  // 8
  it("getHistory on empty channel returns empty array", () => {
    const channel = new DealChannel("deal_none", store, registry);
    expect(channel.getHistory()).toEqual([]);
  });
});
