import { describe, it, expect, beforeEach, afterEach } from "vitest";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";

import { generateKeyPair, publicKeyHex, NonceRegistry } from "../../src/crypto/ed25519";
import { createOffer } from "../../src/protocol/trade_offer";
import { createAccept, deriveDealId } from "../../src/protocol/trade_accept";
import { createCancel } from "../../src/protocol/trade_cancel";
import { createNotice } from "../../src/protocol/settlement_notice";
import { signTradeMessage } from "../../src/runtime/sign_and_verify";
import { MessageStore } from "../../src/relay/message_store";
import { DealChannel } from "../../src/relay/deal_channel";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

let tmpDir: string;

function makeTmpDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), "sost-persist-"));
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("Deal channel persistence", () => {
  beforeEach(() => {
    tmpDir = makeTmpDir();
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  // 1
  it("messages survive reload from same directory", () => {
    const kp = generateKeyPair();
    const nonces = new NonceRegistry();
    const dealId = "persist-deal-001";

    // Write with first store instance
    const store1 = new MessageStore(tmpDir);
    const channel1 = new DealChannel(dealId, store1, nonces);

    const offer = sampleOffer();
    const signed = signTradeMessage(offer, kp.privateKey);
    channel1.addMessage(offer, signed.signature, kp.publicKey);

    // Reload: create fresh store from same directory
    const store2 = new MessageStore(tmpDir);
    const history = store2.getByDealId(dealId);
    expect(history).toHaveLength(1);
    expect(history[0].message.offer_id).toBe(offer.offer_id);
    expect(history[0].verified).toBe(true);
  });

  // 2
  it("add offer, reload, add accept — both visible", () => {
    const makerKp = generateKeyPair();
    const takerKp = generateKeyPair();
    const dealId = "persist-deal-002";

    // Session 1: add offer
    const nonces1 = new NonceRegistry();
    const store1 = new MessageStore(tmpDir);
    const channel1 = new DealChannel(dealId, store1, nonces1);

    const offer = sampleOffer();
    const signedOffer = signTradeMessage(offer, makerKp.privateKey);
    channel1.addMessage(offer, signedOffer.signature, makerKp.publicKey);

    // Session 2: reload, add accept
    const nonces2 = new NonceRegistry();
    const store2 = new MessageStore(tmpDir);
    const channel2 = new DealChannel(dealId, store2, nonces2);

    const accept = sampleAccept(offer.offer_id);
    // Override deal_id to match our channel
    (accept as any).deal_id = dealId;
    const signedAccept = signTradeMessage(accept, takerKp.privateKey);
    channel2.addMessage(accept, signedAccept.signature, takerKp.publicKey);

    // Verify both are visible
    const history = channel2.getHistory();
    expect(history).toHaveLength(2);
    expect(history[0].type).toBe("trade_offer");
    expect(history[1].type).toBe("trade_accept");
  });

  // 3
  it("message ordering preserved after reload", () => {
    const kp = generateKeyPair();
    const dealId = "persist-deal-003";

    const store = new MessageStore(tmpDir);
    const nonces = new NonceRegistry();
    const channel = new DealChannel(dealId, store, nonces);

    // Add three messages in order
    const offer = sampleOffer();
    const s1 = signTradeMessage(offer, kp.privateKey);
    channel.addMessage(offer, s1.signature, kp.publicKey);

    const accept = sampleAccept(offer.offer_id);
    (accept as any).deal_id = dealId;
    const s2 = signTradeMessage(accept, kp.privateKey);
    channel.addMessage(accept, s2.signature, kp.publicKey);

    const cancel = createCancel({
      target_id: dealId,
      target_type: "deal",
      cancelled_by: "sost1maker",
      reason: "test ordering",
    });
    const s3 = signTradeMessage(cancel, kp.privateKey);
    channel.addMessage(cancel, s3.signature, kp.publicKey);

    // Reload and check order
    const store2 = new MessageStore(tmpDir);
    const channel2 = new DealChannel(dealId, store2, new NonceRegistry());
    const history = channel2.getHistory();

    expect(history).toHaveLength(3);
    expect(history.map(m => m.type)).toEqual([
      "trade_offer",
      "trade_accept",
      "trade_cancel",
    ]);
    // received_at should be non-decreasing
    for (let i = 1; i < history.length; i++) {
      expect(history[i].received_at).toBeGreaterThanOrEqual(history[i - 1].received_at);
    }
  });

  // 4
  it("empty channel persists correctly", () => {
    const dealId = "persist-deal-empty";

    // Create store — no messages added
    const store1 = new MessageStore(tmpDir);

    // Reload
    const store2 = new MessageStore(tmpDir);
    const history = store2.getByDealId(dealId);
    expect(history).toHaveLength(0);
  });

  // 5
  it("large channel (20+ messages) persists correctly", () => {
    const kp = generateKeyPair();
    const dealId = "persist-deal-large";

    const store = new MessageStore(tmpDir);
    const nonces = new NonceRegistry();
    const channel = new DealChannel(dealId, store, nonces);

    const messageCount = 25;
    for (let i = 0; i < messageCount; i++) {
      const offer = sampleOffer();
      const signed = signTradeMessage(offer, kp.privateKey);
      channel.addMessage(offer, signed.signature, kp.publicKey);
    }

    // Reload and verify
    const store2 = new MessageStore(tmpDir);
    const history = store2.getByDealId(dealId);
    expect(history).toHaveLength(messageCount);

    // Each message should have a unique id
    const ids = new Set(history.map(m => m.id));
    expect(ids.size).toBe(messageCount);
  });

  // 6
  it("sequential saves don't corrupt data", () => {
    const kp = generateKeyPair();
    const dealId = "persist-deal-seq";

    const store = new MessageStore(tmpDir);
    const nonces = new NonceRegistry();
    const channel = new DealChannel(dealId, store, nonces);

    // First save
    const offer1 = sampleOffer();
    const s1 = signTradeMessage(offer1, kp.privateKey);
    channel.addMessage(offer1, s1.signature, kp.publicKey);

    // Immediately second save
    const offer2 = sampleOffer();
    const s2 = signTradeMessage(offer2, kp.privateKey);
    channel.addMessage(offer2, s2.signature, kp.publicKey);

    // Read back — both must be present and valid JSON
    const raw = fs.readFileSync(
      path.join(tmpDir, `${dealId}.json`),
      "utf-8",
    );
    const parsed = JSON.parse(raw);
    expect(parsed).toHaveLength(2);
    expect(parsed[0].message.offer_id).toBe(offer1.offer_id);
    expect(parsed[1].message.offer_id).toBe(offer2.offer_id);

    // Also verify through store API
    const reloaded = new MessageStore(tmpDir);
    expect(reloaded.getByDealId(dealId)).toHaveLength(2);
  });
});
