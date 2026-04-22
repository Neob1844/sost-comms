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
  return fs.mkdtempSync(path.join(os.tmpdir(), "sost-replay-"));
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

/** Set up an offer + accept on the relay, returning the deal context. */
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

describe("Replay rejection", () => {
  let relay: RelayNode;

  beforeEach(() => {
    tmpDir = makeTmpDir();
    relay = new RelayNode({ dataDir: tmpDir });
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  // 1
  it("same offer submitted twice — second rejected with replay_nonce", () => {
    const kp = generateKeyPair();
    const offer = sampleOffer();
    const signed = signTradeMessage(offer, kp.privateKey);

    const r1 = relay.submit(offer, signed.signature, kp.publicKey);
    expect(r1.accepted).toBe(true);

    const r2 = relay.submit(offer, signed.signature, kp.publicKey);
    expect(r2.accepted).toBe(false);
    expect(r2.reason).toBe("replay_nonce");
  });

  // 2
  it("same accept submitted twice — second rejected", () => {
    const makerKp = generateKeyPair();
    const takerKp = generateKeyPair();

    const offer = sampleOffer();
    const signedOffer = signTradeMessage(offer, makerKp.privateKey);
    relay.submit(offer, signedOffer.signature, makerKp.publicKey);

    const accept = sampleAccept(offer.offer_id);
    const signedAccept = signTradeMessage(accept, takerKp.privateKey);

    const r1 = relay.submit(accept, signedAccept.signature, takerKp.publicKey);
    expect(r1.accepted).toBe(true);

    const r2 = relay.submit(accept, signedAccept.signature, takerKp.publicKey);
    expect(r2.accepted).toBe(false);
    expect(r2.reason).toBe("replay_nonce");
  });

  // 3
  it("same cancel submitted twice — second rejected", () => {
    const { makerKp, dealId } = setupDeal(relay);

    const cancel = createCancel({
      target_id: dealId,
      target_type: "deal",
      cancelled_by: "sost1maker",
      reason: "double cancel test",
    });
    const signedCancel = signTradeMessage(cancel, makerKp.privateKey);

    const r1 = relay.submit(cancel, signedCancel.signature, makerKp.publicKey);
    expect(r1.accepted).toBe(true);

    const r2 = relay.submit(cancel, signedCancel.signature, makerKp.publicKey);
    expect(r2.accepted).toBe(false);
    expect(r2.reason).toBe("replay_nonce");
  });

  // 4
  it("nonce from offer reused in cancel — rejected", () => {
    const kp = generateKeyPair();
    const offer = sampleOffer();
    const signedOffer = signTradeMessage(offer, kp.privateKey);

    const r1 = relay.submit(offer, signedOffer.signature, kp.publicKey);
    expect(r1.accepted).toBe(true);

    // Construct a cancel that reuses the offer's nonce
    const cancel = createCancel({
      target_id: offer.offer_id,
      target_type: "offer",
      cancelled_by: "sost1maker",
      reason: "reuse nonce attack",
    });
    // Overwrite with the same nonce from the offer
    (cancel as any).nonce = offer.nonce;
    const signedCancel = signTradeMessage(cancel, kp.privateKey);

    const r2 = relay.submit(cancel, signedCancel.signature, kp.publicKey);
    expect(r2.accepted).toBe(false);
    expect(r2.reason).toBe("replay_nonce");
  });

  // 5
  it("fresh nonce always accepted", () => {
    const kp = generateKeyPair();

    // Submit multiple offers — each has a fresh nonce from createOffer
    for (let i = 0; i < 5; i++) {
      const offer = sampleOffer();
      const signed = signTradeMessage(offer, kp.privateKey);
      const result = relay.submit(offer, signed.signature, kp.publicKey);
      expect(result.accepted).toBe(true);
    }

    expect(relay.getOffers()).toHaveLength(5);
  });

  // 6
  it("NonceRegistry persists across relay node lifetime (within same process)", () => {
    const kp = generateKeyPair();
    const offer = sampleOffer();
    const signed = signTradeMessage(offer, kp.privateKey);

    // First submission succeeds
    const r1 = relay.submit(offer, signed.signature, kp.publicKey);
    expect(r1.accepted).toBe(true);

    // Later in the same relay lifetime — replay still blocked
    // (simulating time passing by submitting other messages first)
    for (let i = 0; i < 10; i++) {
      const freshOffer = sampleOffer();
      const freshSigned = signTradeMessage(freshOffer, kp.privateKey);
      relay.submit(freshOffer, freshSigned.signature, kp.publicKey);
    }

    // Now try the original nonce again — must still be rejected
    const r2 = relay.submit(offer, signed.signature, kp.publicKey);
    expect(r2.accepted).toBe(false);
    expect(r2.reason).toBe("replay_nonce");
  });
});
