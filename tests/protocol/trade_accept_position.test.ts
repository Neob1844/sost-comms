import { describe, it, expect, beforeEach } from "vitest";
import {
  canonicalHash,
  createAccept,
  deriveDealId,
} from "../../src/protocol/trade_accept";
import { createPositionOffer } from "../../src/protocol/trade_offer";
import { generateKeyPair, NonceRegistry } from "../../src/crypto/ed25519";
import { signTradeMessage, verifyTradeMessage } from "../../src/runtime/sign_and_verify";

const BASE_ACCEPT_PARAMS = {
  offer_id: "abc123def456",
  taker_sost_addr: "sost1taker",
  taker_eth_addr: "0xfeedface",
  fill_amount_sost: "5000.00000000",
  fill_amount_gold: "0",
};

const POSITION_ACCEPT_PARAMS = {
  ...BASE_ACCEPT_PARAMS,
  asset_type: "POSITION_FULL" as const,
  position_id: "pos_abc123",
};

const POSITION_OFFER_PARAMS = {
  asset_type: "POSITION_FULL" as const,
  position_id: "pos_abc123",
  price_sost: "5000.00000000",
  side: "sell" as const,
  amount_sost: "5000.00000000",
  maker_sost_addr: "sost1maker",
  maker_eth_addr: "0xmaker",
};

describe("trade_accept — position trades", () => {
  describe("createAccept with position fields", () => {
    it("includes asset_type and position_id", () => {
      const accept = createAccept(POSITION_ACCEPT_PARAMS);
      expect(accept.asset_type).toBe("POSITION_FULL");
      expect(accept.position_id).toBe("pos_abc123");
      expect(accept.version).toBe(1);
      expect(accept.type).toBe("trade_accept");
    });

    it("deal_id is still deterministic", () => {
      const accept = createAccept(POSITION_ACCEPT_PARAMS);
      const expected = deriveDealId(accept.offer_id, accept.accept_id);
      expect(accept.deal_id).toBe(expected);
    });
  });

  describe("canonicalHash — position fields", () => {
    it("includes position fields in the hash", () => {
      const accept = createAccept(POSITION_ACCEPT_PARAMS);
      const hash = canonicalHash(accept);
      expect(hash).toMatch(/^[0-9a-f]{64}$/);
    });

    it("changes when position_id changes", () => {
      const accept = createAccept(POSITION_ACCEPT_PARAMS);
      const hash1 = canonicalHash(accept);
      const modified = { ...accept, position_id: "pos_different" };
      const hash2 = canonicalHash(modified);
      expect(hash1).not.toBe(hash2);
    });

    it("backward compat: accept without position fields hashes correctly", () => {
      const accept = createAccept(BASE_ACCEPT_PARAMS);
      expect(accept.asset_type).toBeUndefined();
      expect(accept.position_id).toBeUndefined();
      const hash = canonicalHash(accept);
      expect(hash).toMatch(/^[0-9a-f]{64}$/);
      expect(canonicalHash(accept)).toBe(hash);
    });
  });

  describe("sign + verify position accept", () => {
    let registry: NonceRegistry;

    beforeEach(() => {
      registry = new NonceRegistry();
    });

    it("sign and verify position accept works", () => {
      const kp = generateKeyPair();
      const accept = createAccept(POSITION_ACCEPT_PARAMS);
      const signed = signTradeMessage(accept, kp.privateKey);

      const result = verifyTradeMessage(signed, kp.publicKey, registry);
      expect(result.valid).toBe(true);
      expect(result.reason).toBe("ok");
    });

    it("full flow: position offer -> position accept -> verify both", () => {
      const makerKp = generateKeyPair();
      const takerKp = generateKeyPair();

      // Maker creates and signs position offer
      const offer = createPositionOffer(POSITION_OFFER_PARAMS);
      const signedOffer = signTradeMessage(offer, makerKp.privateKey);
      const offerResult = verifyTradeMessage(signedOffer, makerKp.publicKey, registry);
      expect(offerResult.valid).toBe(true);

      // Taker creates and signs position accept
      const accept = createAccept({
        offer_id: offer.offer_id,
        taker_sost_addr: "sost1taker",
        taker_eth_addr: "0xtaker",
        fill_amount_sost: "5000.00000000",
        fill_amount_gold: "0",
        asset_type: "POSITION_FULL",
        position_id: "pos_abc123",
      });
      const signedAccept = signTradeMessage(accept, takerKp.privateKey);
      const acceptResult = verifyTradeMessage(signedAccept, takerKp.publicKey, registry);
      expect(acceptResult.valid).toBe(true);

      // Both share the same position_id
      expect(offer.position_id).toBe(accept.position_id);
      expect(offer.asset_type).toBe(accept.asset_type);
    });
  });
});
