import { describe, it, expect } from "vitest";
import { canonicalHash, createOffer, isExpired } from "../../src/protocol/trade_offer";

const BASE_PARAMS = {
  pair: "SOST/XAUT" as const,
  side: "buy" as const,
  amount_sost: "100.00000000",
  amount_gold: "0.050000000000000000",
  price: "0.0005",
  maker_sost_addr: "sost1abc",
  maker_eth_addr: "0xdeadbeef",
};

describe("trade_offer", () => {
  describe("createOffer", () => {
    it("returns all required fields", () => {
      const offer = createOffer(BASE_PARAMS);
      expect(offer.version).toBe(1);
      expect(offer.type).toBe("trade_offer");
      expect(offer.offer_id).toBeDefined();
      expect(offer.pair).toBe("SOST/XAUT");
      expect(offer.side).toBe("buy");
      expect(offer.amount_sost).toBe("100.00000000");
      expect(offer.amount_gold).toBe("0.050000000000000000");
      expect(offer.price).toBe("0.0005");
      expect(offer.maker_sost_addr).toBe("sost1abc");
      expect(offer.maker_eth_addr).toBe("0xdeadbeef");
      expect(offer.settlement_mode).toBe("escrow_bilateral");
      expect(typeof offer.expires_at).toBe("number");
      expect(typeof offer.nonce).toBe("string");
      expect(typeof offer.created_at).toBe("number");
    });

    it("generates unique offer_id across calls", () => {
      const a = createOffer(BASE_PARAMS);
      const b = createOffer(BASE_PARAMS);
      expect(a.offer_id).not.toBe(b.offer_id);
    });

    it("generates unique nonce across calls", () => {
      const a = createOffer(BASE_PARAMS);
      const b = createOffer(BASE_PARAMS);
      expect(a.nonce).not.toBe(b.nonce);
    });

    it("defaults expires_at to +3600s from created_at", () => {
      const offer = createOffer(BASE_PARAMS);
      expect(offer.expires_at - offer.created_at).toBe(3600);
    });

    it("applies custom ttl_seconds", () => {
      const offer = createOffer({ ...BASE_PARAMS, ttl_seconds: 600 });
      expect(offer.expires_at - offer.created_at).toBe(600);
    });
  });

  describe("canonicalHash", () => {
    it("is stable for the same input", () => {
      const offer = createOffer(BASE_PARAMS);
      expect(canonicalHash(offer)).toBe(canonicalHash(offer));
    });

    it("changes when any field changes", () => {
      const offer = createOffer(BASE_PARAMS);
      const hash1 = canonicalHash(offer);
      const modified = { ...offer, price: "0.0006" };
      const hash2 = canonicalHash(modified);
      expect(hash1).not.toBe(hash2);
    });
  });

  describe("isExpired", () => {
    it("returns false for a fresh offer", () => {
      const offer = createOffer(BASE_PARAMS);
      const signed = { ...offer, signature: "sig" };
      expect(isExpired(signed)).toBe(false);
    });

    it("returns true when expires_at is in the past", () => {
      const offer = createOffer(BASE_PARAMS);
      const expired = { ...offer, expires_at: 0, signature: "sig" };
      expect(isExpired(expired)).toBe(true);
    });
  });
});
