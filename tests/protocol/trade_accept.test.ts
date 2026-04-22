import { describe, it, expect } from "vitest";
import { canonicalHash, createAccept, deriveDealId } from "../../src/protocol/trade_accept";

const BASE_PARAMS = {
  offer_id: "abc123def456",
  taker_sost_addr: "sost1taker",
  taker_eth_addr: "0xfeedface",
  fill_amount_sost: "50.00000000",
  fill_amount_gold: "0.025000000000000000",
};

describe("trade_accept", () => {
  describe("createAccept", () => {
    it("returns all required fields", () => {
      const accept = createAccept(BASE_PARAMS);
      expect(accept.version).toBe(1);
      expect(accept.type).toBe("trade_accept");
      expect(accept.accept_id).toBeDefined();
      expect(accept.offer_id).toBe("abc123def456");
      expect(accept.deal_id).toBeDefined();
      expect(accept.taker_sost_addr).toBe("sost1taker");
      expect(accept.taker_eth_addr).toBe("0xfeedface");
      expect(accept.fill_amount_sost).toBe("50.00000000");
      expect(accept.fill_amount_gold).toBe("0.025000000000000000");
      expect(typeof accept.accepted_at).toBe("number");
      expect(typeof accept.nonce).toBe("string");
    });

    it("generates unique accept_id across calls", () => {
      const a = createAccept(BASE_PARAMS);
      const b = createAccept(BASE_PARAMS);
      expect(a.accept_id).not.toBe(b.accept_id);
    });

    it("generates unique nonce across calls", () => {
      const a = createAccept(BASE_PARAMS);
      const b = createAccept(BASE_PARAMS);
      expect(a.nonce).not.toBe(b.nonce);
    });
  });

  describe("deriveDealId", () => {
    it("is deterministic for same offer_id + accept_id", () => {
      const id1 = deriveDealId("offer_aaa", "accept_bbb");
      const id2 = deriveDealId("offer_aaa", "accept_bbb");
      expect(id1).toBe(id2);
    });

    it("produces a 16-char hex string", () => {
      const id = deriveDealId("offer_aaa", "accept_bbb");
      expect(id).toMatch(/^[0-9a-f]{16}$/);
    });

    it("is consistent with deal_id in createAccept", () => {
      const accept = createAccept(BASE_PARAMS);
      const expected = deriveDealId(accept.offer_id, accept.accept_id);
      expect(accept.deal_id).toBe(expected);
    });
  });

  describe("canonicalHash", () => {
    it("is stable for the same input", () => {
      const accept = createAccept(BASE_PARAMS);
      expect(canonicalHash(accept)).toBe(canonicalHash(accept));
    });

    it("changes when any field changes", () => {
      const accept = createAccept(BASE_PARAMS);
      const hash1 = canonicalHash(accept);
      const modified = { ...accept, fill_amount_sost: "99.00000000" };
      const hash2 = canonicalHash(modified);
      expect(hash1).not.toBe(hash2);
    });
  });
});
