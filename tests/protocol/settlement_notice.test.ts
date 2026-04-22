import { describe, it, expect } from "vitest";
import { canonicalHash, createNotice } from "../../src/protocol/settlement_notice";

const BASE_PARAMS = {
  deal_id: "deal_abc123",
  outcome: "settled" as const,
  eth_tx_hash: "0xtxhash",
  sost_txid: "sostxid123",
  settlement_ref: "ref_001",
  detail: "both sides confirmed",
};

describe("settlement_notice", () => {
  describe("createNotice", () => {
    it("returns all required fields", () => {
      const notice = createNotice(BASE_PARAMS);
      expect(notice.version).toBe(1);
      expect(notice.type).toBe("settlement_notice");
      expect(notice.notice_id).toBeDefined();
      expect(notice.deal_id).toBe("deal_abc123");
      expect(notice.outcome).toBe("settled");
      expect(notice.eth_tx_hash).toBe("0xtxhash");
      expect(notice.sost_txid).toBe("sostxid123");
      expect(notice.settlement_ref).toBe("ref_001");
      expect(notice.detail).toBe("both sides confirmed");
      expect(typeof notice.issued_at).toBe("number");
    });

    it("supports all outcome types", () => {
      const outcomes = ["settled", "refunded", "expired", "disputed"] as const;
      for (const outcome of outcomes) {
        const notice = createNotice({ deal_id: "d1", outcome });
        expect(notice.outcome).toBe(outcome);
      }
    });

    it("defaults null fields when not provided", () => {
      const notice = createNotice({ deal_id: "d1", outcome: "expired" });
      expect(notice.eth_tx_hash).toBeNull();
      expect(notice.sost_txid).toBeNull();
      expect(notice.settlement_ref).toBeNull();
      expect(notice.detail).toBe("");
    });

    it("generates unique notice_id across calls", () => {
      const a = createNotice(BASE_PARAMS);
      const b = createNotice(BASE_PARAMS);
      expect(a.notice_id).not.toBe(b.notice_id);
    });
  });

  describe("canonicalHash", () => {
    it("is stable for the same input", () => {
      const notice = createNotice(BASE_PARAMS);
      expect(canonicalHash(notice)).toBe(canonicalHash(notice));
    });

    it("handles null fields consistently", () => {
      const notice = createNotice({ deal_id: "d1", outcome: "expired" });
      const h1 = canonicalHash(notice);
      const h2 = canonicalHash(notice);
      expect(h1).toBe(h2);
    });

    it("changes when any field changes", () => {
      const notice = createNotice(BASE_PARAMS);
      const hash1 = canonicalHash(notice);
      const modified = { ...notice, detail: "different detail" };
      const hash2 = canonicalHash(modified);
      expect(hash1).not.toBe(hash2);
    });
  });
});
