import { describe, it, expect } from "vitest";
import { canonicalHash, createCancel } from "../../src/protocol/trade_cancel";

const BASE_PARAMS = {
  target_id: "deal_xyz789",
  target_type: "deal" as const,
  cancelled_by: "sost1canceller",
};

describe("trade_cancel", () => {
  describe("createCancel", () => {
    it("returns all required fields", () => {
      const cancel = createCancel(BASE_PARAMS);
      expect(cancel.version).toBe(1);
      expect(cancel.type).toBe("trade_cancel");
      expect(cancel.cancel_id).toBeDefined();
      expect(cancel.target_id).toBe("deal_xyz789");
      expect(cancel.target_type).toBe("deal");
      expect(cancel.cancelled_by).toBe("sost1canceller");
      expect(typeof cancel.reason).toBe("string");
      expect(typeof cancel.cancelled_at).toBe("number");
      expect(typeof cancel.nonce).toBe("string");
    });

    it("preserves target_type offer", () => {
      const cancel = createCancel({ ...BASE_PARAMS, target_type: "offer" });
      expect(cancel.target_type).toBe("offer");
    });

    it("preserves target_type deal", () => {
      const cancel = createCancel({ ...BASE_PARAMS, target_type: "deal" });
      expect(cancel.target_type).toBe("deal");
    });

    it("defaults reason to empty string", () => {
      const cancel = createCancel(BASE_PARAMS);
      expect(cancel.reason).toBe("");
    });

    it("accepts a custom reason", () => {
      const cancel = createCancel({ ...BASE_PARAMS, reason: "changed my mind" });
      expect(cancel.reason).toBe("changed my mind");
    });

    it("generates unique cancel_id across calls", () => {
      const a = createCancel(BASE_PARAMS);
      const b = createCancel(BASE_PARAMS);
      expect(a.cancel_id).not.toBe(b.cancel_id);
    });

    it("generates unique nonce across calls", () => {
      const a = createCancel(BASE_PARAMS);
      const b = createCancel(BASE_PARAMS);
      expect(a.nonce).not.toBe(b.nonce);
    });
  });

  describe("canonicalHash", () => {
    it("is stable for the same input", () => {
      const cancel = createCancel(BASE_PARAMS);
      expect(canonicalHash(cancel)).toBe(canonicalHash(cancel));
    });

    it("changes when any field changes", () => {
      const cancel = createCancel(BASE_PARAMS);
      const hash1 = canonicalHash(cancel);
      const modified = { ...cancel, reason: "different reason" };
      const hash2 = canonicalHash(modified);
      expect(hash1).not.toBe(hash2);
    });
  });
});
