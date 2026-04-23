import { describe, it, expect } from "vitest";

import { createReceipt } from "../../src/e2e/receipts";

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("delivery receipts", () => {
  it("create receipt with correct fields", () => {
    const receipt = createReceipt("deal-100", "msg-abc", "delivered", "sender-xyz");

    expect(receipt.deal_id).toBe("deal-100");
    expect(receipt.msg_id).toBe("msg-abc");
    expect(receipt.receipt_type).toBe("delivered");
    expect(receipt.sender_id).toBe("sender-xyz");
  });

  it("receipt types: delivered, acknowledged, processed", () => {
    const r1 = createReceipt("d", "m", "delivered", "s");
    const r2 = createReceipt("d", "m", "acknowledged", "s");
    const r3 = createReceipt("d", "m", "processed", "s");

    expect(r1.receipt_type).toBe("delivered");
    expect(r2.receipt_type).toBe("acknowledged");
    expect(r3.receipt_type).toBe("processed");
  });

  it("receipt has timestamp", () => {
    const before = Date.now();
    const receipt = createReceipt("deal-200", "msg-def", "processed", "sender-abc");
    const after = Date.now();

    expect(receipt.timestamp).toBeGreaterThanOrEqual(before);
    expect(receipt.timestamp).toBeLessThanOrEqual(after);
  });
});
