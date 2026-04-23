import { describe, it, expect } from "vitest";

import { ReplayGuard } from "../../src/e2e/replay_guard";

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("replay guard", () => {
  it("first message is accepted", () => {
    const guard = new ReplayGuard();
    const result = guard.accept("session-1", 0, "nonce-aaa");
    expect(result.accepted).toBe(true);
  });

  it("duplicate nonce is rejected", () => {
    const guard = new ReplayGuard();
    guard.accept("session-1", 0, "nonce-dup");

    const result = guard.accept("session-1", 1, "nonce-dup");
    expect(result.accepted).toBe(false);
    expect(result.reason).toBe("duplicate_nonce");
  });

  it("duplicate seq_no is rejected", () => {
    const guard = new ReplayGuard();
    guard.accept("session-1", 5, "nonce-a");

    const result = guard.accept("session-1", 5, "nonce-b");
    expect(result.accepted).toBe(false);
    expect(result.reason).toBe("duplicate_seq_no");
  });

  it("sequential messages are accepted", () => {
    const guard = new ReplayGuard();

    for (let i = 0; i < 10; i++) {
      const result = guard.accept("session-1", i, `nonce-${i}`);
      expect(result.accepted).toBe(true);
    }
  });

  it("gap within window is accepted", () => {
    const guard = new ReplayGuard(100);
    guard.accept("session-1", 0, "nonce-0");
    guard.accept("session-1", 50, "nonce-50");

    // seq_no 25 is within the window (50 - 100 + 1 = -49, so 25 >= -49)
    const result = guard.accept("session-1", 25, "nonce-25");
    expect(result.accepted).toBe(true);
  });

  it("gap beyond window is rejected", () => {
    const guard = new ReplayGuard(10);

    // Advance to seq_no 100
    guard.accept("session-1", 100, "nonce-100");

    // seq_no 89 is at the edge: 100 - 10 + 1 = 91, so 89 < 91 → rejected
    const result = guard.accept("session-1", 89, "nonce-89");
    expect(result.accepted).toBe(false);
    expect(result.reason).toBe("behind_window");

    // seq_no 91 is exactly at the edge → accepted
    const result2 = guard.accept("session-1", 91, "nonce-91");
    expect(result2.accepted).toBe(true);
  });
});
