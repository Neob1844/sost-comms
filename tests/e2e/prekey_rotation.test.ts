import { describe, it, expect, beforeEach } from "vitest";

import { generateKeyBundle } from "../../src/crypto/key_bundle";
import { createPrekeyBundle } from "../../src/e2e/prekey_bundle";
import { _resetPrekeyIdCounter } from "../../src/e2e/prekeys";
import {
  shouldRotateSignedPrekey,
  shouldReplenishOneTimePrekeys,
} from "../../src/e2e/prekey_rotation";
import { evaluateKeyHealth } from "../../src/e2e/key_lifecycle";

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("prekey rotation", () => {
  beforeEach(() => {
    _resetPrekeyIdCounter();
  });

  it("shouldRotateSignedPrekey false when fresh", () => {
    const bundle = generateKeyBundle();
    const { prekeyBundle } = createPrekeyBundle(bundle);

    // Just created — should not need rotation
    expect(shouldRotateSignedPrekey(prekeyBundle.signedPrekey)).toBe(false);
  });

  it("shouldRotateSignedPrekey true when expired", () => {
    const bundle = generateKeyBundle();
    const { prekeyBundle } = createPrekeyBundle(bundle);

    // Backdate the signed prekey by 8 days
    const eightDaysMs = 8 * 24 * 60 * 60 * 1000;
    prekeyBundle.signedPrekey.createdAt = Date.now() - eightDaysMs;

    expect(shouldRotateSignedPrekey(prekeyBundle.signedPrekey)).toBe(true);
  });

  it("shouldReplenishOneTimePrekeys true when below threshold", () => {
    // Below default threshold of 5
    expect(shouldReplenishOneTimePrekeys(4)).toBe(true);
    expect(shouldReplenishOneTimePrekeys(0)).toBe(true);

    // At or above threshold
    expect(shouldReplenishOneTimePrekeys(5)).toBe(false);
    expect(shouldReplenishOneTimePrekeys(10)).toBe(false);
  });

  it("evaluateKeyHealth returns correct actions", () => {
    const bundle = generateKeyBundle();
    const { prekeyBundle } = createPrekeyBundle(bundle, 10);

    // Fresh bundle should be healthy
    const healthy = evaluateKeyHealth(prekeyBundle);
    expect(healthy.healthy).toBe(true);
    expect(healthy.actions).toHaveLength(0);

    // Expire the signed prekey
    prekeyBundle.signedPrekey.createdAt = Date.now() - 8 * 24 * 60 * 60 * 1000;

    // Mark most OTKs as used (leave 3 unused, below default threshold of 5)
    for (let i = 0; i < 7; i++) {
      prekeyBundle.oneTimePrekeys[i].used = true;
    }

    const unhealthy = evaluateKeyHealth(prekeyBundle);
    expect(unhealthy.healthy).toBe(false);
    expect(unhealthy.actions).toContain("rotate_signed_prekey");
    expect(unhealthy.actions).toContain("replenish_otk");
  });
});
