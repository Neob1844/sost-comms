/**
 * SOST Comms — Prekey Rotation
 *
 * Lifecycle management for signed prekeys and one-time prekeys.
 * Signed prekeys should be rotated periodically (default 7 days).
 * One-time prekeys should be replenished when the count drops below a threshold.
 */

import * as crypto from "crypto";
import { SignedPrekey, OneTimePrekey, generateSignedPrekey, generateOneTimePrekeys } from "./prekeys";

// ---------------------------------------------------------------------------
// Signed prekey rotation
// ---------------------------------------------------------------------------

const MS_PER_DAY = 24 * 60 * 60 * 1000;

/**
 * Check whether a signed prekey should be rotated based on age.
 *
 * @param prekey      - the signed prekey to check
 * @param maxAgeDays  - maximum age in days (default 7)
 */
export function shouldRotateSignedPrekey(
  prekey: SignedPrekey,
  maxAgeDays: number = 7,
): boolean {
  const ageMs = Date.now() - prekey.createdAt;
  return ageMs >= maxAgeDays * MS_PER_DAY;
}

/**
 * Generate a new signed prekey to replace the current one.
 */
export function rotateSignedPrekey(
  signingKey: crypto.KeyObject,
): { signed: SignedPrekey; privateKey: crypto.KeyObject } {
  return generateSignedPrekey(signingKey);
}

// ---------------------------------------------------------------------------
// One-time prekey replenishment
// ---------------------------------------------------------------------------

/**
 * Check whether one-time prekeys should be replenished.
 *
 * @param remaining  - number of unused one-time prekeys remaining
 * @param threshold  - minimum acceptable count (default 5)
 */
export function shouldReplenishOneTimePrekeys(
  remaining: number,
  threshold: number = 5,
): boolean {
  return remaining < threshold;
}

/**
 * Generate a new batch of one-time prekeys.
 */
export function replenishOneTimePrekeys(
  count: number,
): { prekeys: OneTimePrekey[]; privateKeys: Map<number, crypto.KeyObject> } {
  return generateOneTimePrekeys(count);
}
