/**
 * SOST Comms — Key Lifecycle Policy
 *
 * Configurable policies for key rotation, replenishment, and session limits.
 * The evaluateKeyHealth function inspects a prekey bundle and returns
 * a list of actions needed to maintain healthy key state.
 */

import { PrekeyBundle } from "./prekey_bundle";
import { shouldRotateSignedPrekey, shouldReplenishOneTimePrekeys } from "./prekey_rotation";

// ---------------------------------------------------------------------------
// Policy
// ---------------------------------------------------------------------------

export interface KeyLifecyclePolicy {
  signedPrekeyMaxAgeDays: number;      // 7
  oneTimePrekeyMinCount: number;       // 5
  oneTimePrekeyBatchSize: number;      // 10
  sessionRekeyAfterMessages: number;   // 100
  sessionMaxAgeDays: number;           // 30
}

export const DEFAULT_POLICY: KeyLifecyclePolicy = {
  signedPrekeyMaxAgeDays: 7,
  oneTimePrekeyMinCount: 5,
  oneTimePrekeyBatchSize: 10,
  sessionRekeyAfterMessages: 100,
  sessionMaxAgeDays: 30,
};

// ---------------------------------------------------------------------------
// Health evaluation
// ---------------------------------------------------------------------------

/**
 * Evaluate the health of a prekey bundle and return required actions.
 *
 * @param bundle  - the prekey bundle to evaluate
 * @param policy  - lifecycle policy (defaults to DEFAULT_POLICY)
 * @returns healthy status and list of action strings
 */
export function evaluateKeyHealth(
  bundle: PrekeyBundle,
  policy: KeyLifecyclePolicy = DEFAULT_POLICY,
): { healthy: boolean; actions: string[] } {
  const actions: string[] = [];

  // Check signed prekey age
  if (shouldRotateSignedPrekey(bundle.signedPrekey, policy.signedPrekeyMaxAgeDays)) {
    actions.push("rotate_signed_prekey");
  }

  // Check one-time prekey count
  const remaining = bundle.oneTimePrekeys.filter((k) => !k.used).length;
  if (shouldReplenishOneTimePrekeys(remaining, policy.oneTimePrekeyMinCount)) {
    actions.push("replenish_otk");
  }

  return {
    healthy: actions.length === 0,
    actions,
  };
}
