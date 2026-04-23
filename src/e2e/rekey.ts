/**
 * SOST Comms — Channel Rekey
 *
 * Derives fresh channel keys from a new shared secret (e.g. after a new
 * ephemeral DH exchange). The deal_id is preserved; the session_id changes.
 */

import { deriveChannelKeys, ChannelKeys } from "./channel_keys";

/**
 * Derive new channel keys from a fresh shared secret.
 *
 * @param currentKeys    - existing channel keys (used only for deal_id reference)
 * @param newSharedSecret - freshly derived 32-byte DH shared secret
 * @param dealId         - deal identifier (should match currentKeys.dealId)
 * @param isInitiator    - true for the party that initiated the rekey
 * @returns new ChannelKeys with updated send/recv keys and session_id
 */
export function rekeyChannel(
  currentKeys: ChannelKeys,
  newSharedSecret: Buffer,
  dealId: string,
  isInitiator: boolean,
): ChannelKeys {
  return deriveChannelKeys(newSharedSecret, dealId, isInitiator);
}
