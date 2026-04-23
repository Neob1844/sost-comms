/**
 * SOST Comms — Session Bootstrap Manager
 *
 * High-level session manager that orchestrates prekey lookup,
 * async handshake initiation, and session acceptance.
 */

import { KeyBundle } from "../crypto/key_bundle";
import { ChannelKeys } from "./channel_keys";
import { PrekeyPrivateKeys } from "./prekey_bundle";
import { PrekeyStore } from "./prekey_store";
import { AsyncSessionInit, initiateAsyncSession, receiveAsyncSession } from "./async_handshake";

// ---------------------------------------------------------------------------
// Session Manager
// ---------------------------------------------------------------------------

export class SessionManager {
  private readonly store: PrekeyStore;
  private readonly sessions = new Map<string, ChannelKeys>();

  constructor(store: PrekeyStore) {
    this.store = store;
  }

  /**
   * Start an encrypted session with an offline recipient.
   * Returns null if no prekey bundle is available for the recipient.
   */
  startSession(
    senderBundle: KeyBundle,
    recipientIdentity: string,
    dealId: string,
  ): { sessionInit: AsyncSessionInit; channelKeys: ChannelKeys } | null {
    const recipientBundle = this.store.getBundle(recipientIdentity);
    if (!recipientBundle) return null;

    const { sessionInit, channelKeys } = initiateAsyncSession(
      senderBundle,
      recipientBundle,
      dealId,
    );

    // Consume the one-time prekey if one was used
    if (sessionInit.usedOneTimePrekeyId !== undefined) {
      this.store.consumeOneTimePrekey(recipientIdentity, sessionInit.usedOneTimePrekeyId);
    }

    this.sessions.set(dealId, channelKeys);
    return { sessionInit, channelKeys };
  }

  /**
   * Accept an incoming async session init from a sender.
   */
  acceptSession(
    recipientBundle: KeyBundle,
    recipientPrivateKeys: PrekeyPrivateKeys,
    sessionInit: AsyncSessionInit,
  ): ChannelKeys {
    const channelKeys = receiveAsyncSession(
      recipientBundle,
      recipientPrivateKeys,
      sessionInit,
      sessionInit.senderIdentityKey,
    );

    this.sessions.set(sessionInit.dealId, channelKeys);
    return channelKeys;
  }

  /**
   * Check if a session exists for a given deal ID.
   */
  hasSession(dealId: string): boolean {
    return this.sessions.has(dealId);
  }
}
