/**
 * SOST Comms — Deal Channel
 *
 * Private message channel per deal. Validates signatures and nonces
 * before accepting messages into the channel.
 */

import * as crypto from "crypto";

import { MessageStore, StoredMessage } from "./message_store";
import { NonceRegistry } from "../crypto/ed25519";
import { verifyTradeMessage, SignedMessage } from "../runtime/sign_and_verify";

// ---------------------------------------------------------------------------
// DealChannel
// ---------------------------------------------------------------------------

export class DealChannel {
  readonly dealId: string;
  private readonly store: MessageStore;
  private readonly nonceRegistry: NonceRegistry;

  constructor(dealId: string, store: MessageStore, nonceRegistry: NonceRegistry) {
    this.dealId = dealId;
    this.store = store;
    this.nonceRegistry = nonceRegistry;
  }

  /**
   * Add a signed message to this channel.
   * Validates signature and nonce before storing.
   */
  addMessage(
    msg: any,
    signature: string,
    senderPubKey: crypto.KeyObject,
  ): { accepted: boolean; reason?: string } {
    // Recompute hash for verification
    const signed: SignedMessage = {
      message: msg,
      signature,
      hash: "",  // verifyTradeMessage recomputes hash internally
    };

    const result = verifyTradeMessage(signed, senderPubKey, this.nonceRegistry);
    if (!result.valid) {
      return { accepted: false, reason: result.reason };
    }

    const stored: StoredMessage = {
      id: msg.offer_id || msg.accept_id || msg.cancel_id || msg.notice_id || crypto.randomBytes(8).toString("hex"),
      deal_id: this.dealId,
      type: msg.type,
      message: msg,
      signature,
      hash: computeHashSafe(msg),
      received_at: Math.floor(Date.now() / 1000),
      verified: true,
    };

    this.store.save(stored);
    return { accepted: true };
  }

  /**
   * Get full message history for this deal, ordered by received_at.
   */
  getHistory(): StoredMessage[] {
    return this.store.getByDealId(this.dealId).sort((a, b) => a.received_at - b.received_at);
  }

  /**
   * Get a summary of the current deal state.
   */
  getSummary(): { deal_id: string; messages: number; last_type: string; last_at: number } {
    const history = this.getHistory();
    const last = history[history.length - 1];
    return {
      deal_id: this.dealId,
      messages: history.length,
      last_type: last ? last.type : "",
      last_at: last ? last.received_at : 0,
    };
  }
}

// ---------------------------------------------------------------------------
// Internal helper
// ---------------------------------------------------------------------------

function computeHashSafe(msg: any): string {
  try {
    const { canonicalHash: offerHash } = require("../protocol/trade_offer");
    const { canonicalHash: acceptHash } = require("../protocol/trade_accept");
    const { canonicalHash: cancelHash } = require("../protocol/trade_cancel");
    const { canonicalHash: noticeHash } = require("../protocol/settlement_notice");

    switch (msg.type) {
      case "trade_offer":    return offerHash(msg);
      case "trade_accept":   return acceptHash(msg);
      case "trade_cancel":   return cancelHash(msg);
      case "settlement_notice": return noticeHash(msg);
      default: return "";
    }
  } catch {
    return "";
  }
}
