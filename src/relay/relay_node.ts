/**
 * SOST Comms — Relay Node
 *
 * Minimal relay node that receives signed messages, validates them,
 * and routes them to the appropriate deal channel.
 */

import * as crypto from "crypto";
import * as http from "http";

import { MessageStore, StoredMessage } from "./message_store";
import { DealChannel } from "./deal_channel";
import { NonceRegistry } from "../crypto/ed25519";
import { verifyTradeMessage, SignedMessage } from "../runtime/sign_and_verify";
import { canonicalHash as offerHash } from "../protocol/trade_offer";
import { canonicalHash as acceptHash } from "../protocol/trade_accept";
import { canonicalHash as cancelHash } from "../protocol/trade_cancel";
import { canonicalHash as noticeHash } from "../protocol/settlement_notice";

// ---------------------------------------------------------------------------
// RelayNode
// ---------------------------------------------------------------------------

export class RelayNode {
  private readonly channels = new Map<string, DealChannel>();
  private readonly store: MessageStore;
  private readonly nonceRegistry: NonceRegistry;
  private server: http.Server | null = null;

  constructor(config: { dataDir: string; port?: number }) {
    this.store = new MessageStore(config.dataDir);
    this.nonceRegistry = new NonceRegistry();
  }

  /**
   * Submit a signed message of any protocol type.
   */
  submit(
    msg: any,
    signature: string,
    senderPubKey: crypto.KeyObject,
  ): { accepted: boolean; deal_id?: string; reason?: string } {
    if (!msg || !msg.type) {
      return { accepted: false, reason: "missing_type" };
    }

    // Validate signature + nonce + expiry
    const signed: SignedMessage = {
      message: msg,
      signature,
      hash: this.computeHash(msg),
    };

    const verifyResult = verifyTradeMessage(signed, senderPubKey, this.nonceRegistry);
    if (!verifyResult.valid) {
      return { accepted: false, reason: verifyResult.reason };
    }

    const now = Math.floor(Date.now() / 1000);

    switch (msg.type) {
      case "trade_offer":
        return this.handleOffer(msg, signature, signed.hash, now);

      case "trade_accept":
        return this.handleAccept(msg, signature, signed.hash, now);

      case "trade_cancel":
        return this.handleCancel(msg, signature, signed.hash, now);

      case "settlement_notice":
        return this.handleSettlementNotice(msg, signature, signed.hash, now);

      default:
        return { accepted: false, reason: "unknown_type" };
    }
  }

  /**
   * Get the full message history for a deal.
   */
  getDealHistory(dealId: string): StoredMessage[] {
    return this.store.getByDealId(dealId);
  }

  /**
   * List all active deals.
   */
  listDeals(): { deal_id: string; messages: number; last_type: string }[] {
    const result: { deal_id: string; messages: number; last_type: string }[] = [];
    for (const [dealId, channel] of this.channels) {
      const summary = channel.getSummary();
      result.push({
        deal_id: dealId,
        messages: summary.messages,
        last_type: summary.last_type,
      });
    }
    return result;
  }

  /**
   * Get open (unmatched) offers.
   */
  getOffers(): StoredMessage[] {
    return this.store.getOffers();
  }

  /**
   * Start HTTP API server.
   */
  startServer(port: number): http.Server {
    const { createHttpHandler } = require("./http_api");
    this.server = http.createServer(createHttpHandler(this));
    this.server!.listen(port);
    return this.server!;
  }

  /**
   * Stop HTTP server.
   */
  stopServer(): void {
    if (this.server) {
      this.server.close();
      this.server = null;
    }
  }

  // -------------------------------------------------------------------------
  // Handlers
  // -------------------------------------------------------------------------

  private handleOffer(
    msg: any, signature: string, hash: string, now: number,
  ): { accepted: boolean; deal_id?: string; reason?: string } {
    const stored: StoredMessage = {
      id: msg.offer_id,
      deal_id: null,
      type: "trade_offer",
      message: msg,
      signature,
      hash,
      received_at: now,
      verified: true,
    };
    this.store.save(stored);
    return { accepted: true };
  }

  private handleAccept(
    msg: any, signature: string, hash: string, now: number,
  ): { accepted: boolean; deal_id?: string; reason?: string } {
    const dealId = msg.deal_id;
    if (!dealId) {
      return { accepted: false, reason: "missing_deal_id" };
    }

    // Move the original offer from _offers into the deal file
    this.store.moveOfferToDeal(msg.offer_id, dealId);

    // Create a channel for this deal
    const channel = new DealChannel(dealId, this.store, this.nonceRegistry);
    this.channels.set(dealId, channel);

    // Store the accept message
    const stored: StoredMessage = {
      id: msg.accept_id,
      deal_id: dealId,
      type: "trade_accept",
      message: msg,
      signature,
      hash,
      received_at: now,
      verified: true,
    };
    this.store.save(stored);

    return { accepted: true, deal_id: dealId };
  }

  private handleCancel(
    msg: any, signature: string, hash: string, now: number,
  ): { accepted: boolean; deal_id?: string; reason?: string } {
    const targetId = msg.target_id;
    const targetType = msg.target_type;

    if (targetType === "deal") {
      if (!this.channels.has(targetId)) {
        return { accepted: false, reason: "deal_not_found" };
      }
      const stored: StoredMessage = {
        id: msg.cancel_id,
        deal_id: targetId,
        type: "trade_cancel",
        message: msg,
        signature,
        hash,
        received_at: now,
        verified: true,
      };
      this.store.save(stored);
      return { accepted: true, deal_id: targetId };
    }

    // Cancel an offer
    const stored: StoredMessage = {
      id: msg.cancel_id,
      deal_id: null,
      type: "trade_cancel",
      message: msg,
      signature,
      hash,
      received_at: now,
      verified: true,
    };
    this.store.save(stored);
    return { accepted: true };
  }

  private handleSettlementNotice(
    msg: any, signature: string, hash: string, now: number,
  ): { accepted: boolean; deal_id?: string; reason?: string } {
    const dealId = msg.deal_id;
    if (!this.channels.has(dealId)) {
      return { accepted: false, reason: "deal_not_found" };
    }

    const stored: StoredMessage = {
      id: msg.notice_id,
      deal_id: dealId,
      type: "settlement_notice",
      message: msg,
      signature,
      hash,
      received_at: now,
      verified: true,
    };
    this.store.save(stored);
    return { accepted: true, deal_id: dealId };
  }

  // -------------------------------------------------------------------------
  // Internal
  // -------------------------------------------------------------------------

  private computeHash(msg: any): string {
    switch (msg.type) {
      case "trade_offer":       return offerHash(msg);
      case "trade_accept":      return acceptHash(msg);
      case "trade_cancel":      return cancelHash(msg);
      case "settlement_notice": return noticeHash(msg);
      default: return "";
    }
  }
}
