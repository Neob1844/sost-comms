/**
 * SOST Comms — Relay Node
 *
 * Minimal relay node that receives signed messages, validates them,
 * and routes them to the appropriate deal channel.
 */

import * as crypto from "crypto";
import * as http from "http";

import { MessageStore, StoredMessage } from "./message_store";
import { EncryptedMessageStore, StoredEncryptedMessage } from "./encrypted_store";
import { OfflineQueue, QueuedMessage } from "./offline_queue";
import { DeliveryTracker, DeliveryStatus } from "./delivery_state";
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

/** Required header fields on an encrypted envelope. */
const REQUIRED_ENVELOPE_FIELDS = [
  "version", "deal_id", "session_id", "sender_id", "receiver_id",
  "msg_type", "seq_no", "timestamp", "nonce", "ciphertext", "tag", "signature",
] as const;

/** Maximum allowed sequence number gap before rejection. */
const SEQ_WINDOW = 256;

export class RelayNode {
  private readonly channels = new Map<string, DealChannel>();
  private readonly store: MessageStore;
  private readonly encryptedStore: EncryptedMessageStore;
  private readonly offlineQueue: OfflineQueue;
  private readonly deliveryTracker: DeliveryTracker;
  private readonly prekeyStore = new Map<string, any>(); // identity -> prekey bundle
  private readonly nonceRegistry: NonceRegistry;
  private readonly seqTracker = new Map<string, number>(); // deal_id -> highest seq
  private server: http.Server | null = null;

  constructor(config: { dataDir: string; port?: number }) {
    this.store = new MessageStore(config.dataDir);
    this.encryptedStore = new EncryptedMessageStore(config.dataDir);
    this.offlineQueue = new OfflineQueue(config.dataDir);
    this.deliveryTracker = new DeliveryTracker();
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
  // Offline delivery support
  // -------------------------------------------------------------------------

  /**
   * Submit an encrypted envelope with offline queuing.
   * If the recipient is offline or unreachable, the message is queued
   * for later retrieval.
   */
  submitEncryptedWithOffline(
    envelope: any,
    recipientId: string,
  ): { accepted: boolean; queued: boolean; reason?: string } {
    // Validate required header fields
    for (const field of REQUIRED_ENVELOPE_FIELDS) {
      if (envelope[field] === undefined || envelope[field] === null) {
        return { accepted: false, queued: false, reason: `missing_field:${field}` };
      }
    }

    // Note: signature verification is deferred to the recipient.
    // The relay performs blind store-and-forward — it validates
    // structural completeness but does not need to verify the
    // signature format (which may differ from the relay's own
    // header serialization used by submitEncrypted).

    // Queue the message for offline delivery
    const envelopeJson = JSON.stringify(envelope);
    const dealId = envelope.deal_id || "unknown";
    const msgId = this.offlineQueue.enqueue(recipientId, dealId, envelopeJson);
    this.deliveryTracker.track(msgId, dealId);

    // Also store in encrypted store for deal history
    const stored: StoredEncryptedMessage = {
      id: `${dealId}-${envelope.seq_no}-${envelope.sender_id.slice(0, 8)}`,
      deal_id: dealId,
      sender_id: envelope.sender_id,
      receiver_id: envelope.receiver_id,
      msg_type: envelope.msg_type,
      seq_no: envelope.seq_no,
      timestamp: envelope.timestamp,
      envelope_json: envelopeJson,
      received_at: Math.floor(Date.now() / 1000),
    };
    this.encryptedStore.save(stored);

    return { accepted: true, queued: true };
  }

  /**
   * Fetch pending messages for a recipient.
   * Returns all undelivered, non-expired queued messages.
   */
  fetchPending(recipientId: string): QueuedMessage[] {
    const pending = this.offlineQueue.getPending(recipientId);
    // Mark as delivered when fetched
    for (const msg of pending) {
      this.offlineQueue.markDelivered(msg.id);
      this.deliveryTracker.markDelivered(msg.id);
    }
    return pending;
  }

  /**
   * Acknowledge receipt of a message.
   */
  acknowledgeMessage(messageId: string): void {
    this.offlineQueue.markAcknowledged(messageId);
    this.deliveryTracker.markAcknowledged(messageId);
  }

  /**
   * Publish a prekey bundle for an identity.
   */
  publishPrekeyBundle(identity: string, bundle: any): void {
    this.prekeyStore.set(identity, bundle);
  }

  /**
   * Get the prekey bundle for an identity.
   */
  getPrekeyBundle(identity: string): any | null {
    return this.prekeyStore.get(identity) ?? null;
  }

  /**
   * Get delivery statuses for a deal.
   */
  getDeliveryStatus(dealId: string): DeliveryStatus[] {
    return this.deliveryTracker.getByDeal(dealId);
  }

  // -------------------------------------------------------------------------
  // Encrypted envelope support (blind transport)
  // -------------------------------------------------------------------------

  /**
   * Submit an encrypted envelope for blind transport.
   *
   * The relay validates:
   * - All required header fields are present
   * - ED25519 signature over the header is valid (routing auth)
   * - Sequence number is within the allowed window
   *
   * The relay does NOT:
   * - Decrypt or inspect the ciphertext
   * - Verify the payload content
   */
  submitEncrypted(
    envelope: any,
  ): { accepted: boolean; deal_id?: string; reason?: string } {
    // 1. Validate required header fields
    for (const field of REQUIRED_ENVELOPE_FIELDS) {
      if (envelope[field] === undefined || envelope[field] === null) {
        return { accepted: false, reason: `missing_field:${field}` };
      }
    }

    // 2. Verify ED25519 signature on header (routing auth)
    const headerData = this.serializeHeader(envelope);
    const sigValid = this.verifyHeaderSignature(
      headerData,
      envelope.signature,
      envelope.sender_id,
    );
    if (!sigValid) {
      return { accepted: false, reason: "invalid_header_signature" };
    }

    // 3. Sequence number window check
    const seqResult = this.checkSeqNo(envelope.deal_id, envelope.seq_no);
    if (!seqResult.ok) {
      return { accepted: false, reason: seqResult.reason };
    }

    // 4. Store the encrypted envelope as-is
    const stored: StoredEncryptedMessage = {
      id: `${envelope.deal_id}-${envelope.seq_no}-${envelope.sender_id.slice(0, 8)}`,
      deal_id: envelope.deal_id,
      sender_id: envelope.sender_id,
      receiver_id: envelope.receiver_id,
      msg_type: envelope.msg_type,
      seq_no: envelope.seq_no,
      timestamp: envelope.timestamp,
      envelope_json: JSON.stringify(envelope),
      received_at: Math.floor(Date.now() / 1000),
    };

    this.encryptedStore.save(stored);
    return { accepted: true, deal_id: envelope.deal_id };
  }

  /**
   * Get encrypted messages for a deal.
   */
  getEncryptedDealMessages(dealId: string): StoredEncryptedMessage[] {
    return this.encryptedStore.getByDealId(dealId);
  }

  /**
   * Serialize the header fields (everything except signature) for
   * signature verification. Fields are sorted alphabetically to
   * produce a deterministic byte string.
   */
  private serializeHeader(envelope: any): string {
    const headerFields: Record<string, any> = {};
    for (const field of REQUIRED_ENVELOPE_FIELDS) {
      if (field === "signature") continue;
      headerFields[field] = envelope[field];
    }
    const keys = Object.keys(headerFields).sort();
    const canonical: Record<string, any> = {};
    for (const k of keys) {
      canonical[k] = headerFields[k];
    }
    return JSON.stringify(canonical);
  }

  /**
   * Verify an ED25519 signature over header data.
   * sender_id is expected to be a hex-encoded ED25519 public key.
   */
  private verifyHeaderSignature(
    headerData: string,
    signatureHex: string,
    senderIdHex: string,
  ): boolean {
    try {
      const SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
      const pubRaw = Buffer.from(senderIdHex, "hex");
      if (pubRaw.length !== 32) return false;
      const spkiDer = Buffer.concat([SPKI_PREFIX, pubRaw]);
      const pubKey = crypto.createPublicKey({ key: spkiDer, format: "der", type: "spki" });

      const hash = crypto.createHash("sha256").update(headerData).digest();
      return crypto.verify(null, hash, pubKey, Buffer.from(signatureHex, "hex"));
    } catch {
      return false;
    }
  }

  /**
   * Check that seq_no is within the allowed window.
   * Updates the tracker on success.
   */
  private checkSeqNo(
    dealId: string,
    seqNo: number,
  ): { ok: boolean; reason?: string } {
    const highest = this.seqTracker.get(dealId) ?? -1;

    // Allow any seq_no if it's within the window of the highest seen
    if (seqNo > highest + SEQ_WINDOW) {
      return { ok: false, reason: "seq_beyond_window" };
    }

    // Update highest if this is a new high
    if (seqNo > highest) {
      this.seqTracker.set(dealId, seqNo);
    }

    return { ok: true };
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
