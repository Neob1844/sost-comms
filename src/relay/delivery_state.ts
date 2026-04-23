/**
 * SOST Comms — Delivery State Tracker
 *
 * In-memory tracker for message delivery lifecycle:
 * queued → delivered → acknowledged (or expired).
 */

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface DeliveryStatus {
  message_id: string;
  deal_id: string;
  state: "queued" | "delivered" | "acknowledged" | "expired";
  queued_at: number;
  delivered_at?: number;
  acknowledged_at?: number;
}

// ---------------------------------------------------------------------------
// DeliveryTracker
// ---------------------------------------------------------------------------

export class DeliveryTracker {
  private readonly statuses = new Map<string, DeliveryStatus>();
  private readonly dealIndex = new Map<string, Set<string>>(); // deal_id -> msg_ids

  /**
   * Start tracking a message.
   */
  track(msgId: string, dealId: string): void {
    const status: DeliveryStatus = {
      message_id: msgId,
      deal_id: dealId,
      state: "queued",
      queued_at: Math.floor(Date.now() / 1000),
    };
    this.statuses.set(msgId, status);

    if (!this.dealIndex.has(dealId)) {
      this.dealIndex.set(dealId, new Set());
    }
    this.dealIndex.get(dealId)!.add(msgId);
  }

  /**
   * Mark a message as delivered.
   */
  markDelivered(msgId: string): void {
    const status = this.statuses.get(msgId);
    if (!status) return;
    status.state = "delivered";
    status.delivered_at = Math.floor(Date.now() / 1000);
  }

  /**
   * Mark a message as acknowledged by the recipient.
   */
  markAcknowledged(msgId: string): void {
    const status = this.statuses.get(msgId);
    if (!status) return;
    status.state = "acknowledged";
    status.acknowledged_at = Math.floor(Date.now() / 1000);
  }

  /**
   * Get the delivery status for a specific message.
   */
  getStatus(msgId: string): DeliveryStatus | null {
    return this.statuses.get(msgId) ?? null;
  }

  /**
   * Get all delivery statuses for a deal.
   */
  getByDeal(dealId: string): DeliveryStatus[] {
    const msgIds = this.dealIndex.get(dealId);
    if (!msgIds) return [];
    const result: DeliveryStatus[] = [];
    for (const id of msgIds) {
      const status = this.statuses.get(id);
      if (status) result.push(status);
    }
    return result;
  }
}
