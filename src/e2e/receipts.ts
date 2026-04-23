/**
 * SOST Comms — Delivery Receipts
 *
 * Lightweight delivery receipt messages for confirming message processing.
 */

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface DeliveryReceipt {
  deal_id: string;
  msg_id: string;       // references the original message
  receipt_type: "delivered" | "acknowledged" | "processed";
  timestamp: number;
  sender_id: string;
}

// ---------------------------------------------------------------------------
// Creation
// ---------------------------------------------------------------------------

/**
 * Create a delivery receipt for a specific message.
 */
export function createReceipt(
  dealId: string,
  msgId: string,
  type: DeliveryReceipt["receipt_type"],
  senderId: string,
): DeliveryReceipt {
  return {
    deal_id: dealId,
    msg_id: msgId,
    receipt_type: type,
    timestamp: Date.now(),
    sender_id: senderId,
  };
}
