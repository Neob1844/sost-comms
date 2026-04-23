/**
 * SOST Comms — Offline Queue (Store-and-Forward)
 *
 * Queues encrypted envelopes for recipients that are currently offline.
 * Messages are stored as JSON files per recipient and expire after a
 * configurable TTL (default 7 days).
 */

import * as crypto from "crypto";
import * as fs from "fs";
import * as path from "path";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface QueuedMessage {
  id: string;
  recipient_id: string;
  deal_id: string;
  envelope_json: string;
  queued_at: number;
  expires_at: number;       // messages expire after 7 days by default
  delivered: boolean;
  delivered_at?: number;
  acknowledged: boolean;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Default time-to-live: 7 days in seconds. */
const DEFAULT_TTL_SECONDS = 604800;

// ---------------------------------------------------------------------------
// OfflineQueue
// ---------------------------------------------------------------------------

export class OfflineQueue {
  private readonly dataDir: string;

  constructor(dataDir: string) {
    this.dataDir = dataDir;
    fs.mkdirSync(dataDir, { recursive: true });
  }

  /**
   * Enqueue a message for an offline recipient.
   * Returns the generated message ID.
   *
   * @param recipientId  - recipient's public key hex
   * @param dealId       - deal identifier
   * @param envelopeJson - serialized encrypted envelope
   * @param ttlSeconds   - time-to-live in seconds (default: 7 days)
   */
  enqueue(
    recipientId: string,
    dealId: string,
    envelopeJson: string,
    ttlSeconds: number = DEFAULT_TTL_SECONDS,
  ): string {
    const now = Math.floor(Date.now() / 1000);
    const id = `msg_${crypto.randomBytes(16).toString("hex")}`;

    const msg: QueuedMessage = {
      id,
      recipient_id: recipientId,
      deal_id: dealId,
      envelope_json: envelopeJson,
      queued_at: now,
      expires_at: now + ttlSeconds,
      delivered: false,
      acknowledged: false,
    };

    const queue = this.readQueue(recipientId);
    queue.push(msg);
    this.writeQueue(recipientId, queue);

    return id;
  }

  /**
   * Get all undelivered, non-expired messages for a recipient.
   */
  getPending(recipientId: string): QueuedMessage[] {
    const now = Math.floor(Date.now() / 1000);
    const queue = this.readQueue(recipientId);
    return queue.filter(m => !m.delivered && m.expires_at > now);
  }

  /**
   * Mark a message as delivered.
   */
  markDelivered(messageId: string): void {
    this.updateMessage(messageId, (msg) => {
      msg.delivered = true;
      msg.delivered_at = Math.floor(Date.now() / 1000);
    });
  }

  /**
   * Mark a message as acknowledged by the recipient.
   */
  markAcknowledged(messageId: string): void {
    this.updateMessage(messageId, (msg) => {
      msg.acknowledged = true;
    });
  }

  /**
   * Remove all expired messages across all recipients.
   * Returns the number of messages removed.
   */
  purgeExpired(): number {
    const now = Math.floor(Date.now() / 1000);
    let removed = 0;

    if (!fs.existsSync(this.dataDir)) return 0;

    const files = fs.readdirSync(this.dataDir).filter(f => f.endsWith(".queue.json"));
    for (const file of files) {
      const filePath = path.join(this.dataDir, file);
      const queue = this.readFile(filePath);
      const before = queue.length;
      const filtered = queue.filter(m => m.expires_at > now);
      removed += before - filtered.length;
      if (filtered.length === 0) {
        fs.unlinkSync(filePath);
      } else if (filtered.length < before) {
        fs.writeFileSync(filePath, JSON.stringify(filtered, null, 2) + "\n");
      }
    }

    return removed;
  }

  /**
   * Get queue statistics.
   */
  getStats(): { total: number; pending: number; delivered: number; expired: number } {
    const now = Math.floor(Date.now() / 1000);
    let total = 0;
    let pending = 0;
    let delivered = 0;
    let expired = 0;

    if (!fs.existsSync(this.dataDir)) {
      return { total: 0, pending: 0, delivered: 0, expired: 0 };
    }

    const files = fs.readdirSync(this.dataDir).filter(f => f.endsWith(".queue.json"));
    for (const file of files) {
      const queue = this.readFile(path.join(this.dataDir, file));
      for (const msg of queue) {
        total++;
        if (msg.expires_at <= now) {
          expired++;
        } else if (msg.delivered) {
          delivered++;
        } else {
          pending++;
        }
      }
    }

    return { total, pending, delivered, expired };
  }

  // -------------------------------------------------------------------------
  // Internal
  // -------------------------------------------------------------------------

  private queuePath(recipientId: string): string {
    return path.join(this.dataDir, `${recipientId}.queue.json`);
  }

  private readQueue(recipientId: string): QueuedMessage[] {
    return this.readFile(this.queuePath(recipientId));
  }

  private writeQueue(recipientId: string, queue: QueuedMessage[]): void {
    fs.writeFileSync(this.queuePath(recipientId), JSON.stringify(queue, null, 2) + "\n");
  }

  private readFile(filePath: string): QueuedMessage[] {
    if (!fs.existsSync(filePath)) return [];
    try {
      const raw = fs.readFileSync(filePath, "utf-8");
      return JSON.parse(raw) as QueuedMessage[];
    } catch {
      return [];
    }
  }

  /**
   * Find a message by ID across all queue files and apply a mutation.
   */
  private updateMessage(messageId: string, mutate: (msg: QueuedMessage) => void): void {
    if (!fs.existsSync(this.dataDir)) return;

    const files = fs.readdirSync(this.dataDir).filter(f => f.endsWith(".queue.json"));
    for (const file of files) {
      const filePath = path.join(this.dataDir, file);
      const queue = this.readFile(filePath);
      const msg = queue.find(m => m.id === messageId);
      if (msg) {
        mutate(msg);
        fs.writeFileSync(filePath, JSON.stringify(queue, null, 2) + "\n");
        return;
      }
    }
  }
}
