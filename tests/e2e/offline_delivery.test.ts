/**
 * Offline delivery tests — store-and-forward queue for offline recipients.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import * as crypto from "crypto";

import { OfflineQueue } from "../../src/relay/offline_queue";
import { DeliveryTracker } from "../../src/relay/delivery_state";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

let tmpDir: string;

function makeTmpDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), "sost-offline-"));
}

function makeEnvelopeJson(dealId: string): string {
  return JSON.stringify({
    version: 1,
    deal_id: dealId,
    ciphertext: crypto.randomBytes(64).toString("hex"),
    tag: crypto.randomBytes(16).toString("hex"),
  });
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("Offline delivery queue", () => {
  let queue: OfflineQueue;

  beforeEach(() => {
    tmpDir = makeTmpDir();
    queue = new OfflineQueue(tmpDir);
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  // 1
  it("enqueues message for offline recipient", () => {
    const recipientId = crypto.randomBytes(32).toString("hex");
    const dealId = "deal_" + crypto.randomBytes(8).toString("hex");
    const envelope = makeEnvelopeJson(dealId);

    const msgId = queue.enqueue(recipientId, dealId, envelope);

    expect(msgId).toBeTruthy();
    expect(msgId.startsWith("msg_")).toBe(true);

    const stats = queue.getStats();
    expect(stats.total).toBe(1);
    expect(stats.pending).toBe(1);
  });

  // 2
  it("getPending returns queued messages", () => {
    const recipientId = crypto.randomBytes(32).toString("hex");
    const dealId = "deal_" + crypto.randomBytes(8).toString("hex");
    const envelope = makeEnvelopeJson(dealId);

    queue.enqueue(recipientId, dealId, envelope);
    queue.enqueue(recipientId, dealId, envelope);

    const pending = queue.getPending(recipientId);
    expect(pending).toHaveLength(2);
    expect(pending[0].delivered).toBe(false);
    expect(pending[0].deal_id).toBe(dealId);
  });

  // 3
  it("markDelivered updates state", () => {
    const recipientId = crypto.randomBytes(32).toString("hex");
    const dealId = "deal_test";
    const msgId = queue.enqueue(recipientId, dealId, makeEnvelopeJson(dealId));

    queue.markDelivered(msgId);

    const pending = queue.getPending(recipientId);
    expect(pending).toHaveLength(0);

    const stats = queue.getStats();
    expect(stats.delivered).toBe(1);
    expect(stats.pending).toBe(0);
  });

  // 4
  it("markAcknowledged updates state", () => {
    const recipientId = crypto.randomBytes(32).toString("hex");
    const dealId = "deal_test";
    const msgId = queue.enqueue(recipientId, dealId, makeEnvelopeJson(dealId));

    queue.markDelivered(msgId);
    queue.markAcknowledged(msgId);

    const stats = queue.getStats();
    expect(stats.delivered).toBe(1);
  });

  // 5
  it("purgeExpired removes old messages", () => {
    const recipientId = crypto.randomBytes(32).toString("hex");
    const dealId = "deal_expired";

    // Enqueue with TTL of 0 seconds (already expired)
    queue.enqueue(recipientId, dealId, makeEnvelopeJson(dealId), 0);

    const stats = queue.getStats();
    expect(stats.expired).toBe(1);

    const removed = queue.purgeExpired();
    expect(removed).toBe(1);

    const afterStats = queue.getStats();
    expect(afterStats.total).toBe(0);
  });

  // 6
  it("message with 0 TTL expires immediately", () => {
    const recipientId = crypto.randomBytes(32).toString("hex");
    const dealId = "deal_zero_ttl";

    queue.enqueue(recipientId, dealId, makeEnvelopeJson(dealId), 0);

    const pending = queue.getPending(recipientId);
    expect(pending).toHaveLength(0);
  });

  // 7
  it("multiple messages per recipient queued correctly", () => {
    const recipientId = crypto.randomBytes(32).toString("hex");

    for (let i = 0; i < 5; i++) {
      const dealId = `deal_${i}`;
      queue.enqueue(recipientId, dealId, makeEnvelopeJson(dealId));
    }

    const pending = queue.getPending(recipientId);
    expect(pending).toHaveLength(5);

    const dealIds = pending.map(m => m.deal_id);
    expect(dealIds).toEqual(["deal_0", "deal_1", "deal_2", "deal_3", "deal_4"]);
  });

  // 8
  it("delivery tracker tracks full lifecycle", () => {
    const tracker = new DeliveryTracker();
    const dealId = "deal_lifecycle";

    tracker.track("msg_1", dealId);

    let status = tracker.getStatus("msg_1");
    expect(status).not.toBeNull();
    expect(status!.state).toBe("queued");

    tracker.markDelivered("msg_1");
    status = tracker.getStatus("msg_1");
    expect(status!.state).toBe("delivered");
    expect(status!.delivered_at).toBeDefined();

    tracker.markAcknowledged("msg_1");
    status = tracker.getStatus("msg_1");
    expect(status!.state).toBe("acknowledged");
    expect(status!.acknowledged_at).toBeDefined();

    const byDeal = tracker.getByDeal(dealId);
    expect(byDeal).toHaveLength(1);
    expect(byDeal[0].state).toBe("acknowledged");
  });
});
