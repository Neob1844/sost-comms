/**
 * SOST Comms — Persistent Message Store
 *
 * Stores signed messages as JSON files, one file per deal_id.
 * Offers without a deal_id are stored in _offers.json.
 */

import * as fs from "fs";
import * as path from "path";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface StoredMessage {
  id: string;
  deal_id: string | null;   // null for offers not yet accepted
  type: string;              // "trade_offer" | "trade_accept" | "trade_cancel" | "settlement_notice"
  message: any;
  signature: string;
  hash: string;
  received_at: number;
  verified: boolean;
}

// ---------------------------------------------------------------------------
// MessageStore
// ---------------------------------------------------------------------------

export class MessageStore {
  private readonly dataDir: string;

  constructor(dataDir: string) {
    this.dataDir = dataDir;
    fs.mkdirSync(dataDir, { recursive: true });
  }

  /**
   * Save a message. Messages with deal_id go to <deal_id>.json,
   * messages without deal_id go to _offers.json.
   */
  save(msg: StoredMessage): void {
    const file = msg.deal_id
      ? path.join(this.dataDir, `${msg.deal_id}.json`)
      : path.join(this.dataDir, "_offers.json");

    const existing = this.readFile(file);
    existing.push(msg);
    fs.writeFileSync(file, JSON.stringify(existing, null, 2) + "\n");
  }

  /**
   * Get all messages for a given deal_id.
   */
  getByDealId(dealId: string): StoredMessage[] {
    const file = path.join(this.dataDir, `${dealId}.json`);
    return this.readFile(file);
  }

  /**
   * Get all unmatched offers (stored without a deal_id).
   */
  getOffers(): StoredMessage[] {
    const file = path.join(this.dataDir, "_offers.json");
    return this.readFile(file);
  }

  /**
   * Get all stored messages across all files.
   */
  getAll(): StoredMessage[] {
    if (!fs.existsSync(this.dataDir)) return [];

    const files = fs.readdirSync(this.dataDir).filter(f => f.endsWith(".json"));
    const all: StoredMessage[] = [];
    for (const f of files) {
      const msgs = this.readFile(path.join(this.dataDir, f));
      all.push(...msgs);
    }
    return all;
  }

  /**
   * Total number of stored messages.
   */
  count(): number {
    return this.getAll().length;
  }

  /**
   * Move an offer from _offers.json into a deal file.
   * Used when an offer is accepted and assigned a deal_id.
   */
  moveOfferToDeal(offerId: string, dealId: string): void {
    const offersFile = path.join(this.dataDir, "_offers.json");
    const offers = this.readFile(offersFile);
    const idx = offers.findIndex(m => m.message?.offer_id === offerId);
    if (idx === -1) return;

    const offer = offers.splice(idx, 1)[0];
    offer.deal_id = dealId;

    fs.writeFileSync(offersFile, JSON.stringify(offers, null, 2) + "\n");
    this.save(offer);
  }

  // -------------------------------------------------------------------------
  // Internal
  // -------------------------------------------------------------------------

  private readFile(filePath: string): StoredMessage[] {
    if (!fs.existsSync(filePath)) return [];
    try {
      const raw = fs.readFileSync(filePath, "utf-8");
      return JSON.parse(raw) as StoredMessage[];
    } catch {
      return [];
    }
  }
}
