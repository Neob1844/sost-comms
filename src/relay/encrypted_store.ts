/**
 * SOST Comms — Encrypted Message Store
 *
 * Stores encrypted envelopes as JSON files, one file per deal_id.
 * The relay cannot read the encrypted content — it only stores and
 * retrieves the opaque envelopes based on header metadata.
 */

import * as fs from "fs";
import * as path from "path";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface StoredEncryptedMessage {
  id: string;
  deal_id: string;
  sender_id: string;
  receiver_id: string;
  msg_type: string;
  seq_no: number;
  timestamp: number;
  // Encrypted payload stored as-is (relay cannot read)
  envelope_json: string;  // full EncryptedEnvelope serialized
  received_at: number;
}

// ---------------------------------------------------------------------------
// EncryptedMessageStore
// ---------------------------------------------------------------------------

export class EncryptedMessageStore {
  private readonly dataDir: string;

  constructor(dataDir: string) {
    this.dataDir = dataDir;
    fs.mkdirSync(dataDir, { recursive: true });
  }

  /**
   * Save an encrypted message. Stored in <deal_id>.enc.json.
   */
  save(msg: StoredEncryptedMessage): void {
    const file = path.join(this.dataDir, `${msg.deal_id}.enc.json`);
    const existing = this.readFile(file);
    existing.push(msg);
    fs.writeFileSync(file, JSON.stringify(existing, null, 2) + "\n");
  }

  /**
   * Get all encrypted messages for a given deal_id.
   */
  getByDealId(dealId: string): StoredEncryptedMessage[] {
    const file = path.join(this.dataDir, `${dealId}.enc.json`);
    return this.readFile(file);
  }

  /**
   * Get all stored encrypted messages across all files.
   */
  getAll(): StoredEncryptedMessage[] {
    if (!fs.existsSync(this.dataDir)) return [];

    const files = fs.readdirSync(this.dataDir).filter(f => f.endsWith(".enc.json"));
    const all: StoredEncryptedMessage[] = [];
    for (const f of files) {
      const msgs = this.readFile(path.join(this.dataDir, f));
      all.push(...msgs);
    }
    return all;
  }

  /**
   * Total number of stored encrypted messages.
   */
  count(): number {
    return this.getAll().length;
  }

  // -------------------------------------------------------------------------
  // Internal
  // -------------------------------------------------------------------------

  private readFile(filePath: string): StoredEncryptedMessage[] {
    if (!fs.existsSync(filePath)) return [];
    try {
      const raw = fs.readFileSync(filePath, "utf-8");
      return JSON.parse(raw) as StoredEncryptedMessage[];
    } catch {
      return [];
    }
  }
}
