import { describe, it, expect, beforeEach, afterEach } from "vitest";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";

import { MessageStore, StoredMessage } from "../../src/relay/message_store";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

let tmpDir: string;

function makeTmpDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), "sost-store-"));
}

function sampleMessage(overrides: Partial<StoredMessage> = {}): StoredMessage {
  return {
    id: "msg001",
    deal_id: "deal_abc",
    type: "trade_offer",
    message: { type: "trade_offer", offer_id: "offer001" },
    signature: "aabb",
    hash: "ccdd",
    received_at: 1700000000,
    verified: true,
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("MessageStore", () => {
  beforeEach(() => {
    tmpDir = makeTmpDir();
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  // 1
  it("save and retrieve message by deal_id", () => {
    const store = new MessageStore(tmpDir);
    const msg = sampleMessage();
    store.save(msg);

    const retrieved = store.getByDealId("deal_abc");
    expect(retrieved).toHaveLength(1);
    expect(retrieved[0].id).toBe("msg001");
    expect(retrieved[0].type).toBe("trade_offer");
  });

  // 2
  it("getByDealId returns only messages for that deal", () => {
    const store = new MessageStore(tmpDir);
    store.save(sampleMessage({ id: "m1", deal_id: "deal_A" }));
    store.save(sampleMessage({ id: "m2", deal_id: "deal_B" }));
    store.save(sampleMessage({ id: "m3", deal_id: "deal_A" }));

    const a = store.getByDealId("deal_A");
    expect(a).toHaveLength(2);
    expect(a.map(m => m.id)).toEqual(["m1", "m3"]);

    const b = store.getByDealId("deal_B");
    expect(b).toHaveLength(1);
  });

  // 3
  it("getOffers returns unmatched offers (deal_id = null)", () => {
    const store = new MessageStore(tmpDir);
    store.save(sampleMessage({ id: "o1", deal_id: null }));
    store.save(sampleMessage({ id: "o2", deal_id: null }));
    store.save(sampleMessage({ id: "d1", deal_id: "deal_X" }));

    const offers = store.getOffers();
    expect(offers).toHaveLength(2);
    expect(offers.map(m => m.id)).toEqual(["o1", "o2"]);
  });

  // 4
  it("persistence: new store instance reads previously saved data", () => {
    const store1 = new MessageStore(tmpDir);
    store1.save(sampleMessage({ id: "p1", deal_id: "deal_persist" }));
    store1.save(sampleMessage({ id: "p2", deal_id: null }));

    // Create a new instance pointing at the same directory
    const store2 = new MessageStore(tmpDir);
    expect(store2.getByDealId("deal_persist")).toHaveLength(1);
    expect(store2.getOffers()).toHaveLength(1);
  });

  // 5
  it("empty store returns empty arrays", () => {
    const store = new MessageStore(tmpDir);
    expect(store.getByDealId("nonexistent")).toEqual([]);
    expect(store.getOffers()).toEqual([]);
    expect(store.getAll()).toEqual([]);
  });

  // 6
  it("count tracks correctly", () => {
    const store = new MessageStore(tmpDir);
    expect(store.count()).toBe(0);

    store.save(sampleMessage({ id: "c1", deal_id: "d1" }));
    expect(store.count()).toBe(1);

    store.save(sampleMessage({ id: "c2", deal_id: "d1" }));
    store.save(sampleMessage({ id: "c3", deal_id: null }));
    expect(store.count()).toBe(3);
  });

  // 7
  it("getAll returns messages from all files", () => {
    const store = new MessageStore(tmpDir);
    store.save(sampleMessage({ id: "a1", deal_id: "d1" }));
    store.save(sampleMessage({ id: "a2", deal_id: "d2" }));
    store.save(sampleMessage({ id: "a3", deal_id: null }));

    const all = store.getAll();
    expect(all).toHaveLength(3);
  });

  // 8
  it("moveOfferToDeal moves offer from _offers to deal file", () => {
    const store = new MessageStore(tmpDir);
    store.save(sampleMessage({
      id: "o1",
      deal_id: null,
      message: { type: "trade_offer", offer_id: "offer_xyz" },
    }));

    expect(store.getOffers()).toHaveLength(1);

    store.moveOfferToDeal("offer_xyz", "deal_new");

    expect(store.getOffers()).toHaveLength(0);
    expect(store.getByDealId("deal_new")).toHaveLength(1);
    expect(store.getByDealId("deal_new")[0].deal_id).toBe("deal_new");
  });
});
