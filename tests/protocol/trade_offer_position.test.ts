import { describe, it, expect, beforeEach } from "vitest";
import {
  canonicalHash,
  createOffer,
  createPositionOffer,
  isExpired,
} from "../../src/protocol/trade_offer";
import { generateKeyPair, NonceRegistry } from "../../src/crypto/ed25519";
import { signTradeMessage, verifyTradeMessage } from "../../src/runtime/sign_and_verify";

const POSITION_PARAMS = {
  asset_type: "POSITION_FULL" as const,
  position_id: "pos_abc123",
  price_sost: "5000.00000000",
  side: "sell" as const,
  amount_sost: "5000.00000000",
  maker_sost_addr: "sost1maker",
  maker_eth_addr: "0xmaker",
};

const GOLD_PARAMS = {
  pair: "SOST/XAUT" as const,
  side: "buy" as const,
  amount_sost: "100.00000000",
  amount_gold: "0.050000000000000000",
  price: "0.0005",
  maker_sost_addr: "sost1abc",
  maker_eth_addr: "0xdeadbeef",
};

describe("trade_offer — position trades", () => {
  describe("createPositionOffer", () => {
    it("returns all required fields", () => {
      const offer = createPositionOffer(POSITION_PARAMS);
      expect(offer.version).toBe(1);
      expect(offer.type).toBe("trade_offer");
      expect(offer.offer_id).toBeDefined();
      expect(offer.pair).toBe("SOST/XAUT");
      expect(offer.side).toBe("sell");
      expect(offer.amount_sost).toBe("5000.00000000");
      expect(offer.amount_gold).toBe("0");
      expect(offer.price).toBe("0");
      expect(offer.maker_sost_addr).toBe("sost1maker");
      expect(offer.maker_eth_addr).toBe("0xmaker");
      expect(offer.settlement_mode).toBe("escrow_bilateral");
      expect(typeof offer.expires_at).toBe("number");
      expect(typeof offer.nonce).toBe("string");
      expect(typeof offer.created_at).toBe("number");
    });

    it("sets asset_type to POSITION_FULL", () => {
      const offer = createPositionOffer(POSITION_PARAMS);
      expect(offer.asset_type).toBe("POSITION_FULL");
    });

    it("sets asset_type to POSITION_REWARD_RIGHT", () => {
      const offer = createPositionOffer({
        ...POSITION_PARAMS,
        asset_type: "POSITION_REWARD_RIGHT",
      });
      expect(offer.asset_type).toBe("POSITION_REWARD_RIGHT");
    });

    it("includes position_id", () => {
      const offer = createPositionOffer(POSITION_PARAMS);
      expect(offer.position_id).toBe("pos_abc123");
    });

    it("sets price_sost", () => {
      const offer = createPositionOffer(POSITION_PARAMS);
      expect(offer.price_sost).toBe("5000.00000000");
    });
  });

  describe("canonicalHash — position fields", () => {
    it("includes position fields in the hash", () => {
      const offer = createPositionOffer(POSITION_PARAMS);
      const hash = canonicalHash(offer);
      expect(hash).toMatch(/^[0-9a-f]{64}$/);
    });

    it("changes when position_id changes", () => {
      const offer = createPositionOffer(POSITION_PARAMS);
      const hash1 = canonicalHash(offer);
      const modified = { ...offer, position_id: "pos_different" };
      const hash2 = canonicalHash(modified);
      expect(hash1).not.toBe(hash2);
    });

    it("backward compat: old-style offer without position fields hashes correctly", () => {
      const offer = createOffer(GOLD_PARAMS);
      // No position fields set — should still produce a valid hash
      const hash = canonicalHash(offer);
      expect(hash).toMatch(/^[0-9a-f]{64}$/);
      // Hash should be stable
      expect(canonicalHash(offer)).toBe(hash);
    });
  });

  describe("sign + verify position offer", () => {
    let registry: NonceRegistry;

    beforeEach(() => {
      registry = new NonceRegistry();
    });

    it("sign and verify position offer works", () => {
      const kp = generateKeyPair();
      const offer = createPositionOffer(POSITION_PARAMS);
      const signed = signTradeMessage(offer, kp.privateKey);

      const result = verifyTradeMessage(signed, kp.publicKey, registry);
      expect(result.valid).toBe(true);
      expect(result.reason).toBe("ok");
    });

    it("expired position offer detected", () => {
      const kp = generateKeyPair();
      const offer = createPositionOffer(POSITION_PARAMS);
      (offer as any).expires_at = Math.floor(Date.now() / 1000) - 100;
      const signed = signTradeMessage(offer, kp.privateKey);

      const result = verifyTradeMessage(signed, kp.publicKey, registry);
      expect(result.valid).toBe(false);
      expect(result.reason).toBe("expired");
    });

    it("unique nonces across position offers", () => {
      const a = createPositionOffer(POSITION_PARAMS);
      const b = createPositionOffer(POSITION_PARAMS);
      expect(a.nonce).not.toBe(b.nonce);
    });
  });
});
