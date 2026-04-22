/**
 * SOST Comms — Trade Offer Protocol
 *
 * Signed offer message: maker publishes intent to buy/sell SOST for gold.
 */

export interface TradeOffer {
  version: 1;
  type: "trade_offer";
  offer_id: string;
  pair: "SOST/XAUT" | "SOST/PAXG";
  side: "buy" | "sell";  // from maker perspective
  amount_sost: string;   // decimal string, e.g. "100.00000000"
  amount_gold: string;   // decimal string, e.g. "0.050000000000000000"
  price: string;         // gold per SOST, e.g. "0.0005"
  maker_sost_addr: string;
  maker_eth_addr: string;
  expires_at: number;    // unix timestamp
  settlement_mode: "escrow_bilateral";
  nonce: string;         // unique, prevents replay
  created_at: number;
  signature: string;     // ed25519 signature over canonical hash

  // Position trade fields (optional — only for position trades)
  asset_type?: "GOLD" | "POSITION_FULL" | "POSITION_REWARD_RIGHT";
  position_id?: string;
  price_sost?: string;   // price in SOST for the position
}

export function canonicalHash(offer: Omit<TradeOffer, "signature">): string {
  const fields = [
    offer.version,
    offer.type,
    offer.offer_id,
    offer.pair,
    offer.side,
    offer.amount_sost,
    offer.amount_gold,
    offer.price,
    offer.maker_sost_addr,
    offer.maker_eth_addr,
    offer.expires_at,
    offer.settlement_mode,
    offer.nonce,
    offer.created_at,
    offer.asset_type ?? "",
    offer.position_id ?? "",
    offer.price_sost ?? "",
  ];
  const raw = fields.map(f => String(f)).join("|");
  // SHA-256 of canonical string
  return sha256(raw);
}

export function createOffer(params: {
  pair: TradeOffer["pair"];
  side: TradeOffer["side"];
  amount_sost: string;
  amount_gold: string;
  price: string;
  maker_sost_addr: string;
  maker_eth_addr: string;
  ttl_seconds?: number;
  asset_type?: "GOLD" | "POSITION_FULL" | "POSITION_REWARD_RIGHT";
  position_id?: string;
  price_sost?: string;
}): Omit<TradeOffer, "signature"> {
  const now = Math.floor(Date.now() / 1000);
  const base: Omit<TradeOffer, "signature"> = {
    version: 1,
    type: "trade_offer",
    offer_id: generateId(),
    pair: params.pair,
    side: params.side,
    amount_sost: params.amount_sost,
    amount_gold: params.amount_gold,
    price: params.price,
    maker_sost_addr: params.maker_sost_addr,
    maker_eth_addr: params.maker_eth_addr,
    expires_at: now + (params.ttl_seconds || 3600),
    settlement_mode: "escrow_bilateral",
    nonce: generateNonce(),
    created_at: now,
  };
  if (params.asset_type) base.asset_type = params.asset_type;
  if (params.position_id) base.position_id = params.position_id;
  if (params.price_sost) base.price_sost = params.price_sost;
  return base;
}

export function createPositionOffer(params: {
  asset_type: "POSITION_FULL" | "POSITION_REWARD_RIGHT";
  position_id: string;
  price_sost: string;
  side: TradeOffer["side"];
  amount_sost: string;
  maker_sost_addr: string;
  maker_eth_addr: string;
  ttl_seconds?: number;
}): Omit<TradeOffer, "signature"> {
  return createOffer({
    pair: "SOST/XAUT",
    side: params.side,
    amount_sost: params.amount_sost,
    amount_gold: "0",
    price: "0",
    maker_sost_addr: params.maker_sost_addr,
    maker_eth_addr: params.maker_eth_addr,
    ttl_seconds: params.ttl_seconds,
    asset_type: params.asset_type,
    position_id: params.position_id,
    price_sost: params.price_sost,
  });
}

export function isExpired(offer: TradeOffer): boolean {
  return Math.floor(Date.now() / 1000) > offer.expires_at;
}

// Utility stubs — replace with real crypto
function sha256(input: string): string {
  // In production: use crypto.createHash('sha256')
  const { createHash } = require("crypto");
  return createHash("sha256").update(input).digest("hex");
}

function generateId(): string {
  const { randomBytes } = require("crypto");
  return randomBytes(8).toString("hex");
}

function generateNonce(): string {
  const { randomBytes } = require("crypto");
  return randomBytes(16).toString("hex");
}
