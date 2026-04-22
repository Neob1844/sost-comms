#!/usr/bin/env ts-node
/**
 * SOST Comms — Create Signed Offer (CLI)
 *
 * Usage:
 *   npx ts-node scripts/create_signed_offer.ts \
 *     --keypair keys/maker \
 *     --pair SOST/XAUT \
 *     --side sell \
 *     --amount-sost 100.00000000 \
 *     --amount-gold 0.050000000000000000 \
 *     --price 0.0005 \
 *     --maker-sost-addr sost1abc \
 *     --maker-eth-addr 0xdef
 */

import * as path from "path";
import { loadKeyPair } from "../src/crypto/keyring";
import { createOffer, TradeOffer } from "../src/protocol/trade_offer";
import { signTradeMessage } from "../src/runtime/sign_and_verify";

// ---------------------------------------------------------------------------
// Argument parsing
// ---------------------------------------------------------------------------

function parseArgs(argv: string[]): Record<string, string> {
  const args: Record<string, string> = {};
  for (let i = 0; i < argv.length; i++) {
    if (argv[i].startsWith("--")) {
      const key = argv[i].slice(2);
      const val = argv[i + 1];
      if (val && !val.startsWith("--")) {
        args[key] = val;
        i++;
      } else {
        args[key] = "true";
      }
    }
  }
  return args;
}

function required(args: Record<string, string>, key: string): string {
  const val = args[key];
  if (!val) {
    console.error(`Missing required argument: --${key}`);
    process.exit(1);
  }
  return val;
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

function main(): void {
  const args = parseArgs(process.argv.slice(2));

  const keypairPath = required(args, "keypair");
  const pair = required(args, "pair") as TradeOffer["pair"];
  const side = required(args, "side") as TradeOffer["side"];
  const amountSost = required(args, "amount-sost");
  const amountGold = required(args, "amount-gold");
  const price = required(args, "price");
  const makerSostAddr = required(args, "maker-sost-addr");
  const makerEthAddr = required(args, "maker-eth-addr");
  const ttl = args["ttl"] ? parseInt(args["ttl"], 10) : undefined;

  // Resolve keypair path
  const dir = path.dirname(keypairPath);
  const name = path.basename(keypairPath);
  const kp = loadKeyPair(dir, name);

  // Create and sign the offer
  const offer = createOffer({
    pair,
    side,
    amount_sost: amountSost,
    amount_gold: amountGold,
    price,
    maker_sost_addr: makerSostAddr,
    maker_eth_addr: makerEthAddr,
    ttl_seconds: ttl,
  });

  const signed = signTradeMessage(offer, kp.privateKey);

  // Output the signed offer as JSON
  const output = {
    ...signed.message,
    signature: signed.signature,
  };

  console.log(JSON.stringify(output, null, 2));
}

main();
