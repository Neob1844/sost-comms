#!/usr/bin/env ts-node
/**
 * SOST Comms — Create Signed Accept (CLI)
 *
 * Usage:
 *   npx ts-node scripts/create_signed_accept.ts \
 *     --keypair keys/taker \
 *     --offer-json path/to/offer.json \
 *     --taker-sost-addr sost1xyz \
 *     --taker-eth-addr 0x999 \
 *     --fill-amount-sost 50.00000000 \
 *     --fill-amount-gold 0.025000000000000000
 *
 * The --offer-json can be a file path. If omitted, reads from stdin.
 */

import * as fs from "fs";
import * as path from "path";
import { loadKeyPair } from "../src/crypto/keyring";
import { createAccept } from "../src/protocol/trade_accept";
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
  const takerSostAddr = required(args, "taker-sost-addr");
  const takerEthAddr = required(args, "taker-eth-addr");
  const fillAmountSost = required(args, "fill-amount-sost");
  const fillAmountGold = required(args, "fill-amount-gold");

  // Load the offer
  let offerJson: string;
  if (args["offer-json"]) {
    offerJson = fs.readFileSync(args["offer-json"], "utf-8");
  } else {
    // Read from stdin
    offerJson = fs.readFileSync(0, "utf-8");
  }
  const offer = JSON.parse(offerJson);

  if (!offer.offer_id) {
    console.error("Offer JSON must contain an offer_id field");
    process.exit(1);
  }

  // Resolve keypair path
  const dir = path.dirname(keypairPath);
  const name = path.basename(keypairPath);
  const kp = loadKeyPair(dir, name);

  // Create and sign the accept
  const accept = createAccept({
    offer_id: offer.offer_id,
    taker_sost_addr: takerSostAddr,
    taker_eth_addr: takerEthAddr,
    fill_amount_sost: fillAmountSost,
    fill_amount_gold: fillAmountGold,
  });

  const signed = signTradeMessage(accept, kp.privateKey);

  // Output the signed accept as JSON
  const output = {
    ...signed.message,
    signature: signed.signature,
  };

  console.log(JSON.stringify(output, null, 2));
}

main();
