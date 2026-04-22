#!/usr/bin/env ts-node
/**
 * SOST Comms — Submit Position Offer to Relay (CLI)
 *
 * Creates a signed position offer and POSTs it to the relay /submit endpoint.
 *
 * Usage:
 *   npx ts-node scripts/demo_submit_offer.ts \
 *     --keypair keys/seller \
 *     --position-id pos_abc123 \
 *     --price-sost 5000000 \
 *     --asset-type POSITION_FULL \
 *     --relay-url http://localhost:3000
 */

import * as path from "path";
import * as http from "http";
import { loadKeyPair } from "../src/crypto/keyring";
import { publicKeyHex } from "../src/crypto/ed25519";
import { createPositionOffer } from "../src/protocol/trade_offer";
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
// HTTP POST helper
// ---------------------------------------------------------------------------

function postJson(url: string, body: any): Promise<{ status: number; data: any }> {
  return new Promise((resolve, reject) => {
    const parsed = new URL(url);
    const data = JSON.stringify(body);
    const opts: http.RequestOptions = {
      hostname: parsed.hostname,
      port: parsed.port,
      path: parsed.pathname,
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Content-Length": Buffer.byteLength(data),
      },
    };

    const req = http.request(opts, (res) => {
      const chunks: Buffer[] = [];
      res.on("data", (chunk: Buffer) => chunks.push(chunk));
      res.on("end", () => {
        const raw = Buffer.concat(chunks).toString("utf-8");
        try {
          resolve({ status: res.statusCode || 0, data: JSON.parse(raw) });
        } catch {
          resolve({ status: res.statusCode || 0, data: raw });
        }
      });
    });

    req.on("error", reject);
    req.write(data);
    req.end();
  });
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));

  const relayUrl = args["relay-url"] || "http://localhost:3000";
  const keypairPath = required(args, "keypair");
  const positionId = required(args, "position-id");
  const priceSost = required(args, "price-sost");
  const assetType = (args["asset-type"] || "POSITION_FULL") as "POSITION_FULL" | "POSITION_REWARD_RIGHT";

  // Resolve keypair path
  const dir = path.dirname(keypairPath);
  const name = path.basename(keypairPath);
  const kp = loadKeyPair(dir, name);
  const pubHex = publicKeyHex(kp.publicKey);

  console.log("Creating position offer...");
  console.log(`  position_id: ${positionId}`);
  console.log(`  asset_type:  ${assetType}`);
  console.log(`  price_sost:  ${priceSost}`);
  console.log(`  relay:       ${relayUrl}`);

  // Create and sign the offer
  const offer = createPositionOffer({
    asset_type: assetType,
    position_id: positionId,
    price_sost: priceSost,
    side: "sell",
    amount_sost: priceSost,
    maker_sost_addr: `sost1_${pubHex.substring(0, 16)}`,
    maker_eth_addr: "0x0000000000000000000000000000000000000000",
    ttl_seconds: 3600,
  });

  const signed = signTradeMessage(offer, kp.privateKey);

  console.log(`  offer_id:    ${offer.offer_id}`);
  console.log(`  hash:        ${signed.hash.substring(0, 32)}...`);

  // POST to relay
  const payload = {
    message: signed.message,
    signature: signed.signature,
    sender_pubkey_hex: pubHex,
  };

  try {
    const resp = await postJson(`${relayUrl}/submit`, payload);
    console.log(`\nRelay response (${resp.status}):`);
    console.log(JSON.stringify(resp.data, null, 2));
  } catch (err: any) {
    console.error(`\nFailed to reach relay at ${relayUrl}: ${err.message}`);
    console.log("\nSigned offer (for manual submission):");
    console.log(JSON.stringify({ ...signed.message, signature: signed.signature }, null, 2));
    process.exit(1);
  }
}

main();
