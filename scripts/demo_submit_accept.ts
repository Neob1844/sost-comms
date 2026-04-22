#!/usr/bin/env ts-node
/**
 * SOST Comms — Submit Position Accept to Relay (CLI)
 *
 * Fetches an offer from the relay, creates a signed accept, and POSTs it.
 *
 * Usage:
 *   npx ts-node scripts/demo_submit_accept.ts \
 *     --keypair keys/buyer \
 *     --offer-id abc123def456 \
 *     --relay-url http://localhost:3000
 */

import * as path from "path";
import * as http from "http";
import { loadKeyPair } from "../src/crypto/keyring";
import { publicKeyHex } from "../src/crypto/ed25519";
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
// HTTP helpers
// ---------------------------------------------------------------------------

function getJson(url: string): Promise<any> {
  return new Promise((resolve, reject) => {
    http.get(url, (res) => {
      const chunks: Buffer[] = [];
      res.on("data", (chunk: Buffer) => chunks.push(chunk));
      res.on("end", () => {
        const raw = Buffer.concat(chunks).toString("utf-8");
        try {
          resolve(JSON.parse(raw));
        } catch {
          resolve(raw);
        }
      });
    }).on("error", reject);
  });
}

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
  const offerId = required(args, "offer-id");

  // Resolve keypair path
  const dir = path.dirname(keypairPath);
  const name = path.basename(keypairPath);
  const kp = loadKeyPair(dir, name);
  const pubHex = publicKeyHex(kp.publicKey);

  console.log("Fetching offers from relay...");

  // Fetch offers to find the target offer
  let targetOffer: any = null;
  try {
    const offersResp = await getJson(`${relayUrl}/offers`);
    const offers = offersResp.offers || [];
    console.log(`  found ${offers.length} open offer(s)`);

    for (const stored of offers) {
      if (stored.message?.offer_id === offerId) {
        targetOffer = stored.message;
        break;
      }
    }
  } catch (err: any) {
    console.error(`Failed to reach relay at ${relayUrl}: ${err.message}`);
    process.exit(1);
  }

  if (!targetOffer) {
    console.error(`Offer ${offerId} not found on relay`);
    process.exit(1);
  }

  console.log(`\nFound offer:`);
  console.log(`  offer_id:    ${targetOffer.offer_id}`);
  console.log(`  asset_type:  ${targetOffer.asset_type || "GOLD"}`);
  console.log(`  position_id: ${targetOffer.position_id || "n/a"}`);
  console.log(`  price_sost:  ${targetOffer.price_sost || targetOffer.amount_sost}`);
  console.log(`  maker:       ${targetOffer.maker_sost_addr}`);

  // Create and sign the accept
  const accept = createAccept({
    offer_id: targetOffer.offer_id,
    taker_sost_addr: `sost1_${pubHex.substring(0, 16)}`,
    taker_eth_addr: "0x0000000000000000000000000000000000000000",
    fill_amount_sost: targetOffer.price_sost || targetOffer.amount_sost,
    fill_amount_gold: targetOffer.amount_gold || "0",
    asset_type: targetOffer.asset_type,
    position_id: targetOffer.position_id,
  });

  const signed = signTradeMessage(accept, kp.privateKey);

  console.log(`\nCreated accept:`);
  console.log(`  accept_id:   ${accept.accept_id}`);
  console.log(`  deal_id:     ${accept.deal_id}`);
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

    if (resp.data?.deal_id) {
      console.log(`\ndeal_id: ${resp.data.deal_id}`);
    }
  } catch (err: any) {
    console.error(`\nFailed to submit accept to relay: ${err.message}`);
    console.log("\nSigned accept (for manual submission):");
    console.log(JSON.stringify({ ...signed.message, signature: signed.signature }, null, 2));
    process.exit(1);
  }
}

main();
