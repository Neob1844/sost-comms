/**
 * SOST Comms — HTTP API for Relay Node
 *
 * Simple HTTP API using Node.js built-in http module.
 * No Express dependency.
 *
 * Endpoints:
 *   POST /submit        — submit a signed message
 *   GET  /deals         — list active deals
 *   GET  /deals/:id     — get deal history
 *   GET  /offers        — list open offers
 *   GET  /health        — relay status
 */

import * as http from "http";
import type { RelayNode } from "./relay_node";

// ---------------------------------------------------------------------------
// Request body parser
// ---------------------------------------------------------------------------

function readBody(req: http.IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on("data", (chunk: Buffer) => chunks.push(chunk));
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf-8")));
    req.on("error", reject);
  });
}

function jsonResponse(
  res: http.ServerResponse,
  status: number,
  body: any,
): void {
  res.writeHead(status, { "Content-Type": "application/json" });
  res.end(JSON.stringify(body));
}

// ---------------------------------------------------------------------------
// Route handler factory
// ---------------------------------------------------------------------------

export function createHttpHandler(relay: RelayNode) {
  return async (req: http.IncomingMessage, res: http.ServerResponse) => {
    const url = req.url || "/";
    const method = req.method || "GET";

    try {
      // POST /submit
      if (method === "POST" && url === "/submit") {
        const raw = await readBody(req);
        const body = JSON.parse(raw);

        // Expect { message, signature, sender_pubkey_hex }
        // Note: public key reconstruction from hex requires the caller to
        // provide the key. For the HTTP layer, we accept raw hex and
        // reconstruct the KeyObject.
        if (!body.message || !body.signature || !body.sender_pubkey_hex) {
          return jsonResponse(res, 400, {
            error: "missing fields: message, signature, sender_pubkey_hex",
          });
        }

        const { keyPairFromHex } = require("../crypto/keyring");
        // We only need the public key — use a dummy private key approach
        // Instead, reconstruct public key from hex
        const crypto = require("crypto");
        const SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
        const pubRaw = Buffer.from(body.sender_pubkey_hex, "hex");
        const spkiDer = Buffer.concat([SPKI_PREFIX, pubRaw]);
        const pubKey = crypto.createPublicKey({ key: spkiDer, format: "der", type: "spki" });

        const result = relay.submit(body.message, body.signature, pubKey);
        const status = result.accepted ? 200 : 400;
        return jsonResponse(res, status, result);
      }

      // GET /deals
      if (method === "GET" && url === "/deals") {
        const deals = relay.listDeals();
        return jsonResponse(res, 200, { deals });
      }

      // GET /deals/:id
      if (method === "GET" && url.startsWith("/deals/")) {
        const dealId = url.slice("/deals/".length);
        if (!dealId) {
          return jsonResponse(res, 400, { error: "missing deal_id" });
        }
        const history = relay.getDealHistory(dealId);
        return jsonResponse(res, 200, { deal_id: dealId, messages: history });
      }

      // GET /offers
      if (method === "GET" && url === "/offers") {
        const offers = relay.getOffers();
        return jsonResponse(res, 200, { offers });
      }

      // GET /health
      if (method === "GET" && url === "/health") {
        return jsonResponse(res, 200, {
          status: "ok",
          deals: relay.listDeals().length,
          offers: relay.getOffers().length,
        });
      }

      // 404
      jsonResponse(res, 404, { error: "not found" });
    } catch (err: any) {
      jsonResponse(res, 500, { error: err.message || "internal error" });
    }
  };
}

// ---------------------------------------------------------------------------
// Standalone startup
// ---------------------------------------------------------------------------

if (require.main === module) {
  const { RelayNode } = require("./relay_node");
  const port = parseInt(process.env.PORT || "8400", 10);
  const dataDir = process.env.DATA_DIR || "./data/relay";

  const relay = new RelayNode({ dataDir });
  const server = relay.startServer(port);

  console.log(`SOST relay node listening on port ${port}`);
  console.log(`Data directory: ${dataDir}`);
}
