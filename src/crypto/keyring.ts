/**
 * SOST Comms — Keyring (Key Management)
 *
 * Load/save Ed25519 keypairs from/to filesystem.
 * File format: JSON { publicKey: hex, privateKey: hex }
 */

import * as crypto from "crypto";
import * as fs from "fs";
import * as path from "path";
import { generateKeyPair, publicKeyHex, privateKeyHex, KeyPair } from "./ed25519";

// Re-export KeyPair for convenience
export { KeyPair };

// ---------------------------------------------------------------------------
// DER prefixes for Ed25519
// ---------------------------------------------------------------------------

/** SPKI DER prefix for Ed25519 public keys (12 bytes) */
const SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

/** PKCS8 DER prefix for Ed25519 private keys (16 bytes) */
const PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");

// ---------------------------------------------------------------------------
// File info
// ---------------------------------------------------------------------------

export interface KeyPairFiles {
  publicKeyPath: string;
  privateKeyPath: string;
  publicKeyHex: string;
}

// ---------------------------------------------------------------------------
// Core functions
// ---------------------------------------------------------------------------

/**
 * Reconstruct a KeyPair from raw hex-encoded 32-byte keys.
 */
export function keyPairFromHex(pubHex: string, privHex: string): KeyPair {
  if (!/^[0-9a-f]{64}$/i.test(pubHex)) {
    throw new Error(`Invalid public key hex: expected 64 hex chars, got ${pubHex.length}`);
  }
  if (!/^[0-9a-f]{64}$/i.test(privHex)) {
    throw new Error(`Invalid private key hex: expected 64 hex chars, got ${privHex.length}`);
  }

  const pubRaw = Buffer.from(pubHex, "hex");
  const privRaw = Buffer.from(privHex, "hex");

  const spkiDer = Buffer.concat([SPKI_PREFIX, pubRaw]);
  const pkcs8Der = Buffer.concat([PKCS8_PREFIX, privRaw]);

  const publicKey = crypto.createPublicKey({ key: spkiDer, format: "der", type: "spki" });
  const privateKey = crypto.createPrivateKey({ key: pkcs8Der, format: "der", type: "pkcs8" });

  return { publicKey, privateKey };
}

/**
 * Generate a new Ed25519 key pair and save to files.
 *
 * Creates `<dirPath>/<name>.pub.json` and `<dirPath>/<name>.key.json`.
 */
export function generateAndSave(dirPath: string, name: string): KeyPairFiles {
  const kp = generateKeyPair();
  const pubHex = publicKeyHex(kp.publicKey);
  const privHex = privateKeyHex(kp.privateKey);

  fs.mkdirSync(dirPath, { recursive: true });

  const pubPath = path.join(dirPath, `${name}.pub.json`);
  const privPath = path.join(dirPath, `${name}.key.json`);

  const data = JSON.stringify({ publicKey: pubHex, privateKey: privHex }, null, 2) + "\n";
  fs.writeFileSync(privPath, data, { mode: 0o600 });
  fs.writeFileSync(pubPath, JSON.stringify({ publicKey: pubHex }, null, 2) + "\n", { mode: 0o644 });

  return {
    publicKeyPath: pubPath,
    privateKeyPath: privPath,
    publicKeyHex: pubHex,
  };
}

/**
 * Load a key pair from `<dirPath>/<name>.key.json`.
 *
 * The key file must contain JSON with `publicKey` and `privateKey` hex fields.
 */
export function loadKeyPair(dirPath: string, name: string): KeyPair {
  const privPath = path.join(dirPath, `${name}.key.json`);

  if (!fs.existsSync(privPath)) {
    throw new Error(`Key file not found: ${privPath}`);
  }

  const raw = fs.readFileSync(privPath, "utf-8");
  const data = JSON.parse(raw) as { publicKey: string; privateKey: string };

  if (!data.publicKey || !data.privateKey) {
    throw new Error(`Key file missing publicKey or privateKey field: ${privPath}`);
  }

  return keyPairFromHex(data.publicKey, data.privateKey);
}
