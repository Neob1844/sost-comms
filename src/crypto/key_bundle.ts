/**
 * SOST Comms — Key Bundle
 *
 * Combined identity: Ed25519 signing key + X25519 encryption key.
 * Each participant in a deal has both a long-lived signing identity
 * and an encryption key for end-to-end channel security.
 */

import * as crypto from "crypto";
import * as fs from "fs";
import * as path from "path";

import { generateKeyPair, publicKeyHex, privateKeyHex, KeyPair } from "./ed25519";
import { keyPairFromHex } from "./keyring";
import {
  generateX25519KeyPair,
  x25519PublicKeyHex,
  x25519PrivateKeyHex,
  x25519KeyPairFromHex,
  X25519KeyPair,
} from "./x25519";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface KeyBundle {
  signing: KeyPair;          // Ed25519 for signatures
  encryption: X25519KeyPair; // X25519 for key agreement
}

// ---------------------------------------------------------------------------
// Generation
// ---------------------------------------------------------------------------

/**
 * Generate a new key bundle (Ed25519 + X25519).
 */
export function generateKeyBundle(): KeyBundle {
  return {
    signing: generateKeyPair(),
    encryption: generateX25519KeyPair(),
  };
}

// ---------------------------------------------------------------------------
// Save / Load
// ---------------------------------------------------------------------------

/**
 * Save a key bundle to `<dirPath>/<name>.bundle.json`.
 * File contains hex-encoded keys for both signing and encryption.
 */
export function saveKeyBundle(bundle: KeyBundle, dirPath: string, name: string): void {
  fs.mkdirSync(dirPath, { recursive: true });

  const data = {
    signingPublicKey: publicKeyHex(bundle.signing.publicKey),
    signingPrivateKey: privateKeyHex(bundle.signing.privateKey),
    encryptionPublicKey: x25519PublicKeyHex(bundle.encryption.publicKey),
    encryptionPrivateKey: x25519PrivateKeyHex(bundle.encryption.privateKey),
  };

  const filePath = path.join(dirPath, `${name}.bundle.json`);
  fs.writeFileSync(filePath, JSON.stringify(data, null, 2) + "\n", { mode: 0o600 });
}

/**
 * Load a key bundle from `<dirPath>/<name>.bundle.json`.
 */
export function loadKeyBundle(dirPath: string, name: string): KeyBundle {
  const filePath = path.join(dirPath, `${name}.bundle.json`);

  if (!fs.existsSync(filePath)) {
    throw new Error(`Key bundle file not found: ${filePath}`);
  }

  const raw = fs.readFileSync(filePath, "utf-8");
  const data = JSON.parse(raw) as {
    signingPublicKey: string;
    signingPrivateKey: string;
    encryptionPublicKey: string;
    encryptionPrivateKey: string;
  };

  if (!data.signingPublicKey || !data.signingPrivateKey) {
    throw new Error(`Bundle file missing signing key fields: ${filePath}`);
  }
  if (!data.encryptionPublicKey || !data.encryptionPrivateKey) {
    throw new Error(`Bundle file missing encryption key fields: ${filePath}`);
  }

  return {
    signing: keyPairFromHex(data.signingPublicKey, data.signingPrivateKey),
    encryption: x25519KeyPairFromHex(data.encryptionPublicKey, data.encryptionPrivateKey),
  };
}

// ---------------------------------------------------------------------------
// Public-only export
// ---------------------------------------------------------------------------

/**
 * Extract hex-encoded public keys from a key bundle.
 */
export function keyBundleToPublicHex(bundle: KeyBundle): {
  signingPub: string;
  encryptionPub: string;
} {
  return {
    signingPub: publicKeyHex(bundle.signing.publicKey),
    encryptionPub: x25519PublicKeyHex(bundle.encryption.publicKey),
  };
}
