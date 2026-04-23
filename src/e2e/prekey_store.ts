/**
 * SOST Comms — Prekey Store
 *
 * Persistent JSON-file-based storage for prekey bundles and private keys.
 * Each identity gets its own directory under the data root.
 */

import * as crypto from "crypto";
import * as fs from "fs";
import * as path from "path";

import {
  x25519PrivateKeyHex,
  x25519KeyPairFromHex,
  x25519PublicKeyHex,
} from "../crypto/x25519";
import { PrekeyBundle, PrekeyPrivateKeys } from "./prekey_bundle";
import { OneTimePrekey } from "./prekeys";

// ---------------------------------------------------------------------------
// Store
// ---------------------------------------------------------------------------

export class PrekeyStore {
  private readonly dataDir: string;

  constructor(dataDir: string) {
    this.dataDir = dataDir;
    fs.mkdirSync(dataDir, { recursive: true });
  }

  // -----------------------------------------------------------------------
  // Bundle persistence
  // -----------------------------------------------------------------------

  /**
   * Save a prekey bundle for an identity.
   */
  saveBundle(identity: string, bundle: PrekeyBundle): void {
    const dir = this.identityDir(identity);
    fs.mkdirSync(dir, { recursive: true });
    const filePath = path.join(dir, "bundle.json");
    fs.writeFileSync(filePath, JSON.stringify(bundle, null, 2) + "\n", { mode: 0o600 });
  }

  /**
   * Load a prekey bundle for an identity. Returns null if not found.
   */
  getBundle(identity: string): PrekeyBundle | null {
    const filePath = path.join(this.identityDir(identity), "bundle.json");
    if (!fs.existsSync(filePath)) return null;
    const raw = fs.readFileSync(filePath, "utf-8");
    return JSON.parse(raw) as PrekeyBundle;
  }

  /**
   * Consume (mark as used) a one-time prekey. Returns the prekey if it was
   * available and unused, or null if already used or not found.
   */
  consumeOneTimePrekey(identity: string, prekeyId: number): OneTimePrekey | null {
    const bundle = this.getBundle(identity);
    if (!bundle) return null;

    const otk = bundle.oneTimePrekeys.find((k) => k.id === prekeyId);
    if (!otk || otk.used) return null;

    otk.used = true;
    this.saveBundle(identity, bundle);
    return otk;
  }

  /**
   * Count remaining (unused) one-time prekeys for an identity.
   */
  getRemainingCount(identity: string): number {
    const bundle = this.getBundle(identity);
    if (!bundle) return 0;
    return bundle.oneTimePrekeys.filter((k) => !k.used).length;
  }

  // -----------------------------------------------------------------------
  // Private key persistence
  // -----------------------------------------------------------------------

  /**
   * Save private keys associated with a prekey bundle.
   */
  savePrivateKeys(identity: string, keys: PrekeyPrivateKeys): void {
    const dir = this.identityDir(identity);
    fs.mkdirSync(dir, { recursive: true });

    // Serialize: signed prekey private as hex, OTK privates as id→hex map
    const data: SerializedPrivateKeys = {
      signedPrekeyPrivate: x25519PrivateKeyHex(keys.signedPrekeyPrivate),
      // We also need the public key to reconstruct the KeyObject
      signedPrekeyPublic: x25519PublicKeyHex(
        crypto.createPublicKey(keys.signedPrekeyPrivate),
      ),
      oneTimePrivates: {} as Record<string, { pub: string; priv: string }>,
    };

    for (const [id, privKey] of keys.oneTimePrivates) {
      const pubKey = crypto.createPublicKey(privKey);
      data.oneTimePrivates[String(id)] = {
        pub: x25519PublicKeyHex(pubKey),
        priv: x25519PrivateKeyHex(privKey),
      };
    }

    const filePath = path.join(dir, "private_keys.json");
    fs.writeFileSync(filePath, JSON.stringify(data, null, 2) + "\n", { mode: 0o600 });
  }

  /**
   * Load private keys for an identity. Returns null if not found.
   */
  loadPrivateKeys(identity: string): PrekeyPrivateKeys | null {
    const filePath = path.join(this.identityDir(identity), "private_keys.json");
    if (!fs.existsSync(filePath)) return null;

    const raw = fs.readFileSync(filePath, "utf-8");
    const data = JSON.parse(raw) as SerializedPrivateKeys;

    const signedKp = x25519KeyPairFromHex(data.signedPrekeyPublic, data.signedPrekeyPrivate);

    const oneTimePrivates = new Map<number, crypto.KeyObject>();
    for (const [idStr, entry] of Object.entries(data.oneTimePrivates)) {
      const kp = x25519KeyPairFromHex(entry.pub, entry.priv);
      oneTimePrivates.set(Number(idStr), kp.privateKey);
    }

    return {
      signedPrekeyPrivate: signedKp.privateKey,
      oneTimePrivates,
    };
  }

  // -----------------------------------------------------------------------
  // Internal
  // -----------------------------------------------------------------------

  private identityDir(identity: string): string {
    // Use first 16 chars of identity hex as directory name (safe for fs)
    const safeName = identity.replace(/[^a-fA-F0-9]/g, "").slice(0, 16);
    return path.join(this.dataDir, safeName);
  }
}

// ---------------------------------------------------------------------------
// Serialization types
// ---------------------------------------------------------------------------

interface SerializedPrivateKeys {
  signedPrekeyPrivate: string;
  signedPrekeyPublic: string;
  oneTimePrivates: Record<string, { pub: string; priv: string }>;
}
