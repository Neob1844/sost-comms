import { describe, it, expect } from "vitest";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";

import {
  generateX25519KeyPair,
  x25519PublicKeyHex,
  x25519PrivateKeyHex,
  x25519KeyPairFromHex,
  deriveSharedSecret,
} from "../../src/crypto/x25519";

import {
  generateKeyBundle,
  saveKeyBundle,
  loadKeyBundle,
  keyBundleToPublicHex,
} from "../../src/crypto/key_bundle";

// ---------------------------------------------------------------------------
// X25519 key exchange
// ---------------------------------------------------------------------------

describe("x25519 key exchange", () => {
  it("generateX25519KeyPair produces valid KeyObjects", () => {
    const kp = generateX25519KeyPair();
    expect(kp.publicKey.type).toBe("public");
    expect(kp.privateKey.type).toBe("private");
    expect(kp.publicKey.asymmetricKeyType).toBe("x25519");
    expect(kp.privateKey.asymmetricKeyType).toBe("x25519");
  });

  it("deriveSharedSecret: both sides derive the same secret", () => {
    const alice = generateX25519KeyPair();
    const bob = generateX25519KeyPair();

    const secretAB = deriveSharedSecret(alice.privateKey, bob.publicKey);
    const secretBA = deriveSharedSecret(bob.privateKey, alice.publicKey);

    expect(secretAB.length).toBe(32);
    expect(secretAB.equals(secretBA)).toBe(true);
  });

  it("different key pairs produce different shared secrets", () => {
    const alice = generateX25519KeyPair();
    const bob = generateX25519KeyPair();
    const carol = generateX25519KeyPair();

    const secretAB = deriveSharedSecret(alice.privateKey, bob.publicKey);
    const secretAC = deriveSharedSecret(alice.privateKey, carol.publicKey);

    expect(secretAB.equals(secretAC)).toBe(false);
  });

  it("hex export produces 64-char hex strings", () => {
    const kp = generateX25519KeyPair();
    const pub = x25519PublicKeyHex(kp.publicKey);
    const priv = x25519PrivateKeyHex(kp.privateKey);
    expect(pub).toMatch(/^[0-9a-f]{64}$/);
    expect(priv).toMatch(/^[0-9a-f]{64}$/);
  });

  it("hex export/import roundtrip preserves keys", () => {
    const kp = generateX25519KeyPair();
    const pubHex = x25519PublicKeyHex(kp.publicKey);
    const privHex = x25519PrivateKeyHex(kp.privateKey);

    const restored = x25519KeyPairFromHex(pubHex, privHex);
    expect(x25519PublicKeyHex(restored.publicKey)).toBe(pubHex);
    expect(x25519PrivateKeyHex(restored.privateKey)).toBe(privHex);

    // DH with restored key pair produces same shared secret
    const peer = generateX25519KeyPair();
    const s1 = deriveSharedSecret(kp.privateKey, peer.publicKey);
    const s2 = deriveSharedSecret(restored.privateKey, peer.publicKey);
    expect(s1.equals(s2)).toBe(true);
  });

  it("x25519KeyPairFromHex rejects invalid hex", () => {
    expect(() => x25519KeyPairFromHex("bad", "0".repeat(64))).toThrow();
    expect(() => x25519KeyPairFromHex("0".repeat(64), "bad")).toThrow();
  });
});

// ---------------------------------------------------------------------------
// Key bundle
// ---------------------------------------------------------------------------

describe("key bundle", () => {
  it("generateKeyBundle creates both signing and encryption keys", () => {
    const bundle = generateKeyBundle();
    expect(bundle.signing.publicKey.asymmetricKeyType).toBe("ed25519");
    expect(bundle.signing.privateKey.asymmetricKeyType).toBe("ed25519");
    expect(bundle.encryption.publicKey.asymmetricKeyType).toBe("x25519");
    expect(bundle.encryption.privateKey.asymmetricKeyType).toBe("x25519");
  });

  it("keyBundleToPublicHex returns valid hex strings", () => {
    const bundle = generateKeyBundle();
    const pubs = keyBundleToPublicHex(bundle);
    expect(pubs.signingPub).toMatch(/^[0-9a-f]{64}$/);
    expect(pubs.encryptionPub).toMatch(/^[0-9a-f]{64}$/);
  });

  it("save and load key bundle roundtrip", () => {
    const bundle = generateKeyBundle();
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "sost-bundle-"));

    try {
      saveKeyBundle(bundle, tmpDir, "test");
      const loaded = loadKeyBundle(tmpDir, "test");

      const origPubs = keyBundleToPublicHex(bundle);
      const loadedPubs = keyBundleToPublicHex(loaded);

      expect(loadedPubs.signingPub).toBe(origPubs.signingPub);
      expect(loadedPubs.encryptionPub).toBe(origPubs.encryptionPub);

      // Verify DH still works with loaded keys
      const peer = generateX25519KeyPair();
      const s1 = deriveSharedSecret(bundle.encryption.privateKey, peer.publicKey);
      const s2 = deriveSharedSecret(loaded.encryption.privateKey, peer.publicKey);
      expect(s1.equals(s2)).toBe(true);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });
});
