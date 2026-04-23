import { describe, it, expect, beforeEach } from "vitest";
import * as os from "os";
import * as fs from "fs";
import * as path from "path";

import { generateKeyPair, publicKeyHex } from "../../src/crypto/ed25519";
import { generateKeyBundle } from "../../src/crypto/key_bundle";
import {
  generateSignedPrekey,
  verifySignedPrekey,
  generateOneTimePrekeys,
  _resetPrekeyIdCounter,
} from "../../src/e2e/prekeys";
import { createPrekeyBundle } from "../../src/e2e/prekey_bundle";
import { PrekeyStore } from "../../src/e2e/prekey_store";

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("prekey generation", () => {
  beforeEach(() => {
    _resetPrekeyIdCounter();
  });

  it("generate signed prekey produces valid structure", () => {
    const identity = generateKeyPair();
    const { signed, privateKey } = generateSignedPrekey(identity.privateKey);

    expect(signed.publicKey).toMatch(/^[0-9a-f]{64}$/);
    expect(signed.signature).toBeTruthy();
    expect(signed.createdAt).toBeGreaterThan(0);
    expect(signed.id).toBeGreaterThan(0);
    expect(privateKey).toBeTruthy();
  });

  it("verify signed prekey with correct key succeeds", () => {
    const identity = generateKeyPair();
    const { signed } = generateSignedPrekey(identity.privateKey);

    const valid = verifySignedPrekey(signed, identity.publicKey);
    expect(valid).toBe(true);
  });

  it("verify signed prekey with wrong key fails", () => {
    const identity1 = generateKeyPair();
    const identity2 = generateKeyPair();
    const { signed } = generateSignedPrekey(identity1.privateKey);

    const valid = verifySignedPrekey(signed, identity2.publicKey);
    expect(valid).toBe(false);
  });

  it("generate one-time prekeys batch", () => {
    const { prekeys, privateKeys } = generateOneTimePrekeys(5);

    expect(prekeys).toHaveLength(5);
    expect(privateKeys.size).toBe(5);

    for (const pk of prekeys) {
      expect(pk.publicKey).toMatch(/^[0-9a-f]{64}$/);
      expect(pk.used).toBe(false);
      expect(privateKeys.has(pk.id)).toBe(true);
    }
  });

  it("one-time prekey IDs are unique", () => {
    const { prekeys } = generateOneTimePrekeys(10);
    const ids = prekeys.map((p) => p.id);
    const uniqueIds = new Set(ids);
    expect(uniqueIds.size).toBe(10);
  });

  it("prekey bundle creation has correct structure", () => {
    const bundle = generateKeyBundle();
    const { prekeyBundle, privateKeys } = createPrekeyBundle(bundle, 5);

    expect(prekeyBundle.identityKey).toBe(publicKeyHex(bundle.signing.publicKey));
    expect(prekeyBundle.signedPrekey.publicKey).toMatch(/^[0-9a-f]{64}$/);
    expect(prekeyBundle.signedPrekey.signature).toBeTruthy();
    expect(prekeyBundle.oneTimePrekeys).toHaveLength(5);
    expect(privateKeys.signedPrekeyPrivate).toBeTruthy();
    expect(privateKeys.oneTimePrivates.size).toBe(5);
  });

  it("prekey bundle default creates 10 one-time prekeys", () => {
    const bundle = generateKeyBundle();
    const { prekeyBundle } = createPrekeyBundle(bundle);

    expect(prekeyBundle.oneTimePrekeys).toHaveLength(10);
  });

  it("prekey store save/load roundtrip", () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "sost-prekey-test-"));
    try {
      const store = new PrekeyStore(tmpDir);
      const bundle = generateKeyBundle();
      const { prekeyBundle, privateKeys } = createPrekeyBundle(bundle, 3);
      const identity = prekeyBundle.identityKey;

      store.saveBundle(identity, prekeyBundle);
      store.savePrivateKeys(identity, privateKeys);

      const loadedBundle = store.getBundle(identity);
      expect(loadedBundle).not.toBeNull();
      expect(loadedBundle!.identityKey).toBe(prekeyBundle.identityKey);
      expect(loadedBundle!.signedPrekey.id).toBe(prekeyBundle.signedPrekey.id);
      expect(loadedBundle!.oneTimePrekeys).toHaveLength(3);

      const loadedKeys = store.loadPrivateKeys(identity);
      expect(loadedKeys).not.toBeNull();
      expect(loadedKeys!.signedPrekeyPrivate).toBeTruthy();
      expect(loadedKeys!.oneTimePrivates.size).toBe(3);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });
});
