import { describe, it, expect, beforeEach } from "vitest";
import * as os from "os";
import * as fs from "fs";
import * as path from "path";

import { publicKeyHex } from "../../src/crypto/ed25519";
import { generateKeyBundle } from "../../src/crypto/key_bundle";
import { createPrekeyBundle } from "../../src/e2e/prekey_bundle";
import { PrekeyStore } from "../../src/e2e/prekey_store";
import { initiateAsyncSession, receiveAsyncSession } from "../../src/e2e/async_handshake";
import { _resetPrekeyIdCounter } from "../../src/e2e/prekeys";

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("one-time prekey consumption", () => {
  let tmpDir: string;
  let store: PrekeyStore;

  beforeEach(() => {
    _resetPrekeyIdCounter();
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "sost-otk-test-"));
    store = new PrekeyStore(tmpDir);
  });

  // Cleanup handled inline in afterEach-style via try/finally isn't needed
  // since vitest handles temp dirs, but let's be explicit:
  const cleanup = () => {
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch { /* ignore */ }
  };

  it("consume first OTK succeeds", () => {
    const bob = generateKeyBundle();
    const { prekeyBundle } = createPrekeyBundle(bob, 3);
    const identity = prekeyBundle.identityKey;
    store.saveBundle(identity, prekeyBundle);

    const firstOtk = prekeyBundle.oneTimePrekeys[0];
    const consumed = store.consumeOneTimePrekey(identity, firstOtk.id);

    expect(consumed).not.toBeNull();
    expect(consumed!.id).toBe(firstOtk.id);
    expect(consumed!.publicKey).toBe(firstOtk.publicKey);
    cleanup();
  });

  it("consume same OTK again returns null", () => {
    const bob = generateKeyBundle();
    const { prekeyBundle } = createPrekeyBundle(bob, 3);
    const identity = prekeyBundle.identityKey;
    store.saveBundle(identity, prekeyBundle);

    const firstOtk = prekeyBundle.oneTimePrekeys[0];
    store.consumeOneTimePrekey(identity, firstOtk.id);

    // Second consumption should fail
    const secondAttempt = store.consumeOneTimePrekey(identity, firstOtk.id);
    expect(secondAttempt).toBeNull();
    cleanup();
  });

  it("consume different OTK succeeds", () => {
    const bob = generateKeyBundle();
    const { prekeyBundle } = createPrekeyBundle(bob, 3);
    const identity = prekeyBundle.identityKey;
    store.saveBundle(identity, prekeyBundle);

    const otk0 = prekeyBundle.oneTimePrekeys[0];
    const otk1 = prekeyBundle.oneTimePrekeys[1];

    const consumed0 = store.consumeOneTimePrekey(identity, otk0.id);
    const consumed1 = store.consumeOneTimePrekey(identity, otk1.id);

    expect(consumed0).not.toBeNull();
    expect(consumed1).not.toBeNull();
    expect(consumed0!.id).not.toBe(consumed1!.id);
    cleanup();
  });

  it("remaining count decreases after consumption", () => {
    const bob = generateKeyBundle();
    const { prekeyBundle } = createPrekeyBundle(bob, 3);
    const identity = prekeyBundle.identityKey;
    store.saveBundle(identity, prekeyBundle);

    expect(store.getRemainingCount(identity)).toBe(3);

    store.consumeOneTimePrekey(identity, prekeyBundle.oneTimePrekeys[0].id);
    expect(store.getRemainingCount(identity)).toBe(2);

    store.consumeOneTimePrekey(identity, prekeyBundle.oneTimePrekeys[1].id);
    expect(store.getRemainingCount(identity)).toBe(1);
    cleanup();
  });

  it("no OTKs left: session still works using signed prekey only", () => {
    const alice = generateKeyBundle();
    const bob = generateKeyBundle();
    // Bundle with 0 OTKs
    const { prekeyBundle, privateKeys } = createPrekeyBundle(bob, 0);

    const { sessionInit, channelKeys: aliceKeys } = initiateAsyncSession(
      alice, prekeyBundle, "deal-no-otk",
    );

    expect(sessionInit.usedOneTimePrekeyId).toBeUndefined();

    const bobKeys = receiveAsyncSession(
      bob, privateKeys, sessionInit, publicKeyHex(alice.signing.publicKey),
    );

    expect(aliceKeys.sendKey.equals(bobKeys.recvKey)).toBe(true);
    expect(aliceKeys.recvKey.equals(bobKeys.sendKey)).toBe(true);
    cleanup();
  });
});
