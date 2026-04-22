import { describe, it, expect, afterEach } from "vitest";
import * as fs from "fs";
import * as path from "path";
import * as os from "os";

import { generateAndSave, loadKeyPair, keyPairFromHex } from "../../src/crypto/keyring";
import { generateKeyPair as genKP, publicKeyHex, privateKeyHex, signCanonicalHash, verifyCanonicalHash } from "../../src/crypto/ed25519";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function tmpDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), "sost-keyring-"));
}

function cleanup(dir: string): void {
  fs.rmSync(dir, { recursive: true, force: true });
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("keyring", () => {
  const dirs: string[] = [];
  afterEach(() => {
    dirs.forEach(cleanup);
    dirs.length = 0;
  });

  // 1
  it("generateAndSave creates pub and key files", () => {
    const dir = tmpDir();
    dirs.push(dir);
    const result = generateAndSave(dir, "test");

    expect(fs.existsSync(result.publicKeyPath)).toBe(true);
    expect(fs.existsSync(result.privateKeyPath)).toBe(true);
    expect(result.publicKeyHex).toMatch(/^[0-9a-f]{64}$/);
  });

  // 2
  it("key file contains valid JSON with publicKey and privateKey", () => {
    const dir = tmpDir();
    dirs.push(dir);
    generateAndSave(dir, "test");

    const data = JSON.parse(fs.readFileSync(path.join(dir, "test.key.json"), "utf-8"));
    expect(data.publicKey).toMatch(/^[0-9a-f]{64}$/);
    expect(data.privateKey).toMatch(/^[0-9a-f]{64}$/);
  });

  // 3
  it("pub file contains only publicKey", () => {
    const dir = tmpDir();
    dirs.push(dir);
    generateAndSave(dir, "test");

    const data = JSON.parse(fs.readFileSync(path.join(dir, "test.pub.json"), "utf-8"));
    expect(data.publicKey).toMatch(/^[0-9a-f]{64}$/);
    expect(data.privateKey).toBeUndefined();
  });

  // 4
  it("loadKeyPair reads files and returns working KeyPair", () => {
    const dir = tmpDir();
    dirs.push(dir);
    generateAndSave(dir, "alice");

    const kp = loadKeyPair(dir, "alice");
    expect(kp.publicKey.type).toBe("public");
    expect(kp.privateKey.type).toBe("private");
    expect(kp.publicKey.asymmetricKeyType).toBe("ed25519");
  });

  // 5
  it("roundtrip: generate → save → load → sign → verify", () => {
    const dir = tmpDir();
    dirs.push(dir);
    generateAndSave(dir, "roundtrip");

    const kp = loadKeyPair(dir, "roundtrip");
    const hash = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
    const sig = signCanonicalHash(hash, kp.privateKey);
    expect(verifyCanonicalHash(hash, sig, kp.publicKey)).toBe(true);
  });

  // 6
  it("keyPairFromHex works with raw hex values", () => {
    const kp = genKP();
    const pubHex = publicKeyHex(kp.publicKey);
    const privHex = privateKeyHex(kp.privateKey);

    const restored = keyPairFromHex(pubHex, privHex);
    const hash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const sig = signCanonicalHash(hash, restored.privateKey);
    expect(verifyCanonicalHash(hash, sig, restored.publicKey)).toBe(true);
    // Cross-verify: original pub can verify restored priv signature
    expect(verifyCanonicalHash(hash, sig, kp.publicKey)).toBe(true);
  });

  // 7
  it("invalid hex throws gracefully", () => {
    expect(() => keyPairFromHex("not-hex", "also-not-hex")).toThrow();
    expect(() => keyPairFromHex("aabb", "ccdd")).toThrow();
  });

  // 8
  it("missing file throws", () => {
    const dir = tmpDir();
    dirs.push(dir);
    expect(() => loadKeyPair(dir, "nonexistent")).toThrow(/not found/);
  });
});
