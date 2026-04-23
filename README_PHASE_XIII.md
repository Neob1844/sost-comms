# Phase XIII: End-to-End Encrypted Deal Channels

Phase XIII adds blind encrypted transport to the SOST relay. Deal
participants encrypt all trade messages end-to-end so the relay
cannot read deal content. The relay becomes a dumb pipe that routes
opaque envelopes based on cleartext header metadata.

## What Phase XIII Adds

- **X25519 key agreement** per deal (ephemeral keypairs)
- **HKDF-SHA256** channel key derivation with directional send/recv keys
- **ChaCha20-Poly1305** AEAD payload encryption
- **Encrypted envelope format** with signed headers for routing auth
- **Blind relay transport** — relay stores and returns envelopes as-is
- **Sequence number windowing** to prevent replay attacks
- **Backward compatibility** — all existing plaintext endpoints still work

## Running Tests

```bash
# All tests
npm test

# Only e2e encryption tests
npx vitest run tests/e2e/

# Specific test file
npx vitest run tests/e2e/relay_blind_transport.test.ts
npx vitest run tests/e2e/wrong_key_rejection.test.ts
npx vitest run tests/e2e/seq_ordering.test.ts
```

## What Is Encrypted vs Plaintext

| Component | Status |
|---|---|
| Trade offer/accept/cancel/settlement content | Encrypted (Phase XIII) |
| Envelope headers (deal_id, sender, receiver, msg_type) | Cleartext (for routing) |
| Header signatures | ED25519 signed (routing auth) |
| Legacy POST /submit endpoint | Still plaintext (backward compat) |
| POST /submit/encrypted endpoint | New encrypted path |

## What the Relay Can and Cannot Do

### Can:
- Route envelopes to the correct deal based on deal_id
- Verify header signatures to confirm sender identity
- Enforce sequence number windows to reject replay
- Store and retrieve encrypted envelopes
- Serve all existing plaintext endpoints unchanged

### Cannot:
- Read the content of any encrypted message
- Decrypt ciphertext without the X25519 shared secret
- Forge envelopes (lacks sender's ED25519 private key)
- Correlate encrypted content across deals (each deal has unique keys)

## Architecture

```
  Seller                     Relay                      Buyer
    |                          |                          |
    |--- X25519 pub key ------>|                          |
    |                          |                          |
    |                          |<--- X25519 pub key ------|
    |                          |                          |
    |  [derive shared secret]  |                          |
    |  [derive channel keys]   |  [derive shared secret]  |
    |                          |  [derive channel keys]   |
    |                          |                          |
    |  encrypt(trade_offer)    |                          |
    |--- EncryptedEnvelope --->|  (stores opaque blob)    |
    |                          |                          |
    |                          |--- EncryptedEnvelope --->|
    |                          |         decrypt(trade_offer)
    |                          |                          |
    |                          |<--- EncryptedEnvelope ---|
    |                          |  encrypt(trade_accept)   |
    |  decrypt(trade_accept)   |                          |
    |<--- EncryptedEnvelope ---|                          |
    |                          |                          |
    |  ... settlement flow ... |                          |
```

## HTTP Endpoints

### Existing (unchanged)
- `POST /submit` — submit plaintext signed message
- `GET /deals` — list active deals
- `GET /deals/:id` — deal history (plaintext messages)
- `GET /offers` — open offers
- `GET /health` — relay status

### New (Phase XIII)
- `POST /submit/encrypted` — submit encrypted envelope
- `GET /deals/:id/encrypted` — get encrypted messages for a deal

## Source Files

### New
- `src/relay/encrypted_store.ts` — persistent storage for encrypted envelopes
- `src/e2e/channel_keys.ts` — HKDF channel key derivation

### Updated
- `src/relay/relay_node.ts` — `submitEncrypted()` method, header sig verification
- `src/relay/http_api.ts` — encrypted HTTP endpoints

### Tests
- `tests/e2e/relay_blind_transport.test.ts` — relay accepts/rejects/stores envelopes
- `tests/e2e/wrong_key_rejection.test.ts` — wrong-key decryption fails
- `tests/e2e/seq_ordering.test.ts` — sequence windowing enforcement

## What Follows: Phase XIV

- **Prekey bundles** — asynchronous key exchange without both parties online
- **Double-ratchet** — forward secrecy on every message via ratcheting
- **Key rotation** — within-session key updates
- **Ephemeral key advertisement** — relay-mediated prekey distribution
