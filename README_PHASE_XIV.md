# Phase XIV: Prekey Bundles and Offline Delivery

Phase XIV adds asynchronous session establishment and store-and-forward
message delivery to the SOST relay. Participants can now establish
encrypted channels and exchange trade messages without both parties
being online simultaneously.

## What Phase XIV Adds

- **Prekey bundles** — publish signed X25519 prekeys to the relay for async key exchange
- **Signed prekey verification** — ED25519 signatures over prekeys prevent tampering
- **One-time prekeys (OTK)** — optional per-session keys for additional forward secrecy
- **Offline message queue** — store-and-forward with configurable TTL (default 7 days)
- **Delivery tracking** — message lifecycle: queued → delivered → acknowledged
- **Pending message fetch** — recipients retrieve queued messages on reconnect
- **Delivery acknowledgment** — explicit receipt confirmation

## How to Publish Prekeys

```bash
# Publish a prekey bundle for your identity
curl -X POST http://localhost:8400/prekeys/<your-identity-hex> \
  -H "Content-Type: application/json" \
  -d '{
    "identity_pub": "<ed25519-pub-hex>",
    "signed_prekey_pub": "<x25519-pub-hex>",
    "signed_prekey_sig": "<ed25519-sig-hex>",
    "otk_pub": "<x25519-otk-pub-hex>"
  }'

# Fetch someone's prekey bundle
curl http://localhost:8400/prekeys/<recipient-identity-hex>
```

## How to Send Offline Messages

```bash
# 1. Fetch recipient's prekey bundle
curl http://localhost:8400/prekeys/<recipient-id>

# 2. Verify signed prekey, derive shared secret, encrypt message
#    (done client-side using channel_keys + encrypt modules)

# 3. Submit encrypted envelope (relay queues if recipient offline)
curl -X POST http://localhost:8400/submit/encrypted \
  -H "Content-Type: application/json" \
  -d '{ ... encrypted envelope ... }'
```

## How to Receive Offline Messages

```bash
# 1. Fetch pending messages
curl http://localhost:8400/pending/<your-identity-hex>

# 2. Decrypt each message client-side

# 3. Acknowledge receipt
curl -X POST http://localhost:8400/ack/<message-id>

# 4. Check delivery status for a deal
curl http://localhost:8400/delivery/<deal-id>
```

## Test Commands

```bash
# All tests
npm test

# Only Phase XIV tests
npx vitest run tests/e2e/offline_delivery.test.ts
npx vitest run tests/e2e/signed_prekey_verification.test.ts
npx vitest run tests/e2e/session_bootstrap.test.ts

# All e2e tests (Phase XIII + XIV)
npx vitest run tests/e2e/
```

## HTTP Endpoints

### Existing (unchanged from Phase XIII)
- `POST /submit` — submit plaintext signed message
- `POST /submit/encrypted` — submit encrypted envelope
- `GET /deals` — list active deals
- `GET /deals/:id` — deal history
- `GET /deals/:id/encrypted` — encrypted messages for deal
- `GET /offers` — open offers
- `GET /health` — relay status

### New (Phase XIV)
- `POST /prekeys/:identity` — publish prekey bundle
- `GET /prekeys/:identity` — fetch prekey bundle
- `GET /pending/:recipientId` — fetch pending offline messages
- `POST /ack/:messageId` — acknowledge delivery
- `GET /delivery/:dealId` — delivery status for deal

## What Is Now Possible vs Phase XIII

| Capability | Phase XIII | Phase XIV |
|---|---|---|
| End-to-end encryption | Yes | Yes |
| Both parties must be online | Yes | No |
| Async session establishment | No | Yes (prekey bundles) |
| Offline message delivery | No | Yes (store-and-forward) |
| Delivery acknowledgment | No | Yes |
| One-time prekeys for forward secrecy | No | Yes |
| Message expiration | No | Yes (configurable TTL) |

## Source Files

### New
- `src/relay/offline_queue.ts` — store-and-forward queue per recipient
- `src/relay/delivery_state.ts` — delivery lifecycle tracker

### Updated
- `src/relay/relay_node.ts` — offline delivery methods, prekey storage
- `src/relay/http_api.ts` — prekey, pending, ack, delivery endpoints

### Tests
- `tests/e2e/offline_delivery.test.ts` — queue and delivery lifecycle
- `tests/e2e/signed_prekey_verification.test.ts` — prekey signing and verification
- `tests/e2e/session_bootstrap.test.ts` — full async session establishment

### Documentation
- `docs/PREKEY_MODEL.md` — key types and verification model
- `docs/OFFLINE_DELIVERY_FLOW.md` — step-by-step delivery flow
- `docs/SESSION_BOOTSTRAP.md` — async session technical details

## What Follows: Phase XV

- **Double ratchet** — forward secrecy on every message via symmetric key ratcheting
- **Header key ratchet** — encrypt envelope headers for metadata privacy
- **Key rotation** — automatic within-session key updates
- **Message ordering** — out-of-order message handling with ratchet state
