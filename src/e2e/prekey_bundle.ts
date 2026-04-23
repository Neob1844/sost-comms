/**
 * SOST Comms — Prekey Bundle
 *
 * Publishable prekey bundle that a recipient makes available so that
 * senders can initiate asynchronous encrypted sessions.
 */

import * as crypto from "crypto";
import { publicKeyHex } from "../crypto/ed25519";
import { KeyBundle } from "../crypto/key_bundle";
import {
  SignedPrekey,
  OneTimePrekey,
  generateSignedPrekey,
  generateOneTimePrekeys,
} from "./prekeys";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface PrekeyBundle {
  identityKey: string;       // ED25519 signing public hex
  signedPrekey: SignedPrekey;
  oneTimePrekeys: OneTimePrekey[];
}

export interface PrekeyPrivateKeys {
  signedPrekeyPrivate: crypto.KeyObject;
  oneTimePrivates: Map<number, crypto.KeyObject>;
}

// ---------------------------------------------------------------------------
// Creation
// ---------------------------------------------------------------------------

/**
 * Create a publishable prekey bundle from a key bundle.
 *
 * @param bundle          - the participant's key bundle (Ed25519 + X25519)
 * @param numOneTimeKeys  - how many one-time prekeys to generate (default 10)
 */
export function createPrekeyBundle(
  bundle: KeyBundle,
  numOneTimeKeys: number = 10,
): { prekeyBundle: PrekeyBundle; privateKeys: PrekeyPrivateKeys } {
  const { signed, privateKey: signedPrekeyPrivate } = generateSignedPrekey(
    bundle.signing.privateKey,
  );

  const { prekeys: oneTimePrekeys, privateKeys: oneTimePrivates } =
    generateOneTimePrekeys(numOneTimeKeys);

  const prekeyBundle: PrekeyBundle = {
    identityKey: publicKeyHex(bundle.signing.publicKey),
    signedPrekey: signed,
    oneTimePrekeys,
  };

  const privateKeys: PrekeyPrivateKeys = {
    signedPrekeyPrivate,
    oneTimePrivates,
  };

  return { prekeyBundle, privateKeys };
}
