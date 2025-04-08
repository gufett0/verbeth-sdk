export interface EncryptedPayload {
  v: number; // version
  epk: string; // base64 of ephemeral public key
  n: string;   // base64 of nonce
  ct: string;  // base64 of ciphertext
  sig?: string; // base64 of detached signature over (epk || n || ct)

}

export function encodePayload(ephemeralPubKey: Uint8Array, nonce: Uint8Array, ciphertext: Uint8Array, sig?: Uint8Array): string {
  const payload: EncryptedPayload = {
    v: 1,
    epk: Buffer.from(ephemeralPubKey).toString('base64'),
    n: Buffer.from(nonce).toString('base64'),
    ct: Buffer.from(ciphertext).toString('base64'),
    ...(sig && { sig: Buffer.from(sig).toString('base64') })
  };
  return JSON.stringify(payload);
}


export function decodePayload(json: string): {
  epk: Uint8Array,
  nonce: Uint8Array,
  ciphertext: Uint8Array,
  sig?: Uint8Array
} {
  const { epk, n, ct, sig } = JSON.parse(json) as EncryptedPayload;
  return {
    epk: Buffer.from(epk, 'base64'),
    nonce: Buffer.from(n, 'base64'),
    ciphertext: Buffer.from(ct, 'base64'),
    ...(sig && { sig: Buffer.from(sig, 'base64') })
  };
}

