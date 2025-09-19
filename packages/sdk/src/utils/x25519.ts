import { sha256 } from '@noble/hashes/sha2';

/**
 * Converts a 64-byte raw secp256k1 public key into a 32-byte x25519-compatible public key.
 * This is done by hashing it and using the first 32 bytes.
 */
export function convertPublicKeyToX25519(secpPubKey: Uint8Array): Uint8Array {
  if (secpPubKey.length !== 64) {
    throw new Error('Expected raw 64-byte secp256k1 public key (uncompressed, no prefix)');
  }

  const hash = sha256(secpPubKey);
  return Uint8Array.from(hash.slice(0, 32));
}
