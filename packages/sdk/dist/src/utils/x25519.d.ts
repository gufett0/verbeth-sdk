/**
 * Converts a 64-byte raw secp256k1 public key into a 32-byte x25519-compatible public key.
 * This is done by hashing it and using the first 32 bytes.
 */
export declare function convertPublicKeyToX25519(secpPubKey: Uint8Array): Uint8Array;
//# sourceMappingURL=x25519.d.ts.map