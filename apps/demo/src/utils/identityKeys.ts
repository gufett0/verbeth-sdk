// CREA QUESTO FILE: apps/demo/src/utils/identityKeys.ts

import { sha256 } from '@noble/hashes/sha256';
import { hkdf } from '@noble/hashes/hkdf';
import { Signer } from 'ethers';
import nacl from 'tweetnacl';

interface IdentityKeyPair {
  publicKey: Uint8Array;
  secretKey: Uint8Array;
}

/**
 * Derives a deterministic X25519 keypair from an Ethereum wallet
 * Uses HKDF (RFC 5869) for secure key derivation from wallet signature
 */
export async function deriveIdentityKeyPair(signer: Signer, address: string): Promise<IdentityKeyPair> {
  // Check if already cached in localStorage
  const cached = localStorage.getItem(`verbeth_identity_${address.toLowerCase()}`);
  if (cached) {
    const parsed = JSON.parse(cached);
    return {
      publicKey: new Uint8Array(parsed.publicKey),
      secretKey: new Uint8Array(parsed.secretKey)
    };
  }

  // Generate deterministic seed from wallet signature
  const message = `VerbEth Identity Key Derivation v1\nAddress: ${address.toLowerCase()}`;
  const signature = await signer.signMessage(message);
  
  // Use HKDF for secure key derivation
  const ikm = sha256(signature);                                    // Input Key Material
  const salt = new Uint8Array(32);                                 // Empty salt (can be customized)
  const info = new TextEncoder().encode("verbeth-x25519-v1");      // Domain separation
  const keyMaterial = hkdf(sha256, ikm, salt, info, 32);           // Derive 32 bytes for X25519
  
  const keyPair = nacl.box.keyPair.fromSecretKey(keyMaterial);
  
  // Cache in localStorage
  const toCache = {
    publicKey: Array.from(keyPair.publicKey),
    secretKey: Array.from(keyPair.secretKey)
  };
  localStorage.setItem(`verbeth_identity_${address.toLowerCase()}`, JSON.stringify(toCache));
  
  return keyPair;
}

/**
 * Clears cached identity keys (useful for logout)
 */
export function clearIdentityKeys(address: string) {
  localStorage.removeItem(`verbeth_identity_${address.toLowerCase()}`);
}