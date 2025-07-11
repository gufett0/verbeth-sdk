import { sha256 } from '@noble/hashes/sha256';
import { hkdf } from '@noble/hashes/hkdf';
import { Signer } from 'ethers';
import nacl from 'tweetnacl';

interface IdentityKeyPair {
  // X25519 keys per encryption/decryption
  publicKey: Uint8Array;
  secretKey: Uint8Array;
  // Ed25519 keys per signing/verification
  signingPublicKey: Uint8Array;
  signingSecretKey: Uint8Array;
}

/**
 * Derives deterministic X25519 + Ed25519 keypairs from an Ethereum wallet
 * Uses HKDF (RFC 5869) for secure key derivation from wallet signature
 */
export async function deriveIdentityKeyPair(signer: Signer, address: string): Promise<IdentityKeyPair> {

  const cached = localStorage.getItem(`verbeth_identity_${address.toLowerCase()}`);
  if (cached) {
    const parsed = JSON.parse(cached);
    return {
      publicKey: new Uint8Array(parsed.publicKey),
      secretKey: new Uint8Array(parsed.secretKey),
      signingPublicKey: new Uint8Array(parsed.signingPublicKey),
      signingSecretKey: new Uint8Array(parsed.signingSecretKey)
    };
  }

  // deterministic seed from wallet signature
  const message = `VerbEth Identity Key Derivation v1\nAddress: ${address.toLowerCase()}`;
  const signature = await signer.signMessage(message);
  
  // Use HKDF for secure key derivation
  const ikm = sha256(signature);                                    // Input Key Material
  const salt = new Uint8Array(32);                                 // Empty salt
  
  // Derive X25519 keys for encryption
  const info_x25519 = new TextEncoder().encode("verbeth-x25519-v1");
  const keyMaterial_x25519 = hkdf(sha256, ikm, salt, info_x25519, 32);  // 32 bytes for X25519
  const boxKeyPair = nacl.box.keyPair.fromSecretKey(keyMaterial_x25519);
  
  // Derive Ed25519 keys for signing
  const info_ed25519 = new TextEncoder().encode("verbeth-ed25519-v1");
  const keyMaterial_ed25519 = hkdf(sha256, ikm, salt, info_ed25519, 32); // 32 bytes for Ed25519 seed
  const signKeyPair = nacl.sign.keyPair.fromSeed(keyMaterial_ed25519);
  
  const result = {
    publicKey: boxKeyPair.publicKey,
    secretKey: boxKeyPair.secretKey,
    signingPublicKey: signKeyPair.publicKey,
    signingSecretKey: signKeyPair.secretKey
  };
  
  // Cache in localStorage
  const toCache = {
    publicKey: Array.from(result.publicKey),
    secretKey: Array.from(result.secretKey),
    signingPublicKey: Array.from(result.signingPublicKey),
    signingSecretKey: Array.from(result.signingSecretKey)
  };
  localStorage.setItem(`verbeth_identity_${address.toLowerCase()}`, JSON.stringify(toCache));
  
  return result;
}

/**
 * Derive both keys (X25519 e Ed25519) from a secp256k1 public key
 */
export function deriveKeysFromSecp256k1(secpPubKey: Uint8Array): {
  x25519Key: Uint8Array;
  ed25519Key: Uint8Array;
} {
  if (secpPubKey.length !== 64) {
    throw new Error('Expected raw 64-byte secp256k1 public key');
  }

  // Deriva X25519 key (stesso metodo dell'SDK)
  const x25519Hash = sha256(secpPubKey);
  const x25519Key = x25519Hash.slice(0, 32);
  
  // Deriva Ed25519 key usando domain separation diverso
  const ed25519Seed = sha256(new Uint8Array([...secpPubKey, ...new TextEncoder().encode("ed25519")]));
  const ed25519KeyPair = nacl.sign.keyPair.fromSeed(ed25519Seed.slice(0, 32));
  
  return {
    x25519Key,
    ed25519Key: ed25519KeyPair.publicKey
  };
}

/**
 * Clears cached identity keys
 */
export function clearIdentityKeys(address: string) {
  localStorage.removeItem(`verbeth_identity_${address.toLowerCase()}`);
}