import { sha256 } from '@noble/hashes/sha256';
import { hkdf } from '@noble/hashes/hkdf';
import nacl from 'tweetnacl';
import { encodeUnifiedPubKeys } from './payload.js';
/**
 * Derives deterministic X25519 + Ed25519 keypairs from an Ethereum wallet
 * Uses HKDF (RFC 5869) for secure key derivation from wallet signature
 * It also returns derivation proof to verify the keypair was derived from the wallet address.
 */
export async function deriveIdentityKeyPairWithProof(signer, address) {
    // deterministic seed from wallet signature
    const message = `VerbEth Identity Key Derivation v1\nAddress: ${address.toLowerCase()}`;
    const signature = await signer.signMessage(message);
    // Use HKDF for secure key derivation
    const ikm = sha256(signature); // Input Key Material
    const salt = new Uint8Array(32); // Empty salt
    // Derive X25519 keys for encryption
    const info_x25519 = new TextEncoder().encode("verbeth-x25519-v1");
    const keyMaterial_x25519 = hkdf(sha256, ikm, salt, info_x25519, 32); // 32 bytes for X25519
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
    return {
        keyPair: result,
        derivationProof: {
            message,
            signature
        }
    };
}
export async function deriveIdentityWithUnifiedKeys(signer, address) {
    const result = await deriveIdentityKeyPairWithProof(signer, address);
    const unifiedPubKeys = encodeUnifiedPubKeys(result.keyPair.publicKey, // X25519
    result.keyPair.signingPublicKey // Ed25519
    );
    return {
        derivationProof: result.derivationProof,
        identityPubKey: result.keyPair.publicKey,
        signingPubKey: result.keyPair.signingPublicKey,
        unifiedPubKeys,
    };
}
