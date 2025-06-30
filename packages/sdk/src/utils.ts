// packages/sdk/src/utils.ts

import { 
  Contract,
  JsonRpcProvider,
  verifyMessage,
  keccak256, 
  toUtf8Bytes  
} from "ethers";
import { sha256 } from '@noble/hashes/sha256';
import { hkdf } from '@noble/hashes/hkdf';
import nacl from 'tweetnacl';
import { DerivationProof } from './types';

/**
 * Generalized EIP-1271 signature verification
 * Checks if a smart contract validates a signature according to EIP-1271
 */
export async function verifyEIP1271Signature(
  contractAddress: string,
  messageHash: string,
  signature: string,
  provider: JsonRpcProvider
): Promise<boolean> {
  try {
    const accountContract = new Contract(
      contractAddress,
      ["function isValidSignature(bytes32, bytes) external view returns (bytes4)"],
      provider
    );

    const result = await accountContract.isValidSignature(messageHash, signature);
    return result === "0x1626ba7e"; 
  } catch (err) {
    console.error("EIP-1271 verification error:", err);
    return false;
  }
}

/**
 * Checks if an address is a smart contract
 * Returns true if the address has deployed code
 */
export async function isSmartContract(
  address: string, 
  provider: JsonRpcProvider
): Promise<boolean> {
  try {
    const code = await provider.getCode(address);
    return code !== "0x";
  } catch (err) {
    console.error("Error checking if address is smart contract:", err);
    return false;
  }
}

/**
 * Verifies derivation proof and re-derives unified keys
 * This is the core verification function for the new unified keys system
 */
export function verifyDerivationProof(
  derivationProof: DerivationProof,
  expectedSenderAddress: string,
  expectedUnifiedKeys: {
    identityPubKey: Uint8Array;
    signingPubKey: Uint8Array;
  }
): boolean {
  try {
    // 1. Verify the derivation signature was created by the expected address
    const recoveredAddress = verifyMessage(
      derivationProof.message,
      derivationProof.signature
    );
    
    if (recoveredAddress.toLowerCase() !== expectedSenderAddress.toLowerCase()) {
      console.error("Derivation signature doesn't match expected sender");
      console.error("  Expected:", expectedSenderAddress);
      console.error("  Got:", recoveredAddress);
      return false;
    }
    
    // 2. Re-derive keys using the provided signature
    const ikm = sha256(derivationProof.signature);
    const salt = new Uint8Array(32);
    
    // Re-derive X25519 keys
    const info_x25519 = new TextEncoder().encode("verbeth-x25519-v1");
    const keyMaterial_x25519 = hkdf(sha256, ikm, salt, info_x25519, 32);
    const boxKeyPair = nacl.box.keyPair.fromSecretKey(keyMaterial_x25519);
    
    // Re-derive Ed25519 keys
    const info_ed25519 = new TextEncoder().encode("verbeth-ed25519-v1");
    const keyMaterial_ed25519 = hkdf(sha256, ikm, salt, info_ed25519, 32);
    const signKeyPair = nacl.sign.keyPair.fromSeed(keyMaterial_ed25519);
    
    // 3. Compare re-derived keys with expected keys
    const identityMatches = Buffer.from(boxKeyPair.publicKey).equals(
      Buffer.from(expectedUnifiedKeys.identityPubKey)
    );
    
    const signingMatches = Buffer.from(signKeyPair.publicKey).equals(
      Buffer.from(expectedUnifiedKeys.signingPubKey)
    );
    
    if (!identityMatches) {
      console.error("Re-derived X25519 identity key doesn't match expected");
      return false;
    }
    
    if (!signingMatches) {
      console.error("Re-derived Ed25519 signing key doesn't match expected");
      return false;
    }
    
    return true;
    
  } catch (err) {
    console.error("verifyDerivationProof error:", err);
    return false;
  }
}

/**
 * Verifies derivation proof for EOA addresses
 * Uses ethers verifyMessage which supports EOA signature verification
 */
export function verifyEOADerivationProof(
  derivationProof: DerivationProof,  // 🆕 Using type from types.ts
  expectedSenderAddress: string,
  expectedUnifiedKeys: {
    identityPubKey: Uint8Array;
    signingPubKey: Uint8Array;
  }
): boolean {
  return verifyDerivationProof(derivationProof, expectedSenderAddress, expectedUnifiedKeys);
}

/**
 * Verifies derivation proof for Smart Account addresses
 * Uses EIP-1271 for smart contract signature verification
 */
export async function verifySmartAccountDerivationProof(
  derivationProof: DerivationProof,  
  smartAccountAddress: string,
  expectedUnifiedKeys: {
    identityPubKey: Uint8Array;
    signingPubKey: Uint8Array;
  },
  provider: JsonRpcProvider
): Promise<boolean> {
  try {
    // 1. Verify using EIP-1271
    const messageHash = keccak256(toUtf8Bytes(derivationProof.message));
    const isValidSignature = await verifyEIP1271Signature(
      smartAccountAddress,
      messageHash,
      derivationProof.signature,
      provider
    );
    
    if (!isValidSignature) {
      console.error("Smart account signature verification failed");
      return false;
    }
    
    // 2. Re-derive keys (same process as EOA)
    const ikm = sha256(derivationProof.signature);
    const salt = new Uint8Array(32);
    
    const info_x25519 = new TextEncoder().encode("verbeth-x25519-v1");
    const keyMaterial_x25519 = hkdf(sha256, ikm, salt, info_x25519, 32);
    const boxKeyPair = nacl.box.keyPair.fromSecretKey(keyMaterial_x25519);
    
    const info_ed25519 = new TextEncoder().encode("verbeth-ed25519-v1");
    const keyMaterial_ed25519 = hkdf(sha256, ikm, salt, info_ed25519, 32);
    const signKeyPair = nacl.sign.keyPair.fromSeed(keyMaterial_ed25519);
    
    // 3. Compare keys
    const identityMatches = Buffer.from(boxKeyPair.publicKey).equals(
      Buffer.from(expectedUnifiedKeys.identityPubKey)
    );
    
    const signingMatches = Buffer.from(signKeyPair.publicKey).equals(
      Buffer.from(expectedUnifiedKeys.signingPubKey)
    );
    
    return identityMatches && signingMatches;
    
  } catch (err) {
    console.error("verifySmartAccountDerivationProof error:", err);
    return false;
  }
}