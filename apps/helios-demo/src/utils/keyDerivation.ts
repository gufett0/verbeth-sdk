import { WalletClient } from 'viem';
import { hashMessage } from 'viem';
import { SigningKey, getBytes } from 'ethers';
import * as nacl from 'tweetnacl';
import { sha256 } from '@noble/hashes/sha256';


function convertPublicKeyToX25519(secpPubKey: Uint8Array): Uint8Array {
  if (secpPubKey.length !== 64) {
    throw new Error('Expected raw 64-byte secp256k1 public key (uncompressed, no prefix)');
  }

  const hash = sha256(secpPubKey);
  return Uint8Array.from(hash.slice(0, 32)); // NaCl-compatible
}


/**
 * Derives a deterministic identity key from an Ethereum address
 * Uses the same approach as the SDK for consistency
 */
export const deriveIdentityKeyFromAddress = async (
  walletClient: WalletClient, 
  address: string
): Promise<Uint8Array> => {
    try {
        // Create a deterministic message to sign (similar to SDK test approach)
        const message = `VerbEth Identity Key for ${address.toLowerCase()}`;
        
        // Sign the message with the wallet
        const signature = await walletClient.signMessage({
            account: address as `0x${string}`,
            message: message
        });

        // Recover the public key from the signature (like in SDK tests)
        const messageHash = hashMessage(message);
        const recoveredPubKey = SigningKey.recoverPublicKey(messageHash, signature);
        
        if (!recoveredPubKey || !recoveredPubKey.startsWith("0x04")) {
            throw new Error("Invalid recovered public key");
        }

        // Convert from secp256k1 to X25519 (like in SDK)
        const pubkeyBytes = getBytes(recoveredPubKey).slice(1); // Remove 0x04 prefix
        if (pubkeyBytes.length !== 64) {
            throw new Error(`Expected 64 bytes, got ${pubkeyBytes.length}`);
        }

        // Use the SDK's conversion function if available, otherwise use hash-based approach
        let identityPubKey: Uint8Array;
        try {
            identityPubKey = convertPublicKeyToX25519(pubkeyBytes);
        } catch (error) {
            console.warn('SDK convertPublicKeyToX25519 not available, using hash fallback:', error);
            identityPubKey = nacl.hash(pubkeyBytes).slice(0, 32);
        }
        
        console.log('Derived identity key from signature:', {
            address,
            message,
            signature: signature.slice(0, 10) + '...',
            recoveredPubKey: recoveredPubKey.slice(0, 10) + '...',
            identityPubKey: Array.from(identityPubKey),
            length: identityPubKey.length
        });
        
        return identityPubKey;
    } catch (error) {
        console.error('Failed to derive identity key from signature:', error);
        throw error;
    }
};