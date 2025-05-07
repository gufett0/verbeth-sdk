import { ethers } from '../utils/ethers';
import { convertPublicKeyToX25519 } from '../utils/x25519';

/**
 * Recovers the secp256k1 public key from the raw transaction and checks if the
 * derived x25519 public key matches the responderIdentityPubKey.
 * 
 * @param rawTxHex Raw transaction hex (signed)
 * @param responderIdentityPubKey x25519 public key emitted in the event
 * @returns true if matching, false otherwise
 */
export function verifyHandshakeResponseIdentity(
    rawTxHex: string,
    responderIdentityPubKey: Uint8Array
  ): boolean {
    try {
      const parsedTx = ethers.Transaction.from(rawTxHex);
      const digest = parsedTx.unsignedHash;

      const sig = parsedTx.signature;
      if (!sig) {
        throw new Error('Invalid or missing signature in parsed transaction');
      }
      
      // Get the public key in uncompressed format (0x04 + x + y)
      const secpPubKey = ethers.SigningKey.recoverPublicKey(digest, sig);
  
      // Ensure the public key is in the correct format
      if (!secpPubKey || !secpPubKey.startsWith('0x04')) {
        throw new Error('Invalid or missing public key in parsed transaction');
      }
  
      // Extract the 64 bytes without the '0x04' prefix
      const pubkeyBytes = ethers.getBytes(secpPubKey).slice(1); // Remove '0x04' prefix
      
      // Now it should be exactly 64 bytes
      if (pubkeyBytes.length !== 64) {
        throw new Error(`Expected 64 bytes after removing prefix, got ${pubkeyBytes.length}`);
      }
      
      const derivedX25519 = convertPublicKeyToX25519(pubkeyBytes);
      return Buffer.from(derivedX25519).equals(Buffer.from(responderIdentityPubKey));
    } catch (err) {
      console.error('verifyHandshakeResponseIdentity error:', err);
      return false;
    }
  }