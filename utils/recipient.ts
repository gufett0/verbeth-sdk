import { ethers } from 'ethers';
import { deriveMessagingPubKey } from './keys';

/**
 * Resolves recipient x25519-compatible public key.
 * @param input Ethereum address or Signer instance
 */
export async function resolveRecipientKey(
  input: string | ethers.Signer,
  provider?: ethers.providers.Provider
): Promise<Uint8Array> {
  if (typeof input === 'string') {
    // Lookup transaction history to try to recover pubkey — not implemented yet
    throw new Error('Address-based lookup not implemented. Use Signer for fallback.');
  }

  return deriveMessagingPubKey(input);
}
