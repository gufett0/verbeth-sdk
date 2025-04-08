// utils/keys.ts
import { ethers } from 'ethers';
import { Signature } from '@noble/secp256k1';
import { convertPublicKeyToX25519 } from './x25519';

export const VERBETH_KEY_FALLBACK_MSG = 'VerbEth: derive messaging key';

/**
 * Recover the secp256k1 public key from a digest and signature (r, s, v)
 */
export function recoverPubKeyFromSig(sigHex: string, digest: string): Uint8Array | null {
  try {
    const sig = ethers.utils.splitSignature(sigHex);
    const recovered = Signature.fromCompact(ethers.utils.arrayify(sig.r + sig.s))
      .addRecoveryBit(sig.recoveryParam!);
    const pub = recovered.recoverPublicKey(ethers.utils.arrayify(digest));
    return pub.toRawBytes(false).slice(1); // uncompressed, skip 0x04
  } catch {
    return null;
  }
}

/**
 * Fallback derivation: asks signer to sign a known message and derives x25519 key
 */
export async function deriveMessagingPubKey(signer: ethers.Signer): Promise<Uint8Array> {
  const sig = await signer.signMessage(VERBETH_KEY_FALLBACK_MSG);
  const digest = ethers.utils.hashMessage(VERBETH_KEY_FALLBACK_MSG);
  const pubKey = recoverPubKeyFromSig(sig, digest);
  if (!pubKey) throw new Error('Failed to recover secp256k1 pubkey');
  return convertPublicKeyToX25519(pubKey);
}
