import { ethers } from 'ethers';
import { convertPublicKeyToX25519 } from './x25519';

let Signature: any;
async function loadSignature() {
  if (!Signature) {
    const mod = await import('@noble/secp256k1');
    Signature = mod.Signature;
  }
  return Signature;
}

export const VERBETH_KEY_FALLBACK_MSG = 'VerbEth: derive messaging key';

/**
 * Recover the secp256k1 public key from a digest and signature (r, s, v)
 */
export async function recoverPubKeyFromSig(sigHex: string, digest: string): Promise<Uint8Array | null> {
  try {
    const sig = ethers.utils.splitSignature(sigHex);
    const Sig = await loadSignature();
    const compactSig = ethers.utils.concat([sig.r, sig.s]);
    const recovered = Sig.fromCompact(compactSig).addRecoveryBit(sig.recoveryParam!);
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
  const pubKey = await recoverPubKeyFromSig(sig, digest);

  if (!pubKey) throw new Error('Failed to recover secp256k1 pubkey from signed message');
  return convertPublicKeyToX25519(pubKey);
}
