import { ethers } from "ethers";
import { recoverPubKeyFromSig } from "./keys";
import { convertPublicKeyToX25519 } from "./x25519";

/**
 * Tries to resolve recipient's x25519 pubkey using either a Signer or past txs from their address.
 */
export async function resolveRecipientKey(
  input: string | ethers.Signer,
  provider?: ethers.providers.Provider
): Promise<Uint8Array> {
  if (typeof input !== "string") {
    return await (await import("./keys")).deriveMessagingPubKey(input);
  }

  if (!provider) throw new Error("Provider required for address lookup");

  const address = ethers.utils.getAddress(input);
  const latest = await provider.getBlock("latest");

  for (let i = latest.number; i > latest.number - 1000 && i >= 0; i--) {
    const block = await provider.getBlock(i);
    if (!block?.transactions?.length) continue;

    for (const txHash of block.transactions) {
      const tx = await provider.getTransaction(txHash);
      if (!tx || tx.from.toLowerCase() !== address.toLowerCase()) continue;
      if (!tx.v || !tx.r || !tx.s) continue;

      const msgHash = ethers.utils.keccak256(tx.data || "0x");
      const sigHex = ethers.utils.joinSignature({
        r: tx.r,
        s: tx.s,
        v: Number(tx.v),
      });

      const pubkey = await recoverPubKeyFromSig(sigHex, msgHash);
      if (pubkey) return convertPublicKeyToX25519(pubkey);
    }
  }

  throw new Error(`Could not resolve pubkey for address: ${address}`);
}
