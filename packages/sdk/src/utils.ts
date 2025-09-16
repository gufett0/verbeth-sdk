// packages/sdk/src/utils.ts

import {
  Contract,
  JsonRpcProvider,
  verifyMessage,
  hashMessage,
  hexlify,
} from "ethers";
import { sha256 } from "@noble/hashes/sha2";
import { hkdf } from "@noble/hashes/hkdf";
import nacl from "tweetnacl";
import { DerivationProof } from "./types.js";
import { keccak256, toUtf8Bytes } from "ethers";
import { AbiCoder } from "ethers";
import { createPublicClient, custom, defineChain, type Address, type PublicClient } from 'viem';

export type Rpcish =
  | import('ethers').JsonRpcProvider            // ethers v6 RPC
  | import('ethers').BrowserProvider           // ethers v6 EIP-1193 (browser)
  | { request: (args: { method: string; params?: any[] }) => Promise<any> }; // generic EIP-1193


function toEip1193(provider: Rpcish) {
  if ((provider as any).request) return provider as { request: ({ method, params }: any) => Promise<any> };
  // ethers JsonRpcProvider → shim .request
  if ((provider as any).send) {
    return {
      request: ({ method, params }: { method: string; params?: any[] }) =>
        (provider as any).send(method, params ?? []),
    };
  }
  throw new Error('Unsupported provider: cannot build EIP-1193 request');
}

export async function makeViemPublicClient(provider: Rpcish): Promise<PublicClient> {
  const eip1193 = toEip1193(provider);

  let chainId = 1;
  try {
    const hex = await eip1193.request({ method: 'eth_chainId' });
    chainId = Number(hex);
  } catch {/* default 1 */}

  const chain = defineChain({
    id: chainId,
    name: `chain-${chainId}`,
    nativeCurrency: { name: 'Ether', symbol: 'ETH', decimals: 18 },
    rpcUrls: { default: { http: [] } },
  });

  return createPublicClient({ chain, transport: custom(eip1193) });
}

export const ERC6492_SUFFIX =
  "0x6492649264926492649264926492649264926492649264926492649264926492";

export function hasERC6492Suffix(sigHex: string): boolean {
  if (!sigHex || typeof sigHex !== "string") return false;
  const s = sigHex.toLowerCase();
  return s.endsWith(ERC6492_SUFFIX.slice(2).toLowerCase());
}

/**
 * Checks if an address is a smart contract that supports EIP-1271 signature verification
 * Returns true if the address has deployed code AND implements isValidSignature function
 */
export async function isSmartContract1271(
  address: string,
  provider: JsonRpcProvider
): Promise<boolean> {
  try {
    const code = await provider.getCode(address);
    if (code === "0x") {
      return false;
    }

    const contract = new Contract(
      address,
      [
        "function isValidSignature(bytes32, bytes) external view returns (bytes4)",
      ],
      provider
    );

    // ECDSA smart contracts
    try {
      await contract.isValidSignature.staticCall(
        "0x0000000000000000000000000000000000000000000000000000000000000000",
        "0x"
      );
      return true;
    } catch (simpleErr) {
      // WebAuthn format
      try {
        const authenticatorData = "0xdeadbeef";
        const clientDataJSON = "0xbeefdead";
        const rawSignature = "0x" + "11".repeat(64);

        const abi = AbiCoder.defaultAbiCoder();
        const webAuthnAuth = abi.encode(
          ["bytes", "bytes", "bytes"],
          [authenticatorData, clientDataJSON, rawSignature]
        );
        const ownerIndex = 0;
        const signatureWrapper = abi.encode(
          ["uint256", "bytes"],
          [ownerIndex, webAuthnAuth]
        );
        const hash = keccak256(toUtf8Bytes("test message"));

        const result = await contract.isValidSignature.staticCall(
          hash,
          signatureWrapper
        );
        return result === "0x1626ba7e";
      } catch (webAuthnErr: any) {
        // if it's a CALL_EXCEPTION without data then function exists
        if (
          (webAuthnErr as any).code === "CALL_EXCEPTION" &&
          (!(webAuthnErr as any).data ||
            (webAuthnErr as any).data === "0x" ||
            (webAuthnErr as any).data === null)
        ) {
          return true;
        }
        return false;
      }
    }
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

    if (
      recoveredAddress.toLowerCase() !== expectedSenderAddress.toLowerCase()
    ) {
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
  derivationProof: DerivationProof,
  expectedSenderAddress: string,
  expectedUnifiedKeys: {
    identityPubKey: Uint8Array;
    signingPubKey: Uint8Array;
  }
): boolean {
  return verifyDerivationProof(
    derivationProof,
    expectedSenderAddress,
    expectedUnifiedKeys
  );
}


/**
 * Verifies derivation proof for smart accounts (EIP-1271 or ERC-6492).
 * Handles both deployed and counterfactual accounts, then re-derives keys.
 */
export async function verifySmartAccountDerivationProof(
  derivationProof: DerivationProof,
  smartAccountAddress: string,
  expectedUnifiedKeys: { identityPubKey: Uint8Array; signingPubKey: Uint8Array },
  provider: Rpcish,
): Promise<boolean> {
  try {
    const client = await makeViemPublicClient(provider);
    const address = smartAccountAddress as Address;
    const sigPrimary = derivationProof.signature as `0x${string}`;

    const okViem = await client.verifyMessage({
      address,
      message: derivationProof.message,
      signature: sigPrimary,
    });

    if (okViem) {
      return rederiveAndMatchKeys(derivationProof, expectedUnifiedKeys);
    }
    return false;
  } catch (err) {
    console.error('verifySmartAccountDerivationProof error:', err);
    return false;
  }
}

// --- identico alla tua re-derivazione, solo estratto in helper -------------
function rederiveAndMatchKeys(
  derivationProof: DerivationProof,
  expectedUnifiedKeys: { identityPubKey: Uint8Array; signingPubKey: Uint8Array }
): boolean {
  const ikm = sha256(derivationProof.signature);
  const salt = new Uint8Array(32);

  const info_x25519 = new TextEncoder().encode("verbeth-x25519-v1");
  const keyMaterial_x25519 = hkdf(sha256, ikm, salt, info_x25519, 32);
  const boxKeyPair = nacl.box.keyPair.fromSecretKey(keyMaterial_x25519);

  const info_ed25519 = new TextEncoder().encode("verbeth-ed25519-v1");
  const keyMaterial_ed25519 = hkdf(sha256, ikm, salt, info_ed25519, 32);
  const signKeyPair = nacl.sign.keyPair.fromSeed(keyMaterial_ed25519);

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
}
