// packages/sdk/src/utils.ts

import { Contract, JsonRpcProvider, verifyMessage, hashMessage } from "ethers";
import { sha256 } from "@noble/hashes/sha2";
import { hkdf } from "@noble/hashes/hkdf";
import nacl from "tweetnacl";
import { DerivationProof } from "./types.js";
import { keccak256, toUtf8Bytes } from "ethers";
import { AbiCoder } from "ethers";

export const ERC6492_SUFFIX =
  "0x6492649264926492649264926492649264926492649264926492649264926492";

export function hasERC6492Suffix(sigHex: string): boolean {
  if (!sigHex || typeof sigHex !== "string") return false;
  const s = sigHex.toLowerCase();
  return s.endsWith(ERC6492_SUFFIX.slice(2).toLowerCase());
}

export const DEFAULT_UNI_SIG_VALIDATOR =
  "0x55E78e1bf2f47051f388F07d77649492A3544eA5"; // Base mainnet (for now)


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
      [
        "function isValidSignature(bytes32, bytes) external view returns (bytes4)",
      ],
      provider
    );

    const result = await accountContract.isValidSignature(
      messageHash,
      signature
    );
    return result === "0x1626ba7e";
  } catch (err) {
    console.error("EIP-1271 verification error:", err);
    return false;
  }
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
 * Verifies derivation proof for smart accounts (EIP-1271 or ERC-6492)
 * Handles both deployed and counterfactual accounts, then re-derives keys.
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
    const messageHash = hashMessage(derivationProof.message);

    // 1) choose 1271 vs 6492
    let ok = false;
    const code = await provider.getCode(smartAccountAddress);

    // try 6492 first if the provided signature is a 6492 envelope or an extra 6492 field is present
    const dpAny: any = derivationProof as any;
    const sigPrimary = derivationProof.signature;
    const sig6492 = hasERC6492Suffix(sigPrimary)
      ? sigPrimary
      : dpAny.signature6492 ?? dpAny.erc6492;

    if (sig6492) {
      ok = await verifyERC6492WithSingleton({
        account: smartAccountAddress,
        messageHash,
        sig6492Envelope: sig6492,
        provider,
      });

      console.log(
        "DEBUG verifySmartAccountDerivationProof - tried ERC-6492:",
        ok
      );
    } else if (code !== "0x") {
      // account is deployed: plain EIP-1271
      ok = await verifyEIP1271Signature(
        smartAccountAddress,
        messageHash,
        sigPrimary,
        provider
      );
    } else {
      // undeployed + no 6492 envelope → cannot verify
      console.error(
        "DEBUG Smart account undeployed and no ERC-6492 signature provided"
      );
      return false;
    }

    if (!ok) return false;

    // 2) key re-derivation stays EXACTLY the same (derive from the *raw* signature field)
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
    return identityMatches && signingMatches;
  } catch (err) {
    console.error("verifySmartAccountDerivationProof error:", err);
    return false;
  }
}

/**
 * Verifies an ERC-6492 envelope using the Universal Signature Validator singleton
 *
 * Supports both deployed and counterfactual smart accounts:
 *  - Wraps the account’s signature in a 6492 envelope
 *  - Calls the singleton’s `isValidSig` helper
 *  - Handles revert-with-data cases used for counterfactual paths
 *
 * Returns true if the validator confirms the signature is valid, false otherwise.
 */
export async function verifyERC6492WithSingleton(params: {
  account: string;
  messageHash: string;
  sig6492Envelope: string;
  provider: JsonRpcProvider;
  validator?: string;
  allowSideEffects?: boolean;
}): Promise<boolean> {
  const {
    account,
    messageHash,
    sig6492Envelope,
    provider,
    validator = DEFAULT_UNI_SIG_VALIDATOR,
    allowSideEffects = false,
  } = params;

  // try 4 args first
  const abi4 = [
    "function isValidSig(address,bytes32,bytes,bool) view returns (bool)",
  ];
  const abi3 = [
    "function isValidSig(address,bytes32,bytes) view returns (bool)",
  ];
  let v = new Contract(validator, abi4, provider);

  const tryCall = async (c: Contract, withSideEffectsArg: boolean) => {
    try {
      if (withSideEffectsArg) {
        return await c.isValidSig.staticCall(
          account,
          messageHash,
          sig6492Envelope,
          allowSideEffects
        );
      } else {
        return await c.isValidSig.staticCall(
          account,
          messageHash,
          sig6492Envelope
        );
      }
    } catch (err: any) {
      // counterfactual path: singleton reverts with 32-byte bool to undo side effects
      const data: string | undefined = err?.data ?? err?.error?.data;
      if (data && data !== "0x" && data.length >= 66) {
        try {
          return BigInt(data) !== 0n;
        } catch {}
      }
      throw err; // for abi fallback
    }
  };

  try {
    return await tryCall(v, true);
  } catch {
    v = new Contract(validator, abi3, provider);
    try {
      return await tryCall(v, false);
    } catch {
      return false;
    }
  }
}
