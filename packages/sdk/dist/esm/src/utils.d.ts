import { JsonRpcProvider } from "ethers";
import { DerivationProof } from './types.js';
/**
 * Generalized EIP-1271 signature verification
 * Checks if a smart contract validates a signature according to EIP-1271
 */
export declare function verifyEIP1271Signature(contractAddress: string, messageHash: string, signature: string, provider: JsonRpcProvider): Promise<boolean>;
/**
 * Checks if an address is a smart contract that supports EIP-1271 signature verification
 * Returns true if the address has deployed code AND implements isValidSignature function
 */
export declare function isSmartContract(address: string, provider: JsonRpcProvider): Promise<boolean>;
/**
 * Verifies derivation proof and re-derives unified keys
 * This is the core verification function for the new unified keys system
 */
export declare function verifyDerivationProof(derivationProof: DerivationProof, expectedSenderAddress: string, expectedUnifiedKeys: {
    identityPubKey: Uint8Array;
    signingPubKey: Uint8Array;
}): boolean;
/**
 * Verifies derivation proof for EOA addresses
 * Uses ethers verifyMessage which supports EOA signature verification
 */
export declare function verifyEOADerivationProof(derivationProof: DerivationProof, expectedSenderAddress: string, expectedUnifiedKeys: {
    identityPubKey: Uint8Array;
    signingPubKey: Uint8Array;
}): boolean;
/**
 * Verifies derivation proof for Smart Account addresses
 * Uses EIP-1271 for smart contract signature verification
 */
export declare function verifySmartAccountDerivationProof(derivationProof: DerivationProof, smartAccountAddress: string, expectedUnifiedKeys: {
    identityPubKey: Uint8Array;
    signingPubKey: Uint8Array;
}, provider: JsonRpcProvider): Promise<boolean>;
//# sourceMappingURL=utils.d.ts.map