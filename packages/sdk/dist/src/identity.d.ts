import { Signer } from 'ethers';
import { DerivationProof } from './types.js';
interface IdentityKeyPair {
    publicKey: Uint8Array;
    secretKey: Uint8Array;
    signingPublicKey: Uint8Array;
    signingSecretKey: Uint8Array;
}
/**
 * Derives deterministic X25519 + Ed25519 keypairs from an Ethereum wallet
 * Uses HKDF (RFC 5869) for secure key derivation from wallet signature
 * It also returns derivation proof to verify the keypair was derived from the wallet address.
 */
export declare function deriveIdentityKeyPairWithProof(signer: Signer, address: string): Promise<{
    keyPair: IdentityKeyPair;
    derivationProof: {
        message: string;
        signature: string;
    };
}>;
export declare function deriveIdentityWithUnifiedKeys(signer: Signer, address: string): Promise<{
    derivationProof: DerivationProof;
    identityPubKey: Uint8Array;
    signingPubKey: Uint8Array;
    unifiedPubKeys: Uint8Array;
}>;
export {};
//# sourceMappingURL=identity.d.ts.map