import { HandshakeResponseContent } from './payload.js';
import { DerivationProof } from './types.js';
/**
 * Encrypts a structured payload (JSON-serializable objects)
 */
export declare function encryptStructuredPayload<T>(payload: T, recipientPublicKey: Uint8Array, ephemeralSecretKey: Uint8Array, ephemeralPublicKey: Uint8Array, staticSigningSecretKey?: Uint8Array, staticSigningPublicKey?: Uint8Array): string;
/**
 * Decrypts a structured payload with converter function
 */
export declare function decryptStructuredPayload<T>(payloadJson: string, recipientSecretKey: Uint8Array, converter: (obj: any) => T, staticSigningPublicKey?: Uint8Array): T | null;
export declare function encryptMessage(message: string, recipientPublicKey: Uint8Array, ephemeralSecretKey: Uint8Array, ephemeralPublicKey: Uint8Array, staticSigningSecretKey?: Uint8Array, staticSigningPublicKey?: Uint8Array): string;
export declare function decryptMessage(payloadJson: string, recipientSecretKey: Uint8Array, staticSigningPublicKey?: Uint8Array): string | null;
/**
 * Decrypts handshake response and extracts individual keys from unified format
 */
export declare function decryptHandshakeResponse(payloadJson: string, initiatorEphemeralSecretKey: Uint8Array): HandshakeResponseContent | null;
/**
 * Convenience function to decrypt handshake response and extract individual keys
 */
export declare function decryptAndExtractHandshakeKeys(payloadJson: string, initiatorEphemeralSecretKey: Uint8Array): {
    identityPubKey: Uint8Array;
    signingPubKey: Uint8Array;
    ephemeralPubKey: Uint8Array;
    note?: string;
    derivationProof: DerivationProof;
} | null;
//# sourceMappingURL=crypto.d.ts.map