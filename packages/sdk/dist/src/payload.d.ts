import { DerivationProof } from './types.js';
export interface EncryptedPayload {
    v: number;
    epk: string;
    n: string;
    ct: string;
    sig?: string;
}
export interface IdentityProof {
    signature: string;
    message: string;
}
export interface MessagePayload {
    content: string;
    timestamp?: number;
    messageType?: 'text' | 'file' | 'media';
    metadata?: Record<string, any>;
}
export interface HandshakeResponsePayload extends EncryptedPayload {
}
export interface HandshakeContent {
    plaintextPayload: string;
    derivationProof: DerivationProof;
}
export declare function parseHandshakePayload(plaintextPayload: string): HandshakeContent;
export declare function serializeHandshakeContent(content: HandshakeContent): string;
export declare function encodePayload(ephemeralPubKey: Uint8Array, nonce: Uint8Array, ciphertext: Uint8Array, sig?: Uint8Array): string;
export declare function decodePayload(json: string): {
    epk: Uint8Array;
    nonce: Uint8Array;
    ciphertext: Uint8Array;
    sig?: Uint8Array;
};
export declare function encodeStructuredContent<T>(content: T): Uint8Array;
export declare function decodeStructuredContent<T>(encoded: Uint8Array, converter: (obj: any) => T): T;
/**
 * Encodes X25519 + Ed25519 keys into a single 65-byte array with versioning
 */
export declare function encodeUnifiedPubKeys(identityPubKey: Uint8Array, // X25519 - 32 bytes
signingPubKey: Uint8Array): Uint8Array;
/**
 * Decodes unified pubKeys back to individual X25519 and Ed25519 keys
 */
export declare function decodeUnifiedPubKeys(pubKeys: Uint8Array): {
    version: number;
    identityPubKey: Uint8Array;
    signingPubKey: Uint8Array;
} | null;
export interface HandshakePayload {
    unifiedPubKeys: Uint8Array;
    ephemeralPubKey: Uint8Array;
    plaintextPayload: string;
}
export interface HandshakeResponseContent {
    unifiedPubKeys: Uint8Array;
    ephemeralPubKey: Uint8Array;
    note?: string;
    derivationProof: DerivationProof;
}
export declare function encodeHandshakePayload(payload: HandshakePayload): Uint8Array;
export declare function decodeHandshakePayload(encoded: Uint8Array): HandshakePayload;
export declare function encodeHandshakeResponseContent(content: HandshakeResponseContent): Uint8Array;
export declare function decodeHandshakeResponseContent(encoded: Uint8Array): HandshakeResponseContent;
/**
 * Creates HandshakePayload from separate identity keys
 */
export declare function createHandshakePayload(identityPubKey: Uint8Array, signingPubKey: Uint8Array, ephemeralPubKey: Uint8Array, plaintextPayload: string): HandshakePayload;
/**
 * Creates HandshakeResponseContent from separate identity keys
 */
export declare function createHandshakeResponseContent(identityPubKey: Uint8Array, signingPubKey: Uint8Array, ephemeralPubKey: Uint8Array, note?: string, derivationProof?: DerivationProof): HandshakeResponseContent;
/**
 * Extracts individual keys from HandshakePayload
 */
export declare function extractKeysFromHandshakePayload(payload: HandshakePayload): {
    identityPubKey: Uint8Array;
    signingPubKey: Uint8Array;
    ephemeralPubKey: Uint8Array;
} | null;
/**
 * Extracts individual keys from HandshakeResponseContent
 */
export declare function extractKeysFromHandshakeResponse(content: HandshakeResponseContent): {
    identityPubKey: Uint8Array;
    signingPubKey: Uint8Array;
    ephemeralPubKey: Uint8Array;
} | null;
/**
 * Parses unified pubKeys from HandshakeLog event
 */
export declare function parseHandshakeKeys(event: {
    pubKeys: string;
}): {
    identityPubKey: Uint8Array;
    signingPubKey: Uint8Array;
} | null;
//# sourceMappingURL=payload.d.ts.map