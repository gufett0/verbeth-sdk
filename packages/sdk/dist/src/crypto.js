// packages/sdk/src/crypto.ts
import nacl from 'tweetnacl';
import { encodePayload, decodePayload, encodeStructuredContent, decodeStructuredContent, extractKeysFromHandshakeResponse } from './payload.js';
/**
 * Encrypts a structured payload (JSON-serializable objects)
 */
export function encryptStructuredPayload(payload, recipientPublicKey, ephemeralSecretKey, ephemeralPublicKey, staticSigningSecretKey, staticSigningPublicKey) {
    // Encode payload as binary JSON
    const plaintext = encodeStructuredContent(payload);
    const nonce = nacl.randomBytes(nacl.box.nonceLength);
    const box = nacl.box(plaintext, nonce, recipientPublicKey, ephemeralSecretKey);
    let sig;
    if (staticSigningSecretKey && staticSigningPublicKey) {
        const dataToSign = Buffer.concat([ephemeralPublicKey, nonce, box]);
        sig = nacl.sign.detached(dataToSign, staticSigningSecretKey);
    }
    return encodePayload(ephemeralPublicKey, nonce, box, sig);
}
/**
 * Decrypts a structured payload with converter function
 */
export function decryptStructuredPayload(payloadJson, recipientSecretKey, converter, staticSigningPublicKey) {
    const { epk, nonce, ciphertext, sig } = decodePayload(payloadJson);
    if (sig && staticSigningPublicKey) {
        const dataToVerify = Buffer.concat([epk, nonce, ciphertext]);
        const valid = nacl.sign.detached.verify(dataToVerify, sig, staticSigningPublicKey);
        if (!valid)
            return null;
    }
    const box = nacl.box.open(ciphertext, nonce, epk, recipientSecretKey);
    if (!box)
        return null;
    return decodeStructuredContent(box, converter);
}
// Convenience wrappers for encrypting and decrypting messages
export function encryptMessage(message, recipientPublicKey, ephemeralSecretKey, ephemeralPublicKey, staticSigningSecretKey, staticSigningPublicKey) {
    const payload = { content: message };
    return encryptStructuredPayload(payload, recipientPublicKey, ephemeralSecretKey, ephemeralPublicKey, staticSigningSecretKey, staticSigningPublicKey);
}
export function decryptMessage(payloadJson, recipientSecretKey, staticSigningPublicKey) {
    const result = decryptStructuredPayload(payloadJson, recipientSecretKey, (obj) => obj, staticSigningPublicKey);
    return result ? result.content : null;
}
/**
 * Decrypts handshake response and extracts individual keys from unified format
 */
export function decryptHandshakeResponse(payloadJson, initiatorEphemeralSecretKey) {
    return decryptStructuredPayload(payloadJson, initiatorEphemeralSecretKey, (obj) => {
        if (!obj.derivationProof) {
            throw new Error("Invalid handshake response: missing derivationProof");
        }
        return {
            unifiedPubKeys: Uint8Array.from(Buffer.from(obj.unifiedPubKeys, 'base64')),
            ephemeralPubKey: Uint8Array.from(Buffer.from(obj.ephemeralPubKey, 'base64')),
            note: obj.note,
            derivationProof: obj.derivationProof
        };
    });
}
/**
 * Convenience function to decrypt handshake response and extract individual keys
 */
export function decryptAndExtractHandshakeKeys(payloadJson, initiatorEphemeralSecretKey) {
    const decrypted = decryptHandshakeResponse(payloadJson, initiatorEphemeralSecretKey);
    if (!decrypted)
        return null;
    const extracted = extractKeysFromHandshakeResponse(decrypted);
    if (!extracted)
        return null;
    return {
        identityPubKey: extracted.identityPubKey,
        signingPubKey: extracted.signingPubKey,
        ephemeralPubKey: extracted.ephemeralPubKey,
        note: decrypted.note,
        derivationProof: decrypted.derivationProof
    };
}
