// packages/sdk/src/send.ts
import { keccak256, toUtf8Bytes, hexlify } from "ethers";
import { getNextNonce } from './utils/nonce.js';
import { encryptMessage, encryptStructuredPayload } from './crypto.js';
import { serializeHandshakeContent, encodeUnifiedPubKeys, createHandshakeResponseContent } from './payload.js';
import nacl from 'tweetnacl';
/**
 * Sends an encrypted message assuming recipient's keys were already obtained via handshake.
 * Executor-agnostic: works with EOA, UserOp, and Direct EntryPoint (for tests)
 */
export async function sendEncryptedMessage({ executor, topic, message, recipientPubKey, senderAddress, senderSignKeyPair, timestamp }) {
    if (!executor) {
        throw new Error("Executor must be provided");
    }
    const ephemeralKeyPair = nacl.box.keyPair();
    const ciphertext = encryptMessage(message, recipientPubKey, // X25519 for encryption
    ephemeralKeyPair.secretKey, ephemeralKeyPair.publicKey, senderSignKeyPair.secretKey, // Ed25519 for signing
    senderSignKeyPair.publicKey);
    const nonce = getNextNonce(senderAddress, topic);
    return executor.sendMessage(toUtf8Bytes(ciphertext), topic, timestamp, nonce);
}
/**
 * Initiates an on-chain handshake with unified keys and mandatory identity proof.
 * Executor-agnostic: works with EOA, UserOp, and Direct EntryPoint (for tests)
 */
export async function initiateHandshake({ executor, recipientAddress, identityKeyPair, ephemeralPubKey, plaintextPayload, derivationProof, signer }) {
    if (!executor) {
        throw new Error("Executor must be provided");
    }
    const recipientHash = keccak256(toUtf8Bytes('contact:' + recipientAddress.toLowerCase()));
    const handshakeContent = {
        plaintextPayload,
        derivationProof
    };
    const serializedPayload = serializeHandshakeContent(handshakeContent);
    // Create unified pubKeys (65 bytes: version + X25519 + Ed25519)
    const unifiedPubKeys = encodeUnifiedPubKeys(identityKeyPair.publicKey, // X25519 for encryption
    identityKeyPair.signingPublicKey // Ed25519 for signing
    );
    return await executor.initiateHandshake(recipientHash, hexlify(unifiedPubKeys), hexlify(ephemeralPubKey), toUtf8Bytes(serializedPayload));
}
/**
 * Responds to a handshake with unified keys and mandatory identity proof.
 * Executor-agnostic: works with EOA, UserOp, and Direct EntryPoint (for tests)
 */
export async function respondToHandshake({ executor, inResponseTo, initiatorPubKey, responderIdentityKeyPair, responderEphemeralKeyPair, note, derivationProof, signer }) {
    if (!executor) {
        throw new Error("Executor must be provided");
    }
    const ephemeralKeyPair = responderEphemeralKeyPair || nacl.box.keyPair();
    const responseContent = createHandshakeResponseContent(responderIdentityKeyPair.publicKey, // X25519
    responderIdentityKeyPair.signingPublicKey, // Ed25519
    ephemeralKeyPair.publicKey, note, derivationProof);
    // Encrypt the response for the initiator
    const payload = encryptStructuredPayload(responseContent, initiatorPubKey, // Encrypt to initiator's X25519 key
    ephemeralKeyPair.secretKey, ephemeralKeyPair.publicKey);
    return executor.respondToHandshake(inResponseTo, toUtf8Bytes(payload));
}
