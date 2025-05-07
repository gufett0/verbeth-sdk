import { LogChain } from '../typechain-types';
import { getNextNonce } from '../utils/nonce';
import { encryptMessage } from './crypto';
import { ethers } from 'ethers';
import nacl from 'tweetnacl';
import { encodePayload, encodeHandshakeResponseContent } from './payload';


/**
 * Sends an encrypted message assuming recipient's pubkey was already obtained via handshake
 */
export async function sendEncryptedMessage({
  contract,
  topic,
  message,
  recipientPubKey,
  senderAddress,
  senderSignKeyPair,
  timestamp
}: {
  contract: LogChain;
  topic: string;
  message: string;
  recipientPubKey: Uint8Array;
  senderAddress: string;
  senderSignKeyPair: nacl.SignKeyPair;
  timestamp: number;
}) {
  const ephemeralKeyPair = nacl.box.keyPair();

  const ciphertext = encryptMessage(
    message,
    recipientPubKey,
    ephemeralKeyPair.secretKey,
    ephemeralKeyPair.publicKey,
    senderSignKeyPair.secretKey,
    senderSignKeyPair.publicKey
  );

  const nonce = getNextNonce(senderAddress, topic);

  return contract.sendMessage(ciphertext, topic, timestamp, nonce);
}

/**
 * Initiates an on-chain handshake with a recipient.
 */
export async function initiateHandshake({
  contract,
  recipientAddress,
  identityPubKey,
  ephemeralPubKey,
  plaintextPayload
}: {
  contract: LogChain;
  recipientAddress: string;
  identityPubKey: Uint8Array;         // x25519 pubkey
  ephemeralPubKey: Uint8Array;        // Ephemeral pubkey used for this handshake
  plaintextPayload: string;           // plaintext message (e.g., "hello")
}) {
  const recipientHash = ethers.keccak256(
    ethers.toUtf8Bytes('contact:' + recipientAddress.toLowerCase())
  );

  await contract.initiateHandshake(
    recipientHash,
    ethers.hexlify(identityPubKey), 
    ethers.hexlify(ephemeralPubKey),
    ethers.toUtf8Bytes(plaintextPayload)
  );
}


/**
 * Responds to a handshake by encrypting the responder's keys for the initiator
 */
export async function respondToHandshake({
  contract,
  inResponseTo,
  initiatorPubKey,
  responderIdentityPubKey,
  responderEphemeralKeyPair,
  note
}: {
  contract: LogChain;
  inResponseTo: string;          // keccak256 hash of the original handshake or sender address
  initiatorPubKey: Uint8Array;   // ephemeral public key from the initiator
  responderIdentityPubKey: Uint8Array; // x25519 public key of the responder
  responderEphemeralKeyPair?: nacl.BoxKeyPair;
  note?: string;                
}) {
  // Generate an ephemeral key pair if one wasn't provided
  const ephemeralKeyPair = responderEphemeralKeyPair || nacl.box.keyPair();
  const responseContent = {
    identityPubKey: responderIdentityPubKey,
    ephemeralPubKey: ephemeralKeyPair.publicKey,
    note
  };
  
  const plaintext = encodeHandshakeResponseContent(responseContent);
  const nonce = nacl.randomBytes(nacl.box.nonceLength);
  
  // Encrypt the content using the initiator's public key
  const ciphertext = nacl.box(
    plaintext,
    nonce,
    initiatorPubKey,
    ephemeralKeyPair.secretKey
  );
  
  // Format the response payload
  const payload = encodePayload(
    ephemeralKeyPair.publicKey,
    nonce,
    ciphertext
  );
  
  // Send the response
  return contract.respondToHandshake(inResponseTo, ethers.toUtf8Bytes(payload));
}