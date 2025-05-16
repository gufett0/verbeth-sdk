import { LogChain } from '../typechain-types';
import { getNextNonce } from '../utils/nonce';
import { encryptMessage, encryptStructuredPayload } from './crypto';
import { ethers, Signer } from '../utils/ethers';
import nacl from 'tweetnacl';
import { HandshakeResponseContent, HandshakeContent, serializeHandshakeContent } from './payload';

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
  plaintextPayload,
  includeIdentityProof = false,
  signer
}: {
  contract: LogChain;
  recipientAddress: string;
  identityPubKey: Uint8Array;         // x25519 pubkey
  ephemeralPubKey: Uint8Array;        // Ephemeral pubkey used for this handshake
  plaintextPayload: string;           // plaintext message (e.g., "hello")
  includeIdentityProof?: boolean;  // Nuovo optional
  signer?: Signer;                // Nuovo optional
}) {
  const recipientHash = ethers.keccak256(
    ethers.toUtf8Bytes('contact:' + recipientAddress.toLowerCase())
  );

  const handshakeContent: HandshakeContent = {
    plaintextPayload
  };

  if (includeIdentityProof && signer) {
    const bindingMessage = ethers.solidityPacked( 
      ['bytes32', 'bytes32', 'string'],
      [identityPubKey, recipientHash, 'VerbEth-Handshake-v1']
    );
    
    const signature = await signer.signMessage(bindingMessage);
    handshakeContent.identityProof = {
      signature,
      message: ethers.keccak256(bindingMessage)
    };
  }

  const serializedPayload = serializeHandshakeContent(handshakeContent);


  await contract.initiateHandshake(
    recipientHash,
    ethers.hexlify(identityPubKey), 
    ethers.hexlify(ephemeralPubKey),
    ethers.toUtf8Bytes(serializedPayload)
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
  note,
  signer,
  includeIdentityProof = false
}: {
  contract: LogChain;
  inResponseTo: string;
  initiatorPubKey: Uint8Array;
  responderIdentityPubKey: Uint8Array;
  responderEphemeralKeyPair?: nacl.BoxKeyPair;
  note?: string;
  signer?: Signer; 
  includeIdentityProof?: boolean;
}) {
  const ephemeralKeyPair = responderEphemeralKeyPair || nacl.box.keyPair();
  
  let identityProof;
  if (includeIdentityProof && signer) {
    const bindingMessage = ethers.solidityPacked(
      ['bytes32', 'bytes32', 'string'],
      [responderIdentityPubKey, inResponseTo, 'VerbEth-HSResponse-v1']
    );
    
    const signature = await signer.signMessage(bindingMessage);
    identityProof = {
      signature,
      message: ethers.keccak256(bindingMessage)
    };
  }
  
  const responseContent: HandshakeResponseContent = {
    identityPubKey: responderIdentityPubKey,
    ephemeralPubKey: ephemeralKeyPair.publicKey,
    note,
    identityProof
  };
  
  // Use the unified encryption for structured payloads
  const payload = encryptStructuredPayload(
    responseContent,
    initiatorPubKey,
    ephemeralKeyPair.secretKey,
    ephemeralKeyPair.publicKey
  );
  
  return contract.respondToHandshake(inResponseTo, ethers.toUtf8Bytes(payload));
}