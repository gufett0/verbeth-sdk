import { 
  keccak256,
  toUtf8Bytes,
  hexlify,
  solidityPacked,
  Signer
} from "ethers";
import type { LogChainV1 } from "@verbeth/contracts/typechain-types";
import { getNextNonce } from './utils/nonce';
import { encryptMessage, encryptStructuredPayload } from './crypto';
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
  contract: LogChainV1;
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

  return contract.sendMessage(toUtf8Bytes(ciphertext), topic, timestamp, nonce);
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
  contract: LogChainV1;
  recipientAddress: string;
  identityPubKey: Uint8Array;         // x25519 pubkey
  ephemeralPubKey: Uint8Array;        // Ephemeral pubkey used for this handshake
  plaintextPayload: string;           // plaintext message (e.g., "hello")
  includeIdentityProof?: boolean;  // Nuovo optional
  signer?: Signer;                // Nuovo optional
}) {
  const recipientHash = keccak256(
    toUtf8Bytes('contact:' + recipientAddress.toLowerCase())
  );

  const handshakeContent: HandshakeContent = {
    plaintextPayload
  };

  if (includeIdentityProof && signer) {
    const bindingMessage = solidityPacked( 
      ['bytes32', 'bytes32', 'string'],
      [identityPubKey, recipientHash, 'VerbEth-Handshake-v1']
    );
    
    const signature = await signer.signMessage(bindingMessage);
    handshakeContent.identityProof = {
      signature,
      message: keccak256(bindingMessage)
    };
  }

  const serializedPayload = serializeHandshakeContent(handshakeContent);


  await contract.initiateHandshake(
    recipientHash,
    hexlify(identityPubKey), 
    hexlify(ephemeralPubKey),
    toUtf8Bytes(serializedPayload)
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
  contract: LogChainV1;
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
    const bindingMessage = solidityPacked(
      ['bytes32', 'bytes32', 'string'],
      [responderIdentityPubKey, inResponseTo, 'VerbEth-HSResponse-v1']
    );
    
    const signature = await signer.signMessage(bindingMessage);
    identityProof = {
      signature,
      message: keccak256(bindingMessage)
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
  
  return contract.respondToHandshake(inResponseTo, toUtf8Bytes(payload));
}