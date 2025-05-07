import { LogChain } from '../typechain-types';
import { getNextNonce } from '../utils/nonce';
import { encryptMessage } from './crypto';
import { ethers } from 'ethers';
import nacl from 'tweetnacl';

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
  const recipientHash = ethers.utils.keccak256(
    ethers.utils.toUtf8Bytes('contact:' + recipientAddress.toLowerCase())
  );

  await contract.initiateHandshake(
    recipientHash,
    ethers.utils.hexlify(identityPubKey), 
    ethers.utils.hexlify(ephemeralPubKey),
    ethers.utils.toUtf8Bytes(plaintextPayload)
  );
}
