import { LogChain } from '../typechain-types';
import { getNextNonce } from '../utils/nonce';
import { resolveRecipientKey } from '../utils/recipient';
import { encryptMessage } from './crypto';
import { ethers } from 'ethers';
import nacl from 'tweetnacl';

export async function sendEncryptedMessage({
  contract,
  topic,
  message,
  recipient,
  senderSignKeyPair,
  timestamp
}: {
  contract: LogChain;
  topic: string;
  message: string;
  recipient: string | ethers.Signer;
  senderSignKeyPair: nacl.SignKeyPair;
  timestamp: number;
}) {
  const recipientPubKey = await resolveRecipientKey(recipient);
  const ephemeralKeyPair = nacl.box.keyPair();

  const ciphertext = encryptMessage(
    message,
    recipientPubKey,
    ephemeralKeyPair.secretKey,
    ephemeralKeyPair.publicKey,
    senderSignKeyPair.secretKey,
    senderSignKeyPair.publicKey
  );

  const senderAddress = typeof recipient === 'string' ? recipient : await recipient.getAddress();
  const nonce = getNextNonce(senderAddress, topic);

  return contract.sendMessage(ciphertext, topic, timestamp, nonce);
}


export async function initiateHandshake({
  contract,
  recipientAddress,
  ephemeralPubKey,
  plaintextPayload
}: {
  contract: LogChain;
  recipientAddress: string;
  ephemeralPubKey: Uint8Array;
  plaintextPayload: string;
}) {
  const recipientHash = ethers.utils.keccak256(
    ethers.utils.toUtf8Bytes('contact:' + recipientAddress.toLowerCase())
  );

  await contract.initiateHandshake(
    recipientHash,
    '0x', // identityPubKey is empty for EOA
    ethers.utils.hexlify(ephemeralPubKey),
    ethers.utils.toUtf8Bytes(plaintextPayload)
  );
}
