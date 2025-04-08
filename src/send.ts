import { LogChain } from '../typechain-types';
import { getNextNonce } from '../utils/nonce';

export async function sendEncryptedMessage({
  contract,
  senderAddress,
  topic,
  ciphertext,
  timestamp
}: {
  contract: LogChain;
  senderAddress: string;
  topic: string;
  ciphertext: string; // JSON string
  timestamp: number;
}) {
  const nonce = await getNextNonce(contract, senderAddress, topic);
  return contract.sendMessage(ciphertext, topic, timestamp, nonce);
}
