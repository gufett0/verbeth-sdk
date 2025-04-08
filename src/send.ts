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
  ciphertext: string;
  timestamp: number;
}) {
  const nonce = getNextNonce(senderAddress, topic);
  return contract.sendMessage(ciphertext, topic, timestamp, nonce);
}
