import { decryptMessage } from './crypto';

export interface LogMessage {
  sender: string;
  ciphertext: string; // JSON string of EncryptedPayload
  timestamp: number;
  topic: string; // hex string (bytes32)
  nonce: bigint
}

export function decryptLog(log: LogMessage, recipientSecretKey: Uint8Array): string | null {
  return decryptMessage(log.ciphertext, recipientSecretKey);
}

const seen = new Set<string>();

export function isDuplicate(log: LogMessage): boolean {
  const key = `${log.sender}:${log.topic}:${log.nonce}`;
  if (seen.has(key)) return true;
  seen.add(key);
  return false;
}

