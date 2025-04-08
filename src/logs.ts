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
