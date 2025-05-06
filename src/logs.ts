import { decryptMessage } from './crypto';

export interface LogMessage {
  sender: string;
  ciphertext: string; // JSON string of EncryptedPayload
  timestamp: number;
  topic: string; // hex string (bytes32)
  nonce: bigint
}

/**
 * Decrypts a log message using the recipient's secret key, and optionally verifies
 * the detached signature using the sender's static signing public key.
 *
 * @param log - The log message object from the event
 * @param recipientSecretKey - The recipient's secret NaCl key (32 bytes)
 * @param senderStaticSigningPublicKey - Optional: static Ed25519 public key of the sender (32 bytes)
 * @returns The decrypted message string or null if decryption or verification fails
 */
export function decryptLog(
  log: LogMessage,
  recipientSecretKey: Uint8Array,
  senderStaticSigningPublicKey?: Uint8Array
): string | null {
  return decryptMessage(log.ciphertext, recipientSecretKey, senderStaticSigningPublicKey);
}

const seen = new Set<string>();

export function isDuplicate(log: LogMessage): boolean {
  const key = `${log.sender}:${log.topic}:${log.nonce}`;
  if (seen.has(key)) return true;
  seen.add(key);
  return false;
}



export interface HandshakeLog {
  recipientHash: string;
  sender: string;
  identityPubKey: string;
  ephemeralPubKey: string;
  plaintextPayload: string;
}

export interface HandshakeResponseLog {
  inResponseTo: string;
  responder: string;
  ciphertext: string;
}
