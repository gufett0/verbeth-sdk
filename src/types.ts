export interface LogMessage {
    sender: string;
    ciphertext: string; // JSON string of EncryptedPayload
    timestamp: number;
    topic: string; // hex string (bytes32)
    nonce: bigint
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