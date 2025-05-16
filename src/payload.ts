export interface EncryptedPayload {
  v: number; // version
  epk: string; // base64 of ephemeral public key
  n: string;   // base64 of nonce
  ct: string;  // base64 of ciphertext
  sig?: string; // base64 of detached signature over (epk || n || ct)
}

export interface IdentityProof {
  signature: string;  // The signature proving identity key ownership
  message: string;    // The keccak256 hash of the signed message
}

// Unified message payload - now structured like HandshakeResponse
export interface MessagePayload {
  content: string;
  timestamp?: number;
  messageType?: 'text' | 'file' | 'media';
  metadata?: Record<string, any>;
}

export interface HandshakePayload {
  identityPubKey: Uint8Array;
  ephemeralPubKey: Uint8Array;
  plaintextPayload: string;
}

export interface HandshakeResponsePayload extends EncryptedPayload {
}

export interface HandshakeResponseContent {
  identityPubKey: Uint8Array; 
  ephemeralPubKey: Uint8Array;
  note?: string;
  identityProof?: IdentityProof;
}

export interface HandshakeContent {
  plaintextPayload: string;
  identityProof?: IdentityProof;
}

export function parseHandshakePayload(plaintextPayload: string): HandshakeContent {
  try {
    // Prova a fare parse come JSON
    const parsed = JSON.parse(plaintextPayload);
    if (typeof parsed === 'object' && parsed.plaintextPayload) {
      return parsed as HandshakeContent;
    }
  } catch (e) {
    // Se fallisce, tratta come string semplice (backward compatibility)
  }
  
  // Fallback per messaggi legacy
  return { plaintextPayload };
}

export function serializeHandshakeContent(content: HandshakeContent): string {
  // Se non ha identityProof, serializza solo il messaggio (comportamento legacy)
  if (!content.identityProof) {
    return content.plaintextPayload;
  }
  // Altrimenti serializza tutto
  return JSON.stringify(content);
}

export function encodePayload(ephemeralPubKey: Uint8Array, nonce: Uint8Array, ciphertext: Uint8Array, sig?: Uint8Array): string {
  const payload: EncryptedPayload = {
    v: 1,
    epk: Buffer.from(ephemeralPubKey).toString('base64'),
    n: Buffer.from(nonce).toString('base64'),
    ct: Buffer.from(ciphertext).toString('base64'),
    ...(sig && { sig: Buffer.from(sig).toString('base64') })
  };
  return JSON.stringify(payload);
}

export function decodePayload(json: string): {
  epk: Uint8Array,
  nonce: Uint8Array,
  ciphertext: Uint8Array,
  sig?: Uint8Array
} {
  const { epk, n, ct, sig } = JSON.parse(json) as EncryptedPayload;
  return {
    epk: Buffer.from(epk, 'base64'),
    nonce: Buffer.from(n, 'base64'),
    ciphertext: Buffer.from(ct, 'base64'),
    ...(sig && { sig: Buffer.from(sig, 'base64') })
  };
}

export function encodeHandshakePayload(payload: HandshakePayload): string {
  return JSON.stringify({
    identityPubKey: Buffer.from(payload.identityPubKey).toString('base64'),
    ephemeralPubKey: Buffer.from(payload.ephemeralPubKey).toString('base64'),
    plaintextPayload: payload.plaintextPayload
  });
}

export function decodeHandshakePayload(encoded: string): HandshakePayload {
  const obj = JSON.parse(encoded);
  return {
    identityPubKey: Uint8Array.from(Buffer.from(obj.identityPubKey, 'base64')),
    ephemeralPubKey: Uint8Array.from(Buffer.from(obj.ephemeralPubKey, 'base64')),
    plaintextPayload: obj.plaintextPayload
  };
}

// Unified function for encoding any structured content as Uint8Array
export function encodeStructuredContent<T>(content: T): Uint8Array {
  // Convert Uint8Arrays to base64 strings for JSON serialization
  const serialized = JSON.stringify(content, (key, value) => {
    if (value instanceof Uint8Array) {
      return Buffer.from(value).toString('base64');
    }
    return value;
  });
  return new TextEncoder().encode(serialized);
}

// Unified function for decoding structured content
export function decodeStructuredContent<T>(
  encoded: Uint8Array,
  converter: (obj: any) => T
): T {
  const decoded = JSON.parse(new TextDecoder().decode(encoded));
  return converter(decoded);
}

// Specific encoders/decoders
export function encodeMessagePayload(payload: MessagePayload): Uint8Array {
  return encodeStructuredContent(payload);
}

export function decodeMessagePayload(encoded: Uint8Array): MessagePayload {
  return decodeStructuredContent(encoded, (obj) => obj);
}

export function encodeHandshakeResponseContent(content: HandshakeResponseContent): Uint8Array {
  return encodeStructuredContent(content);
}

export function decodeHandshakeResponseContent(encoded: Uint8Array): HandshakeResponseContent {
  return decodeStructuredContent(encoded, (obj) => ({
    identityPubKey: Uint8Array.from(Buffer.from(obj.identityPubKey, 'base64')),
    ephemeralPubKey: Uint8Array.from(Buffer.from(obj.ephemeralPubKey, 'base64')),
    note: obj.note,
    identityProof: obj.identityProof
  }));
}