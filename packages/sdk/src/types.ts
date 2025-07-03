// packages/sdk/src/types.ts

export interface LogMessage {
  sender: string;
  ciphertext: string; // JSON string of EncryptedPayload
  timestamp: number;
  topic: string; // hex string (bytes32)
  nonce: bigint;
}

export interface HandshakeLog {
  recipientHash: string;
  sender: string;
  pubKeys: string; // Unified field (hex string of 65 bytes: version + X25519 + Ed25519)
  ephemeralPubKey: string;
  plaintextPayload: string; // Now always contains JSON with derivationProof
}

export interface HandshakeResponseLog {
  inResponseTo: string;
  responder: string;
  ciphertext: string; // Contains unified pubKeys + derivationProof encrypted
}

// Identity key pair structure (from identity.ts)
export interface IdentityKeyPair {
  // X25519 keys per encryption/decryption
  publicKey: Uint8Array;
  secretKey: Uint8Array;
  // Ed25519 keys per signing/verification
  signingPublicKey: Uint8Array;
  signingSecretKey: Uint8Array;
}

// Derivation proof structure (now mandatory in all handshakes)
export interface DerivationProof {
  message: string; // "VerbEth Identity Key Derivation v1\nAddress: ..."
  signature: string; // Ethereum signature of the message
}

export type PackedUserOperation =
  typeof DEFAULT_AA_VERSION extends "v0.6" ? UserOpV06 : UserOpV07;

export interface BaseUserOp {
  sender: string;
  nonce: bigint;
  initCode: string;
  callData: string;
  preVerificationGas: bigint;
  paymasterAndData: string;
  signature: string;
}

export interface UserOpV06 extends BaseUserOp {
  callGasLimit: bigint;
  verificationGasLimit: bigint;
  maxFeePerGas: bigint;
  maxPriorityFeePerGas: bigint;
}

export interface UserOpV07 extends BaseUserOp {
  /**
   * = (verificationGasLimit << 128) \| callGasLimit
   */
  accountGasLimits: bigint;
  /**
   * = (maxFeePerGas << 128) \| maxPriorityFeePerGas
   */
  gasFees: bigint;
}

export type AASpecVersion = "v0.6" | "v0.7";
export const DEFAULT_AA_VERSION: AASpecVersion = "v0.7";

// ========== NOTES ==========
//
// Handshake parsing functions like parseHandshakeKeys() and
// migrateLegacyHandshakeLog() are available in payload.ts and
// re-exported from index.ts for convenience.
//
// All handshakes now REQUIRE derivationProof in the plaintextPayload.
// Legacy handshakes without derivationProof will be rejected.
