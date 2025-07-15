export interface LogMessage {
    sender: string;
    ciphertext: string;
    timestamp: number;
    topic: string;
    nonce: bigint;
}
export interface HandshakeLog {
    recipientHash: string;
    sender: string;
    pubKeys: string;
    ephemeralPubKey: string;
    plaintextPayload: string;
}
export interface HandshakeResponseLog {
    inResponseTo: string;
    responder: string;
    ciphertext: string;
}
export interface IdentityKeyPair {
    publicKey: Uint8Array;
    secretKey: Uint8Array;
    signingPublicKey: Uint8Array;
    signingSecretKey: Uint8Array;
}
export interface DerivationProof {
    message: string;
    signature: string;
}
export type PackedUserOperation = typeof DEFAULT_AA_VERSION extends "v0.6" ? UserOpV06 : UserOpV07;
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
export declare const DEFAULT_AA_VERSION: AASpecVersion;
//# sourceMappingURL=types.d.ts.map