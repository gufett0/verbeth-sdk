import { Signer } from "ethers";
import { IdentityKeyPair, DerivationProof } from './types.js';
import { IExecutor } from './executor.js';
import nacl from 'tweetnacl';
/**
 * Sends an encrypted message assuming recipient's keys were already obtained via handshake.
 * Executor-agnostic: works with EOA, UserOp, and Direct EntryPoint (for tests)
 */
export declare function sendEncryptedMessage({ executor, topic, message, recipientPubKey, senderAddress, senderSignKeyPair, timestamp }: {
    executor: IExecutor;
    topic: string;
    message: string;
    recipientPubKey: Uint8Array;
    senderAddress: string;
    senderSignKeyPair: nacl.SignKeyPair;
    timestamp: number;
}): Promise<any>;
/**
 * Initiates an on-chain handshake with unified keys and mandatory identity proof.
 * Executor-agnostic: works with EOA, UserOp, and Direct EntryPoint (for tests)
 */
export declare function initiateHandshake({ executor, recipientAddress, identityKeyPair, ephemeralPubKey, plaintextPayload, derivationProof, signer }: {
    executor: IExecutor;
    recipientAddress: string;
    identityKeyPair: IdentityKeyPair;
    ephemeralPubKey: Uint8Array;
    plaintextPayload: string;
    derivationProof: DerivationProof;
    signer: Signer;
}): Promise<any>;
/**
 * Responds to a handshake with unified keys and mandatory identity proof.
 * Executor-agnostic: works with EOA, UserOp, and Direct EntryPoint (for tests)
 */
export declare function respondToHandshake({ executor, inResponseTo, initiatorPubKey, responderIdentityKeyPair, responderEphemeralKeyPair, note, derivationProof, signer }: {
    executor: IExecutor;
    inResponseTo: string;
    initiatorPubKey: Uint8Array;
    responderIdentityKeyPair: IdentityKeyPair;
    responderEphemeralKeyPair?: nacl.BoxKeyPair;
    note?: string;
    derivationProof: DerivationProof;
    signer: Signer;
}): Promise<any>;
//# sourceMappingURL=send.d.ts.map