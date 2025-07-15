import { Signer, Contract, BaseContract } from "ethers";
import type { LogChainV1 } from "@verbeth/contracts/typechain-types";
export declare function split128x128(word: bigint): readonly [bigint, bigint];
export interface IExecutor {
    sendMessage(ciphertext: Uint8Array, topic: string, timestamp: number, nonce: bigint): Promise<any>;
    initiateHandshake(recipientHash: string, pubKeys: string, ephemeralPubKey: string, plaintextPayload: Uint8Array): Promise<any>;
    respondToHandshake(inResponseTo: string, ciphertext: Uint8Array): Promise<any>;
}
export declare class EOAExecutor implements IExecutor {
    private contract;
    constructor(contract: LogChainV1);
    sendMessage(ciphertext: Uint8Array, topic: string, timestamp: number, nonce: bigint): Promise<any>;
    initiateHandshake(recipientHash: string, pubKeys: string, ephemeralPubKey: string, plaintextPayload: Uint8Array): Promise<any>;
    respondToHandshake(inResponseTo: string, ciphertext: Uint8Array): Promise<any>;
}
export declare class UserOpExecutor implements IExecutor {
    private smartAccountAddress;
    private logChainAddress;
    private bundlerClient;
    private smartAccountClient;
    private logChainInterface;
    private smartAccountInterface;
    constructor(smartAccountAddress: string, logChainAddress: string, bundlerClient: any, smartAccountClient: any);
    sendMessage(ciphertext: Uint8Array, topic: string, timestamp: number, nonce: bigint): Promise<any>;
    initiateHandshake(recipientHash: string, pubKeys: string, ephemeralPubKey: string, plaintextPayload: Uint8Array): Promise<any>;
    respondToHandshake(inResponseTo: string, ciphertext: Uint8Array): Promise<any>;
    private executeUserOp;
}
export declare class DirectEntryPointExecutor implements IExecutor {
    private smartAccountAddress;
    private logChainAddress;
    private smartAccountClient;
    private signer;
    private logChainInterface;
    private smartAccountInterface;
    private entryPointContract;
    private spec;
    constructor(smartAccountAddress: string, entryPointContract: Contract | BaseContract, logChainAddress: string, smartAccountClient: any, signer: Signer);
    sendMessage(ciphertext: Uint8Array, topic: string, timestamp: number, nonce: bigint): Promise<any>;
    initiateHandshake(recipientHash: string, pubKeys: string, ephemeralPubKey: string, plaintextPayload: Uint8Array): Promise<any>;
    respondToHandshake(inResponseTo: string, ciphertext: Uint8Array): Promise<any>;
    private executeDirectUserOp;
}
export declare class ExecutorFactory {
    static createEOA(contract: LogChainV1): IExecutor;
    static createUserOp(smartAccountAddress: string, _entryPointAddress: string, logChainAddress: string, bundlerClient: any, smartAccountClient: any): IExecutor;
    static createDirectEntryPoint(smartAccountAddress: string, entryPointContract: Contract | BaseContract, logChainAddress: string, smartAccountClient: any, signer: Signer): IExecutor;
    static createAuto(signerOrAccount: any, contract: LogChainV1, options?: {
        entryPointAddress?: string;
        entryPointContract?: Contract | BaseContract;
        logChainAddress?: string;
        bundlerClient?: any;
        isTestEnvironment?: boolean;
    }): Promise<IExecutor>;
}
//# sourceMappingURL=executor.d.ts.map