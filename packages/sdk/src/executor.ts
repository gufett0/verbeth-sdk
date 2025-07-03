// packages/sdk/src/executor.ts

import { 
  Signer,
  Contract,
  Interface,
  BaseContract
} from "ethers";
import type { LogChainV1 } from "@verbeth/contracts/typechain-types";

export interface IExecutor {
  sendMessage(
    ciphertext: Uint8Array,
    topic: string,
    timestamp: number,
    nonce: bigint
  ): Promise<any>;
  
  initiateHandshake(
    recipientHash: string,
    pubKeys: string,
    ephemeralPubKey: string,
    plaintextPayload: Uint8Array
  ): Promise<any>;
  
  respondToHandshake(
    inResponseTo: string,
    ciphertext: Uint8Array
  ): Promise<any>;
}

// EOA Executor - Direct contract calls via wallet signer
export class EOAExecutor implements IExecutor {
  constructor(private contract: LogChainV1) {}

  async sendMessage(
    ciphertext: Uint8Array,
    topic: string,
    timestamp: number,
    nonce: bigint
  ): Promise<any> {
    return this.contract.sendMessage(ciphertext, topic, timestamp, nonce);
  }

  async initiateHandshake(
    recipientHash: string,
    pubKeys: string,
    ephemeralPubKey: string,
    plaintextPayload: Uint8Array
  ): Promise<any> {
    return this.contract.initiateHandshake(
      recipientHash,
      pubKeys,
      ephemeralPubKey,
      plaintextPayload
    );
  }

  async respondToHandshake(
    inResponseTo: string,
    ciphertext: Uint8Array
  ): Promise<any> {
    return this.contract.respondToHandshake(inResponseTo, ciphertext);
  }
}

// UserOp Executor - Account Abstraction via bundler
export class UserOpExecutor implements IExecutor {
  private logChainInterface: Interface;

  constructor(
    private smartAccountAddress: string,
    private bundlerClient: any,
    private smartAccountClient: any
  ) {
    this.logChainInterface = new Interface([
      "function sendMessage(bytes calldata ciphertext, bytes32 topic, uint256 timestamp, uint256 nonce)",
      "function initiateHandshake(bytes32 recipientHash, bytes pubKeys, bytes ephemeralPubKey, bytes plaintextPayload)",
      "function respondToHandshake(bytes32 inResponseTo, bytes ciphertext)"
    ]);
  }

  async sendMessage(
    ciphertext: Uint8Array,
    topic: string,
    timestamp: number,
    nonce: bigint
  ): Promise<any> {
    const callData = this.logChainInterface.encodeFunctionData("sendMessage", [
      ciphertext,
      topic,
      timestamp,
      nonce
    ]);

    return this.executeUserOp(callData);
  }

  async initiateHandshake(
    recipientHash: string,
    pubKeys: string,
    ephemeralPubKey: string,
    plaintextPayload: Uint8Array
  ): Promise<any> {
    const callData = this.logChainInterface.encodeFunctionData("initiateHandshake", [
      recipientHash,
      pubKeys,
      ephemeralPubKey,
      plaintextPayload
    ]);

    return this.executeUserOp(callData);
  }

  async respondToHandshake(
    inResponseTo: string,
    ciphertext: Uint8Array
  ): Promise<any> {
    const callData = this.logChainInterface.encodeFunctionData("respondToHandshake", [
      inResponseTo,
      ciphertext
    ]);

    return this.executeUserOp(callData);
  }

  private async executeUserOp(callData: string): Promise<any> {
    const userOp = {
      sender: this.smartAccountAddress,
      nonce: await this.smartAccountClient.getNonce(),
      initCode: "0x", // assuming account is already deployed
      callData,
      callGasLimit: 1000000n, 
      verificationGasLimit: 1000000n,
      preVerificationGas: 100000n,
      maxFeePerGas: 1000000000n, // 1 gwei
      maxPriorityFeePerGas: 1000000000n,
      paymasterAndData: "0x", // no paymaster
      signature: "0x" // will be filled by smart account client
    };

    const signedUserOp = await this.smartAccountClient.signUserOperation(userOp);
    const userOpHash = await this.bundlerClient.sendUserOperation(signedUserOp);
    
    const receipt = await this.bundlerClient.waitForUserOperationReceipt(userOpHash);
    return receipt;
  }
}

// Direct EntryPoint Executor - for local testing (bypasses bundler)
export class DirectEntryPointExecutor implements IExecutor {
  private logChainInterface: Interface;
  private entryPointContract: Contract;

  constructor(
    private smartAccountAddress: string,
    entryPointContract: Contract | BaseContract,
    private smartAccountClient: any,
    private signer: Signer // direct signer for test transactions
  ) {
    this.logChainInterface = new Interface([
      "function sendMessage(bytes calldata ciphertext, bytes32 topic, uint256 timestamp, uint256 nonce)",
      "function initiateHandshake(bytes32 recipientHash, bytes pubKeys, bytes ephemeralPubKey, bytes plaintextPayload)",
      "function respondToHandshake(bytes32 inResponseTo, bytes ciphertext)"
    ]);
    this.entryPointContract = entryPointContract.connect(signer) as Contract;
  }

  async sendMessage(
    ciphertext: Uint8Array,
    topic: string,
    timestamp: number,
    nonce: bigint
  ): Promise<any> {
    const callData = this.logChainInterface.encodeFunctionData("sendMessage", [
      ciphertext,
      topic,
      timestamp,
      nonce
    ]);

    return this.executeDirectUserOp(callData);
  }

  async initiateHandshake(
    recipientHash: string,
    pubKeys: string,
    ephemeralPubKey: string,
    plaintextPayload: Uint8Array
  ): Promise<any> {
    const callData = this.logChainInterface.encodeFunctionData("initiateHandshake", [
      recipientHash,
      pubKeys,
      ephemeralPubKey,
      plaintextPayload
    ]);

    return this.executeDirectUserOp(callData);
  }

  async respondToHandshake(
    inResponseTo: string,
    ciphertext: Uint8Array
  ): Promise<any> {
    const callData = this.logChainInterface.encodeFunctionData("respondToHandshake", [
      inResponseTo,
      ciphertext
    ]);

    return this.executeDirectUserOp(callData);
  }

  private async executeDirectUserOp(callData: string): Promise<any> {
    const userOp = {
      sender: this.smartAccountAddress,
      nonce: await this.smartAccountClient.getNonce(),
      initCode: "0x",
      callData,
      callGasLimit: 1000000n,
      verificationGasLimit: 1000000n,
      preVerificationGas: 100000n,
      maxFeePerGas: 1000000000n,
      maxPriorityFeePerGas: 1000000000n,
      paymasterAndData: "0x",
      signature: "0x"
    };

    const signedUserOp = await this.smartAccountClient.signUserOperation(userOp);
    
    // execute directly via EntryPoint.handleOps (bypasses bundler)
    const tx = await this.entryPointContract.handleOps([signedUserOp], await this.signer.getAddress());
    const receipt = await tx.wait();
    
    return receipt;
  }
}

export class ExecutorFactory {
  static createEOA(contract: LogChainV1): IExecutor {
    return new EOAExecutor(contract);
  }

  static createUserOp(
    smartAccountAddress: string,
    _entryPointAddress: string,
    _logChainAddress: string,
    bundlerClient: any,
    smartAccountClient: any
  ): IExecutor {
    return new UserOpExecutor(
      smartAccountAddress,
      bundlerClient,
      smartAccountClient
    );
  }

  static createDirectEntryPoint(
    smartAccountAddress: string,
    entryPointContract: Contract | BaseContract,
    _logChainAddress: string,
    smartAccountClient: any,
    signer: Signer
  ): IExecutor {
    return new DirectEntryPointExecutor(
      smartAccountAddress,
      entryPointContract,
      smartAccountClient,
      signer
    );
  }

  // Auto-detect executor based on environment and signer type
  static async createAuto(
    signerOrAccount: any,
    contract: LogChainV1,
    options?: {
      entryPointAddress?: string;
      entryPointContract?: Contract | BaseContract;
      bundlerClient?: any;
      isTestEnvironment?: boolean; 
    }
  ): Promise<IExecutor> {
    if (signerOrAccount.address && (options?.bundlerClient || options?.entryPointContract)) {
      
      if (options.isTestEnvironment && options.entryPointContract) {
        return new DirectEntryPointExecutor(
          signerOrAccount.address,
          options.entryPointContract,
          signerOrAccount,
          signerOrAccount.signer || signerOrAccount
        );
      }
      
      if (options.bundlerClient && options.entryPointAddress) {
        return new UserOpExecutor(
          signerOrAccount.address,
          options.bundlerClient,
          signerOrAccount
        );
      }
    }
    
    return new EOAExecutor(contract);
  }
}