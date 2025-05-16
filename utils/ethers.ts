// utils/ethers.ts
import { ethers as hardhatEthers } from 'hardhat';
import { 
  Wallet,
  parseEther,
  keccak256 as ethersKeccak256,
  toUtf8Bytes as ethersToUtf8Bytes,
  hexlify as ethersHexlify,
  randomBytes as ethersRandomBytes,
  Transaction,
  getBytes,
  Provider,
  Signer,
  solidityPacked
} from 'ethers';

// Create a wrapper that combines functionality
const ethers = {
  ...hardhatEthers,
  
  parseEther: (value: string) => parseEther(value),
  
  BigNumber: {
    from: (value: any) => BigInt(value.toString()),
  },
  
  encodeBytes32String: hardhatEthers.encodeBytes32String,
  keccak256: (data: string | Uint8Array) => ethersKeccak256(typeof data === 'string' ? data : getBytes(data)),
  toUtf8Bytes: (text: string) => ethersToUtf8Bytes(text),
  hexlify: (value: any) => ethersHexlify(value),
  randomBytes: (length: number) => ethersRandomBytes(length),
  verifyMessage: hardhatEthers.verifyMessage,
  solidityPacked: solidityPacked
};

// The tests are importing Wallet separately, so we need to export it
export { Wallet, ethers, Provider, Signer };

export const BigNumber = {
  from: (value: any) => BigInt(value.toString())
};

export function serializeSignedTx(tx: any): string {
  if (!tx.signature) {
    throw new Error('Missing signature in transaction');
  }

  return Transaction.from(tx).serialized;
}

export const toUtf8Bytes = ethers.toUtf8Bytes;
export const keccak256 = ethers.keccak256;
export const hexlify = ethers.hexlify;
export const randomBytes = ethers.randomBytes;
export const verifyMessage = ethers.verifyMessage;