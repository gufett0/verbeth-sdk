// // packages/sdk/src/utils/ethers.ts
// import * as ethersAll from 'ethers';

// // Export the entire ethers library as 'ethers'
// export const ethers = ethersAll;

// // Also export individual functions for convenience
// export const {
//   Wallet,
//   parseEther,
//   keccak256,
//   toUtf8Bytes,
//   hexlify,
//   randomBytes,
//   Transaction,
//   getBytes,
//   solidityPacked,
//   SigningKey,
//   hashMessage,
//   // Contract
// } = ethersAll;

// // Export types for Provider and Signer
// export type Provider = ethersAll.Provider;
// export type Signer = ethersAll.Signer;

// // Custom helper functions
// export function serializeSignedTx(tx: any): string {
//   if (!tx.signature) {
//     throw new Error('Missing signature in transaction');
//   }
//   return Transaction.from(tx).serialized;
// }