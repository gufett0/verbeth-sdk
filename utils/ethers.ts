import { ethers as hardhatEthers } from 'hardhat';
import type { Signer, providers } from 'ethers';
import type { ContractFactory } from 'ethers';

type FixedHardhatEthers = typeof hardhatEthers & {
  provider: providers.JsonRpcProvider;
  getSigners: () => Promise<Signer[]>;
  getContractFactory: (
    name: string,
    signerOrOptions?: Signer | undefined
  ) => Promise<ContractFactory>;
  
};

export const ethers = hardhatEthers as FixedHardhatEthers;
