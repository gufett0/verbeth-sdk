import { ethers as hardhatEthers } from 'hardhat';
import type { Signer } from 'ethers';
import type { ContractFactory } from 'ethers';

type FixedHardhatEthers = typeof hardhatEthers & {
  getSigners: () => Promise<Signer[]>;
  getContractFactory: (
    name: string,
    signerOrOptions?: Signer | undefined
  ) => Promise<ContractFactory>;
};

export const ethers = hardhatEthers as FixedHardhatEthers;
