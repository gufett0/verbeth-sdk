import { HardhatUserConfig } from 'hardhat/config';
import '@nomicfoundation/hardhat-toolbox';
import "@nomicfoundation/hardhat-ignition";
import 'hardhat-gas-reporter';
import "@typechain/hardhat";


const config: HardhatUserConfig = {
  solidity: '0.8.24',
  gasReporter: {
    enabled: true,
    currency: 'USD',
  },
  typechain: {
    outDir: 'typechain-types',
    target: 'ethers-v6',
  },
  paths: {
    sources: "./contracts",
    tests: "./test",
    cache: "./cache",
    artifacts: "./artifacts"
  }
};

export default config;
