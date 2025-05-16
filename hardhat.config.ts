import { HardhatUserConfig } from 'hardhat/config';
import '@nomicfoundation/hardhat-toolbox';
import "@nomicfoundation/hardhat-ignition";
import 'hardhat-gas-reporter';
import "@typechain/hardhat";
import "hardhat-dependency-compiler";

const config: HardhatUserConfig = {
  solidity: {
    compilers: [
      {
        version: "0.8.24", 
        settings: {
          optimizer: { enabled: true, runs: 200 },
        },
      },
    ],
  },
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
  },
  dependencyCompiler: {
    paths: [
      "test/contracts/TestSmartAccount.sol",
    ]
  }
};

export default config;