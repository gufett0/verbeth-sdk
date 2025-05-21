import { HardhatUserConfig } from 'hardhat/config';
import '@nomicfoundation/hardhat-toolbox';
import "@nomicfoundation/hardhat-ignition";
import 'hardhat-gas-reporter';
import "@typechain/hardhat";
import "hardhat-dependency-compiler";
import * as dotenv from "dotenv";

dotenv.config();

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
  networks: {
    baseSepolia: {
      url: "https://base-sepolia-rpc.publicnode.com",
      accounts: [`${process.env.PRIVATE_KEY}`],
      timeout: 60000,
    },
    localhost: {
      url: "http://127.0.0.1:8545", 
      timeout: 60000,
    },

  },
  gasReporter: {
    enabled: true,
    currency: 'USD',
  },
  typechain: {
    outDir: 'typechain-types',
    target: 'ethers-v6',
  },
  ignition: {
    strategyConfig: {
      create2: {
        // "VERBETH" in hex
        salt: "0x5645524245544800000000000000000000000000000000000000000000000000", 
      },
    },
  },
  paths: {
    sources: "./contracts",
    tests: "./test",
    cache: "./cache",
    artifacts: "./artifacts"
  },
  dependencyCompiler: {
    paths: [
      "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol",
      "test/contracts/TestSmartAccount.sol",
    ]
  }
};

export default config;