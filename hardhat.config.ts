import "@nomicfoundation/hardhat-ethers";
import "@nomicfoundation/hardhat-chai-matchers";

import "@solarity/hardhat-zkit";
import "@solarity/hardhat-gobind";
import "@solarity/hardhat-migrate";

import "hardhat-contract-sizer";
import "hardhat-gas-reporter";
import "hardhat-abi-exporter";

import "solidity-coverage";

import "@typechain/hardhat";

import "tsconfig-paths/register";

import { HardhatUserConfig } from "hardhat/config";

import * as dotenv from "dotenv";
dotenv.config();

function privateKey() {
  return process.env.PRIVATE_KEY !== undefined ? [process.env.PRIVATE_KEY] : [];
}

const config: HardhatUserConfig = {
  networks: {
    hardhat: {
      initialDate: "1970-01-01T00:00:00Z",
    },
    localhost: {
      url: "http://127.0.0.1:8545",
      gasMultiplier: 1.2,
    },
    sepolia: {
      url: `https://sepolia.infura.io/v3/${process.env.INFURA_KEY}`,
      accounts: privateKey(),
      gasMultiplier: 1.2,
    },
    qTestnet: {
      url: "https://rpc.qtestnet.org/",
      accounts: privateKey(),
    },
  },
  solidity: {
    version: "0.8.20",
    settings: {
      optimizer: {
        enabled: true,
        runs: 200,
      },
      evmVersion: "paris",
    },
  },
  zkit: {
    circuitsDir: "circuits",
    compilationSettings: {
      artifactsDir: "zkit/artifacts",
      onlyFiles: [],
      skipFiles: [],
      c: false,
      json: false,
      sym: false,
    },
    setupSettings: {
      contributionSettings: {
        contributionTemplate: "groth16",
        contributions: 0,
      },
      onlyFiles: [],
      skipFiles: [],
      ptauDir: "zkit/ptau",
      ptauDownload: true,
    },
    typesSettings: {
      typesArtifactsDir: "zkit/abi",
      typesDir: "generated-types/zkit",
    },
    verifiersDir: "contracts/verifiers",
    nativeCompiler: true,
    quiet: false,
  },
  etherscan: {
    apiKey: {
      sepolia: `${process.env.ETHERSCAN_KEY}`,
      qTestnet: `abc`,
    },
    customChains: [
      {
        network: "qTestnet",
        chainId: 35443,
        urls: {
          apiURL: "https://explorer.qtestnet.org/api",
          browserURL: "https://explorer.qtestnet.org",
        },
      },
    ],
  },
  migrate: {
    pathToMigrations: "./deploy/",
  },
  mocha: {
    timeout: 1000000,
  },
  gobind: {
    deployable: true,
  },
  contractSizer: {
    alphaSort: false,
    disambiguatePaths: false,
    runOnCompile: true,
    strict: false,
  },
  gasReporter: {
    currency: "USD",
    gasPrice: 50,
    enabled: false,
    coinmarketcap: `${process.env.COINMARKETCAP_KEY}`,
  },
  typechain: {
    outDir: "generated-types/ethers",
    target: "ethers-v6",
    alwaysGenerateOverloads: true,
    discriminateTypes: true,
  },
};

// /Users/kirilrs/Desktop/Experiments/eLele/eLele-chat/zkit/artifacts/circuits/VerifiableCommitment.circom/VerifiableCommitment.zkey
// /Users/kirilrs/Desktop/Experiments/eLele/eLele-chat/zkit/artifacts/VerifiableCommitment/VerifiableCommitment.zkey:
export default config;
