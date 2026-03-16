import { HardhatUserConfig } from "hardhat/config";
import "@midl/hardhat-deploy";
import "hardhat-deploy";
import "dotenv/config";
import { midlRegtest } from "@midl/executor";
import { fixedSecretKeyPairConnector } from "@midl/node";

const {
  DEPLOYER_PRIVATE_KEY,
  PRIVATE_KEY,
} = process.env;

const config: HardhatUserConfig = {
  solidity: {
    version: "0.8.28",
    settings: {
      evmVersion: "paris",
      optimizer: {
        enabled: false,
        runs: 200,
      },
      metadata: {
        bytecodeHash: "none",
      },
    },
  },
  midl: {
    path: "deployments/midl",
    networks: {
      midl_regtest: {
        customConnector: (accountIndex: number) =>
          fixedSecretKeyPairConnector({
            privateKeys: [
              PRIVATE_KEY || "",
              DEPLOYER_PRIVATE_KEY || "",
            ],
            accountIndex,
          }),
        network: "regtest",
        hardhatNetwork: "midl_regtest",
        confirmationsRequired: 1,
        btcConfirmationsRequired: 1,
      },
    },
  },
  networks: {
    hardhat: {
      accounts: [
        {
          privateKey: `0x${
            PRIVATE_KEY ||
            "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
          }`,
          balance: "10000000000000000000",
        },
        {
          privateKey: `0x${
            DEPLOYER_PRIVATE_KEY ||
            "59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"
          }`,
          balance: "10000000000000000000",
        },
      ],
    },
    midl_regtest: {
      url: midlRegtest.rpcUrls.default.http[0],
      chainId: midlRegtest.id,
      deploy: ["deploy/midl_regtest/"],
    },
  },
  paths: {
    deploy: ["deploy/midl_regtest/"],
  },
  etherscan: {
    apiKey: {
      midl_regtest: "not-required",
    },
    customChains: [
      {
        network: "midl_regtest",
        chainId: 777,
        urls: {
          apiURL: "https://blockscout.regtest.midl.xyz/api",
          browserURL: "https://blockscout.regtest.midl.xyz",
        },
      },
    ],
  },
};

export default config;
