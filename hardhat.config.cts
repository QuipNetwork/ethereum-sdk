import { HardhatUserConfig } from "hardhat/config";
import "@nomicfoundation/hardhat-toolbox";
import "@midl/hardhat-deploy";
import "hardhat-deploy";
import "dotenv/config";
import { Alchemy, Network } from "alchemy-sdk";
import { task } from "hardhat/config";
import { midlRegtest } from "@midl/executor";
import { fixedSecretKeyPairConnector } from "@midl/node";

task(
  "account",
  "returns nonce and balance for specified address on multiple networks"
)
  .addParam("address")
  .setAction(async (args) => {
    const networks = [
      {
        name: "Ethereum Sepolia:",
        url: API_URL_SEPOLIA,
        network: Network.ETH_SEPOLIA,
      },
      {
        name: "Base Sepolia:",
        url: API_URL_BASE_SEPOLIA,
        network: Network.BASE_SEPOLIA,
      },
      {
        name: "Optimism Sepolia:",
        url: API_URL_OP_SEPOLIA,
        network: Network.OPT_SEPOLIA,
      },
      {
        name: "Ethereum Mainnet:",
        url: API_URL_MAINNET,
        network: Network.ETH_MAINNET,
      },
      {
        name: "Base Mainnet:",
        url: API_URL_BASE,
        network: Network.BASE_MAINNET,
      },
      {
        name: "Optimism Mainnet:",
        url: API_URL_OPTIMISM,
        network: Network.OPT_MAINNET,
      },
    ];

    const resultArr = [["  |NETWORK|   |NONCE|   |BALANCE|  "]];

    for (const network of networks) {
      const settings = {
        apiKey: ALCHEMY_API_KEY,
        network: network.network,
      };

      const alchemy = new Alchemy(settings);

      try {
        const nonce = await alchemy.core.getTransactionCount(args.address);
        const balance = await alchemy.core.getBalance(args.address);
        const balanceInEth = parseFloat(balance.toString()) / 1e18;

        resultArr.push([
          network.name,
          nonce.toString(),
          balanceInEth.toFixed(2) + " ETH",
        ]);
      } catch (error) {
        resultArr.push([network.name, "Error", "Error"]);
      }
    }

    console.log(resultArr);
  });

const {
  API_URL_SEPOLIA,
  API_URL_BASE_SEPOLIA,
  API_URL_OP_SEPOLIA,
  API_URL_MAINNET,
  API_URL_BASE,
  API_URL_OPTIMISM,
  API_URL_BSC,
  API_URL_AVAX,
  API_URL_POLYGON,
  API_URL_MANTLE,
  API_URL_CELO,
  API_URL_ARBITRUM,
  API_URL_DEGEN,
  ALCHEMY_API_KEY,
  DEPLOYER_PRIVATE_KEY,
  PRIVATE_KEY,  
  ETHERSCAN_API_KEY,
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
        // Exclude metadata hash for deterministic bytecode across environments
        // This ensures CREATE2 addresses are consistent regardless of source paths
        bytecodeHash: "none",
      },
    },
  },
  midl: {
    path: "deployments/midl",
    networks: {
      // Multi-key connector for MIDL deployments
      // Index 0: Operations wallet (PRIVATE_KEY)
      // Index 1: Deployer wallet (DEPLOYER_PRIVATE_KEY)
      midl_regtest: {
        customConnector: (accountIndex: number) =>
          fixedSecretKeyPairConnector({
            privateKeys: [
              PRIVATE_KEY || "", // Index 0: Operations wallet
              DEPLOYER_PRIVATE_KEY || "", // Index 1: Deployer wallet
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
          // Test account 1 - uses PRIVATE_KEY or fallback for testing
          privateKey: `0x${
            PRIVATE_KEY ||
            "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
          }`,
          balance: "10000000000000000000", // 10 ETH in wei
        },
        {
          // Test account 2 - uses DEPLOYER_PRIVATE_KEY or fallback for testing
          privateKey: `0x${
            DEPLOYER_PRIVATE_KEY ||
            "59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"
          }`,
          balance: "10000000000000000000", // 10 ETH in wei
        },
      ],
    },
    sepolia: {
      url: API_URL_SEPOLIA,
      accounts: [`0x${PRIVATE_KEY}`],
    },
    sepolia_optimism: {
      url: API_URL_OP_SEPOLIA,
      accounts: [`0x${PRIVATE_KEY}`],
    },
    sepolia_base: {
      url: API_URL_BASE_SEPOLIA,
      accounts: [`0x${PRIVATE_KEY}`],
    },
    mainnet: {
      url: API_URL_MAINNET,
      accounts: [`0x${PRIVATE_KEY}`],
    },
    base: {
      url: API_URL_BASE,
      accounts: [`0x${PRIVATE_KEY}`],
    },
    optimism: {
      url: API_URL_OPTIMISM,
      accounts: [`0x${PRIVATE_KEY}`],
    },
    bsc: {
      url: API_URL_BSC,
      accounts: [`0x${PRIVATE_KEY}`],
    },
    avalanche: {
      url: API_URL_AVAX,
      accounts: [`0x${PRIVATE_KEY}`],
    },
    polygon: {
      url: API_URL_POLYGON,
      accounts: [`0x${PRIVATE_KEY}`],
    },
    mantle: {
      url: API_URL_MANTLE,
      accounts: [`0x${PRIVATE_KEY}`],
    },
    celo: {
      url: API_URL_CELO,
      accounts: [`0x${PRIVATE_KEY}`],
    },
    arbitrum: {
      url: API_URL_ARBITRUM,
      accounts: [`0x${PRIVATE_KEY}`],
    },
    degen: {
      url: API_URL_DEGEN,
      accounts: [`0x${PRIVATE_KEY}`],
    },
    midl_regtest: {
      url: midlRegtest.rpcUrls.default.http[0],
      chainId: midlRegtest.id,
      deploy: ["deploy/midl_regtest/"],
    },
  },
  paths: {
    deploy: ["deploy/evm/"],
  },
  etherscan: {
    apiKey: {
      // V2 API uses the same Etherscan API key for all supported chains
      mainnet: `${ETHERSCAN_API_KEY}`,
      sepolia: `${ETHERSCAN_API_KEY}`,
      base: `${ETHERSCAN_API_KEY}`,
      baseSepolia: `${ETHERSCAN_API_KEY}`,
      optimisticEthereum: `${ETHERSCAN_API_KEY}`,
      optimismSepolia: `${ETHERSCAN_API_KEY}`,
      bsc: `${ETHERSCAN_API_KEY}`,
      avalanche: `${ETHERSCAN_API_KEY}`,
      polygon: `${ETHERSCAN_API_KEY}`,
      arbitrumOne: `${ETHERSCAN_API_KEY}`,
      mantle: `${ETHERSCAN_API_KEY}`,
      celo: `${ETHERSCAN_API_KEY}`,
      // blockscout explorer does not need an API key
      degen: `none`,
    },
    customChains: [
      // ===== Etherscan V2 Supported Chains =====
      {
        network: "mainnet",
        chainId: 1,
        urls: {
          apiURL: "https://api.etherscan.io/v2/api?chainid=1",
          browserURL: "https://etherscan.io",
        },
      },
      {
        network: "sepolia",
        chainId: 11155111,
        urls: {
          apiURL: "https://api.etherscan.io/v2/api?chainid=11155111",
          browserURL: "https://sepolia.etherscan.io",
        },
      },
      {
        network: "base",
        chainId: 8453,
        urls: {
          apiURL: "https://api.etherscan.io/v2/api?chainid=8453",
          browserURL: "https://basescan.org",
        },
      },
      {
        network: "baseSepolia",
        chainId: 84532,
        urls: {
          apiURL: "https://api.etherscan.io/v2/api?chainid=84532",
          browserURL: "https://sepolia.basescan.org",
        },
      },
      {
        network: "optimisticEthereum",
        chainId: 10,
        urls: {
          apiURL: "https://api.etherscan.io/v2/api?chainid=10",
          browserURL: "https://optimistic.etherscan.io",
        },
      },
      {
        network: "optimismSepolia",
        chainId: 11155420,
        urls: {
          apiURL: "https://api.etherscan.io/v2/api?chainid=11155420",
          browserURL: "https://sepolia-optimism.etherscan.io",
        },
      },
      {
        network: "bsc",
        chainId: 56,
        urls: {
          apiURL: "https://api.etherscan.io/v2/api?chainid=56",
          browserURL: "https://bscscan.com",
        },
      },
      {
        network: "avalanche",
        chainId: 43114,
        urls: {
          apiURL: "https://api.etherscan.io/v2/api?chainid=43114",
          browserURL: "https://snowtrace.io",
        },
      },
      {
        network: "polygon",
        chainId: 137,
        urls: {
          apiURL: "https://api.etherscan.io/v2/api?chainid=137",
          browserURL: "https://polygonscan.com",
        },
      },
      {
        network: "arbitrumOne",
        chainId: 42161,
        urls: {
          apiURL: "https://api.etherscan.io/v2/api?chainid=42161",
          browserURL: "https://arbiscan.io",
        },
      },
      {
        network: "mantle",
        chainId: 5000,
        urls: {
          apiURL: "https://api.etherscan.io/v2/api?chainid=5000",
          browserURL: "https://mantlescan.xyz",
        },
      },
      {
        network: "celo",
        chainId: 42220,
        urls: {
          apiURL: "https://api.etherscan.io/v2/api?chainid=42220",
          browserURL: "https://celoscan.io",
        },
      },
      // ===== Non-Etherscan Chains (use their own explorers) =====
      {
        network: "degen",
        chainId: 666666666,
        urls: {
          apiURL: "https://explorer.degen.tips/api",
          browserURL: "https://explorer.degen.tips",
        },
      },
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
