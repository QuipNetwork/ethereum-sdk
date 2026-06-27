import { HardhatUserConfig } from "hardhat/config";
import "@nomicfoundation/hardhat-toolbox";
import "dotenv/config";
import { Alchemy, Network } from "alchemy-sdk";
import { task } from "hardhat/config";

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
  BASE_SEPOLIA_API_KEY,
  BASE_API_KEY,
  ETHERSCAN_API_KEY,
  ETHERSCAN_SEPOLIA_API_KEY,
  OP_ETHERSCAN_API_KEY,
  OP_ETHERSCAN_SEPOLIA_API_KEY,
  ETHERSCAN_API_KEY_AVAX,
  ETHERSCAN_API_KEY_BSC,
  ETHERSCAN_API_KEY_POLYGON,
  ETHERSCAN_API_KEY_MANTLE,
  ETHERSCAN_API_KEY_CELO,
  ETHERSCAN_API_KEY_ARBITRUM,
} = process.env;

const config: HardhatUserConfig = {
  solidity: "0.8.28",
  networks: {
    hardhat: {
      accounts: [
        {
          privateKey: `0x${PRIVATE_KEY}`,
          balance: "10000000000000000000", // 10 ETH in wei
        },
        {
          privateKey: `0x${
            DEPLOYER_PRIVATE_KEY ||
            "1234567890123456789012345678901234567890123456789012345678901234"
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
  },
  etherscan: {
    apiKey: {
      baseSepolia: `${BASE_SEPOLIA_API_KEY}`,
      base: `${BASE_API_KEY}`,
      optimisticEthereum: `${OP_ETHERSCAN_API_KEY}`,
      optimismSepolia: `${OP_ETHERSCAN_SEPOLIA_API_KEY}`,
      sepolia: `${ETHERSCAN_SEPOLIA_API_KEY}`,
      mainnet: `${ETHERSCAN_API_KEY}`,
      bsc: `${ETHERSCAN_API_KEY_BSC}`,
      avalanche: `${ETHERSCAN_API_KEY_AVAX}`,
      polygon: `${ETHERSCAN_API_KEY_POLYGON}`,
      mantle: `${ETHERSCAN_API_KEY_MANTLE}`,
      celo: `${ETHERSCAN_API_KEY_CELO}`,
      arbitrumOne: `${ETHERSCAN_API_KEY_ARBITRUM}`,
      degen: "none",
    },
    customChains: [
      {
        network: "mantle",
        chainId: 5000,
        urls: {
          apiURL: "https://explorer.mantle.xyz/api",
          browserURL: "https://explorer.mantle.xyz",
        },
      },
      {
        network: "celo",
        chainId: 42220,
        urls: {
          apiURL: "https://api.celoscan.io/api",
          browserURL: "https://celoscan.io/",
        },
      },
      {
        network: "degen",
        chainId: 666666666,
        urls: {
          apiURL: "https://explorer.degen.tips/api",
          browserURL: "https://explorer.degen.tips/",
        },
      },
    ],
  },
};

export default config;
