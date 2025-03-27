export * from '../typechain-types';
export * from './addresses';
export * from './constants';

export const SUPPORTED_NETWORKS = {
  SEPOLIA: 'sepolia',
  SEPOLIA_OPTIMISM: 'sepolia_optimism',
  SEPOLIA_BASE: 'sepolia_base',
  MAINNET: 'mainnet',
  BASE: 'base',
  OPTIMISM: 'optimism'
} as const;

export type NetworkType = typeof SUPPORTED_NETWORKS[keyof typeof SUPPORTED_NETWORKS];

export interface QuipConfig {
  network: NetworkType;
  rpcUrl?: string;
  privateKey?: string;
  alchemyKey?: string;
}

export class QuipClient {
  constructor(config: QuipConfig) {
    // Initialize client with network-specific settings
  }

  // Add your contract interaction methods here
}