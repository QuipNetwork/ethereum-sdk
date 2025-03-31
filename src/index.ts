import { ethers } from 'ethers';
import { QuipWallet__factory, QuipFactory__factory, QuipFactory, QuipWallet } from '../typechain-types';
import { QUIP_FACTORY_ADDRESS, WOTS_PLUS_ADDRESS } from './addresses';

import { WOTSPlus } from '@quip.network/hashsigs';
import { keccak_256 } from '@noble/hashes/sha3';
import { randomBytes } from '@noble/ciphers/webcrypto';


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

export interface WinternitzKeyPair {
  privateKey: Uint8Array;
  publicKey: WinternitzPublicKey;
}

export interface WinternitzPublicKey {
  publicSeed: Uint8Array;
  publicKeyHash: Uint8Array;
}

export class QuipSigner {
  // FIXME: in an ideal world these are kept in a secure wallet somewhere and this is
  // merely an interface. For now we are keeping them in memory.
  private quantumSecret: Uint8Array; 
  private wots: WOTSPlus;

  constructor(quantumSecret: Uint8Array) {
    this.wots = new WOTSPlus(keccak_256);
    this.quantumSecret = keccak_256(quantumSecret);
  }

  // generateKeyPair in the domain of a specific vault using the base quantum
  // secret.
  public generateKeyPair(vaultId: Uint8Array): WinternitzKeyPair {
    const publicSeed = randomBytes(32);
    return this.recoverKeyPair(vaultId, publicSeed);
  }

  // recoverKeyPair given a pre-existing public seed, and vault id
  public recoverKeyPair(vaultId: Uint8Array, publicSeed: Uint8Array): WinternitzKeyPair {
    const privateSeed = Uint8Array.from([...this.quantumSecret, ...vaultId]);
    const keypair = this.wots.generateKeyPair(privateSeed, publicSeed);
    const returnedSeed = keypair.publicKey.slice(0, 32);
    if (!Buffer.from(publicSeed).equals(Buffer.from(returnedSeed))) {
      throw new Error('Invalid public seed returned: ' + returnedSeed);
    }
    return {
      privateKey: keypair.privateKey,
      publicKey: {
        publicSeed: keypair.publicKey.slice(0, 32),
        publicKeyHash: keypair.publicKey.slice(32, 64),
      } 
    }
  }

  public sign(message: Uint8Array, vaultId: Uint8Array, publicSeed: Uint8Array): Uint8Array[] {
    const key = this.recoverKeyPair(vaultId, publicSeed);
    return this.wots.sign(key.privateKey, key.publicKey.publicSeed, message);
  }
}

export class QuipWalletClient {
  private wallet: QuipWallet;
  private quipSigner: QuipSigner;
  private vaultId: Uint8Array;

  constructor(quipSigner: QuipSigner, vaultId: Uint8Array, wallet: QuipWallet) {
    this.wallet = wallet;
    this.vaultId = vaultId;
    this.quipSigner = quipSigner;
  }

  async getPqOwner() {
    return await this.wallet.pqOwner();
  }

  async transferWithWinternitz(to: ethers.AddressLike, value: bigint) {
    const nextPqOwner = this.quipSigner.generateKeyPair(this.vaultId);
    const currentPqOwner = await this.wallet.pqOwner();
    const publicSeed = ethers.getBytes(currentPqOwner.publicSeed);

    // TODO: Make a function that does this?
    const packedMessageData = ethers.solidityPacked(
      ["bytes32", "bytes32", "bytes32", "bytes32", "address", "uint256"],
      [
        currentPqOwner.publicSeed,
        currentPqOwner.publicKeyHash,
        nextPqOwner.publicKey.publicSeed,
        nextPqOwner.publicKey.publicKeyHash,
        to,
        value
      ]
    )

    // FIXME: these are stupid in hindsight.
    const message = {
      messageHash: keccak_256(ethers.getBytes(packedMessageData))
    };
    const pqSig = {
      elements: this.quipSigner.sign(message.messageHash, this.vaultId, publicSeed)
    }
    const tx = await this.wallet.transferWithWinternitz(nextPqOwner.publicKey, pqSig, to, value);
    return await tx.wait();
  }

  async executeWithWinternitz(target: ethers.AddressLike, opdata: Uint8Array) {
    const nextPqOwner = this.quipSigner.generateKeyPair(this.vaultId);
    const currentPqOwner = await this.wallet.pqOwner();
    const publicSeed = ethers.getBytes(currentPqOwner.publicSeed);

    // Create and sign execute message
    const packedMessageData = ethers.solidityPacked(
      ["bytes32", "bytes32", "bytes32", "bytes32", "address", "bytes"],
      [
        currentPqOwner.publicSeed,
        currentPqOwner.publicKeyHash,
        nextPqOwner.publicKey.publicSeed,
        nextPqOwner.publicKey.publicKeyHash,
        target,
        opdata
      ]
    )

    const message = {
      messageHash: keccak_256(ethers.getBytes(packedMessageData))
    };
    const pqSig = {
      elements: this.quipSigner.sign(message.messageHash, this.vaultId, publicSeed)
    }
    const tx = await this.wallet.executeWithWinternitz(nextPqOwner.publicKey, pqSig, target, opdata);
    return await tx.wait();
  }
}

export class QuipClient {
  private provider: ethers.Provider;
  private signer?: ethers.Signer;
  private factory?: QuipFactory;
  private initializationPromise: Promise<void>;

  constructor(signer: ethers.Eip1193Provider) {
    this.provider = new ethers.BrowserProvider(signer);
    this.initializationPromise = this.initialize();
  }

  private async initialize() {
    await this.setSigner();
    await this.setQuipFactory();
  }

  private async setSigner() {
    if (this.provider instanceof ethers.BrowserProvider) {
      this.signer = await this.provider.getSigner();
    }
  }

  private async setQuipFactory() {
    this.factory = QuipFactory__factory.connect(QUIP_FACTORY_ADDRESS, this.signer!);
  }

  async createWallet(vaultId: Uint8Array, quipSigner: QuipSigner): Promise<QuipWalletClient> {
    await this.initializationPromise;
    
    // Bind vaultId to signer
    const userWalletAddress = await this.signer!.getAddress();
    
    // Check if wallet already exists
    const existingWalletAddress = await this.factory!.quips(userWalletAddress, vaultId);
    if (existingWalletAddress !== ethers.ZeroAddress) {
      throw new Error(`Wallet already exists for vault ID ${vaultId}`);
    }

    const pqKeyPair = quipSigner.generateKeyPair(vaultId);
    const tx = await this.factory!.depositToWinternitz(
      vaultId,
      userWalletAddress,
      pqKeyPair.publicKey
    );
    const receipt = await tx.wait();
    const event = receipt!.logs[0];  // QuipCreated is the first and only event
    const newWalletAddress = ethers.getAddress(`0x${event.data.slice(-40)}`);
    const newWalletContract = await QuipWallet__factory.connect(newWalletAddress, this.signer!)
    return new QuipWalletClient(quipSigner, vaultId, newWalletContract);
  }

  async getVault(vaultId: Uint8Array, quipSigner: QuipSigner): Promise<QuipWalletClient> {
    await this.initializationPromise;
    const walletAddress = await this.factory!.quips(await this.signer!.getAddress(), vaultId);
    if (walletAddress === ethers.ZeroAddress) {
      throw new Error(`No wallet found for vault ID ${vaultId}`);
    }
    const walletContract = await QuipWallet__factory.connect(walletAddress, this.signer!);
    const client = new QuipWalletClient(quipSigner, vaultId, walletContract);
    // Check if we have the right signer
    const curPqOwner = await client.getPqOwner();
    console.log("curPublicSeed: ", curPqOwner.publicSeed);
    const curSeed = Buffer.from(curPqOwner.publicSeed.replace('0x', ''), 'hex');
    const keypair = quipSigner.recoverKeyPair(vaultId, curSeed);
    if (!Buffer.from(keypair.publicKey.publicKeyHash).equals(Buffer.from(curPqOwner.publicKeyHash))) {
      throw new Error('Invalid signer for this wallet');
    }
    return client
  }

  async getVaults(): Promise<Map<string, string>> {
    await this.initializationPromise;
    if (!this.signer) {
      throw new Error('No signer available. Connect a wallet first.');
    }

    const signerAddress = await this.signer.getAddress();
    const vaultMap = new Map<string, string>();
    
    // Start from index 0 and keep trying until we hit an error
    let index = 0;
    while (true) {
      try {
        const vaultId = await this.factory!.vaultIds(signerAddress, index);
        const walletAddress = await this.factory!.quips(signerAddress, vaultId);
        if (walletAddress === ethers.ZeroAddress) {
          throw new Error(`Invalid contract state for vault ID ${vaultId}`);
        }
        vaultMap.set(ethers.hexlify(vaultId), walletAddress);
        index++;
      } catch (error) {
        // We've reached the end of the array
        break;
      }
    }
    
    return vaultMap;
  }
}


