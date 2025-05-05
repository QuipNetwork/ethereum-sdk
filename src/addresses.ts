// Copyright (C) 2025 quip.network
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
import { NetworkType, QuipWallet__factory, SUPPORTED_NETWORKS } from './index';
import addresses from './addresses.json';
import { ethers } from 'hardhat/internal/lib/hardhat-lib';

export const DEPLOYER_ADDRESS = addresses.Deployer;
export const WOTS_PLUS_ADDRESS = addresses.WOTSPlus;
export const QUIP_FACTORY_ADDRESS = addresses.QuipFactory;



/**
 * getVaultAddress computes the deterministic address of a Quip Vault 
 * based on the owner and vault ID using the public factory and library addresses.
 * 
 * This uses CREATE2 to calculate the same address that would be 
 * deployed by the QuipFactory.
 * 
 * @param initialOwnerAddress - The Ethereum address of the initial vault owner
 * @param vaultId - The unique identifier for this vault as a Uint8Array
 * @returns The Ethereum address where the vault contract would be deployed
 */
export function getVaultAddress(initialOwnerAddress: string, vaultId: Uint8Array): string {
    const quipFactoryAddress = QUIP_FACTORY_ADDRESS;
    const wotsLibraryAddress = WOTS_PLUS_ADDRESS;
    return computeVaultAddress(initialOwnerAddress, vaultId, wotsLibraryAddress, quipFactoryAddress);      
  }
  
/**
 * computeVaultAddress allows calculating a vault address with custom contract addresses
 * @param initialOwnerAddress - The Ethereum address of the initial vault owner
 * @param vaultId - The unique identifier for this vault as a Uint8Array
 * @param wotsLibraryAddress - The address of the WOTSPlus library contract
 * @param quipFactoryAddress - The address of the QuipFactory contract
 * @returns The Ethereum address where the vault contract would be deployed
 */
export function computeVaultAddress(initialOwnerAddress: string,  vaultId: Uint8Array,
    wotsLibraryAddress: string, quipFactoryAddress: string): string {
        // Get bytecode with linked library
        const quipWalletCode = QuipWallet__factory.bytecode.replace(
            /__\$[a-fA-F0-9]{34}\$__/g, // Pattern for unlinked library placeholder
            wotsLibraryAddress.slice(2) // Remove '0x' prefix
          );
          
          const creationCode = ethers.solidityPacked(
            ["bytes", "bytes"],
            [
              quipWalletCode,
              ethers.AbiCoder.defaultAbiCoder().encode(
                ["address", "address"], 
                [
                  quipFactoryAddress,
                  initialOwnerAddress
                ]
              )
            ]
          );
          const hash = ethers.keccak256(
            ethers.solidityPacked(
                ["bytes1", "address", "bytes32", "bytes"],
                [
                    "0xff",
                    quipFactoryAddress,
                    vaultId,
                    ethers.keccak256(creationCode),
                ]
            )
          );
          return ethers.getAddress(`0x${hash.slice(-40)}`);
        }      
