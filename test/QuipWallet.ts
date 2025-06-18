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
import { randomBytes } from "@noble/ciphers/webcrypto";
import { keccak_256 } from "@noble/hashes/sha3";
import { anyValue } from "@nomicfoundation/hardhat-chai-matchers/withArgs";
import { loadFixture } from "@nomicfoundation/hardhat-network-helpers";
import { WOTSPlus } from "@quip.network/hashsigs";
import { expect } from "chai";
import hre from "hardhat";

// Test contract for executeWithWinternitz
// Removed DUMMY_CONTRACT string constant

describe("QuipWallet", function () {
  async function deployQuipFactory() {
    //const ONE_GWEI = 1_000_000_000;

    // Deploy the Deployer contract first
    const DeployerLib = await hre.ethers.getContractFactory("Deployer");
    const deployer = await DeployerLib.deploy();
    await deployer.waitForDeployment();
    console.log(`Deployer deployed to: ${await deployer.getAddress()}`);

    // Deploy the WOTSPlus library - using the full package path
    const WOTSPlusLib = await hre.ethers.getContractFactory(
      "@quip.network/hashsigs-solidity/contracts/WOTSPlus.sol:WOTSPlus"
    );
    const wotsPlusBytecode = WOTSPlusLib.bytecode;

    // Deploy WOTSPlus through the Deployer contract
    const wotsPlusSalt = hre.ethers.keccak256(
      hre.ethers.toUtf8Bytes("WOTSPlus")
    );
    const wotsPlusDeployTx = await deployer.deploy(
      wotsPlusBytecode,
      wotsPlusSalt
    );
    const wotsPlusDeployReceipt = await wotsPlusDeployTx.wait();

    // Get the deployed WOTSPlus address from the Deploy event
    const wotsPlusAddress = wotsPlusDeployReceipt!.logs[0].args[0];
    console.log(`WOTSPlus deployed to: ${wotsPlusAddress}`);

    // Get the bytecode for QuipFactory (with linked WOTSPlus library)
    const QuipFactory = await hre.ethers.getContractFactory("QuipFactory", {
      libraries: {
        "@quip.network/hashsigs-solidity/contracts/WOTSPlus.sol:WOTSPlus":
          wotsPlusAddress,
      },
    });

    // Encode constructor parameters
    const [signer] = await hre.ethers.getSigners();
    const initialOwner = await signer.getAddress();
    console.log(`Deploying with owner: ${initialOwner}`);

    const constructorArgs = hre.ethers.AbiCoder.defaultAbiCoder().encode(
      ["address", "address"],
      [initialOwner, wotsPlusAddress]
    );

    // Combine bytecode with constructor arguments
    const quipFactoryBytecode = QuipFactory.bytecode + constructorArgs.slice(2); // Remove '0x' prefix

    // Deploy QuipFactory through the Deployer contract
    const quipFactorySalt = hre.ethers.keccak256(
      hre.ethers.toUtf8Bytes("QuipFactory")
    );
    const quipFactoryDeployTx = await deployer.deploy(
      quipFactoryBytecode,
      quipFactorySalt
    );
    const quipFactoryDeployReceipt = await quipFactoryDeployTx.wait();

    // Get the deployed QuipFactory address from the Deploy event
    const quipFactoryAddress = quipFactoryDeployReceipt!.logs[0].args[0];
    console.log(`QuipFactory deployed: ${quipFactoryAddress}`);

    // Get contract instances
    const wotsPlus = await hre.ethers.getContractAt(
      "@quip.network/hashsigs-solidity/contracts/WOTSPlus.sol:WOTSPlus",
      wotsPlusAddress
    );

    const quipFactory = await hre.ethers.getContractAt(
      "QuipFactory",
      quipFactoryAddress
    );

    // Note: QuipFactory is already initialized via constructor when deployed through Deployer
    // The constructor parameters (initialOwner, wotsLibrary) are encoded in the bytecode
    expect(await quipFactory.owner()).to.equal(initialOwner);
    expect(await quipFactory.wotsLibrary()).to.equal(wotsPlusAddress);

    const [owner, otherAccount] = await hre.ethers.getSigners();

    return { quipFactory, wotsPlus, owner, otherAccount };
  }

  async function deployQuipWallet(
    quipFactory: any,
    owner: any,
    secret: string,
    vaultId: string,
    initialDeposit: bigint = BigInt(0)
  ) {
    let wots: WOTSPlus = new WOTSPlus(keccak_256);
    let publicSeed = randomBytes(32);
    const keypair = wots.generateKeyPair(keccak_256(secret), publicSeed);
    const quipAddress = {
      publicSeed: keypair.publicKey.slice(0, 32),
      publicKeyHash: keypair.publicKey.slice(32, 64),
    };

    const vaultIdBytes = keccak_256(vaultId);
    const ownerQuipFactory = quipFactory.connect(owner);
    const createTx = await ownerQuipFactory.depositToWinternitz(
      vaultIdBytes,
      owner.address,
      quipAddress,
      { value: initialDeposit }
    );
    const createReceipt = await createTx.wait();

    const quipWalletAddress = hre.ethers.getAddress(
      `0x${createReceipt!.logs[0].data.slice(-40)}`
    );
    const quipWallet = await hre.ethers.getContractAt(
      "QuipWallet",
      quipWalletAddress
    );

    return { quipWallet, keypair };
  }

  describe("Winternitz", function () {
    it("Should transfer funds using Winternitz signature", async function () {
      // Deploy factory and wallet
      const { quipFactory, owner, otherAccount } = await loadFixture(
        deployQuipFactory
      );
      const initialDeposit = hre.ethers.parseEther("1.0");
      const { quipWallet, keypair } = await deployQuipWallet(
        quipFactory,
        owner,
        "Hello World!",
        "Vault ID 1",
        initialDeposit
      );

      // Create new keypair for next owner
      let wots: WOTSPlus = new WOTSPlus(keccak_256);
      const publicSeed = randomBytes(32);
      const nextKeypair = wots.generateKeyPair(
        keccak_256("Next Owner"),
        publicSeed
      );
      const nextQuipAddress = {
        publicSeed: nextKeypair.publicKey.slice(0, 32),
        publicKeyHash: nextKeypair.publicKey.slice(32, 64),
      };

      const transferAmount = hre.ethers.parseEther("0.5");
      const currentQuipAddress = {
        publicSeed: keypair.publicKey.slice(0, 32),
        publicKeyHash: keypair.publicKey.slice(32, 64),
      };

      // Create and sign transfer message
      const packedMessageData = hre.ethers.solidityPacked(
        ["bytes32", "bytes32", "bytes32", "bytes32", "address", "uint256"],
        [
          currentQuipAddress.publicSeed,
          currentQuipAddress.publicKeyHash,
          nextQuipAddress.publicSeed,
          nextQuipAddress.publicKeyHash,
          otherAccount.address,
          transferAmount,
        ]
      );

      const message = {
        messageHash: keccak_256(hre.ethers.getBytes(packedMessageData)),
      };

      const signature = {
        elements: wots.sign(
          keypair.privateKey,
          keypair.publicKey.slice(0, 32),
          message.messageHash
        ),
      };

      // Execute transfer
      const transferTx = await quipWallet.transferWithWinternitz(
        nextQuipAddress,
        signature,
        otherAccount.address,
        transferAmount
      );
      const transferReceipt = await transferTx.wait();
      const transferGasFee =
        transferReceipt!.gasUsed * transferReceipt!.gasPrice;
      console.log(`\nTransfer gas used: ${transferReceipt!.gasUsed} units`);
      console.log(`Transfer gas price: ${transferReceipt!.gasPrice} wei`);
      console.log(
        `Transfer total gas fee: ${hre.ethers.formatEther(transferGasFee)} ETH`
      );

      // Verify transfer
      expect(await hre.ethers.provider.getBalance(quipWallet.target)).to.equal(
        initialDeposit - transferAmount
      );
      expect(await quipWallet.pqOwner()).to.deep.equal([
        hre.ethers.hexlify(nextQuipAddress.publicSeed),
        hre.ethers.hexlify(nextQuipAddress.publicKeyHash),
      ]);

      // Verify event
      await expect(transferTx)
        .to.emit(quipWallet, "pqTransfer")
        .withArgs(
          transferAmount,
          anyValue,
          [currentQuipAddress.publicSeed, currentQuipAddress.publicKeyHash],
          [nextQuipAddress.publicSeed, nextQuipAddress.publicKeyHash],
          otherAccount.address
        );
    });

    it("Should transfer between two QuipWallets and withdraw", async function () {
      // Deploy factory and first wallet for owner
      const { quipFactory, owner, otherAccount } = await loadFixture(
        deployQuipFactory
      );
      const initialDeposit = hre.ethers.parseEther("1.0");
      const { quipWallet: ownerQuipWallet, keypair: ownerKeypair } =
        await deployQuipWallet(
          quipFactory,
          owner,
          "Owner Secret",
          "Owner Vault",
          initialDeposit
        );

      // Deploy second wallet for otherAccount
      const { quipWallet: otherQuipWallet, keypair: otherKeypair } =
        await deployQuipWallet(
          quipFactory,
          otherAccount,
          "Other Secret",
          "Other Vault"
        );

      // Setup transfer from owner's wallet to other's wallet
      const transferAmount = hre.ethers.parseEther("0.5");

      // Create new keypair for owner's next state
      let wots: WOTSPlus = new WOTSPlus(keccak_256);
      const publicSeed = randomBytes(32);
      const ownerNextKeypair = wots.generateKeyPair(
        keccak_256("Owner Next State"),
        publicSeed
      );
      const ownerNextQuipAddress = {
        publicSeed: ownerNextKeypair.publicKey.slice(0, 32),
        publicKeyHash: ownerNextKeypair.publicKey.slice(32, 64),
      };

      const ownerCurrentQuipAddress = {
        publicSeed: ownerKeypair.publicKey.slice(0, 32),
        publicKeyHash: ownerKeypair.publicKey.slice(32, 64),
      };

      // Get initial balance of otherAccount
      const initialBalance = await hre.ethers.provider.getBalance(
        otherAccount.address
      );

      // Create and sign transfer message from owner's wallet to other's wallet
      const packedTransferData = hre.ethers.solidityPacked(
        ["bytes32", "bytes32", "bytes32", "bytes32", "address", "uint256"],
        [
          ownerCurrentQuipAddress.publicSeed,
          ownerCurrentQuipAddress.publicKeyHash,
          ownerNextQuipAddress.publicSeed,
          ownerNextQuipAddress.publicKeyHash,
          otherQuipWallet.target,
          transferAmount,
        ]
      );

      const transferMessage = {
        messageHash: keccak_256(hre.ethers.getBytes(packedTransferData)),
      };

      const transferSignature = {
        elements: wots.sign(
          ownerKeypair.privateKey,
          ownerKeypair.publicKey.slice(0, 32),
          transferMessage.messageHash
        ),
      };

      // Execute transfer from owner's wallet to other's wallet
      const targetAddress = await otherQuipWallet.getAddress();
      await ownerQuipWallet.transferWithWinternitz(
        ownerNextQuipAddress,
        transferSignature,
        targetAddress,
        transferAmount
      );

      // Verify the transfer was successful
      expect(
        await hre.ethers.provider.getBalance(otherQuipWallet.target)
      ).to.equal(transferAmount);

      // Now otherAccount withdraws from their wallet to their personal address
      const publicSeed2 = randomBytes(32);
      const otherNextKeypair = wots.generateKeyPair(
        keccak_256("Other Next State"),
        publicSeed2
      );
      const otherNextQuipAddress = {
        publicSeed: otherNextKeypair.publicKey.slice(0, 32),
        publicKeyHash: otherNextKeypair.publicKey.slice(32, 64),
      };

      const otherCurrentQuipAddress = {
        publicSeed: otherKeypair.publicKey.slice(0, 32),
        publicKeyHash: otherKeypair.publicKey.slice(32, 64),
      };

      // Create and sign withdrawal message
      const packedWithdrawalData = hre.ethers.solidityPacked(
        ["bytes32", "bytes32", "bytes32", "bytes32", "address", "uint256"],
        [
          otherCurrentQuipAddress.publicSeed,
          otherCurrentQuipAddress.publicKeyHash,
          otherNextQuipAddress.publicSeed,
          otherNextQuipAddress.publicKeyHash,
          otherAccount.address,
          transferAmount,
        ]
      );

      const withdrawalMessage = {
        messageHash: keccak_256(hre.ethers.getBytes(packedWithdrawalData)),
      };

      const withdrawalSignature = {
        elements: wots.sign(
          otherKeypair.privateKey,
          otherKeypair.publicKey.slice(0, 32),
          withdrawalMessage.messageHash
        ),
      };

      // Execute withdrawal
      const otherQuipWalletConnected = otherQuipWallet.connect(
        otherAccount
      ) as typeof otherQuipWallet;
      const withdrawalTx =
        await otherQuipWalletConnected.transferWithWinternitz(
          otherNextQuipAddress,
          withdrawalSignature,
          otherAccount.address,
          transferAmount
        );
      const withdrawalReceipt = await withdrawalTx.wait();

      // Calculate gas costs for withdrawal
      const withdrawalGasCost =
        withdrawalReceipt!.gasUsed * withdrawalReceipt!.gasPrice;

      // Verify final balances
      expect(
        await hre.ethers.provider.getBalance(otherQuipWallet.target)
      ).to.equal(0);
      expect(
        await hre.ethers.provider.getBalance(otherAccount.address)
      ).to.equal(initialBalance + transferAmount - BigInt(withdrawalGasCost));
    });

    it("Should properly handle transfer fees with Winternitz", async function () {
      // Deploy factory and wallet
      const { quipFactory, owner, otherAccount } = await loadFixture(
        deployQuipFactory
      );

      // Set transfer fee
      const transferFee = hre.ethers.parseEther("0.005"); // 0.005 ETH
      await quipFactory.setTransferFee(transferFee);

      // Deploy wallet with initial balance
      const initialDeposit = hre.ethers.parseEther("1.0");
      const { quipWallet, keypair } = await deployQuipWallet(
        quipFactory,
        owner,
        "Fee Test Secret",
        "Fee Test Vault",
        initialDeposit
      );

      // Create new keypair for next owner
      let wots: WOTSPlus = new WOTSPlus(keccak_256);
      const publicSeed = randomBytes(32);
      const nextKeypair = wots.generateKeyPair(
        keccak_256("Next Owner"),
        publicSeed
      );
      const nextQuipAddress = {
        publicSeed: nextKeypair.publicKey.slice(0, 32),
        publicKeyHash: nextKeypair.publicKey.slice(32, 64),
      };

      const transferAmount = hre.ethers.parseEther("0.5");
      const currentQuipAddress = {
        publicSeed: keypair.publicKey.slice(0, 32),
        publicKeyHash: keypair.publicKey.slice(32, 64),
      };

      // Get initial balances
      const factoryInitialBalance = await hre.ethers.provider.getBalance(
        await quipFactory.getAddress()
      );
      const recipientInitialBalance = await hre.ethers.provider.getBalance(
        otherAccount.address
      );

      // Create and sign transfer message
      const packedMessageData = hre.ethers.solidityPacked(
        ["bytes32", "bytes32", "bytes32", "bytes32", "address", "uint256"],
        [
          currentQuipAddress.publicSeed,
          currentQuipAddress.publicKeyHash,
          nextQuipAddress.publicSeed,
          nextQuipAddress.publicKeyHash,
          otherAccount.address,
          transferAmount,
        ]
      );

      const message = {
        messageHash: keccak_256(hre.ethers.getBytes(packedMessageData)),
      };

      const signature = {
        elements: wots.sign(
          keypair.privateKey,
          keypair.publicKey.slice(0, 32),
          message.messageHash
        ),
      };

      // Execute transfer with fee
      const transferTx = await quipWallet.transferWithWinternitz(
        nextQuipAddress,
        signature,
        otherAccount.address,
        transferAmount,
        { value: transferFee }
      );
      await transferTx.wait();

      // Verify balances after transfer
      expect(await hre.ethers.provider.getBalance(quipWallet.target)).to.equal(
        initialDeposit - transferAmount
      );
      expect(
        await hre.ethers.provider.getBalance(otherAccount.address)
      ).to.equal(recipientInitialBalance + transferAmount);
      expect(
        await hre.ethers.provider.getBalance(await quipFactory.getAddress())
      ).to.equal(factoryInitialBalance + transferFee);

      // Try transfer without fee
      await expect(
        quipWallet.transferWithWinternitz(
          nextQuipAddress,
          signature,
          otherAccount.address,
          transferAmount
        )
      ).to.be.revertedWith("Insufficient fee");

      // Try transfer with insufficient fee
      await expect(
        quipWallet.transferWithWinternitz(
          nextQuipAddress,
          signature,
          otherAccount.address,
          transferAmount,
          { value: transferFee - BigInt(1) }
        )
      ).to.be.revertedWith("Insufficient fee");

      // Verify admin can withdraw accumulated fees
      const adminInitialBalance = await hre.ethers.provider.getBalance(
        owner.address
      );
      const withdrawTx = await quipFactory.withdraw(transferFee);
      const withdrawReceipt = await withdrawTx.wait();
      const withdrawGasCost =
        withdrawReceipt!.gasUsed * withdrawReceipt!.gasPrice;

      expect(
        await hre.ethers.provider.getBalance(await quipFactory.getAddress())
      ).to.equal(factoryInitialBalance);
      expect(await hre.ethers.provider.getBalance(owner.address)).to.equal(
        adminInitialBalance + transferFee - withdrawGasCost
      );
    });

    it("Should execute contract calls using Winternitz signature", async function () {
      // Deploy factory and wallet
      const { quipFactory, owner, otherAccount } = await loadFixture(
        deployQuipFactory
      );
      const initialDeposit = hre.ethers.parseEther("1.0");
      const { quipWallet, keypair } = await deployQuipWallet(
        quipFactory,
        owner,
        "Hello World!",
        "Vault ID 1",
        initialDeposit
      );

      // Deploy the dummy contract
      const DummyContract = await hre.ethers.getContractFactory(
        "DummyContract"
      );
      const dummyContract = await DummyContract.deploy();
      await dummyContract.waitForDeployment();

      // Create new keypair for next state
      let wots: WOTSPlus = new WOTSPlus(keccak_256);
      const publicSeed = randomBytes(32);
      const nextKeypair = wots.generateKeyPair(
        keccak_256("Next State"),
        publicSeed
      );
      const nextQuipAddress = {
        publicSeed: nextKeypair.publicKey.slice(0, 32),
        publicKeyHash: nextKeypair.publicKey.slice(32, 64),
      };

      const currentQuipAddress = {
        publicSeed: keypair.publicKey.slice(0, 32),
        publicKeyHash: keypair.publicKey.slice(32, 64),
      };

      // Set execute fee
      const executeFee = hre.ethers.parseEther("0.001");
      await quipFactory.setExecuteFee(executeFee);

      // Prepare the call data for setValue(42)
      const value = 42;
      const requiredEth = hre.ethers.parseEther("0.01"); // Required by dummy contract
      const callData = dummyContract.interface.encodeFunctionData("setValue", [
        value,
      ]);

      // Create and sign execution message
      const packedMessageData = hre.ethers.solidityPacked(
        ["bytes32", "bytes32", "bytes32", "bytes32", "address", "bytes"],
        [
          currentQuipAddress.publicSeed,
          currentQuipAddress.publicKeyHash,
          nextQuipAddress.publicSeed,
          nextQuipAddress.publicKeyHash,
          await dummyContract.getAddress(),
          callData,
        ]
      );

      const message = {
        messageHash: keccak_256(hre.ethers.getBytes(packedMessageData)),
      };

      const signature = {
        elements: wots.sign(
          keypair.privateKey,
          keypair.publicKey.slice(0, 32),
          message.messageHash
        ),
      };

      // Execute the call
      const executeTx = await quipWallet.executeWithWinternitz(
        nextQuipAddress,
        signature,
        await dummyContract.getAddress(),
        callData,
        { value: executeFee + requiredEth }
      );
      await executeTx.wait();

      // Verify the call was successful
      expect(await (dummyContract as any).value()).to.equal(value);

      // Now test a failing call
      const failingCallData =
        dummyContract.interface.encodeFunctionData("failingFunction");

      // Create and sign failing execution message
      const failingMessageData = hre.ethers.solidityPacked(
        ["bytes32", "bytes32", "bytes32", "bytes32", "address", "bytes"],
        [
          nextQuipAddress.publicSeed,
          nextQuipAddress.publicKeyHash,
          nextQuipAddress.publicSeed, // reuse same key for simplicity
          nextQuipAddress.publicKeyHash,
          await dummyContract.getAddress(),
          failingCallData,
        ]
      );

      const failingMessage = {
        messageHash: keccak_256(hre.ethers.getBytes(failingMessageData)),
      };

      const failingSignature = {
        elements: wots.sign(
          nextKeypair.privateKey,
          nextKeypair.publicKey.slice(0, 32),
          failingMessage.messageHash
        ),
      };

      // Execute the failing call and expect it to revert
      let failed = false;
      try {
        await quipWallet.executeWithWinternitz(
          nextQuipAddress,
          failingSignature,
          await dummyContract.getAddress(),
          failingCallData,
          { value: executeFee }
        );
      } catch (error) {
        failed = true;
      }
      expect(failed).to.be.true;

      // Test the no-fee function
      const noFeeValue = 84;
      const noFeeCallData = dummyContract.interface.encodeFunctionData(
        "setValueNoFee",
        [noFeeValue]
      );

      // Create and sign no-fee execution message
      const noFeeMessageData = hre.ethers.solidityPacked(
        ["bytes32", "bytes32", "bytes32", "bytes32", "address", "bytes"],
        [
          nextQuipAddress.publicSeed,
          nextQuipAddress.publicKeyHash,
          nextQuipAddress.publicSeed, // reuse same key for simplicity
          nextQuipAddress.publicKeyHash,
          await dummyContract.getAddress(),
          noFeeCallData,
        ]
      );

      const noFeeMessage = {
        messageHash: keccak_256(hre.ethers.getBytes(noFeeMessageData)),
      };

      const noFeeSignature = {
        elements: wots.sign(
          nextKeypair.privateKey,
          nextKeypair.publicKey.slice(0, 32),
          noFeeMessage.messageHash
        ),
      };

      // Execute the no-fee call
      const noFeeTx = await quipWallet.executeWithWinternitz(
        nextQuipAddress,
        noFeeSignature,
        await dummyContract.getAddress(),
        noFeeCallData,
        { value: executeFee } // Only need to pay the execute fee, no additional ETH required
      );
      await noFeeTx.wait();

      // Verify the no-fee call was successful
      expect(await dummyContract.value()).to.equal(noFeeValue);
    });

    it("Should execute contract calls without additional fees using Winternitz signature", async function () {
      // Deploy factory and wallet
      const { quipFactory, owner } = await loadFixture(deployQuipFactory);
      const initialDeposit = hre.ethers.parseEther("1.0");
      const { quipWallet, keypair } = await deployQuipWallet(
        quipFactory,
        owner,
        "No Fee Test",
        "Vault ID NoFee",
        initialDeposit
      );

      // Deploy the dummy contract
      const DummyContract = await hre.ethers.getContractFactory(
        "DummyContract"
      );
      const dummyContract = await DummyContract.deploy();
      await dummyContract.waitForDeployment();

      // Create new keypair for next state
      let wots: WOTSPlus = new WOTSPlus(keccak_256);
      const publicSeed = randomBytes(32);
      const nextKeypair = wots.generateKeyPair(
        keccak_256("No Fee Next State"),
        publicSeed
      );
      const nextQuipAddress = {
        publicSeed: nextKeypair.publicKey.slice(0, 32),
        publicKeyHash: nextKeypair.publicKey.slice(32, 64),
      };

      const currentQuipAddress = {
        publicSeed: keypair.publicKey.slice(0, 32),
        publicKeyHash: keypair.publicKey.slice(32, 64),
      };

      // Set execute fee
      const executeFee = hre.ethers.parseEther("0.001");
      await quipFactory.setExecuteFee(executeFee);

      // Prepare the call data for setValueNoFee(84)
      const noFeeValue = 84;
      const noFeeCallData = dummyContract.interface.encodeFunctionData(
        "setValueNoFee",
        [noFeeValue]
      );

      // Create and sign execution message
      const packedMessageData = hre.ethers.solidityPacked(
        ["bytes32", "bytes32", "bytes32", "bytes32", "address", "bytes"],
        [
          currentQuipAddress.publicSeed,
          currentQuipAddress.publicKeyHash,
          nextQuipAddress.publicSeed,
          nextQuipAddress.publicKeyHash,
          await dummyContract.getAddress(),
          noFeeCallData,
        ]
      );

      const message = {
        messageHash: keccak_256(hre.ethers.getBytes(packedMessageData)),
      };

      const signature = {
        elements: wots.sign(
          keypair.privateKey,
          keypair.publicKey.slice(0, 32),
          message.messageHash
        ),
      };

      // Execute the no-fee call
      const noFeeTx = await quipWallet.executeWithWinternitz(
        nextQuipAddress,
        signature,
        await dummyContract.getAddress(),
        noFeeCallData,
        { value: executeFee } // Only need to pay the execute fee, no additional ETH required
      );
      await noFeeTx.wait();

      // Verify the no-fee call was successful
      expect(await dummyContract.value()).to.equal(noFeeValue);

      // Try without execute fee - should fail
      await expect(
        quipWallet.executeWithWinternitz(
          nextQuipAddress,
          signature,
          await dummyContract.getAddress(),
          noFeeCallData,
          { value: 0 }
        )
      ).to.be.revertedWith("Insufficient fee");
    });
  });
});
