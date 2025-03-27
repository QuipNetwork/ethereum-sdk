"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const hardhat_network_helpers_1 = require("@nomicfoundation/hardhat-network-helpers");
const chai_1 = require("chai");
const sha3_1 = require("@noble/hashes/sha3");
const hashsigs_1 = require("@quip.network/hashsigs");
const withArgs_1 = require("@nomicfoundation/hardhat-chai-matchers/withArgs");
const hardhat_1 = __importDefault(require("hardhat"));
describe("QuipWallet", function () {
    async function deployQuipFactory() {
        // Deploy the WOTSPlus library first - using the full package path
        const WOTSPlusLib = await hardhat_1.default.ethers.getContractFactory("@quip.network/hashsigs-solidity/contracts/WOTSPlus.sol:WOTSPlus");
        const wotsPlus = await WOTSPlusLib.deploy();
        await wotsPlus.waitForDeployment();
        // Link the library when deploying QuipFactory - using the full package path
        const QuipFactory = await hardhat_1.default.ethers.getContractFactory("QuipFactory", {
            libraries: {
                "@quip.network/hashsigs-solidity/contracts/WOTSPlus.sol:WOTSPlus": await wotsPlus.getAddress()
            }
        });
        const quipFactory = await QuipFactory.deploy(await wotsPlus.getAddress());
        const deployReceipt = await quipFactory.waitForDeployment();
        // Get deployment transaction
        const deployTx = deployReceipt.deploymentTransaction();
        const receipt = await deployTx.wait();
        const [owner, otherAccount] = await hardhat_1.default.ethers.getSigners();
        return { quipFactory, wotsPlus, owner, otherAccount };
    }
    async function deployQuipWallet(quipFactory, owner, secret, vaultId, initialDeposit = BigInt(0)) {
        let wots = new hashsigs_1.WOTSPlus(sha3_1.keccak_256);
        const keypair = wots.generateKeyPair((0, sha3_1.keccak_256)(secret));
        const quipAddress = {
            publicSeed: keypair.publicKey.slice(0, 32),
            publicKeyHash: keypair.publicKey.slice(32, 64),
        };
        const vaultIdBytes = (0, sha3_1.keccak_256)(vaultId);
        const ownerQuipFactory = quipFactory.connect(owner);
        const createTx = await ownerQuipFactory.depositToWinternitz(vaultIdBytes, owner.address, quipAddress, { value: initialDeposit });
        const createReceipt = await createTx.wait();
        const quipWalletAddress = hardhat_1.default.ethers.getAddress(`0x${createReceipt.logs[0].data.slice(-40)}`);
        const quipWallet = await hardhat_1.default.ethers.getContractAt("QuipWallet", quipWalletAddress);
        return { quipWallet, keypair };
    }
    describe("Winternitz", function () {
        it("Should transfer funds using Winternitz signature", async function () {
            // Deploy factory and wallet
            const { quipFactory, owner, otherAccount } = await (0, hardhat_network_helpers_1.loadFixture)(deployQuipFactory);
            const initialDeposit = hardhat_1.default.ethers.parseEther("1.0");
            const { quipWallet, keypair } = await deployQuipWallet(quipFactory, owner, "Hello World!", "Vault ID 1", initialDeposit);
            // Create new keypair for next owner
            let wots = new hashsigs_1.WOTSPlus(sha3_1.keccak_256);
            const nextKeypair = wots.generateKeyPair((0, sha3_1.keccak_256)("Next Owner"));
            const nextQuipAddress = {
                publicSeed: nextKeypair.publicKey.slice(0, 32),
                publicKeyHash: nextKeypair.publicKey.slice(32, 64),
            };
            const transferAmount = hardhat_1.default.ethers.parseEther("0.5");
            const currentQuipAddress = {
                publicSeed: keypair.publicKey.slice(0, 32),
                publicKeyHash: keypair.publicKey.slice(32, 64),
            };
            // Create and sign transfer message
            const packedMessageData = hardhat_1.default.ethers.solidityPacked(["bytes32", "bytes32", "bytes32", "bytes32", "address", "uint256"], [
                currentQuipAddress.publicSeed,
                currentQuipAddress.publicKeyHash,
                nextQuipAddress.publicSeed,
                nextQuipAddress.publicKeyHash,
                otherAccount.address,
                transferAmount
            ]);
            const message = {
                messageHash: (0, sha3_1.keccak_256)(hardhat_1.default.ethers.getBytes(packedMessageData))
            };
            const signature = {
                elements: wots.sign(keypair.privateKey, message.messageHash)
            };
            // Execute transfer
            const transferTx = await quipWallet.transferWithWinternitz(nextQuipAddress, signature, otherAccount.address, transferAmount);
            const transferReceipt = await transferTx.wait();
            const transferGasFee = transferReceipt.gasUsed * transferReceipt.gasPrice;
            console.log(`\nTransfer gas used: ${transferReceipt.gasUsed} units`);
            console.log(`Transfer gas price: ${transferReceipt.gasPrice} wei`);
            console.log(`Transfer total gas fee: ${hardhat_1.default.ethers.formatEther(transferGasFee)} ETH`);
            // Verify transfer
            (0, chai_1.expect)(await hardhat_1.default.ethers.provider.getBalance(quipWallet.target)).to.equal(initialDeposit - transferAmount);
            (0, chai_1.expect)(await quipWallet.pqOwner()).to.deep.equal([
                hardhat_1.default.ethers.hexlify(nextQuipAddress.publicSeed),
                hardhat_1.default.ethers.hexlify(nextQuipAddress.publicKeyHash)
            ]);
            // Verify event
            await (0, chai_1.expect)(transferTx)
                .to.emit(quipWallet, "pqTransfer")
                .withArgs(transferAmount, withArgs_1.anyValue, [currentQuipAddress.publicSeed, currentQuipAddress.publicKeyHash], [nextQuipAddress.publicSeed, nextQuipAddress.publicKeyHash], otherAccount.address);
        });
        it("Should transfer between two QuipWallets and withdraw", async function () {
            // Deploy factory and first wallet for owner
            const { quipFactory, owner, otherAccount } = await (0, hardhat_network_helpers_1.loadFixture)(deployQuipFactory);
            const initialDeposit = hardhat_1.default.ethers.parseEther("1.0");
            const { quipWallet: ownerQuipWallet, keypair: ownerKeypair } = await deployQuipWallet(quipFactory, owner, "Owner Secret", "Owner Vault", initialDeposit);
            // Deploy second wallet for otherAccount
            const { quipWallet: otherQuipWallet, keypair: otherKeypair } = await deployQuipWallet(quipFactory, otherAccount, "Other Secret", "Other Vault");
            // Setup transfer from owner's wallet to other's wallet
            const transferAmount = hardhat_1.default.ethers.parseEther("0.5");
            // Create new keypair for owner's next state
            let wots = new hashsigs_1.WOTSPlus(sha3_1.keccak_256);
            const ownerNextKeypair = wots.generateKeyPair((0, sha3_1.keccak_256)("Owner Next State"));
            const ownerNextQuipAddress = {
                publicSeed: ownerNextKeypair.publicKey.slice(0, 32),
                publicKeyHash: ownerNextKeypair.publicKey.slice(32, 64),
            };
            const ownerCurrentQuipAddress = {
                publicSeed: ownerKeypair.publicKey.slice(0, 32),
                publicKeyHash: ownerKeypair.publicKey.slice(32, 64),
            };
            // Get initial balance of otherAccount
            const initialBalance = await hardhat_1.default.ethers.provider.getBalance(otherAccount.address);
            // Create and sign transfer message from owner's wallet to other's wallet
            const packedTransferData = hardhat_1.default.ethers.solidityPacked(["bytes32", "bytes32", "bytes32", "bytes32", "address", "uint256"], [
                ownerCurrentQuipAddress.publicSeed,
                ownerCurrentQuipAddress.publicKeyHash,
                ownerNextQuipAddress.publicSeed,
                ownerNextQuipAddress.publicKeyHash,
                otherQuipWallet.target,
                transferAmount
            ]);
            const transferMessage = {
                messageHash: (0, sha3_1.keccak_256)(hardhat_1.default.ethers.getBytes(packedTransferData))
            };
            const transferSignature = {
                elements: wots.sign(ownerKeypair.privateKey, transferMessage.messageHash)
            };
            // Execute transfer from owner's wallet to other's wallet
            const targetAddress = await otherQuipWallet.getAddress();
            await ownerQuipWallet.transferWithWinternitz(ownerNextQuipAddress, transferSignature, targetAddress, transferAmount);
            // Verify the transfer was successful
            (0, chai_1.expect)(await hardhat_1.default.ethers.provider.getBalance(otherQuipWallet.target)).to.equal(transferAmount);
            // Now otherAccount withdraws from their wallet to their personal address
            const otherNextKeypair = wots.generateKeyPair((0, sha3_1.keccak_256)("Other Next State"));
            const otherNextQuipAddress = {
                publicSeed: otherNextKeypair.publicKey.slice(0, 32),
                publicKeyHash: otherNextKeypair.publicKey.slice(32, 64),
            };
            const otherCurrentQuipAddress = {
                publicSeed: otherKeypair.publicKey.slice(0, 32),
                publicKeyHash: otherKeypair.publicKey.slice(32, 64),
            };
            // Create and sign withdrawal message
            const packedWithdrawalData = hardhat_1.default.ethers.solidityPacked(["bytes32", "bytes32", "bytes32", "bytes32", "address", "uint256"], [
                otherCurrentQuipAddress.publicSeed,
                otherCurrentQuipAddress.publicKeyHash,
                otherNextQuipAddress.publicSeed,
                otherNextQuipAddress.publicKeyHash,
                otherAccount.address,
                transferAmount
            ]);
            const withdrawalMessage = {
                messageHash: (0, sha3_1.keccak_256)(hardhat_1.default.ethers.getBytes(packedWithdrawalData))
            };
            const withdrawalSignature = {
                elements: wots.sign(otherKeypair.privateKey, withdrawalMessage.messageHash)
            };
            // Execute withdrawal
            const withdrawalTx = await otherQuipWallet.connect(otherAccount).transferWithWinternitz(otherNextQuipAddress, withdrawalSignature, otherAccount.address, transferAmount);
            const withdrawalReceipt = await withdrawalTx.wait();
            // Calculate gas costs for withdrawal
            const withdrawalGasCost = withdrawalReceipt.gasUsed * withdrawalReceipt.gasPrice;
            // Verify final balances
            (0, chai_1.expect)(await hardhat_1.default.ethers.provider.getBalance(otherQuipWallet.target)).to.equal(0);
            (0, chai_1.expect)(await hardhat_1.default.ethers.provider.getBalance(otherAccount.address)).to.equal(initialBalance + transferAmount - withdrawalGasCost);
        });
    });
});
