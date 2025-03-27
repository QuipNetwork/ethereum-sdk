"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const network_helpers_1 = require("@nomicfoundation/hardhat-toolbox/network-helpers");
const withArgs_1 = require("@nomicfoundation/hardhat-chai-matchers/withArgs");
const chai_1 = require("chai");
const hardhat_1 = __importDefault(require("hardhat"));
const hashsigs_1 = require("@quip.network/hashsigs");
const sha3_1 = require("@noble/hashes/sha3");
describe("QuipFactory", function () {
    // We define a fixture to reuse the same setup in every test.
    // We use loadFixture to run this setup once, snapshot that state,
    // and reset Hardhat Network to that snapshot in every test.
    async function deployQuipFactory() {
        //const ONE_GWEI = 1_000_000_000;
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
        const quipFactory = await QuipFactory.deploy(await wotsPlus.getAddress()); // Pass WOTSPlus address
        const deployReceipt = await quipFactory.waitForDeployment();
        // Get deployment transaction
        const deployTx = deployReceipt.deploymentTransaction();
        const receipt = await deployTx.wait();
        const deployGasFee = receipt.gasUsed * receipt.gasPrice;
        console.log(`\nDeploy gas used: ${receipt.gasUsed} units`);
        console.log(`Deploy gas price: ${receipt.gasPrice} wei`);
        console.log(`Deploy total gas fee: ${hardhat_1.default.ethers.formatEther(deployGasFee)} ETH`);
        const [owner, otherAccount] = await hardhat_1.default.ethers.getSigners();
        return { quipFactory, wotsPlus, owner, otherAccount };
    }
    async function computeQuipWalletAddress(vaultId, quipFactoryAddress, ownerAddress, pqAddress) {
        const quipFactory = await hardhat_1.default.ethers.getContractAt("QuipFactory", quipFactoryAddress);
        const wotsPlusAddress = await quipFactory.wotsLibrary();
        const quipWalletCode = (await hardhat_1.default.ethers.getContractFactory("QuipWallet", {
            libraries: {
                "@quip.network/hashsigs-solidity/contracts/WOTSPlus.sol:WOTSPlus": wotsPlusAddress
            }
        })).bytecode;
        const creationCode = hardhat_1.default.ethers.solidityPacked(["bytes", "bytes"], [
            quipWalletCode,
            hardhat_1.default.ethers.AbiCoder.defaultAbiCoder().encode(["address", "address", "bytes32", "bytes32"], [
                quipFactoryAddress,
                ownerAddress,
                hardhat_1.default.ethers.hexlify(pqAddress[0]),
                hardhat_1.default.ethers.hexlify(pqAddress[1])
            ]),
        ]);
        //console.log(`QuipWallet code: ${creationCode}`);
        const hash = hardhat_1.default.ethers.keccak256(hardhat_1.default.ethers.solidityPacked(["bytes1", "address", "bytes32", "bytes"], [
            "0xff",
            quipFactoryAddress,
            vaultId,
            hardhat_1.default.ethers.keccak256(creationCode),
        ]));
        return hardhat_1.default.ethers.getAddress(`0x${hash.slice(-40)}`);
    }
    describe("Deployment", function () {
        it("Should set and transfer the right owner", async function () {
            const { quipFactory, owner, otherAccount } = await (0, network_helpers_1.loadFixture)(deployQuipFactory);
            (0, chai_1.expect)(await quipFactory.owner()).to.equal(owner.address);
            const transferTx = await quipFactory.transferOwnership(otherAccount.address);
            await transferTx.wait();
            (0, chai_1.expect)(await quipFactory.owner()).to.equal(otherAccount.address);
        });
        it("Should fail to transferOwner if not the right owner", async function () {
            const { quipFactory, owner, otherAccount } = await (0, network_helpers_1.loadFixture)(deployQuipFactory);
            (0, chai_1.expect)(await quipFactory.owner()).to.equal(owner.address);
            const otherQuipFactory = quipFactory.connect(otherAccount);
            await (0, chai_1.expect)(otherQuipFactory.transferOwnership(otherAccount.address)).to.be.revertedWith("You aren't the admin");
            (0, chai_1.expect)(await otherQuipFactory.owner()).to.equal(owner.address);
        });
        it("Should deploy a new quip wallet from non-owner", async function () {
            const { quipFactory, wotsPlus, otherAccount } = await (0, network_helpers_1.loadFixture)(deployQuipFactory);
            const vaultId = (0, sha3_1.keccak_256)("Vault ID 1");
            let wots = new hashsigs_1.WOTSPlus(sha3_1.keccak_256);
            let secret = (0, sha3_1.keccak_256)("Hello World!");
            const keypair = wots.generateKeyPair(secret);
            const quipAddress = {
                publicSeed: keypair.publicKey.slice(0, 32),
                publicKeyHash: keypair.publicKey.slice(32, 64),
            };
            const computedAddress = await computeQuipWalletAddress(vaultId, await quipFactory.getAddress(), otherAccount.address, [quipAddress.publicSeed, quipAddress.publicKeyHash]);
            const otherQuipFactory = quipFactory.connect(otherAccount);
            const createTx = await otherQuipFactory.depositToWinternitz(vaultId, otherAccount.address, quipAddress);
            const createReceipt = await createTx.wait();
            const createGasFee = createReceipt.gasUsed * createReceipt.gasPrice;
            console.log(`\depositToWinternitz gas used: ${createReceipt.gasUsed} units`);
            console.log(`depositToWinternitz gas price: ${createReceipt.gasPrice} wei`);
            console.log(`depositToWinternitz total gas fee: ${hardhat_1.default.ethers.formatEther(createGasFee)} ETH`);
            (0, chai_1.expect)(createReceipt).to.not.be.null;
            // Get the return value directly
            const returnData = createReceipt.logs[0].data;
            const quipWalletAddress = hardhat_1.default.ethers.getAddress(`0x${returnData.slice(-40)}`);
            (0, chai_1.expect)(quipWalletAddress).to.not.equal(0);
            (0, chai_1.expect)(quipWalletAddress).to.equal(computedAddress);
            // Assert event creation.
            await (0, chai_1.expect)(createTx)
                .to.emit(quipFactory, "QuipCreated")
                .withArgs(0, // amount
            withArgs_1.anyValue, // when
            vaultId, otherAccount.address, // creator
            [quipAddress.publicSeed, quipAddress.publicKeyHash], // pqPubkey
            quipWalletAddress // quip address
            );
            // Check contract state
            const quip = await quipFactory.quips(otherAccount.address, vaultId);
            (0, chai_1.expect)(quip).to.equal(quipWalletAddress);
            // Now get contract instance.
            const quipWallet = await hardhat_1.default.ethers.getContractAt("QuipWallet", quipWalletAddress);
            (0, chai_1.expect)(quipWalletAddress).to.equal(quipWallet.target);
        });
        it("Should deploy a new quip wallet with initial balance", async function () {
            const { quipFactory, wotsPlus, otherAccount } = await (0, network_helpers_1.loadFixture)(deployQuipFactory);
            const vaultId = (0, sha3_1.keccak_256)("Vault ID 1");
            let wots = new hashsigs_1.WOTSPlus(sha3_1.keccak_256);
            let secret = (0, sha3_1.keccak_256)("Hello World!");
            const keypair = wots.generateKeyPair(secret);
            const quipAddress = {
                publicSeed: keypair.publicKey.slice(0, 32),
                publicKeyHash: keypair.publicKey.slice(32, 64),
            };
            const initialDeposit = hardhat_1.default.ethers.parseEther("1.0");
            const computedAddress = await computeQuipWalletAddress(vaultId, await quipFactory.getAddress(), otherAccount.address, [quipAddress.publicSeed, quipAddress.publicKeyHash]);
            const otherQuipFactory = quipFactory.connect(otherAccount);
            const createTx = await otherQuipFactory.depositToWinternitz(vaultId, otherAccount.address, quipAddress, { value: initialDeposit });
            const createReceipt = await createTx.wait();
            const createGasFee = createReceipt.gasUsed * createReceipt.gasPrice;
            console.log(`\depositToWinternitz with deposit gas used: ${createReceipt.gasUsed} units`);
            console.log(`depositToWinternitz with deposit gas price: ${createReceipt.gasPrice} wei`);
            console.log(`depositToWinternitz with deposit total gas fee: ${hardhat_1.default.ethers.formatEther(createGasFee)} ETH`);
            (0, chai_1.expect)(createReceipt).to.not.be.null;
            const quipWalletAddress = hardhat_1.default.ethers.getAddress(`0x${createReceipt.logs[0].data.slice(-40)}`);
            (0, chai_1.expect)(quipWalletAddress).to.equal(computedAddress);
            // Verify the balance was transferred
            (0, chai_1.expect)(await hardhat_1.default.ethers.provider.getBalance(quipWalletAddress)).to.equal(initialDeposit);
            // Assert event creation with the deposit amount
            await (0, chai_1.expect)(createTx)
                .to.emit(quipFactory, "QuipCreated")
                .withArgs(initialDeposit, // amount
            withArgs_1.anyValue, // when
            vaultId, otherAccount.address, // creator
            [quipAddress.publicSeed, quipAddress.publicKeyHash], // pqPubkey
            quipWalletAddress // quip address
            );
            // Check contract state
            const quip = await quipFactory.quips(otherAccount.address, vaultId);
            (0, chai_1.expect)(quip).to.equal(quipWalletAddress);
            // Now get contract instance and verify its state
            const quipWallet = await hardhat_1.default.ethers.getContractAt("QuipWallet", quipWalletAddress);
            (0, chai_1.expect)(await quipWallet.owner()).to.equal(otherAccount.address);
            (0, chai_1.expect)(await quipWallet.pqOwner()).to.deep.equal([
                hardhat_1.default.ethers.hexlify(quipAddress.publicSeed),
                hardhat_1.default.ethers.hexlify(quipAddress.publicKeyHash)
            ]);
        });
    });
});
