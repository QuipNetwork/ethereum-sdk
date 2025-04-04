import {
  time,
  loadFixture,
} from "@nomicfoundation/hardhat-toolbox/network-helpers";
import { anyValue } from "@nomicfoundation/hardhat-chai-matchers/withArgs";
import { expect } from "chai";
import hre from "hardhat";
import { WOTSPlus } from "@quip.network/hashsigs";
import { keccak_256 } from '@noble/hashes/sha3';

describe("QuipFactory", function () {
  // We define a fixture to reuse the same setup in every test.
  // We use loadFixture to run this setup once, snapshot that state,
  // and reset Hardhat Network to that snapshot in every test.
  async function deployQuipFactory() {
    //const ONE_GWEI = 1_000_000_000;

    // Deploy the WOTSPlus library first - using the full package path
    const WOTSPlusLib = await hre.ethers.getContractFactory("@quip.network/hashsigs-solidity/contracts/WOTSPlus.sol:WOTSPlus");
    const wotsPlus = await WOTSPlusLib.deploy();
    await wotsPlus.waitForDeployment();

    // Link the library when deploying QuipFactory - using the full package path
    const QuipFactory = await hre.ethers.getContractFactory("QuipFactory", {
      libraries: {
        "@quip.network/hashsigs-solidity/contracts/WOTSPlus.sol:WOTSPlus": await wotsPlus.getAddress()
      }
    });
    const [signer] = await hre.ethers.getSigners();
    const initialOwner = signer.getAddress();
    console.log(`Deploying with signer: ${initialOwner}`);
    const wotsPlusAddress = await wotsPlus.getAddress();
    console.log(`WOTSPlus deployed to: ${wotsPlusAddress}`);
    const quipFactory = await QuipFactory.deploy(initialOwner, wotsPlusAddress);  
    const deployReceipt = await quipFactory.waitForDeployment();
    // Get deployment transaction
    const deployTx = deployReceipt.deploymentTransaction();
    const receipt = await deployTx!.wait();
    const deployGasFee = receipt!.gasUsed * receipt!.gasPrice;
    console.log(`\nDeploy gas used: ${receipt!.gasUsed} units`);
    console.log(`Deploy gas price: ${receipt!.gasPrice} wei`);
    console.log(`Deploy total gas fee: ${hre.ethers.formatEther(deployGasFee)} ETH`);


    const [owner, otherAccount] = await hre.ethers.getSigners();

    return { quipFactory, wotsPlus, owner, otherAccount };
  }

  async function computeQuipWalletAddress(vaultId: Uint8Array, quipFactoryAddress: string, 
    ownerAddress: string) {
    const quipFactory = await hre.ethers.getContractAt("QuipFactory", quipFactoryAddress);
    const wotsPlusAddress = await quipFactory.wotsLibrary();
    
    const quipWalletCode = (await hre.ethers.getContractFactory("QuipWallet", {
        libraries: {
            "@quip.network/hashsigs-solidity/contracts/WOTSPlus.sol:WOTSPlus": wotsPlusAddress
        }
    })).bytecode;
    
    const creationCode = hre.ethers.solidityPacked(
      ["bytes", "bytes"],
      [
        quipWalletCode,
        hre.ethers.AbiCoder.defaultAbiCoder().encode(
          ["address", "address"], 
          [
            quipFactoryAddress,
            ownerAddress
          ]
        ),
      ]
    );
    //console.log(`QuipWallet code: ${creationCode}`);

    const hash = hre.ethers.keccak256(
        hre.ethers.solidityPacked(
            ["bytes1", "address", "bytes32", "bytes"],
            [
                "0xff",
                quipFactoryAddress,
                vaultId,
                hre.ethers.keccak256(creationCode),
            ]
        )
    );
    return hre.ethers.getAddress(`0x${hash.slice(-40)}`);
  }

  describe("Deployment", function () {
    it("Should set and transfer the right owner", async function () {
      const { quipFactory, owner, otherAccount } = await loadFixture(deployQuipFactory);

      expect(await quipFactory.owner()).to.equal(owner.address);

      const transferTx = await quipFactory.transferOwnership(otherAccount.address);
      await transferTx.wait();

      expect(await quipFactory.owner()).to.equal(otherAccount.address);
    });

    it("Should fail to transferOwner if not the right owner", async function () {
      const { quipFactory, owner, otherAccount } = await loadFixture(deployQuipFactory);

      expect(await quipFactory.owner()).to.equal(owner.address);

      const otherQuipFactory = quipFactory.connect(otherAccount) as typeof quipFactory;

      await expect(
        otherQuipFactory.transferOwnership(otherAccount.address)
      ).to.be.revertedWith("You aren't the admin");

      expect(await otherQuipFactory.owner()).to.equal(owner.address);
    });

    it("Should deploy a new quip wallet from non-owner", async function () {
      const { quipFactory, wotsPlus, otherAccount } = await loadFixture(deployQuipFactory);

      const vaultId = keccak_256("Vault ID 1");
      let wots: WOTSPlus = new WOTSPlus(keccak_256);
      let secret = keccak_256("Hello World!");
      const publicSeed = hre.ethers.randomBytes(32);
      const keypair = wots.generateKeyPair(secret, publicSeed);
      const quipAddress = {
        publicSeed: keypair.publicKey.slice(0, 32),
        publicKeyHash: keypair.publicKey.slice(32, 64),
      }

      const computedAddress = await computeQuipWalletAddress(vaultId, 
        await quipFactory.getAddress(), otherAccount.address);
      const otherQuipFactory = quipFactory.connect(otherAccount) as typeof quipFactory;
      const createTx = await otherQuipFactory.depositToWinternitz(vaultId, otherAccount.address, quipAddress);
      const createReceipt = await createTx.wait();
      const createGasFee = createReceipt!.gasUsed * createReceipt!.gasPrice;
      console.log(`\depositToWinternitz gas used: ${createReceipt!.gasUsed} units`);
      console.log(`depositToWinternitz gas price: ${createReceipt!.gasPrice} wei`);
      console.log(`depositToWinternitz total gas fee: ${hre.ethers.formatEther(createGasFee)} ETH`);
      
      expect(createReceipt).to.not.be.null;

      // Get the return value directly
      const returnData = createReceipt!.logs[0].data;
      const quipWalletAddress = hre.ethers.getAddress(`0x${returnData.slice(-40)}`);
      expect(quipWalletAddress).to.not.equal(0);
      expect(quipWalletAddress).to.equal(computedAddress);

      // Assert event creation.
      await expect(createTx)
        .to.emit(quipFactory, "QuipCreated")
        .withArgs(
          0, // amount
          anyValue, // when
          vaultId,
          otherAccount.address, // creator
          [quipAddress.publicSeed, quipAddress.publicKeyHash], // pqPubkey
          quipWalletAddress // quip address
        );
      
      // Check contract state
      const quip = await quipFactory.quips(otherAccount.address, vaultId);
      expect(quip).to.equal(quipWalletAddress);

      // Now get contract instance.
      const quipWallet = await hre.ethers.getContractAt("QuipWallet", quipWalletAddress);
      expect(quipWalletAddress).to.equal(quipWallet.target);
    });

    it("Should deploy a new quip wallet with initial balance", async function () {
      const { quipFactory, wotsPlus, otherAccount } = await loadFixture(deployQuipFactory);

      const vaultId = keccak_256("Vault ID 1");
      let wots: WOTSPlus = new WOTSPlus(keccak_256);
      let secret = keccak_256("Hello World!");
      const publicSeed = hre.ethers.randomBytes(32);
      const keypair = wots.generateKeyPair(secret, publicSeed);
      const quipAddress = {
        publicSeed: keypair.publicKey.slice(0, 32),
        publicKeyHash: keypair.publicKey.slice(32, 64),
      }

      const initialDeposit = hre.ethers.parseEther("1.0");
      const computedAddress = await computeQuipWalletAddress(vaultId, 
        await quipFactory.getAddress(), otherAccount.address);
      
      const otherQuipFactory = quipFactory.connect(otherAccount) as typeof quipFactory;
      const createTx = await otherQuipFactory.depositToWinternitz(
        vaultId, 
        otherAccount.address, 
        quipAddress,
        { value: initialDeposit }
      );
      const createReceipt = await createTx.wait();
      const createGasFee = createReceipt!.gasUsed * createReceipt!.gasPrice;
      console.log(`\depositToWinternitz with deposit gas used: ${createReceipt!.gasUsed} units`);
      console.log(`depositToWinternitz with deposit gas price: ${createReceipt!.gasPrice} wei`);
      console.log(`depositToWinternitz with deposit total gas fee: ${hre.ethers.formatEther(createGasFee)} ETH`);
      
      expect(createReceipt).to.not.be.null;

      const quipWalletAddress = hre.ethers.getAddress(`0x${createReceipt!.logs[0].data.slice(-40)}`);
      expect(quipWalletAddress).to.equal(computedAddress);

      // Verify the balance was transferred
      expect(await hre.ethers.provider.getBalance(quipWalletAddress)).to.equal(initialDeposit);

      // Assert event creation with the deposit amount
      await expect(createTx)
        .to.emit(quipFactory, "QuipCreated")
        .withArgs(
          initialDeposit, // amount
          anyValue, // when
          vaultId,
          otherAccount.address, // creator
          [quipAddress.publicSeed, quipAddress.publicKeyHash], // pqPubkey
          quipWalletAddress // quip address
        );
      
      // Check contract state
      const quip = await quipFactory.quips(otherAccount.address, vaultId);
      expect(quip).to.equal(quipWalletAddress);

      // Now get contract instance and verify its state
      const quipWallet = await hre.ethers.getContractAt("QuipWallet", quipWalletAddress);
      expect(await quipWallet.owner()).to.equal(otherAccount.address);
      expect(await quipWallet.pqOwner()).to.deep.equal([
        hre.ethers.hexlify(quipAddress.publicSeed),
        hre.ethers.hexlify(quipAddress.publicKeyHash)
      ]);
    });

    it("Should properly handle fees and withdrawals", async function () {
      const { quipFactory, owner, otherAccount } = await loadFixture(deployQuipFactory);
      
      // Set fees
      const creationFee = hre.ethers.parseEther("0.01");  // 0.01 ETH
      const transferFee = hre.ethers.parseEther("0.005"); // 0.005 ETH
      const executeFee = hre.ethers.parseEther("0.002"); // 0.002 ETH
      
      await quipFactory.setCreationFee(creationFee);
      await quipFactory.setTransferFee(transferFee);
      await quipFactory.setExecuteFee(executeFee);
      
      // Verify fees were set
      expect(await quipFactory.creationFee()).to.equal(creationFee);
      expect(await quipFactory.transferFee()).to.equal(transferFee);
      expect(await quipFactory.executeFee()).to.equal(executeFee);

      // Create a new wallet with initial deposit, including creation fee
      const initialDeposit = hre.ethers.parseEther("1.0");
      const totalDeposit = initialDeposit + creationFee;
      
      const vaultId = keccak_256("Fee Test Vault");
      let wots: WOTSPlus = new WOTSPlus(keccak_256);
      let secret = keccak_256("Fee Test Secret");
      const publicSeed = hre.ethers.randomBytes(32);
      const keypair = wots.generateKeyPair(secret, publicSeed);
      const quipAddress = {
        publicSeed: keypair.publicKey.slice(0, 32),
        publicKeyHash: keypair.publicKey.slice(32, 64),
      }

      // Get factory's initial balance
      const factoryInitialBalance = await hre.ethers.provider.getBalance(await quipFactory.getAddress());

      // Create wallet with fee
      const createTx = await quipFactory.depositToWinternitz(
        vaultId,
        owner.address,
        quipAddress,
        { value: totalDeposit }
      );
      await createTx.wait();

      // Verify factory received the creation fee
      expect(await hre.ethers.provider.getBalance(await quipFactory.getAddress()))
        .to.equal(factoryInitialBalance + creationFee);

      // Withdraw fees as admin
      const adminInitialBalance = await hre.ethers.provider.getBalance(owner.address);
      const withdrawTx = await quipFactory.withdraw(creationFee);
      const withdrawReceipt = await withdrawTx.wait();
      const withdrawGasCost = withdrawReceipt!.gasUsed * withdrawReceipt!.gasPrice;

      // Verify withdrawal
      expect(await hre.ethers.provider.getBalance(await quipFactory.getAddress()))
        .to.equal(factoryInitialBalance);
      expect(await hre.ethers.provider.getBalance(owner.address))
        .to.equal(adminInitialBalance + creationFee - withdrawGasCost);

      // Verify non-admin cannot withdraw
      const otherFactoryInstance = quipFactory.connect(otherAccount);
      await expect(otherFactoryInstance.withdraw(creationFee))
        .to.be.revertedWith("You aren't the admin");

      // Verify non-admin cannot set fees
      await expect(otherFactoryInstance.setCreationFee(0))
        .to.be.revertedWith("You aren't the admin");
      await expect(otherFactoryInstance.setTransferFee(0))
        .to.be.revertedWith("You aren't the admin");
      await expect(otherFactoryInstance.setExecuteFee(0))
        .to.be.revertedWith("You aren't the admin");
    });
  });
});
