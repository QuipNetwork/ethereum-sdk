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
    
    const quipFactory = await QuipFactory.deploy(await wotsPlus.getAddress());  // Pass WOTSPlus address
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
    ownerAddress: string, pqAddress: [Uint8Array, Uint8Array]) {
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
          ["address", "address", "bytes32", "bytes32"], 
          [
            quipFactoryAddress,
            ownerAddress, 
            hre.ethers.hexlify(pqAddress[0]),
            hre.ethers.hexlify(pqAddress[1])
          ]
        ),
      ]
  );
    console.log(`QuipWallet code: ${creationCode}`);

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

      const otherQuipFactory = quipFactory.connect(otherAccount);

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
      const keypair = wots.generateKeyPair(secret);
      const quipAddress = {
        publicSeed: keypair.publicKey.slice(0, 32),
        publicKeyHash: keypair.publicKey.slice(32, 64),
      }

      const computedAddress = await computeQuipWalletAddress(vaultId, 
        await quipFactory.getAddress(), otherAccount.address, 
        [quipAddress.publicSeed, quipAddress.publicKeyHash]);
      const otherQuipFactory = quipFactory.connect(otherAccount);
      const createTx = await otherQuipFactory.depositToWinternitz(vaultId, otherAccount.address, quipAddress);
      const createReceipt = await createTx.wait();
      expect(createReceipt).to.not.be.null;

      // Get the return value directly
      const returnData = createReceipt!.logs[0].data;
      const quipWalletAddress = hre.ethers.getAddress(`0x${returnData.slice(-40)}`);
      expect(quipWalletAddress).to.not.equal(0);
      expect(quipWalletAddress).to.equal(computedAddress);

      //console.log(`Quip wallet deployed to ${quipWalletAddress}`);

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
  });

  describe("Withdrawals", function () {
    describe("Validations", function () {
      it("Should revert with the right error if called too soon", async function () {
        const { lock } = await loadFixture(deployOneYearLockFixture);

        await expect(lock.withdraw()).to.be.revertedWith(
          "You can't withdraw yet"
        );
      });

      it("Should revert with the right error if called from another account", async function () {
        const { lock, unlockTime, otherAccount } = await loadFixture(
          deployOneYearLockFixture
        );

        // We can increase the time in Hardhat Network
        await time.increaseTo(unlockTime);

        // We use lock.connect() to send a transaction from another account
        await expect(lock.connect(otherAccount).withdraw()).to.be.revertedWith(
          "You aren't the owner"
        );
      });

      it("Shouldn't fail if the unlockTime has arrived and the owner calls it", async function () {
        const { lock, unlockTime } = await loadFixture(
          deployOneYearLockFixture
        );

        // Transactions are sent using the first signer by default
        await time.increaseTo(unlockTime);

        await expect(lock.withdraw()).not.to.be.reverted;
      });
    });

    describe("Events", function () {
      it("Should emit an event on withdrawals", async function () {
        const { lock, unlockTime, lockedAmount } = await loadFixture(
          deployOneYearLockFixture
        );

        await time.increaseTo(unlockTime);

        await expect(lock.withdraw())
          .to.emit(lock, "Withdrawal")
          .withArgs(lockedAmount, anyValue); // We accept any value as `when` arg
      });
    });

    describe("Transfers", function () {
      it("Should transfer the funds to the owner", async function () {
        const { lock, unlockTime, lockedAmount, owner } = await loadFixture(
          deployOneYearLockFixture
        );

        await time.increaseTo(unlockTime);

        await expect(lock.withdraw()).to.changeEtherBalances(
          [owner, lock],
          [lockedAmount, -lockedAmount]
        );
      });
    });

    describe("Winternitz", function () {
      it("Should deposit and withdraw to/from Winternitz", async function () {
        const { lock, unlockTime, lockedAmount, owner } = await loadFixture(
          deployOneYearLockFixture
        );

        const initialBalance = await hre.ethers.provider.getBalance(owner.address);
        let wots: WOTSPlus = new WOTSPlus(keccak_256);
        let secret = keccak_256("Hello World!");
        const keypair = wots.generateKeyPair(secret);
        const quipAddress = {
          publicSeed: keypair.publicKey.slice(0, 32),
          publicKeyHash: keypair.publicKey.slice(32, 64),
        }

        // Deposit and track gas
        const depositAmount = hre.ethers.parseEther("1.0");
        const depositTx = await lock.depositToWinternitz(quipAddress, { value: depositAmount });
        const depositReceipt = await depositTx.wait();
        const depositGasFee = depositReceipt!.gasUsed * depositReceipt!.gasPrice;
        console.log(`Deposit gas used: ${depositReceipt!.gasUsed} units`);
        console.log(`Deposit gas price: ${depositReceipt!.gasPrice} wei`);
        console.log(`Deposit total gas fee: ${hre.ethers.formatEther(depositGasFee)} ETH`);

        // Verify deposit
        const balance = await lock.balances(owner.address, quipAddress.publicKeyHash);
        expect(balance).to.equal(depositAmount);
        expect(await hre.ethers.provider.getBalance(lock.target)).to.equal(
          BigInt(lockedAmount) + depositAmount
        );
        expect(await hre.ethers.provider.getBalance(owner.address)).to.equal(
          initialBalance - depositAmount - depositGasFee
        );

        // Withdraw
        const message = {
          messageHash: keccak_256(`Withdraw 1.0 ETH to ${owner.address}`)
        };
        let signature = {
          elements: wots.sign(keypair.privateKey, message.messageHash)
        };

        const withdrawTx = await lock.withdrawWithWinternitz(quipAddress, message, signature);
        const withdrawReceipt = await withdrawTx.wait();
        const withdrawGasFee = withdrawReceipt!.gasUsed * withdrawReceipt!.gasPrice;
        console.log(`\nWithdraw gas used: ${withdrawReceipt!.gasUsed} units`);
        console.log(`Withdraw gas price: ${withdrawReceipt!.gasPrice} wei`);
        console.log(`Withdraw total gas fee: ${hre.ethers.formatEther(withdrawGasFee)} ETH`);

        console.log(`\nTotal gas fees: ${hre.ethers.formatEther(depositGasFee + withdrawGasFee)} ETH`);

        // Verify withdraw
        expect(await hre.ethers.provider.getBalance(lock.target)).to.equal(
          BigInt(lockedAmount)
        );
        expect(await hre.ethers.provider.getBalance(owner.address)).to.equal(
          initialBalance - depositGasFee - withdrawGasFee
        );
        expect(await lock.balances(owner.address, quipAddress.publicKeyHash)).to.equal(0);
      });
    });

  });
});
