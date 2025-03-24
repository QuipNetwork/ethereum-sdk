import {
  time,
  loadFixture,
} from "@nomicfoundation/hardhat-toolbox/network-helpers";
import { anyValue } from "@nomicfoundation/hardhat-chai-matchers/withArgs";
import { expect } from "chai";
import hre from "hardhat";
import { WOTSPlus } from "@quip.network/hashsigs";
import { keccak_256 } from '@noble/hashes/sha3';

describe("Lock", function () {
  // We define a fixture to reuse the same setup in every test.
  // We use loadFixture to run this setup once, snapshot that state,
  // and reset Hardhat Network to that snapshot in every test.
  async function deployOneYearLockFixture() {
    const ONE_YEAR_IN_SECS = 365 * 24 * 60 * 60;
    const ONE_GWEI = 1_000_000_000;

    const lockedAmount = ONE_GWEI;
    const unlockTime = (await time.latest()) + ONE_YEAR_IN_SECS;

    // Deploy the WOTSPlus library first - using the full package path
    const WOTSPlusLib = await hre.ethers.getContractFactory("@quip.network/hashsigs-solidity/contracts/WOTSPlus.sol:WOTSPlus");
    const wotsPlus = await WOTSPlusLib.deploy();
    await wotsPlus.waitForDeployment();

    // Link the library when deploying Lock - using the full package path
    const Lock = await hre.ethers.getContractFactory("Lock", {
      libraries: {
        "@quip.network/hashsigs-solidity/contracts/WOTSPlus.sol:WOTSPlus": await wotsPlus.getAddress()
      }
    });
    
    const lock = await Lock.deploy(unlockTime, { value: lockedAmount });
    await lock.waitForDeployment();

    const [owner, otherAccount] = await hre.ethers.getSigners();

    return { lock, unlockTime, lockedAmount, owner, otherAccount };
  }

  describe("Deployment", function () {
    it("Should set the right unlockTime", async function () {
      const { lock, unlockTime } = await loadFixture(deployOneYearLockFixture);

      expect(await lock.unlockTime()).to.equal(unlockTime);
    });

    it("Should set the right owner", async function () {
      const { lock, owner } = await loadFixture(deployOneYearLockFixture);

      expect(await lock.owner()).to.equal(owner.address);
    });

    it("Should receive and store the funds to lock", async function () {
      const { lock, lockedAmount } = await loadFixture(
        deployOneYearLockFixture
      );

      expect(await hre.ethers.provider.getBalance(lock.target)).to.equal(
        lockedAmount
      );
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
