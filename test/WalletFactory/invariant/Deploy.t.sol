// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WalletFactoryTest} from "../WalletFactory.t.sol";
import {WalletFactoryDeployHandler} from "./DeployHandler.t.sol";
import {WOTSPlusImplementation} from "../../../contracts/deprecated/wots/WOTSPlusImplementation.sol";

/// forge-config: default.invariant.runs = 8
/// forge-config: default.invariant.depth = 10

contract WalletFactory_Deploy_Invariant is WalletFactoryTest {
    uint256 internal constant SEED_FEE = 0.05 ether;

    WalletFactoryDeployHandler public deployHandler;

    function setUp() public override {
        super.setUp();
        deployHandler = new WalletFactoryDeployHandler();
        deployHandler.initialize(factory, address(walletImplementation));
        vm.prank(ADMIN);
        factory.transferOwnership(address(deployHandler));
        deployHandler.fuzzSetCreationFee(SEED_FEE);
        deployHandler.fuzzDeployLatest(1, 1);
        deployHandler.fuzzDeploySpecific(0);
        targetContract(address(deployHandler));

        bytes4[] memory selectors = new bytes4[](5);
        selectors[0] = WalletFactoryDeployHandler.fuzzDeployLatest.selector;
        selectors[1] = WalletFactoryDeployHandler.fuzzDeploySpecific.selector;
        selectors[2] = WalletFactoryDeployHandler.fuzzSetCreationFee.selector;
        selectors[3] = WalletFactoryDeployHandler.fuzzDeprecateSeed.selector;
        selectors[4] = WalletFactoryDeployHandler.fuzzUndeprecateSeed.selector;
        targetSelector(FuzzSelector({addr: address(deployHandler), selectors: selectors}));
    }

    function test_setUp() public view override {
        assertEq(factory.owner(), address(deployHandler));
        assertEq(factory.creationFee(), SEED_FEE, "seeded fee update landed");
        assertTrue(deployHandler.feeEverSet(), "fee mirror recorded the seeded update");
        assertEq(factory.getVettedCodeCount(), 1);
        assertEq(deployHandler.deployCount(), 2, "one seeded deploy per entry point");
        assertEq(deployHandler.callsDeploySpecific(), 1, "seeded specific deploy landed");
    }

    function invariant_registryBindingsHold() public view {
        uint256 n = deployHandler.deployCount();
        for (uint256 i = 0; i < n; i++) {
            WalletFactoryDeployHandler.DeployRecord memory rec = deployHandler.deployAt(i);
            assertEq(factory.wallets(rec.commitment), rec.wallet, "wallets salt binding broken");
            assertEq(factory.commitmentOf(rec.wallet), rec.commitment, "commitmentOf binding broken");
            assertEq(factory.walletOwner(rec.wallet), rec.to, "walletOwner binding broken");
            assertTrue(
                factory.getCommitmentIndex(rec.to, rec.commitment) != type(uint256).max,
                "owner commitment-set missing deployment"
            );
        }
    }

    function invariant_deployedAddressMatchesPrediction() public view {
        uint256 n = deployHandler.deployCount();
        for (uint256 i = 0; i < n; i++) {
            assertTrue(deployHandler.deployAt(i).addrMatch, "deployed address diverged from CREATE3 prediction");
        }
    }

    function invariant_feeSplitExact() public view {
        assertEq(address(factory).balance, deployHandler.expectedFactoryFees(), "factory retained wrong fee total");
        uint256 n = deployHandler.deployCount();
        for (uint256 i = 0; i < n; i++) {
            WalletFactoryDeployHandler.DeployRecord memory rec = deployHandler.deployAt(i);
            assertEq(rec.wallet.balance, rec.value - rec.fee, "wallet received wrong remainder");
        }
    }

    function invariant_walletLinkageHolds() public view {
        uint256 n = deployHandler.deployCount();
        for (uint256 i = 0; i < n; i++) {
            WalletFactoryDeployHandler.DeployRecord memory rec = deployHandler.deployAt(i);
            WOTSPlusImplementation wallet = WOTSPlusImplementation(payable(rec.wallet));
            assertEq(wallet.owner(), rec.to, "wallet owner diverged from deploy-time owner");
            assertEq(wallet.quipFactory(), address(factory), "wallet factory pointer diverged");
        }
    }

    function invariant_latestTracksSeedDeprecation() public view {
        assertEq(factory.getVettedCodeCount(), 1, "deploy touched the vetted set");
        if (deployHandler.seedDeprecated()) {
            assertEq(factory.latestWalletImpl(), address(0), "deprecated seed still latest");
        } else {
            assertEq(factory.latestWalletImpl(), address(walletImplementation), "live seed not latest");
        }
    }

    function invariant_creationFeeBounded() public view {
        assertLe(factory.creationFee(), factory.MAX_FEE(), "creationFee exceeds MAX_FEE");
    }

    function invariant_feeWriteTookEffect() public view {
        assertTrue(deployHandler.feeEverSet(), "no fee update ever landed");
        assertEq(factory.creationFee(), deployHandler.lastSetFee(), "live fee diverged from mirrored update");
    }

    function invariant_getWalletsMatchesMirror() public view {
        uint256 n = deployHandler.deployCount();
        for (uint256 o = 1; o <= 5; o++) {
            address owner_ = address(uint160(o));
            address[] memory addrs = factory.getWallets(owner_);
            uint256 expected;
            for (uint256 i = 0; i < n; i++) {
                if (deployHandler.deployAt(i).to == owner_) expected++;
            }
            assertEq(addrs.length, expected, "getWallets length diverged from mirror");
            for (uint256 j = 0; j < addrs.length; j++) {
                assertTrue(addrs[j] != address(0), "getWallets returned a zero slot");
                assertEq(factory.walletOwner(addrs[j]), owner_, "getWallets entry owned elsewhere");
            }
        }
    }
}
