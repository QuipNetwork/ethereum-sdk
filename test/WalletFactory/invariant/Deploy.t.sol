// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WalletFactoryTest} from "../WalletFactory.t.sol";
import {WalletFactoryDeployHandler} from "./DeployHandler.t.sol";
import {WOTSPlusImplementation} from "../../../contracts/deprecated/wots/WOTSPlusImplementation.sol";

/// forge-config: default.invariant.runs = 8
/// forge-config: default.invariant.depth = 10

contract WalletFactory_Deploy_Invariant is WalletFactoryTest {
    bytes32 internal constant IMPLEMENTATION_SLOT =
        0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
    uint256 internal constant SEED_FEE = 0.05 ether;

    WalletFactoryDeployHandler public deployHandler;
    WOTSPlusImplementation public secondImplementation;

    function setUp() public override {
        super.setUp();
        secondImplementation = new WOTSPlusImplementation(
            payable(address(factory))
        );
        vm.prank(ADMIN);
        factory.vetImplementation(address(secondImplementation));
        deployHandler = new WalletFactoryDeployHandler();
        deployHandler.initialize(
            factory,
            address(walletImplementation),
            address(secondImplementation)
        );
        vm.prank(ADMIN);
        factory.transferOwnership(address(deployHandler));
        deployHandler.fuzzSetCreationFee(SEED_FEE);
        deployHandler.fuzzDeployLatest(1, 1);
        deployHandler.fuzzDeploySpecific(0);
        deployHandler.fuzzWithdraw(0.02 ether, false);
        targetContract(address(deployHandler));

        bytes4[] memory selectors = new bytes4[](8);
        selectors[0] = WalletFactoryDeployHandler.fuzzDeployLatest.selector;
        selectors[1] = WalletFactoryDeployHandler.fuzzDeploySpecific.selector;
        selectors[2] = WalletFactoryDeployHandler.fuzzSetCreationFee.selector;
        selectors[3] = WalletFactoryDeployHandler.fuzzDeprecateSeed.selector;
        selectors[4] = WalletFactoryDeployHandler.fuzzUndeprecateSeed.selector;
        selectors[5] = WalletFactoryDeployHandler.fuzzDeprecateSecond.selector;
        selectors[6] = WalletFactoryDeployHandler
            .fuzzUndeprecateSecond
            .selector;
        selectors[7] = WalletFactoryDeployHandler.fuzzWithdraw.selector;
        targetSelector(
            FuzzSelector({addr: address(deployHandler), selectors: selectors})
        );
    }

    function test_setUp() public view override {
        assertEq(factory.owner(), address(deployHandler));
        assertEq(factory.creationFee(), SEED_FEE, "seeded fee update landed");
        assertTrue(
            deployHandler.feeEverSet(),
            "fee mirror recorded the seeded update"
        );
        assertEq(factory.getVettedCodeCount(), 2);
        assertEq(factory.latestWalletImpl(), address(secondImplementation));
        assertEq(
            deployHandler.deployCount(),
            2,
            "one seeded deploy per entry point"
        );
        assertEq(
            deployHandler.callsDeploySpecific(),
            1,
            "seeded specific deploy landed"
        );
        assertEq(deployHandler.callsWithdraw(), 1, "seeded withdrawal landed");
    }

    function invariant_registryBindingsHold() public view {
        uint256 n = deployHandler.deployCount();
        for (uint256 i = 0; i < n; i++) {
            WalletFactoryDeployHandler.DeployRecord memory rec = deployHandler
                .deployAt(i);
            assertEq(
                factory.wallets(rec.commitment),
                rec.wallet,
                "wallets salt binding broken"
            );
            assertEq(
                factory.commitmentOf(rec.wallet),
                rec.commitment,
                "commitmentOf binding broken"
            );
            assertEq(
                factory.walletOwner(rec.wallet),
                rec.to,
                "walletOwner binding broken"
            );
            assertTrue(
                factory.getCommitmentIndex(rec.to, rec.commitment) !=
                    type(uint256).max,
                "owner commitment-set missing deployment"
            );
        }
    }

    function invariant_deployedAddressMatchesPrediction() public view {
        uint256 n = deployHandler.deployCount();
        for (uint256 i = 0; i < n; i++) {
            assertTrue(
                deployHandler.deployAt(i).addrMatch,
                "deployed address diverged from CREATE3 prediction"
            );
        }
    }

    function invariant_feeSplitExact() public view {
        assertEq(
            address(factory).balance,
            deployHandler.expectedFactoryFees() -
                deployHandler.expectedWithdrawn(),
            "factory retained wrong fee total"
        );
        assertEq(
            address(deployHandler).balance,
            deployHandler.expectedHandlerBalance(),
            "factory owner balance diverged from fee flow"
        );
        uint256 n = deployHandler.deployCount();
        for (uint256 i = 0; i < n; i++) {
            WalletFactoryDeployHandler.DeployRecord memory rec = deployHandler
                .deployAt(i);
            assertEq(
                rec.wallet.balance,
                rec.value - rec.fee,
                "wallet received wrong remainder"
            );
        }
    }

    function invariant_walletLinkageHolds() public view {
        uint256 n = deployHandler.deployCount();
        for (uint256 i = 0; i < n; i++) {
            WalletFactoryDeployHandler.DeployRecord memory rec = deployHandler
                .deployAt(i);
            WOTSPlusImplementation wallet = WOTSPlusImplementation(
                payable(rec.wallet)
            );
            assertEq(
                wallet.owner(),
                rec.to,
                "wallet owner diverged from deploy-time owner"
            );
            assertEq(
                wallet.quipFactory(),
                address(factory),
                "wallet factory pointer diverged"
            );
            assertEq(
                address(
                    uint160(uint256(vm.load(rec.wallet, IMPLEMENTATION_SLOT)))
                ),
                rec.implementation,
                "proxy points to the wrong implementation"
            );
        }
    }

    function invariant_latestTracksDeprecation() public view {
        assertEq(
            factory.getVettedCodeCount(),
            2,
            "deploy touched the vetted set"
        );
        address expectedLatest = deployHandler.secondDeprecated()
            ? (
                deployHandler.seedDeprecated()
                    ? address(0)
                    : address(walletImplementation)
            )
            : address(secondImplementation);
        assertEq(
            factory.latestWalletImpl(),
            expectedLatest,
            "latest implementation diverged from mirror"
        );
        assertEq(
            deployHandler.unexpectedSuccesses(),
            0,
            "deployment bypassed implementation deprecation"
        );
        assertEq(
            deployHandler.unexpectedFailures(),
            0,
            "valid deployment unexpectedly reverted"
        );
    }

    function invariant_creationFeeBounded() public view {
        assertLe(
            factory.creationFee(),
            factory.MAX_FEE(),
            "creationFee exceeds MAX_FEE"
        );
    }

    function invariant_feeWriteTookEffect() public view {
        assertTrue(deployHandler.feeEverSet(), "no fee update ever landed");
        assertEq(
            factory.creationFee(),
            deployHandler.lastSetFee(),
            "live fee diverged from mirrored update"
        );
    }

    function invariant_getWalletsMatchesMirror() public view {
        uint256 n = deployHandler.deployCount();
        for (uint256 o = 1; o <= 5; o++) {
            address owner_ = vm.addr(o);
            address[] memory addrs = factory.getWallets(owner_);
            uint256 expected;
            for (uint256 i = 0; i < n; i++) {
                if (deployHandler.deployAt(i).to == owner_) expected++;
            }
            assertEq(
                addrs.length,
                expected,
                "getWallets length diverged from mirror"
            );
            for (uint256 j = 0; j < addrs.length; j++) {
                bool found;
                for (uint256 i = 0; i < n; i++) {
                    WalletFactoryDeployHandler.DeployRecord
                        memory record = deployHandler.deployAt(i);
                    if (record.to == owner_ && record.wallet == addrs[j]) {
                        found = true;
                        break;
                    }
                }
                assertTrue(found, "getWallets returned an unrecorded wallet");
                for (uint256 k = 0; k < j; k++) {
                    assertTrue(
                        addrs[k] != addrs[j],
                        "getWallets returned a duplicate wallet"
                    );
                }
            }
        }
    }

    function test_deploymentActionsReachBothEntryPointsAndDeprecationRecovery()
        public
    {
        uint256 originalCount = deployHandler.deployCount();
        deployHandler.fuzzDeprecateSecond();
        assertEq(factory.latestWalletImpl(), address(walletImplementation));
        deployHandler.fuzzDeployLatest(4, 4);
        deployHandler.fuzzDeploySpecific(1);
        assertEq(deployHandler.deployCount(), originalCount + 1);
        deployHandler.fuzzUndeprecateSecond();
        assertEq(factory.latestWalletImpl(), address(secondImplementation));
        deployHandler.fuzzUndeprecateSecond();
        assertEq(deployHandler.callsUndeprecate(), 1);
        deployHandler.fuzzDeprecateSeed();
        assertEq(deployHandler.callsDeprecate(), 2);
        deployHandler.fuzzDeprecateSeed();
        assertEq(deployHandler.callsDeprecate(), 3);
        deployHandler.fuzzDeploySpecific(0);
        assertEq(deployHandler.deployCount(), originalCount + 1);

        deployHandler.fuzzSetCreationFee(0.02 ether);
        deployHandler.fuzzDeploySpecific(1);
        assertEq(deployHandler.deployCount(), originalCount + 2);
        deployHandler.fuzzWithdraw(0.03 ether, false);
        deployHandler.fuzzWithdraw(0, true);
        assertEq(deployHandler.callsDeploy(), 2);
        assertEq(deployHandler.callsDeploySpecific(), 2);
        assertEq(deployHandler.callsDeprecate(), 3);
        assertEq(deployHandler.callsUndeprecate(), 1);
        assertEq(deployHandler.callsWithdraw(), 2);
        assertEq(factory.creationFee(), 0.02 ether);
        assertEq(deployHandler.revertCount(), 4);
        invariant_walletLinkageHolds();
        invariant_getWalletsMatchesMirror();
        invariant_feeSplitExact();
        invariant_latestTracksDeprecation();
    }
}
