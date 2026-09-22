// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WalletFactoryTest} from "../WalletFactory.t.sol";
import {WalletFactoryDeployHandler} from "./DeployHandler.t.sol";
import {WOTSPlusImplementation} from "../../../contracts/deprecated/wots/WOTSPlusImplementation.sol";

/// forge-config: default.invariant.runs = 8
/// forge-config: default.invariant.depth = 10

/// @title WalletFactory — Deploy Invariant Suite (deploy registry + fee split)
/// @dev Stateful fuzz over wallet deployment (`deployLatestWalletProxy` and
///      `deploySpecificWalletProxy`) interleaved with creation-fee updates
///      and seed deprecate/undeprecate cycles. Every successful deploy is
///      mirrored with its fee/value context; invariants replay the full
///      registry binding (`wallets`, `commitmentOf`, `walletOwner`, owner
///      commitment-sets, `getWallets`), the fee split (factory keeps exactly
///      the live creation fee, the wallet receives the remainder), and the
///      wallet-to-factory linkage (`owner`, `quipFactory`).
///
///      setUp seeds one fee update and one deploy per entry point so the
///      suite is never vacuous: a mutant that disables deploys or fee writes
///      fails `test_setUp` deterministically rather than passing on an empty
///      mirror.
///
///      Deploy calls carry a full WOTS+ init payload, so this suite runs a
///      scoped budget (8 runs x 10 calls) rather than the foundry.toml
///      defaults. `fail_on_revert` stays false: underfunded and
///      no-active-implementation attempts are expected reverts.
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

    /// @dev Every mirrored deploy resolves through all four registry views:
    ///      salt -> wallet, wallet -> commitment, wallet -> owner, and the
    ///      owner's commitment-set membership.
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

    /// @dev CREATE3 addressing is deterministic per (commitment, factory):
    ///      the returned address must equal the prediction on every deploy.
    function invariant_deployedAddressMatchesPrediction() public view {
        uint256 n = deployHandler.deployCount();
        for (uint256 i = 0; i < n; i++) {
            assertTrue(deployHandler.deployAt(i).addrMatch, "deployed address diverged from CREATE3 prediction");
        }
    }

    /// @dev Fee split: the factory retains exactly the creation fee live at
    ///      deploy time, the wallet receives the remainder. The factory
    ///      balance therefore equals the sum of fees charged across all
    ///      mirrored deploys — no more, no less.
    function invariant_feeSplitExact() public view {
        assertEq(address(factory).balance, deployHandler.expectedFactoryFees(), "factory retained wrong fee total");
        uint256 n = deployHandler.deployCount();
        for (uint256 i = 0; i < n; i++) {
            WalletFactoryDeployHandler.DeployRecord memory rec = deployHandler.deployAt(i);
            assertEq(rec.wallet.balance, rec.value - rec.fee, "wallet received wrong remainder");
        }
    }

    /// @dev Wallet-to-factory linkage: every deployed wallet answers its
    ///      deploy-time owner and points back at this factory.
    function invariant_walletLinkageHolds() public view {
        uint256 n = deployHandler.deployCount();
        for (uint256 i = 0; i < n; i++) {
            WalletFactoryDeployHandler.DeployRecord memory rec = deployHandler.deployAt(i);
            WOTSPlusImplementation wallet = WOTSPlusImplementation(payable(rec.wallet));
            assertEq(wallet.owner(), rec.to, "wallet owner diverged from deploy-time owner");
            assertEq(wallet.quipFactory(), address(factory), "wallet factory pointer diverged");
        }
    }

    /// @dev The seed is the only vetted impl: while it is live it must be
    ///      the latest, while deprecated no latest may exist. Deploys never
    ///      touch the vetted set itself.
    function invariant_latestTracksSeedDeprecation() public view {
        assertEq(factory.getVettedCodeCount(), 1, "deploy touched the vetted set");
        if (deployHandler.seedDeprecated()) {
            assertEq(factory.latestWalletImpl(), address(0), "deprecated seed still latest");
        } else {
            assertEq(factory.latestWalletImpl(), address(walletImplementation), "live seed not latest");
        }
    }

    /// @dev The fee cap holds at every boundary, including interleaved
    ///      mid-campaign updates.
    function invariant_creationFeeBounded() public view {
        assertLe(factory.creationFee(), factory.MAX_FEE(), "creationFee exceeds MAX_FEE");
    }

    /// @dev The last successful fee update took effect verbatim: the live
    ///      fee always equals the handler's mirror. A deleted, constant, or
    ///      gated fee write diverges here.
    function invariant_feeWriteTookEffect() public view {
        assertTrue(deployHandler.feeEverSet(), "no fee update ever landed");
        assertEq(factory.creationFee(), deployHandler.lastSetFee(), "live fee diverged from mirrored update");
    }

    /// @dev The `getWallets` view resolves every owner's commitment-set
    ///      through `wallets`: for each fuzz owner the returned set equals
    ///      the mirrored deploys addressed to them — no more, no fewer, no
    ///      zero slots.
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
