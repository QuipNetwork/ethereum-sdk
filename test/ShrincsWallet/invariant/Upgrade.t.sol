// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {ShrincsWalletTest} from "../ShrincsWallet.t.sol";
import {ShrincsWalletUpgradeHandler} from "./UpgradeHandler.t.sol";
import {ShrincsWalletCodec as Codec} from "../../../contracts/shrincs/ShrincsWalletCodec.sol";
import {SHRINCS} from "@quip.network/hashsigs-solidity-0.2.0/contracts/SHRINCS.sol";
import {ShrincsWalletHarness} from "../../harness/ShrincsWalletHarness.sol";
import {SHRINCSTestSigner} from "@quip.network/hashsigs-solidity-0.2.0/test/helpers/SHRINCSTestSigner.sol";

/// forge-config: default.invariant.runs = 8
/// forge-config: default.invariant.depth = 16

/// @title ShrincsWallet — Upgrade Invariant Suite (valid-signature chain + migrate tail)
/// @dev Stateful fuzz over the `upgradeToAndCall` valid path. The suite
///      pre-deploys three fresh implementations (each vetted individually —
///      every deployment bakes its own address into the `_SELF` immutable,
///      so codehashes are distinct), pre-signs a
///      CHAIN of upgrade authorizations — entries 0 and 1 plain, entry 2
///      migrating to fresh bundles — then fuzzes replay order. Entry `k`
///      lands if and only if entries `0..k-1` already did, so successes
///      always form the prefix `{0..m-1}`: the nonce, implementation slot,
///      epoch, installed-commitment, and leaf-accounting invariants replay
///      that prefix off the handler mirror.
///
///      The wallet's blob-nonce gate fires before any verification, so every
///      stale replay reverts with the exact `StaleActionNonce(live, k)` the
///      handler asserts; any other reason fails `invariant_noBadReason`.
contract ShrincsWallet_Upgrade_Invariant is ShrincsWalletTest {
    bytes32 internal constant IMPL_SLOT =
        0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

    uint256 internal constant CHAIN_LEN = 3;

    ShrincsWalletUpgradeHandler public upHandler;
    uint256 internal upInitialNonce;
    address[3] internal chainImpls;
    bytes32 internal migrateCommitment;
    bytes32 internal migrateErc1271Commitment;
    SHRINCS.PublicKey internal migrateMainPk;
    SHRINCS.PublicKey internal migrateErc1271Pk;

    /// @dev Signs entry `k`: UPGRADE over (impl, flag, migrator) bound to
    ///      blob nonce `k` at epoch 0, authorized at leaf `SIGN_BASE + 1 + k`.
    function _signUpgradeEntry(
        address impl,
        bool shouldMigrate,
        bytes memory migrator,
        uint256 k
    ) internal view returns (SHRINCS.Signature memory) {
        bytes32 payloadHash = Codec.upgradePayloadHash(impl, shouldMigrate, keccak256(migrator));
        SHRINCS.ActionContext memory ctx = Codec.buildActionContext(
            wallet.exposed_shrincsDomainSeparator(),
            upInitialNonce + k,
            0,
            Codec.ACTION_UPGRADE,
            payloadHash
        );
        return _signStatefulActionWith(mainKey, mainCommitment, ctx, SIGN_BASE + 1 + uint32(k));
    }

    function _implSlot() internal view returns (address) {
        return address(uint160(uint256(vm.load(WALLET, IMPL_SLOT))));
    }

    function setUp() public override {
        super.setUp();
        upInitialNonce = wallet.actionNonce();
        for (uint256 k = 0; k < CHAIN_LEN; k++) {
            chainImpls[k] =
                address(new ShrincsWalletHarness(payable(address(factory)), address(shrincsVerifier)));
        }
        // Each deployment bakes its own address into the `_SELF` immutable,
        // so every candidate has a distinct codehash and needs its own
        // vetting (one shared vetting would leave the others unvetted).
        vm.startPrank(ADMIN);
        for (uint256 k = 0; k < CHAIN_LEN; k++) {
            factory.vetImplementation(chainImpls[k]);
        }
        vm.stopPrank();

        (bytes memory migrator, bytes32 freshCommitment) = _freshInitPayload("upgrade-chain-migrate");
        migrateCommitment = freshCommitment;
        migrateErc1271Pk = _freshErc1271Pk("upgrade-chain-migrate");
        migrateErc1271Commitment = _commitment32(migrateErc1271Pk);
        (, migrateMainPk, ) = _chainFreshMain("upgrade-chain-migrate");

        upHandler = new ShrincsWalletUpgradeHandler();
        upHandler.initialize(wallet, OWNER);
        for (uint256 k = 0; k < CHAIN_LEN; k++) {
            bool tail = k == CHAIN_LEN - 1;
            bytes memory mig = tail ? migrator : bytes("");
            upHandler.pushValidUpgrade(
                chainImpls[k],
                _mainPk(),
                _signUpgradeEntry(chainImpls[k], tail, mig, k),
                tail,
                mig,
                upInitialNonce + k,
                _probeVectorFor(chainImpls[k])
            );
        }
        // Seeded prefix: land entry 0, then replay it for the deterministic
        // stale (blob nonce 0 against live nonce 1). The remaining chain
        // stays aligned — entry k binds blob nonce k — and the suite is never
        // vacuous: a mutant that breaks all upgrades fails `test_setUp`
        // instead of passing on an empty mirror.
        upHandler.fuzzUpgradeReplay(0);
        upHandler.fuzzUpgradeReplay(0);
        targetContract(address(upHandler));
        bytes4[] memory selectors = new bytes4[](1);
        selectors[0] = ShrincsWalletUpgradeHandler.fuzzUpgradeReplay.selector;
        targetSelector(FuzzSelector({addr: address(upHandler), selectors: selectors}));
    }

    /// @dev Re-derives the migrate tail's fresh main bundle (same deterministic
    ///      seed `_freshInitPayload` used, so this is the installed bundle).
    function _chainFreshMain(bytes memory seed)
        internal
        view
        returns (SHRINCS.SigningKey memory key, SHRINCS.PublicKey memory pk, bool ok)
    {
        (key, pk, ok) = SHRINCSTestSigner.keygen(seed, MAX_SIG);
        require(ok, "chain fresh keygen");
    }

    function test_setUp() public view override {
        assertEq(upHandler.poolLength(), CHAIN_LEN, "upgrade chain seeded");
        for (uint256 k = 0; k < CHAIN_LEN; k++) {
            assertTrue(
                factory.getVettedCodeIndex(chainImpls[k].codehash) != type(uint256).max,
                "chain impl codehash vetted"
            );
        }
        assertEq(upHandler.callsUpgrade(), 1, "seeded entry landed");
        assertEq(upHandler.staleCount(), 1, "seeded duplicate reported stale blob nonce");
        assertEq(_implSlot(), chainImpls[0], "impl slot holds the seeded upgrade");
        assertEq(wallet.actionNonce(), upInitialNonce + 1, "seeded landing advanced the nonce");
        assertEq(wallet.keyVersion(), 0, "plain seeded upgrade keeps the epoch");
        assertEq(wallet.statefulLeavesUsed(), 1, "seeded landing consumed its leaf");
    }

    /// @dev Every landing upgrade advances the nonce by exactly one.
    function invariant_nonceTracksSuccesses() public view {
        assertEq(
            wallet.actionNonce(),
            upInitialNonce + upHandler.callsUpgrade(),
            "nonce diverged from upgrade success count"
        );
    }

    /// @dev Successes always form the prefix `{0..m-1}`, and the ERC-1967
    ///      slot always points at the last landed entry's implementation.
    function invariant_implSlotTracksPrefix() public view {
        uint256 m = upHandler.successLength();
        assertEq(m, upHandler.callsUpgrade(), "success mirror diverged from counter");
        for (uint256 i = 0; i < m; i++) {
            assertLt(upHandler.successAt(i), m, "success outside the landed prefix");
        }
        address expected = m == 0 ? address(walletImplementation) : upHandler.entryImpl(m - 1);
        assertEq(_implSlot(), expected, "implementation slot left the landed prefix");
    }

    /// @dev The migrating tail (entry 2) bumps the epoch and installs fresh
    ///      bundles; plain upgrades touch neither. The tail lands only as
    ///      the full prefix, so `m == 3` is exactly "migrated".
    function invariant_epochAndCommitmentsTrackTail() public view {
        uint256 m = upHandler.successLength();
        bool migrated = m == CHAIN_LEN;
        assertEq(wallet.keyVersion(), migrated ? 1 : 0, "epoch diverged from migrate tail");
        assertEq(
            wallet.getShrincsPublicKeyCommitment(),
            migrated ? migrateCommitment : mainCommitment,
            "main commitment diverged from migrate tail"
        );
        assertEq(
            wallet.getErc1271PublicKeyCommitment(),
            migrated ? migrateErc1271Commitment : erc1271Commitment,
            "1271 commitment diverged from migrate tail"
        );
    }

    /// @dev Each landing upgrade consumes its auth leaf; the migrating tail
    ///      additionally resets the epoch bitmap. Used is therefore the
    ///      landed count — or zero after a migration.
    function invariant_usedTracksPrefix() public view {
        uint256 m = upHandler.successLength();
        assertEq(wallet.statefulLeavesUsed(), m == CHAIN_LEN ? 0 : m, "used counter left the landed prefix");
    }

    /// @dev The migrating tail installs genuinely fresh trees: they read
    ///      spent afterwards, while the seed trees stay spent throughout.
    function invariant_migratedTreesSpent() public view {
        uint256 m = upHandler.successLength();
        if (m != CHAIN_LEN) return;
        assertTrue(
            wallet.harness_isStatefulTreeSpent(_treeId(migrateMainPk.statefulPublicKey)),
            "migrated main stateful tree not spent"
        );
        assertTrue(
            wallet.harness_isStatelessTreeSpent(_statelessId(migrateMainPk)),
            "migrated main stateless tree not spent"
        );
        assertTrue(
            wallet.harness_isStatefulTreeSpent(_treeId(migrateErc1271Pk.statefulPublicKey)),
            "migrated 1271 stateful tree not spent"
        );
        assertTrue(
            wallet.harness_isStatelessTreeSpent(_statelessId(migrateErc1271Pk)),
            "migrated 1271 stateless tree not spent"
        );
    }

    /// @dev Stale replays must revert with the exact `StaleActionNonce` the
    ///      blob carries. Any other reason fails here.
    function invariant_noBadReason() public view {
        assertEq(upHandler.badReasonCount(), 0, "upgradeToAndCall reverted with an unexpected reason");
    }

    /// @dev Upgrades touch neither ownership nor the factory linkage.
    function invariant_upgradeTouchesNothingElse() public view {
        assertEq(wallet.owner(), OWNER, "wallet owner drifted");
        assertEq(wallet.maxSignatures(), MAX_SIG, "maxSignatures drifted");
    }
}
