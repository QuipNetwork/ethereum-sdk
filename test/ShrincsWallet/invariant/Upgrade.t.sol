// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {ShrincsWalletTest} from "../ShrincsWallet.t.sol";
import {ShrincsWalletUpgradeHandler} from "./support/UpgradeHandler.t.sol";
import {ShrincsWalletCodec as Codec} from "../../../contracts/shrincs/ShrincsWalletCodec.sol";
import {IShrincsWallet} from "../../../contracts/shrincs/interfaces/IShrincsWallet.sol";
import {SHRINCS} from "@quip.network/hashsigs-solidity-0.2.0/contracts/SHRINCS.sol";
import {ShrincsWalletHarness} from "../../harness/ShrincsWalletHarness.sol";
import {SHRINCSTestSigner} from "@quip.network/hashsigs-solidity-0.2.0/test/helpers/SHRINCSTestSigner.sol";

/// forge-config: default.invariant.runs = 8
/// forge-config: default.invariant.depth = 16

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

    function _signUpgradeEntry(
        address impl,
        bool shouldMigrate,
        bytes memory migrator,
        uint32 k
    ) internal view returns (SHRINCS.Signature memory) {
        bytes32 payloadHash = Codec.upgradePayloadHash(
            impl,
            shouldMigrate,
            keccak256(migrator)
        );
        SHRINCS.ActionContext memory ctx = Codec.buildActionContext(
            wallet.exposed_shrincsDomainSeparator(),
            upInitialNonce + k,
            0,
            Codec.ACTION_UPGRADE,
            payloadHash
        );
        return
            _signStatefulActionWith(
                mainKey,
                mainCommitment,
                ctx,
                SIGN_BASE + 1 + k
            );
    }

    function _implSlot() internal view returns (address) {
        return address(uint160(uint256(vm.load(WALLET, IMPL_SLOT))));
    }

    function setUp() public override {
        super.setUp();
        upInitialNonce = wallet.actionNonce();
        for (uint32 k = 0; k < CHAIN_LEN; k++) {
            chainImpls[k] = address(
                new ShrincsWalletHarness(
                    payable(address(factory)),
                    address(shrincsVerifier)
                )
            );
        }
        vm.startPrank(ADMIN);
        for (uint32 k = 0; k < CHAIN_LEN; k++) {
            factory.vetImplementation(chainImpls[k]);
        }
        vm.stopPrank();

        (bytes memory migrator, bytes32 freshCommitment) = _freshInitPayload(
            "upgrade-chain-migrate"
        );
        migrateCommitment = freshCommitment;
        migrateErc1271Pk = _freshErc1271Pk("upgrade-chain-migrate");
        migrateErc1271Commitment = _commitment32(migrateErc1271Pk);
        (, migrateMainPk, ) = _chainFreshMain("upgrade-chain-migrate");

        upHandler = new ShrincsWalletUpgradeHandler();
        upHandler.initialize(wallet, OWNER);
        for (uint32 k = 0; k < CHAIN_LEN; k++) {
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
        upHandler.fuzzUpgradeReplay(0);
        upHandler.fuzzUpgradeReplay(0);
        targetContract(address(upHandler));
        bytes4[] memory selectors = new bytes4[](1);
        selectors[0] = ShrincsWalletUpgradeHandler.fuzzUpgradeReplay.selector;
        targetSelector(
            FuzzSelector({addr: address(upHandler), selectors: selectors})
        );
    }

    function _chainFreshMain(
        bytes memory seed
    )
        internal
        view
        returns (
            SHRINCS.SigningKey memory key,
            SHRINCS.PublicKey memory pk,
            bool ok
        )
    {
        (key, pk, ok) = SHRINCSTestSigner.keygen(seed, MAX_SIG);
        require(ok, "chain fresh keygen");
    }

    function test_setUp() public view override {
        assertEq(upHandler.poolLength(), CHAIN_LEN, "upgrade chain seeded");
        for (uint256 k = 0; k < CHAIN_LEN; k++) {
            assertTrue(
                factory.getVettedCodeIndex(chainImpls[k].codehash) !=
                    type(uint256).max,
                "chain impl codehash vetted"
            );
        }
        assertEq(upHandler.callsUpgrade(), 1, "seeded entry landed");
        assertEq(
            upHandler.staleCount(),
            1,
            "seeded duplicate reported stale blob nonce"
        );
        assertEq(
            _implSlot(),
            chainImpls[0],
            "impl slot holds the seeded upgrade"
        );
        assertEq(
            wallet.actionNonce(),
            upInitialNonce + 1,
            "seeded landing advanced the nonce"
        );
        assertEq(
            wallet.keyVersion(),
            0,
            "plain seeded upgrade keeps the epoch"
        );
        assertEq(
            wallet.statefulLeavesUsed(),
            1,
            "seeded landing consumed its leaf"
        );
    }

    function invariant_nonceTracksSuccesses() public view {
        assertEq(
            wallet.actionNonce(),
            upInitialNonce + upHandler.callsUpgrade(),
            "nonce diverged from upgrade success count"
        );
    }

    function invariant_implSlotTracksPrefix() public view {
        uint256 m = upHandler.successLength();
        assertEq(
            m,
            upHandler.callsUpgrade(),
            "success mirror diverged from counter"
        );
        for (uint256 i = 0; i < m; i++) {
            assertEq(
                upHandler.successAt(i),
                i,
                "upgrade successes skipped an entry"
            );
        }
        address expected = m == 0
            ? address(walletImplementation)
            : upHandler.entryImpl(m - 1);
        assertEq(
            _implSlot(),
            expected,
            "implementation slot left the landed prefix"
        );
    }

    function invariant_epochAndCommitmentsTrackTail() public view {
        uint256 m = upHandler.successLength();
        bool migrated = m == CHAIN_LEN;
        assertEq(
            wallet.keyVersion(),
            migrated ? 1 : 0,
            "epoch diverged from migrate tail"
        );
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

    function invariant_usedTracksPrefix() public view {
        uint256 m = upHandler.successLength();
        assertEq(
            wallet.statefulLeavesUsed(),
            m == CHAIN_LEN ? 0 : m,
            "used counter left the landed prefix"
        );
    }

    function invariant_bitmapTracksPrefix() public view {
        uint256 landed = upHandler.successLength();
        for (uint32 leaf = 0; leaf <= MAX_SIG + 1; leaf++) {
            bool expectedUsed = landed < CHAIN_LEN &&
                leaf > SIGN_BASE &&
                leaf <= SIGN_BASE + landed;
            assertEq(
                wallet.isStatefulLeafUsed(leaf),
                expectedUsed,
                "upgrade consumed an unexpected leaf"
            );
        }
    }

    function invariant_migratedTreesSpent() public view {
        uint256 m = upHandler.successLength();
        if (m != CHAIN_LEN) return;
        assertTrue(
            wallet.harness_isStatefulTreeSpent(
                _treeId(migrateMainPk.statefulPublicKey)
            ),
            "migrated main stateful tree not spent"
        );
        assertTrue(
            wallet.harness_isStatelessTreeSpent(_statelessId(migrateMainPk)),
            "migrated main stateless tree not spent"
        );
        assertTrue(
            wallet.harness_isStatefulTreeSpent(
                _treeId(migrateErc1271Pk.statefulPublicKey)
            ),
            "migrated 1271 stateful tree not spent"
        );
        assertTrue(
            wallet.harness_isStatelessTreeSpent(_statelessId(migrateErc1271Pk)),
            "migrated 1271 stateless tree not spent"
        );
    }

    function invariant_noBadReason() public view {
        assertEq(
            upHandler.badReasonCount(),
            0,
            "upgradeToAndCall reverted with an unexpected reason"
        );
    }

    function invariant_upgradeTouchesNothingElse() public view {
        assertEq(wallet.owner(), OWNER, "wallet owner drifted");
        assertEq(wallet.maxSignatures(), MAX_SIG, "maxSignatures drifted");
    }

    function test_upgradeChainLandsMigration() public {
        for (uint256 i = 1; i < CHAIN_LEN; i++) {
            upHandler.fuzzUpgradeReplay(i);
            assertEq(upHandler.callsUpgrade(), i + 1, "next upgrade rejected");
            assertEq(upHandler.successAt(i), i, "upgrade landed out of order");
            assertEq(
                _implSlot(),
                chainImpls[i],
                "implementation did not change"
            );
        }

        assertEq(upHandler.badReasonCount(), 0, "valid upgrade reverted");
        assertEq(wallet.actionNonce(), upInitialNonce + CHAIN_LEN);
        assertEq(wallet.keyVersion(), 1);
        assertEq(wallet.getShrincsPublicKeyCommitment(), migrateCommitment);
        assertEq(
            wallet.getErc1271PublicKeyCommitment(),
            migrateErc1271Commitment
        );
        assertEq(wallet.statefulLeavesUsed(), 0);
        invariant_migratedTreesSpent();

        address sink = vm.addr(0xD003);
        uint256 value = 0.1 ether;
        vm.deal(WALLET, 1 ether);
        bytes32 payloadHash = Codec.executePayloadHash(
            sink,
            value,
            keccak256(""),
            0
        );
        SHRINCS.ActionContext memory oldContext = Codec.buildActionContext(
            wallet.exposed_shrincsDomainSeparator(),
            upInitialNonce + CHAIN_LEN,
            1,
            Codec.ACTION_EXECUTE,
            payloadHash
        );
        SHRINCS.Signature memory oldSignature = _signStatefulActionWith(
            mainKey,
            mainCommitment,
            oldContext,
            SIGN_BASE + 4
        );
        vm.prank(OWNER);
        vm.expectRevert(IShrincsWallet.InvalidSignature.selector);
        wallet.execute(_mainPk(), oldSignature, sink, value, "", 0);
        assertEq(wallet.actionNonce(), upInitialNonce + CHAIN_LEN);

        (SHRINCS.SigningKey memory newKey, , ) = _chainFreshMain(
            "upgrade-chain-migrate"
        );
        SHRINCS.ActionContext memory newContext = Codec.buildActionContext(
            wallet.exposed_shrincsDomainSeparator(),
            upInitialNonce + CHAIN_LEN,
            1,
            Codec.ACTION_EXECUTE,
            payloadHash
        );
        SHRINCS.Signature memory newSignature = _signStatefulActionWith(
            newKey,
            migrateCommitment,
            newContext,
            SIGN_BASE + 1
        );
        vm.prank(OWNER);
        wallet.execute(migrateMainPk, newSignature, sink, value, "", 0);
        assertEq(wallet.actionNonce(), upInitialNonce + CHAIN_LEN + 1);
        assertEq(wallet.statefulLeavesUsed(), 1);
        for (uint32 leaf = 0; leaf <= MAX_SIG + 1; leaf++) {
            assertEq(
                wallet.isStatefulLeafUsed(leaf),
                leaf == SIGN_BASE + 1,
                "post-migration execute marked an unexpected leaf"
            );
        }
        assertEq(WALLET.balance, 1 ether - value);
        assertEq(sink.balance, value);
    }
}
