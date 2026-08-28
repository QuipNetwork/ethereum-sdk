// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {Vm} from "forge-std-1.14.0/Vm.sol";
import {SHRINCS} from "@quip.network/hashsigs-solidity-0.2.0/contracts/SHRINCS.sol";
import {SPHINCSPlusC} from "@quip.network/hashsigs-solidity-0.2.0/contracts/SPHINCSPlusC.sol";
import {UXMSS} from "@quip.network/hashsigs-solidity-0.2.0/contracts/UXMSS.sol";
import {HashSuite} from "shrincs-hash/HashSuite.sol";
import {SHRINCSParams} from "shrincs-profile/SHRINCSParams.sol";
import {SHRINCSTestSigner} from "@quip.network/hashsigs-solidity-0.2.0/test/helpers/SHRINCSTestSigner.sol";
import {IShrincsWallet} from "../../../contracts/shrincs/interfaces/IShrincsWallet.sol";
import {ShrincsWalletTest} from "../ShrincsWallet.t.sol";

/// @dev Behavior tests for `migrate`. Like `initialize` it verifies NO signature, so its success
///      path and reverts are fully testable; gating to the `upgradeToAndCall` transient context is
///      driven via the harness helper `harness_migrateInUpgradeContext`.
contract ShrincsWallet_migrate is ShrincsWalletTest {
    function test_migrate_reinstallsAndResets() public {
        // Dirty the per-epoch counter first, so the reset is observable.
        wallet.harness_markLeafUsed(SIGN_BASE + 1);
        assertEq(wallet.statefulLeavesUsed(), 1);

        (bytes memory payload, bytes32 freshCommitment,) = _freshInitPayload("migrate-fresh-bundle");
        wallet.harness_migrateInUpgradeContext(payload);

        assertEq(wallet.keyVersion(), 1, "keyVersion bumped");
        assertEq(wallet.statefulLeavesUsed(), 0, "leaves-used reset");
        assertEq(wallet.getShrincsPublicKeyCommitment(), freshCommitment, "fresh bundle installed");
        // Fresh epoch ⇒ the previously-marked leaf is unused again under keyVersion 1.
        assertFalse(wallet.isStatefulLeafUsed(SIGN_BASE + 1), "fresh namespace");
    }

    function test_migrate_doesNotAdvanceActionNonce() public {
        wallet.harness_setNonce(5);
        (bytes memory payload,,) = _freshInitPayload("migrate-fresh-bundle");
        wallet.harness_migrateInUpgradeContext(payload);
        // The keyVersion bump already invalidates every outstanding context; the nonce is
        // deliberately untouched by migration.
        assertEq(wallet.actionNonce(), 5, "migrate leaves the action nonce unchanged");
    }

    function test_migrate_emitsWalletMigrated() public {
        vm.recordLogs();
        (bytes memory payload, bytes32 freshCommitment,) = _freshInitPayload("migrate-fresh-bundle");
        wallet.harness_migrateInUpgradeContext(payload);

        Vm.Log[] memory logs = vm.getRecordedLogs();
        bool found;
        for (uint256 i; i < logs.length; i++) {
            if (logs[i].topics[0] == IShrincsWallet.WalletMigrated.selector) {
                found = true;
                assertEq(logs[i].topics[1], freshCommitment, "commitment indexed");
            }
        }
        assertTrue(found, "WalletMigrated not emitted");
    }

    function test_migrate_revertsWhen_notUpgrading() public {
        // Called directly (outside the transient upgrade guard) it must revert.
        vm.expectRevert(IShrincsWallet.NotUpgrading.selector);
        wallet.migrate(_validInitPayload());
    }

    function test_migrate_revertsWhen_zeroErc1271Commitment() public {
        vm.expectRevert(IShrincsWallet.ZeroErc1271Commitment.selector);
        wallet.harness_migrateInUpgradeContext(_zeroErc1271Payload());
    }

    function test_migrate_revertsWhen_unsupportedHashSuite() public {
        vm.expectRevert(IShrincsWallet.UnsupportedHashSuite.selector);
        wallet.harness_migrateInUpgradeContext(_unsupportedHashSuitePayload());
    }

    function test_migrate_revertsWhen_unsupportedErc1271HashSuite() public {
        vm.expectRevert(IShrincsWallet.UnsupportedHashSuite.selector);
        wallet.harness_migrateInUpgradeContext(_unsupportedErc1271HashSuitePayload());
    }

    function test_migrate_revertsWhen_invalidBundle() public {
        vm.expectRevert(IShrincsWallet.CommitmentMismatch.selector);
        wallet.harness_migrateInUpgradeContext(_corruptBundlePayload());
    }

    function test_migrate_revertsWhen_declaredCommitmentMismatch() public {
        vm.expectRevert(IShrincsWallet.CommitmentMismatch.selector);
        wallet.harness_migrateInUpgradeContext(_wrongDeclaredCommitmentPayload());
    }

    function test_migrate_revertsWhen_zeroMaxSignatures() public {
        vm.expectRevert(IShrincsWallet.ZeroMaxSignatures.selector);
        wallet.harness_migrateInUpgradeContext(_zeroMaxSignaturesPayload());
    }

    /// @dev Proves migrate actually INSTALLS the supplied bundle (not a no-op on existing state):
    ///      migrates to a freshly generated bundle plus a distinct ERC-1271 commitment, and asserts
    ///      the new main commitment and ERC-1271 commitment are installed.
    function test_migrate_installsSuppliedBundle() public {
        (, SHRINCS.PublicKey memory next, bool ok) = SHRINCSTestSigner.keygen("migrated-main-key", MAX_SIG);
        assertTrue(ok, "next keygen");
        bytes32 nextCommit = _commitment32(next);
        bytes32 newErc1271 = keccak256("migrated-erc1271");
        assertTrue(nextCommit != wallet.getShrincsPublicKeyCommitment(), "precondition: a different bundle");

        bytes memory payload = _buildInitPayload(
            nextCommit,
            keccak256("indexing-handle"), // top-level pkSeed slot — ignored by migrate
            next,
            HashSuite.HASH_SUITE_ID,
            newErc1271,
            HashSuite.HASH_SUITE_ID
        );
        wallet.harness_migrateInUpgradeContext(payload);

        assertEq(wallet.getShrincsPublicKeyCommitment(), nextCommit, "new main commitment installed");
        assertEq(wallet.getErc1271Commitment(), newErc1271, "new erc1271 commitment installed");
        assertEq(wallet.getErc1271HashSuite(), HashSuite.HASH_SUITE_ID, "erc1271 suite installed");
        assertEq(wallet.keyVersion(), 1, "epoch bumped");
    }

    /*──────────────────── spent-tree tracking ────────────────────*/

    function test_migrate_spendsBothInstalledTrees() public {
        (bytes memory payload,, SHRINCS.PublicKey memory fresh) = _freshInitPayload("migrate-spends");
        _assertTreesUnspent(fresh);

        wallet.harness_migrateInUpgradeContext(payload);

        _assertTreesSpent(fresh);
    }

    function test_migrate_revertsWhen_currentBundle() public {
        vm.expectRevert(
            abi.encodeWithSelector(IShrincsWallet.StatefulTreeSpent.selector, _treeId(mainPk.statefulPublicKey))
        );
        wallet.harness_migrateInUpgradeContext(_validInitPayload());
    }

    function test_migrate_revertsWhen_statelessTreeCarriedForward() public {
        // Fresh stateful tree, current stateless tree: migration is strictly fresh on both halves.
        (, SHRINCS.PublicKey memory pk, bool ok) = SHRINCSTestSigner.keygen("migrate-carry-stateless", MAX_SIG);
        require(ok, "keygen");
        pk.pkSeed = mainPk.pkSeed;
        pk.hypertreeRoot = mainPk.hypertreeRoot;
        bytes32 c = SHRINCS.publicKeyCommitmentFromParts(pk.statefulPublicKey, pk.pkSeed, pk.hypertreeRoot);
        pk.publicKeyCommitment = abi.encodePacked(c);
        bytes memory payload = _buildInitPayload(
            c, _toBytes32(pk.pkSeed), pk, HashSuite.HASH_SUITE_ID, erc1271Commitment, HashSuite.HASH_SUITE_ID
        );
        vm.expectRevert(abi.encodeWithSelector(IShrincsWallet.StatelessTreeSpent.selector, _statelessId(mainPk)));
        wallet.harness_migrateInUpgradeContext(payload);
    }

    function test_migrate_revertsWhen_cyclingBackToEarlierBundle() public {
        (bytes memory fresh,,) = _freshInitPayload("migrate-cycle-B");
        wallet.harness_migrateInUpgradeContext(fresh);
        assertEq(wallet.keyVersion(), 1);
        // Back to the original bundle: its stateful tree was spent at install.
        vm.expectRevert(
            abi.encodeWithSelector(IShrincsWallet.StatefulTreeSpent.selector, _treeId(mainPk.statefulPublicKey))
        );
        wallet.harness_migrateInUpgradeContext(_validInitPayload());
    }
}
