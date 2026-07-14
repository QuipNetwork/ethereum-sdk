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
        wallet.harness_markLeafUsed(1);
        assertEq(wallet.statefulLeavesUsed(), 1);

        wallet.harness_migrateInUpgradeContext(_validInitPayload());

        assertEq(wallet.keyVersion(), 1, "keyVersion bumped");
        assertEq(wallet.statefulLeavesUsed(), 0, "leaves-used reset");
        assertEq(wallet.getShrincsPublicKeyCommitment(), mainCommitment, "commitment reinstalled");
        // Fresh epoch ⇒ the previously-marked leaf is unused again under keyVersion 1.
        assertFalse(wallet.isStatefulLeafUsed(1), "fresh namespace");
    }

    function test_migrate_doesNotAdvanceActionNonce() public {
        wallet.harness_setNonce(5);
        wallet.harness_migrateInUpgradeContext(_validInitPayload());
        // The keyVersion bump already invalidates every outstanding context; the nonce is
        // deliberately untouched by migration.
        assertEq(wallet.actionNonce(), 5, "migrate leaves the action nonce unchanged");
    }

    function test_migrate_emitsWalletMigrated() public {
        vm.recordLogs();
        wallet.harness_migrateInUpgradeContext(_validInitPayload());

        Vm.Log[] memory logs = vm.getRecordedLogs();
        bool found;
        for (uint256 i; i < logs.length; i++) {
            if (logs[i].topics[0] == IShrincsWallet.WalletMigrated.selector) {
                found = true;
                assertEq(logs[i].topics[1], mainCommitment, "commitment indexed");
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
        SHRINCS.PublicKey memory pk = _mainPk();
        bytes memory payload = _buildInitPayload(
            mainCommitment,
            _toBytes32(pk.pkSeed),
            pk,
            HashSuite.HASH_SUITE_ID,
            bytes32(0),
            HashSuite.HASH_SUITE_ID
        );
        vm.expectRevert(IShrincsWallet.ZeroErc1271Commitment.selector);
        wallet.harness_migrateInUpgradeContext(payload);
    }

    function test_migrate_revertsWhen_unsupportedHashSuite() public {
        SHRINCS.PublicKey memory pk = _mainPk();
        bytes memory payload = _buildInitPayload(
            mainCommitment,
            _toBytes32(pk.pkSeed),
            pk,
            SHRINCS.HASH_SUITE_UNSUPPORTED,
            erc1271Commitment,
            HashSuite.HASH_SUITE_ID
        );
        vm.expectRevert(IShrincsWallet.UnsupportedHashSuite.selector);
        wallet.harness_migrateInUpgradeContext(payload);
    }

    function test_migrate_revertsWhen_invalidBundle() public {
        // Corrupt the bundle's embedded commitment so `validPublicKey` fails its recompute check.
        SHRINCS.PublicKey memory pk = _mainPk();
        pk.publicKeyCommitment = abi.encodePacked(keccak256("corrupted-embedded-commitment"));
        bytes memory payload = _buildInitPayload(
            mainCommitment,
            _toBytes32(pk.pkSeed),
            pk,
            HashSuite.HASH_SUITE_ID,
            erc1271Commitment,
            HashSuite.HASH_SUITE_ID
        );
        vm.expectRevert(IShrincsWallet.CommitmentMismatch.selector);
        wallet.harness_migrateInUpgradeContext(payload);
    }

    function test_migrate_revertsWhen_declaredCommitmentMismatch() public {
        SHRINCS.PublicKey memory pk = _mainPk();
        // Valid bundle, but the standalone declared commitment is wrong.
        bytes memory payload = _buildInitPayload(
            keccak256("wrong-commitment"),
            _toBytes32(pk.pkSeed),
            pk,
            HashSuite.HASH_SUITE_ID,
            erc1271Commitment,
            HashSuite.HASH_SUITE_ID
        );
        vm.expectRevert(IShrincsWallet.CommitmentMismatch.selector);
        wallet.harness_migrateInUpgradeContext(payload);
    }

    function test_migrate_revertsWhen_zeroMaxSignatures() public {
        SHRINCS.PublicKey memory pk = _mainPk();
        // Zero the trailing 4-byte maxSignatures, then recompute the commitment so the shape/
        // commitment checks pass and the explicit `ZeroMaxSignatures` guard fires.
        bytes memory spk = pk.statefulPublicKey;
        spk[64] = 0;
        spk[65] = 0;
        spk[66] = 0;
        spk[67] = 0;
        bytes32 newCommit = SHRINCS.publicKeyCommitmentFromParts(spk, pk.pkSeed, pk.hypertreeRoot);
        pk.statefulPublicKey = spk;
        pk.publicKeyCommitment = abi.encodePacked(newCommit);
        bytes memory payload = _buildInitPayload(
            newCommit,
            _toBytes32(pk.pkSeed),
            pk,
            HashSuite.HASH_SUITE_ID,
            erc1271Commitment,
            HashSuite.HASH_SUITE_ID
        );
        vm.expectRevert(IShrincsWallet.ZeroMaxSignatures.selector);
        wallet.harness_migrateInUpgradeContext(payload);
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
}
