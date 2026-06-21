// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {Vm} from "forge-std-1.14.0/Vm.sol";
import {ShrincsTypes} from "@quip.network/hashsigs-solidity-0.1.0/contracts/ShrincsTypes.sol";
import {ShrincsUtils} from "@quip.network/hashsigs-solidity-0.1.0/contracts/ShrincsUtils.sol";
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
        assertEq(
            wallet.getShrincsPublicKeyCommitment(), _bytes32(".mainKey.publicKeyCommitment"), "commitment reinstalled"
        );
        // Fresh epoch ⇒ the previously-marked leaf is unused again under keyVersion 1.
        assertFalse(wallet.isStatefulLeafUsed(1), "fresh namespace");
    }

    function test_migrate_emitsWalletMigrated() public {
        vm.recordLogs();
        wallet.harness_migrateInUpgradeContext(_validInitPayload());

        Vm.Log[] memory logs = vm.getRecordedLogs();
        bool found;
        for (uint256 i; i < logs.length; i++) {
            if (logs[i].topics[0] == IShrincsWallet.WalletMigrated.selector) {
                found = true;
                assertEq(logs[i].topics[1], _bytes32(".mainKey.publicKeyCommitment"), "commitment indexed");
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
        ShrincsTypes.PublicKey memory pk = _parsePublicKey(".mainKey");
        bytes memory payload = _buildInitPayload(
            _bytes32(".mainKey.publicKeyCommitment"),
            _bytes32(".mainKey.pkSeed"),
            pk,
            uint8(vm.parseJsonUint(vectors, ".mainKey.parameterSetId")),
            bytes32(0),
            0
        );
        vm.expectRevert(IShrincsWallet.ZeroErc1271Commitment.selector);
        wallet.harness_migrateInUpgradeContext(payload);
    }

    function test_migrate_revertsWhen_invalidParams() public {
        ShrincsTypes.PublicKey memory pk = _parsePublicKey(".mainKey");
        bytes memory payload = _buildInitPayload(
            _bytes32(".mainKey.publicKeyCommitment"),
            _bytes32(".mainKey.pkSeed"),
            pk,
            1, // Unsupported
            _bytes32(".erc1271Key.publicKeyCommitment"),
            0
        );
        vm.expectRevert(IShrincsWallet.CommitmentMismatch.selector);
        wallet.harness_migrateInUpgradeContext(payload);
    }

    function test_migrate_revertsWhen_declaredCommitmentMismatch() public {
        ShrincsTypes.PublicKey memory pk = _parsePublicKey(".mainKey");
        // Valid params + valid bundle, but the standalone declared commitment is wrong.
        bytes memory payload = _buildInitPayload(
            keccak256("wrong-commitment"),
            _bytes32(".mainKey.pkSeed"),
            pk,
            uint8(vm.parseJsonUint(vectors, ".mainKey.parameterSetId")),
            _bytes32(".erc1271Key.publicKeyCommitment"),
            0
        );
        vm.expectRevert(IShrincsWallet.CommitmentMismatch.selector);
        wallet.harness_migrateInUpgradeContext(payload);
    }

    function test_migrate_revertsWhen_zeroMaxSignatures() public {
        ShrincsTypes.PublicKey memory pk = _parsePublicKey(".mainKey");
        // Zero the trailing 4-byte maxSignatures, then recompute the commitment so the param/
        // commitment checks pass and the explicit `ZeroMaxSignatures` guard fires.
        bytes memory spk = pk.statefulPublicKey;
        spk[64] = 0;
        spk[65] = 0;
        spk[66] = 0;
        spk[67] = 0;
        bytes32 newCommit =
            ShrincsUtils.publicKeyCommitmentFromParts(ShrincsTypes.ParameterSetId(0), spk, pk.pkSeed, pk.hypertreeRoot);
        pk.statefulPublicKey = spk;
        pk.publicKeyCommitment = abi.encodePacked(newCommit);
        bytes memory payload = _buildInitPayload(
            newCommit, _bytes32(".mainKey.pkSeed"), pk, 0, _bytes32(".erc1271Key.publicKeyCommitment"), 0
        );
        vm.expectRevert(IShrincsWallet.ZeroMaxSignatures.selector);
        wallet.harness_migrateInUpgradeContext(payload);
    }

    /// @dev Proves migrate actually INSTALLS the supplied bundle (not a no-op on existing state):
    ///      migrates to a different valid bundle (`rotateFullKey.nextKey`) plus a distinct ERC-1271
    ///      key, and asserts the new main commitment, ERC-1271 commitment, and ERC-1271 param set.
    function test_migrate_installsSuppliedBundle() public {
        ShrincsTypes.PublicKey memory next = _parsePublicKey(".cases.rotateFullKey.nextKey");
        bytes32 nextCommit = _bytes32(".cases.rotateFullKey.nextKey.publicKeyCommitment");
        bytes32 newErc1271 = keccak256("migrated-erc1271");
        assertTrue(nextCommit != wallet.getShrincsPublicKeyCommitment(), "precondition: a different bundle");

        bytes memory payload = _buildInitPayload(
            nextCommit,
            keccak256("indexing-handle"), // top-level pkSeed slot — ignored by migrate
            next,
            uint8(vm.parseJsonUint(vectors, ".cases.rotateFullKey.nextKey.parameterSetId")),
            newErc1271,
            1
        );
        wallet.harness_migrateInUpgradeContext(payload);

        assertEq(wallet.getShrincsPublicKeyCommitment(), nextCommit, "new main commitment installed");
        assertEq(wallet.getErc1271Commitment(), newErc1271, "new erc1271 commitment installed");
        assertEq(uint8(wallet.getErc1271ParameterSetId()), 1, "new erc1271 paramId installed");
        assertEq(wallet.keyVersion(), 1, "epoch bumped");
    }
}
