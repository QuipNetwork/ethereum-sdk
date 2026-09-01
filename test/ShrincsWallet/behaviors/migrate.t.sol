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
///      path and reverts are fully testable; the mid-upgrade shape it gates on (the wallet's OWN
///      ERC-1967 pointer still holding the previous implementation) is emulated via the harness
///      helper `harness_migrateInUpgradeContext`.
contract ShrincsWallet_migrate is ShrincsWalletTest {
    function test_migrate_reinstallsAndResets() public {
        // Dirty the per-epoch counter first, so the reset is observable.
        wallet.harness_markLeafUsed(SIGN_BASE + 1);
        assertEq(wallet.statefulLeavesUsed(), 1);

        (bytes memory payload, bytes32 freshCommitment) = _freshInitPayload("migrate-fresh-bundle");
        wallet.harness_migrateInUpgradeContext(payload);

        assertEq(wallet.keyVersion(), 1, "keyVersion bumped");
        assertEq(wallet.statefulLeavesUsed(), 0, "leaves-used reset");
        assertEq(wallet.getShrincsPublicKeyCommitment(), freshCommitment, "fresh bundle installed");
        // Fresh epoch ⇒ the previously-marked leaf is unused again under keyVersion 1.
        assertFalse(wallet.isStatefulLeafUsed(SIGN_BASE + 1), "fresh namespace");
    }

    function test_migrate_doesNotAdvanceActionNonce() public {
        wallet.harness_setNonce(5);
        (bytes memory payload,) = _freshInitPayload("migrate-fresh-bundle");
        wallet.harness_migrateInUpgradeContext(payload);
        // The keyVersion bump already invalidates every outstanding context; the nonce is
        // deliberately untouched by migration.
        assertEq(wallet.actionNonce(), 5, "migrate leaves the action nonce unchanged");
    }

    function test_migrate_emitsWalletMigrated() public {
        vm.recordLogs();
        (bytes memory payload, bytes32 freshCommitment) = _freshInitPayload("migrate-fresh-bundle");
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
        // Called directly (no upgrade in flight: the ERC-1967 pointer is empty or self) it must revert.
        vm.expectRevert(IShrincsWallet.NotUpgrading.selector);
        wallet.migrate(_validInitPayload());
    }

    function test_migrate_revertsWhen_invalidErc1271Bundle() public {
        (, SHRINCS.PublicKey memory pk, bool ok) = SHRINCSTestSigner.keygen("migrate-bad-1271", MAX_SIG);
        require(ok, "keygen");
        SHRINCS.PublicKey memory epk = _freshErc1271Pk("migrate-bad-1271");
        epk.publicKeyCommitment = abi.encodePacked(keccak256("corrupted-erc1271-commitment"));
        bytes memory payload = _buildInitPayload(
            _commitment32(pk), _toBytes32(pk.pkSeed), pk, HashSuite.HASH_SUITE_ID, epk, HashSuite.HASH_SUITE_ID
        );
        vm.expectRevert(IShrincsWallet.CommitmentMismatch.selector);
        wallet.harness_migrateInUpgradeContext(payload);
    }

    function test_migrate_revertsWhen_unsupportedHashSuite() public {
        SHRINCS.PublicKey memory pk = _mainPk();
        bytes memory payload = _buildInitPayload(
            mainCommitment,
            _toBytes32(pk.pkSeed),
            pk,
            SHRINCS.HASH_SUITE_UNSUPPORTED,
            erc1271Pk,
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
            erc1271Pk,
            HashSuite.HASH_SUITE_ID
        );
        vm.expectRevert(IShrincsWallet.CommitmentMismatch.selector);
        wallet.harness_migrateInUpgradeContext(payload);
    }

    function test_migrate_revertsWhen_declaredCommitmentMismatch() public {
        // A FRESH valid bundle (the current one would trip the spent-tree registry first),
        // but the standalone declared commitment is wrong.
        (, SHRINCS.PublicKey memory pk, bool ok) = SHRINCSTestSigner.keygen("migrate-wrong-declared", MAX_SIG);
        require(ok, "keygen");
        bytes memory payload = _buildInitPayload(
            keccak256("wrong-commitment"),
            _toBytes32(pk.pkSeed),
            pk,
            HashSuite.HASH_SUITE_ID,
            erc1271Pk,
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
            erc1271Pk,
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
        SHRINCS.PublicKey memory newErc1271Pk = _freshErc1271Pk("migrated-erc1271");
        bytes32 newErc1271 = _commitment32(newErc1271Pk);
        assertTrue(nextCommit != wallet.getShrincsPublicKeyCommitment(), "precondition: a different bundle");

        bytes memory payload = _buildInitPayload(
            nextCommit,
            keccak256("indexing-handle"), // top-level pkSeed slot — ignored by migrate
            next,
            HashSuite.HASH_SUITE_ID,
            newErc1271Pk,
            HashSuite.HASH_SUITE_ID
        );
        wallet.harness_migrateInUpgradeContext(payload);

        assertEq(wallet.getShrincsPublicKeyCommitment(), nextCommit, "new main commitment installed");
        assertEq(wallet.getErc1271PublicKeyCommitment(), newErc1271, "new erc1271 commitment installed");
        assertEq(wallet.getErc1271HashSuite(), HashSuite.HASH_SUITE_ID, "erc1271 suite installed");
        assertEq(wallet.keyVersion(), 1, "epoch bumped");
    }

    /*──────────────────── spent-tree tracking ────────────────────*/

    function test_migrate_spendsAllFourInstalledTrees() public {
        (, SHRINCS.PublicKey memory fresh, bool ok) = SHRINCSTestSigner.keygen("migrate-spends", MAX_SIG);
        require(ok, "keygen");
        SHRINCS.PublicKey memory fresh1271 = _freshErc1271Pk("migrate-spends");
        _assertTreesUnspent(fresh);
        _assertTreesUnspent(fresh1271);

        (bytes memory payload,) = _freshInitPayload("migrate-spends");
        wallet.harness_migrateInUpgradeContext(payload);

        _assertTreesSpent(fresh);
        _assertTreesSpent(fresh1271);
    }

    /// @dev Regression (audit): migration must present a fresh ERC-1271 bundle too — carrying
    ///      the current one forward is a re-install of a held tree.
    function test_migrate_revertsWhen_erc1271BundleCarriedForward() public {
        (, SHRINCS.PublicKey memory pk, bool ok) = SHRINCSTestSigner.keygen("migrate-carry-1271", MAX_SIG);
        require(ok, "keygen");
        bytes memory payload = _buildInitPayload(
            _commitment32(pk), _toBytes32(pk.pkSeed), pk, HashSuite.HASH_SUITE_ID, erc1271Pk, HashSuite.HASH_SUITE_ID
        );
        vm.expectRevert(
            abi.encodeWithSelector(IShrincsWallet.StatefulTreeSpent.selector, _treeId(erc1271Pk.statefulPublicKey))
        );
        wallet.harness_migrateInUpgradeContext(payload);
    }

    /// @dev Regression (audit): the ERC-1271 bundle may not be the (fresh) main bundle.
    function test_migrate_revertsWhen_erc1271BundleEqualsMain() public {
        (, SHRINCS.PublicKey memory pk, bool ok) = SHRINCSTestSigner.keygen("migrate-1271-eq-main", MAX_SIG);
        require(ok, "keygen");
        bytes memory payload = _buildInitPayload(
            _commitment32(pk), _toBytes32(pk.pkSeed), pk, HashSuite.HASH_SUITE_ID, pk, HashSuite.HASH_SUITE_ID
        );
        vm.expectRevert(
            abi.encodeWithSelector(IShrincsWallet.StatefulTreeSpent.selector, _treeId(pk.statefulPublicKey))
        );
        wallet.harness_migrateInUpgradeContext(payload);
    }

    /// @dev Regression (audit): a 1271 bundle reusing the OLD main key's stateless root under a
    ///      fresh stateful subkey (new commitment, held recovery root) is rejected.
    function test_migrate_revertsWhen_erc1271SharesFormerMainStatelessRoot() public {
        (, SHRINCS.PublicKey memory pk, bool ok) = SHRINCSTestSigner.keygen("migrate-1271-old-root", MAX_SIG);
        require(ok, "keygen");
        SHRINCS.PublicKey memory epk = _bundleSharingStatelessRoot("migrate-1271-old-root-sub", mainPk);
        bytes memory payload = _buildInitPayload(
            _commitment32(pk), _toBytes32(pk.pkSeed), pk, HashSuite.HASH_SUITE_ID, epk, HashSuite.HASH_SUITE_ID
        );
        vm.expectRevert(abi.encodeWithSelector(IShrincsWallet.StatelessTreeSpent.selector, _statelessId(mainPk)));
        wallet.harness_migrateInUpgradeContext(payload);
    }

    /// @dev Regression (audit): the reverse cross-role direction — a NEW MAIN bundle may not
    ///      reuse the dedicated ERC-1271 key's stateless root.
    function test_migrate_revertsWhen_mainSharesErc1271StatelessRoot() public {
        SHRINCS.PublicKey memory pk = _bundleSharingStatelessRoot("migrate-main-1271-root", erc1271Pk);
        bytes memory payload = _buildInitPayload(
            _commitment32(pk),
            _toBytes32(pk.pkSeed),
            pk,
            HashSuite.HASH_SUITE_ID,
            _freshErc1271Pk("migrate-main-1271-root"),
            HashSuite.HASH_SUITE_ID
        );
        vm.expectRevert(abi.encodeWithSelector(IShrincsWallet.StatelessTreeSpent.selector, _statelessId(erc1271Pk)));
        wallet.harness_migrateInUpgradeContext(payload);
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
            c, _toBytes32(pk.pkSeed), pk, HashSuite.HASH_SUITE_ID, erc1271Pk, HashSuite.HASH_SUITE_ID
        );
        vm.expectRevert(abi.encodeWithSelector(IShrincsWallet.StatelessTreeSpent.selector, _statelessId(mainPk)));
        wallet.harness_migrateInUpgradeContext(payload);
    }

    function test_migrate_revertsWhen_cyclingBackToEarlierBundle() public {
        (bytes memory fresh,) = _freshInitPayload("migrate-cycle-B");
        wallet.harness_migrateInUpgradeContext(fresh);
        assertEq(wallet.keyVersion(), 1);
        // Back to the original bundle: its stateful tree was spent at install.
        vm.expectRevert(
            abi.encodeWithSelector(IShrincsWallet.StatefulTreeSpent.selector, _treeId(mainPk.statefulPublicKey))
        );
        wallet.harness_migrateInUpgradeContext(_validInitPayload());
    }
}
