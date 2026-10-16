// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {Vm} from "forge-std-1.14.0/Vm.sol";
import {LibClone} from "solady-0.1.26/src/utils/LibClone.sol";
import {SHRINCS} from "@quip.network/hashsigs-solidity-0.2.0/contracts/SHRINCS.sol";
import {HashSuite} from "shrincs-hash/HashSuite.sol";
import {SHRINCSTestSigner} from "@quip.network/hashsigs-solidity-0.2.0/test/helpers/SHRINCSTestSigner.sol";
import {IShrincsWallet} from "../../../contracts/shrincs/interfaces/IShrincsWallet.sol";
import {ShrincsWalletCodec as Codec} from "../../../contracts/shrincs/ShrincsWalletCodec.sol";
import {WalletFactory} from "../../../contracts/WalletFactory.sol";
import {ShrincsWalletHarness} from "../../harness/ShrincsWalletHarness.sol";
import {ShrincsWalletTest} from "../ShrincsWallet.t.sol";

/// @dev Behavior tests for `migrate`. It is reachable ONLY mid-upgrade (the ERC-1967 gate), so
///      every case here runs through a REAL signed `upgradeToAndCall` carrying the payload under
///      test as the bound migrator (`_migrateViaUpgrade` / `_migrateViaUpgradeExpect` in the
///      base); migrate reverts bubble through the upgrade verbatim. Note the upgrade itself
///      consumes leaf `SIGN_BASE + 1` and advances the action nonce by exactly one BEFORE
///      `migrate` runs.
contract ShrincsWallet_migrate is ShrincsWalletTest {
    function test_migrate_reinstallsAndResets() public {
        // Dirty the per-epoch counter first, so the reset is observable. (Leaf 2 — the upgrade
        // authorization itself signs at leaf 1.)
        wallet.harness_markLeafUsed(SIGN_BASE + 2);
        assertEq(wallet.statefulLeavesUsed(), 1);

        (bytes memory payload, bytes32 freshCommitment) = _freshInitPayload("migrate-fresh-bundle");
        _migrateViaUpgrade(payload);

        assertEq(wallet.keyVersion(), 1, "keyVersion bumped");
        assertEq(wallet.statefulLeavesUsed(), 0, "leaves-used reset");
        assertEq(wallet.getShrincsPublicKeyCommitment(), freshCommitment, "fresh bundle installed");
        // Fresh epoch ⇒ the previously-marked leaf (and the upgrade's own consumed leaf) read
        // unused again under keyVersion 1.
        assertFalse(wallet.isStatefulLeafUsed(SIGN_BASE + 2), "fresh namespace");
        assertFalse(wallet.isStatefulLeafUsed(SIGN_BASE + 1), "fresh namespace (upgrade leaf)");
    }

    function test_migrate_doesNotAdvanceActionNonce() public {
        wallet.harness_setNonce(5);
        (bytes memory payload,) = _freshInitPayload("migrate-fresh-bundle");
        _migrateViaUpgrade(payload);
        // The upgrade authorization consumes exactly one nonce (5 -> 6); `migrate` itself adds
        // none — the keyVersion bump already invalidates every outstanding signed context.
        assertEq(wallet.actionNonce(), 6, "only the upgrade's own consumption advances the nonce");
    }

    function test_migrate_emitsWalletMigrated() public {
        vm.recordLogs();
        (bytes memory payload, bytes32 freshCommitment) = _freshInitPayload("migrate-fresh-bundle");
        _migrateViaUpgrade(payload);

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

    function test_migrate_repinsWalletFactoryToNewImplementation() public {
        WalletFactory factory2Impl = new WalletFactory(MAX_FEE);
        WalletFactory factory2 = WalletFactory(payable(LibClone.deployERC1967(address(factory2Impl))));
        factory2.initialize(payable(ADMIN));
        ShrincsWalletHarness implB =
            new ShrincsWalletHarness(payable(address(factory2)), address(shrincsVerifier));

        vm.prank(ADMIN);
        factory.vetImplementation(address(implB));

        (bytes memory payload,) = _freshInitPayload("migrate-repin-factory");
        SHRINCS.Signature memory sig = _signStatefulAction(
            Codec.ACTION_UPGRADE,
            Codec.upgradePayloadHash(address(implB), true, keccak256(payload)),
            1
        );
        bytes memory data = abi.encode(
            _mainPk(), sig, true, payload, wallet.actionNonce(), _probeVectorFor(address(implB))
        );
        vm.prank(OWNER);
        wallet.upgradeToAndCall(address(implB), data);

        assertEq(wallet.walletFactory(), address(factory2), "factory pin follows the new implementation");
    }

    function test_migrate_installsNewBudget() public {
        uint32 nextBudget = MAX_SIG + 4;
        (, SHRINCS.PublicKey memory pk, bool ok) =
            SHRINCSTestSigner.keygen("migrate-diff-budget", nextBudget);
        require(ok, "keygen");
        bytes32 commitment = _commitment32(pk);
        bytes memory payload = _buildInitPayload(
            commitment,
            _toBytes32(pk.pkSeed),
            pk,
            HashSuite.HASH_SUITE_ID,
            _freshErc1271Pk("migrate-diff-budget"),
            HashSuite.HASH_SUITE_ID
        );
        _migrateViaUpgrade(payload);
        assertEq(wallet.maxSignatures(), nextBudget, "new bundle budget installed");
        assertEq(wallet.getShrincsPublicKeyCommitment(), commitment, "fresh bundle installed");
    }

    function test_migrate_revertsWhen_notUpgrading() public {
        // Called directly (no upgrade in flight: the live proxy's pointer is the code that
        // runs) it must revert.
        vm.expectRevert(IShrincsWallet.NotUpgrading.selector);
        wallet.migrate(_validInitPayload());
    }

    function test_migrate_revertsWhen_invalidErc1271Bundle() public {
        (, SHRINCS.PublicKey memory pk, bool ok) =
            SHRINCSTestSigner.keygen("migrate-bad-1271", MAX_SIG);
        require(ok, "keygen");
        SHRINCS.PublicKey memory epk = _freshErc1271Pk("migrate-bad-1271");
        epk.publicKeyCommitment = abi.encodePacked(keccak256("corrupted-erc1271-commitment"));
        bytes memory payload = _buildInitPayload(
            _commitment32(pk),
            _toBytes32(pk.pkSeed),
            pk,
            HashSuite.HASH_SUITE_ID,
            epk,
            HashSuite.HASH_SUITE_ID
        );
        _migrateViaUpgradeExpect(
            payload, abi.encodeWithSelector(IShrincsWallet.CommitmentMismatch.selector)
        );
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
        _migrateViaUpgradeExpect(
            payload, abi.encodeWithSelector(IShrincsWallet.UnsupportedHashSuite.selector)
        );
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
        _migrateViaUpgradeExpect(
            payload, abi.encodeWithSelector(IShrincsWallet.CommitmentMismatch.selector)
        );
    }

    function test_migrate_revertsWhen_declaredCommitmentMismatch() public {
        // A FRESH valid bundle (the current one would trip the spent-tree registry first),
        // but the standalone declared commitment is wrong.
        (, SHRINCS.PublicKey memory pk, bool ok) =
            SHRINCSTestSigner.keygen("migrate-wrong-declared", MAX_SIG);
        require(ok, "keygen");
        bytes memory payload = _buildInitPayload(
            keccak256("wrong-commitment"),
            _toBytes32(pk.pkSeed),
            pk,
            HashSuite.HASH_SUITE_ID,
            erc1271Pk,
            HashSuite.HASH_SUITE_ID
        );
        _migrateViaUpgradeExpect(
            payload, abi.encodeWithSelector(IShrincsWallet.CommitmentMismatch.selector)
        );
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
        _migrateViaUpgradeExpect(
            payload, abi.encodeWithSelector(IShrincsWallet.ZeroMaxSignatures.selector)
        );
    }

    /// @dev Proves migrate actually INSTALLS the supplied bundle (not a no-op on existing state):
    ///      migrates to a freshly generated bundle plus a distinct ERC-1271 commitment, and asserts
    ///      the new main commitment and ERC-1271 commitment are installed.
    function test_migrate_installsSuppliedBundle() public {
        (, SHRINCS.PublicKey memory next, bool ok) =
            SHRINCSTestSigner.keygen("migrated-main-key", MAX_SIG);
        assertTrue(ok, "next keygen");
        bytes32 nextCommit = _commitment32(next);
        SHRINCS.PublicKey memory newErc1271Pk = _freshErc1271Pk("migrated-erc1271");
        bytes32 newErc1271 = _commitment32(newErc1271Pk);
        assertTrue(
            nextCommit != wallet.getShrincsPublicKeyCommitment(), "precondition: a different bundle"
        );

        bytes memory payload = _buildInitPayload(
            nextCommit,
            keccak256("indexing-handle"), // top-level pkSeed slot — ignored by migrate
            next,
            HashSuite.HASH_SUITE_ID,
            newErc1271Pk,
            HashSuite.HASH_SUITE_ID
        );
        _migrateViaUpgrade(payload);

        assertEq(wallet.getShrincsPublicKeyCommitment(), nextCommit, "new main commitment installed");
        assertEq(wallet.getErc1271PublicKeyCommitment(), newErc1271, "new erc1271 commitment installed");
        assertEq(wallet.getErc1271HashSuite(), HashSuite.HASH_SUITE_ID, "erc1271 suite installed");
        assertEq(wallet.keyVersion(), 1, "epoch bumped");
    }

    /*──────────────────── spent-tree tracking ────────────────────*/

    function test_migrate_spendsAllFourInstalledTrees() public {
        (, SHRINCS.PublicKey memory fresh, bool ok) =
            SHRINCSTestSigner.keygen("migrate-spends", MAX_SIG);
        require(ok, "keygen");
        SHRINCS.PublicKey memory fresh1271 = _freshErc1271Pk("migrate-spends");
        _assertTreesUnspent(fresh);
        _assertTreesUnspent(fresh1271);

        (bytes memory payload,) = _freshInitPayload("migrate-spends");
        _migrateViaUpgrade(payload);

        _assertTreesSpent(fresh);
        _assertTreesSpent(fresh1271);
    }

    /// @dev Regression (audit): migration must present a fresh ERC-1271 bundle too — carrying
    ///      the current one forward is a re-install of a held tree.
    function test_migrate_revertsWhen_erc1271BundleCarriedForward() public {
        (, SHRINCS.PublicKey memory pk, bool ok) =
            SHRINCSTestSigner.keygen("migrate-carry-1271", MAX_SIG);
        require(ok, "keygen");
        bytes memory payload = _buildInitPayload(
            _commitment32(pk),
            _toBytes32(pk.pkSeed),
            pk,
            HashSuite.HASH_SUITE_ID,
            erc1271Pk,
            HashSuite.HASH_SUITE_ID
        );
        _migrateViaUpgradeExpect(
            payload,
            abi.encodeWithSelector(
                IShrincsWallet.StatefulTreeSpent.selector, _treeId(erc1271Pk.statefulPublicKey)
            )
        );
    }

    /// @dev Regression (audit): the ERC-1271 bundle may not be the (fresh) main bundle.
    function test_migrate_revertsWhen_erc1271BundleEqualsMain() public {
        (, SHRINCS.PublicKey memory pk, bool ok) =
            SHRINCSTestSigner.keygen("migrate-1271-eq-main", MAX_SIG);
        require(ok, "keygen");
        bytes memory payload = _buildInitPayload(
            _commitment32(pk),
            _toBytes32(pk.pkSeed),
            pk,
            HashSuite.HASH_SUITE_ID,
            pk,
            HashSuite.HASH_SUITE_ID
        );
        _migrateViaUpgradeExpect(
            payload,
            abi.encodeWithSelector(
                IShrincsWallet.StatefulTreeSpent.selector, _treeId(pk.statefulPublicKey)
            )
        );
    }

    /// @dev Regression (audit): a 1271 bundle reusing the OLD main key's stateless root under a
    ///      fresh stateful subkey (new commitment, held recovery root) is rejected.
    function test_migrate_revertsWhen_erc1271SharesFormerMainStatelessRoot() public {
        (, SHRINCS.PublicKey memory pk, bool ok) =
            SHRINCSTestSigner.keygen("migrate-1271-old-root", MAX_SIG);
        require(ok, "keygen");
        SHRINCS.PublicKey memory epk = _bundleSharingStatelessRoot("migrate-1271-old-root-sub", mainPk);
        bytes memory payload = _buildInitPayload(
            _commitment32(pk),
            _toBytes32(pk.pkSeed),
            pk,
            HashSuite.HASH_SUITE_ID,
            epk,
            HashSuite.HASH_SUITE_ID
        );
        _migrateViaUpgradeExpect(
            payload,
            abi.encodeWithSelector(IShrincsWallet.StatelessTreeSpent.selector, _statelessId(mainPk))
        );
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
        _migrateViaUpgradeExpect(
            payload,
            abi.encodeWithSelector(
                IShrincsWallet.StatelessTreeSpent.selector, _statelessId(erc1271Pk)
            )
        );
    }

    function test_migrate_revertsWhen_currentBundle() public {
        _migrateViaUpgradeExpect(
            _validInitPayload(),
            abi.encodeWithSelector(
                IShrincsWallet.StatefulTreeSpent.selector, _treeId(mainPk.statefulPublicKey)
            )
        );
    }

    function test_migrate_revertsWhen_statelessTreeCarriedForward() public {
        // Fresh stateful tree, current stateless tree: migration is strictly fresh on both halves.
        (, SHRINCS.PublicKey memory pk, bool ok) =
            SHRINCSTestSigner.keygen("migrate-carry-stateless", MAX_SIG);
        require(ok, "keygen");
        pk.pkSeed = mainPk.pkSeed;
        pk.hypertreeRoot = mainPk.hypertreeRoot;
        bytes32 c =
            SHRINCS.publicKeyCommitmentFromParts(pk.statefulPublicKey, pk.pkSeed, pk.hypertreeRoot);
        pk.publicKeyCommitment = abi.encodePacked(c);
        bytes memory payload = _buildInitPayload(
            c, _toBytes32(pk.pkSeed), pk, HashSuite.HASH_SUITE_ID, erc1271Pk, HashSuite.HASH_SUITE_ID
        );
        _migrateViaUpgradeExpect(
            payload,
            abi.encodeWithSelector(IShrincsWallet.StatelessTreeSpent.selector, _statelessId(mainPk))
        );
    }

    function test_migrate_revertsWhen_cyclingBackToEarlierBundle() public {
        // Capture the ORIGINAL bundle's payload and tree id before rebinding the suite's keys.
        bytes memory originalPayload = _validInitPayload();
        bytes32 originalStatefulTree = _treeId(mainPk.statefulPublicKey);

        (bytes memory fresh,) = _freshInitPayload("migrate-cycle-B");
        _migrateViaUpgrade(fresh);
        assertEq(wallet.keyVersion(), 1);

        // Rebind the suite's signing identity to the migrated (B) bundle so the second
        // upgrade can be authorized by the wallet's CURRENT key.
        bool ok;
        (mainKey, mainPk, ok) = SHRINCSTestSigner.keygen("migrate-cycle-B", MAX_SIG);
        require(ok, "rebind keygen");
        mainCommitment = _commitment32(mainPk);

        // Back to the original bundle: its stateful tree was spent at install.
        _migrateViaUpgradeExpect(
            originalPayload,
            abi.encodeWithSelector(
                IShrincsWallet.StatefulTreeSpent.selector, originalStatefulTree
            )
        );
    }
}
