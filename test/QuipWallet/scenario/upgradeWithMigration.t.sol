// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {QuipWalletTest} from "../QuipWallet.t.sol";
import {QuipWallet} from "../../../contracts/QuipWallet.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";
import {WOTSPlusCodec as Codec} from "../../../contracts/WOTSPlusCodec.sol";
import {EfficientHashLib} from "solady-0.1.26/src/utils/EfficientHashLib.sol";

/// @title Upgrade with Migration Scenario Test
/// @dev Full upgrade-with-migration flow: deploy → use → upgrade with
///      shouldMigrate=true → verify state re-initialised → resume operations.
contract QuipWallet_upgradeWithMigration is QuipWalletTest {
    QuipWallet public newImpl;

    WOTSPlus.WinternitzAddress internal currentPq;
    bytes32 internal currentPrivKey;

    function setUp() public override {
        super.setUp();
        newImpl = new QuipWallet(payable(address(factory)));
        vm.prank(ADMIN);
        factory.vetImplementation(address(newImpl));
    }

    function _buildVerifierData(
        address impl,
        bytes32 verifierSeed
    ) internal view returns (
        WOTSPlus.WinternitzAddress memory vPub,
        WOTSPlus.WinternitzElements memory vSig
    ) {
        bytes32 vPriv;
        (vPub, vPriv) = _generateKeyPair(verifierSeed);
        bytes32 vHash = Codec.verificationDigest(
            address(wallet), block.chainid, impl,
            vPub.publicSeed, vPub.publicKeyHash
        );
        vSig = _sign(vPriv, vHash);
    }

    function _doUpgradeWithMigration(
        address impl,
        WOTSPlus.WinternitzAddress memory migratePq,
        WOTSPlus.WinternitzAddress[] memory migrateRecoveryKeys
    ) internal {
        (WOTSPlus.WinternitzAddress memory nextPq,) = _generateKeyPair("upgrade-next-pq");

        // Auth signature
        bytes32 digest = Codec.upgradeDigest(
            address(wallet), block.chainid, impl,
            currentPq.publicSeed, currentPq.publicKeyHash,
            nextPq.publicSeed, nextPq.publicKeyHash
        );
        WOTSPlus.WinternitzElements memory pqSig = _sign(currentPrivKey, digest);

        // Verifier
        (
            WOTSPlus.WinternitzAddress memory vPub,
            WOTSPlus.WinternitzElements memory vSig
        ) = _buildVerifierData(impl, "migrate-verifier");

        // Migrator payload (704 bytes init layout)
        bytes memory migratorPayload = _encodeInitPayload(migratePq, migrateRecoveryKeys);

        bytes memory data = Codec.encodeUpgradeToAndCall(
            nextPq, pqSig, vPub, vSig, true, migratorPayload
        );

        vm.prank(ALICE);
        wallet.upgradeToAndCall(impl, data);
    }

    /// @dev Deploy → execute → upgrade with migration → verify state reset → resume.
    function test_simulation_upgradeWithMigration() public {
        currentPq = alicePubkey;
        currentPrivKey = alicePrivateKey;

        // Step 1: Execute a transfer before upgrading (wallet is operational)
        {
            (WOTSPlus.WinternitzAddress memory nextPq, bytes32 nextPriv) =
                _generateKeyPair("pre-upgrade-key");
            uint256 fee = wallet.getExecuteFee();
            bytes32 msgHash = _buildExecuteMessageHash(
                address(wallet), currentPq, nextPq, BOB, 0.1 ether, "", fee
            );
            WOTSPlus.WinternitzElements memory sig = _sign(currentPrivKey, msgHash);

            vm.prank(ALICE);
            wallet.execute(Codec.encodeExecute(nextPq, sig, BOB, 0.1 ether, ""));

            currentPq = nextPq;
            currentPrivKey = nextPriv;
        }

        // Step 2: Prepare migration state
        (WOTSPlus.WinternitzAddress memory migratePq, bytes32 migratePriv) =
            _generateKeyPair("migrate-pq");
        bytes32 migrateRecBase = keccak256("migrate-recovery-base");
        WOTSPlus.WinternitzAddress[] memory migrateKeys =
            _generateRecoveryKeys(migrateRecBase, 10);

        uint256 balBefore = address(wallet).balance;

        // Step 3: Upgrade with migration
        _doUpgradeWithMigration(address(newImpl), migratePq, migrateKeys);

        // Step 4: Verify state after migration
        // 4a: Implementation changed
        assertEq(
            wallet.version(),
            factory.getVettedCodeIndex(address(newImpl).codehash)
        );

        // 4b: pqOwner is the migrate payload's key (migrate overwrites the auth rotation)
        (bytes32 s, bytes32 h) = wallet.pqOwner();
        assertEq(s, migratePq.publicSeed);
        assertEq(h, migratePq.publicKeyHash);

        // 4c: Recovery keys are the new set from migration
        assertEq(wallet.getRecoveryKeyCount(), 10);
        for (uint256 i = 0; i < migrateKeys.length; i++) {
            bytes32 keyHash = EfficientHashLib.hash(
                migrateKeys[i].publicSeed, migrateKeys[i].publicKeyHash
            );
            assertTrue(wallet.isRecoveryKey(keyHash));
        }

        // 4d: Old recovery keys are gone
        for (uint256 i = 0; i < recoveryPubkeys.length; i++) {
            bytes32 keyHash = EfficientHashLib.hash(
                recoveryPubkeys[i].publicSeed, recoveryPubkeys[i].publicKeyHash
            );
            assertFalse(wallet.isRecoveryKey(keyHash));
        }

        // 4e: Balance and owner preserved
        assertEq(address(wallet).balance, balBefore);
        assertEq(wallet.owner(), ALICE);

        // Step 5: Resume operations with the migrated key
        currentPq = migratePq;
        currentPrivKey = migratePriv;

        (WOTSPlus.WinternitzAddress memory postPq,) = _generateKeyPair("post-migrate-key");
        uint256 fee = wallet.getExecuteFee();
        bytes32 msgHash = _buildExecuteMessageHash(
            address(wallet), currentPq, postPq, BOB, 0.05 ether, "", fee
        );
        WOTSPlus.WinternitzElements memory postSig = _sign(currentPrivKey, msgHash);

        uint256 bobBal = BOB.balance;
        vm.prank(ALICE);
        wallet.execute(Codec.encodeExecute(postPq, postSig, BOB, 0.05 ether, ""));
        assertEq(BOB.balance, bobBal + 0.05 ether);
    }
}
