// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {IWOTSPlusImplementation} from "../../../../contracts/deprecated/wots/interfaces/IWOTSPlusImplementation.sol";

import {WOTSPlusImplementationTest} from "../WOTSPlusImplementation.t.sol";
import {WOTSPlusImplementation} from "../../../../contracts/deprecated/wots/WOTSPlusImplementation.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.2.0/contracts/WOTSPlus.sol";
import {WOTSPlusCodec as Codec} from "../../../../contracts/deprecated/wots/WOTSPlusCodec.sol";

/// @title Upgrade with Migration Scenario Test
/// @dev Full upgrade-with-migration flow: deploy → use → upgrade with
///      shouldMigrate=true → verify state re-initialised → resume operations.
contract WOTSPlusImplementation_upgradeWithMigration is WOTSPlusImplementationTest {
    WOTSPlusImplementation public newImpl;

    WOTSPlus.WinternitzAddress internal currentPq;
    bytes32 internal currentPrivKey;

    function setUp() public override {
        super.setUp();
        newImpl = new WOTSPlusImplementation(payable(address(factory)));
        vm.prank(ADMIN);
        factory.vetImplementation(address(newImpl));
    }

    function _buildVerifierData(address impl, bytes32 verifierSeed)
        internal
        view
        returns (WOTSPlus.WinternitzAddress memory vPub, WOTSPlus.WinternitzElements memory vSig)
    {
        bytes32 vPriv;
        (vPub, vPriv) = _generateKeyPair(verifierSeed);
        bytes32 vHash =
            Codec.verificationDigest(address(wallet), block.chainid, impl, vPub.publicSeed, vPub.publicKeyHash);
        vSig = _sign(vPriv, vHash);
    }

    function _doUpgradeWithMigration(
        address impl,
        WOTSPlus.WinternitzAddress memory migratePq,
        WOTSPlus.WinternitzAddress[] memory migrateRecoveryKeys
    ) internal {
        (WOTSPlus.WinternitzAddress memory nextPq,) = _generateKeyPair("upgrade-next-pq");

        // Migrator payload (2048 bytes init layout)
        bytes memory migratorPayload = _encodeInitPayload(
            migratePq,
            migrateRecoveryKeys
        );

        // Auth signature
        bytes32 digest = Codec.upgradeDigest(
            address(wallet),
            block.chainid,
            impl,
            currentPq.publicSeed,
            currentPq.publicKeyHash,
            nextPq.publicSeed,
            nextPq.publicKeyHash,
            true,
            keccak256(migratorPayload)
        );
        WOTSPlus.WinternitzElements memory pqSig = _sign(
            currentPrivKey,
            digest
        );

        // Verifier
        (
            WOTSPlus.WinternitzAddress memory vPub,
            WOTSPlus.WinternitzElements memory vSig
        ) = _buildVerifierData(impl, "migrate-verifier");

        bytes memory data = Codec.encodeUpgradeToAndCall(
            currentPq,
            nextPq,
            pqSig,
            vPub,
            vSig,
            true,
            migratorPayload
        );

        vm.prank(ALICE);
        wallet.upgradeToAndCall(impl, data);
    }

    /// @dev Deploy → execute → upgrade with migration → verify state reset → resume.
    function test_simulation_upgradeWithMigration() public {
        uint256 balBefore;
        (currentPq, currentPrivKey, balBefore) = _primeUpgradeScenario();

        // Step 2: Prepare migration state
        (WOTSPlus.WinternitzAddress memory migratePq, bytes32 migratePriv) = _generateKeyPair("migrate-pq");
        bytes32 migrateRecBase = keccak256("migrate-recovery-base");
        WOTSPlus.WinternitzAddress[] memory migrateKeys = _generateRecoveryKeys(migrateRecBase, 10);

        // Step 3: Upgrade with migration
        _doUpgradeWithMigration(address(newImpl), migratePq, migrateKeys);

        // Step 4: Verify state after migration
        // pqOwner is the migrate payload's key (migrate overwrites the auth rotation)
        _assertUpgradePreservedBasics(address(newImpl), migratePq, balBefore);

        // Recovery keys are the new set from migration
        for (uint256 i = 0; i < migrateKeys.length; i++) {
            assertTrue(wallet.isKey(Codec.KeyType.Recovery, migrateKeys[i]));
        }

        // Old recovery keys are gone
        for (uint256 i = 0; i < recoveryPubkeys.length; i++) {
            assertFalse(wallet.isKey(Codec.KeyType.Recovery, recoveryPubkeys[i]));
        }

        // Step 5: Resume operations with the migrated key
        currentPq = migratePq;
        currentPrivKey = migratePriv;
        _resumeExecuteAfterUpgrade(currentPq, currentPrivKey, "post-migrate-key");
    }
}
