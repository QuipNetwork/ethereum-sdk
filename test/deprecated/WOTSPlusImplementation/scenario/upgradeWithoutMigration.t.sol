// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {IWOTSPlusImplementation} from "../../../../contracts/deprecated/wots/interfaces/IWOTSPlusImplementation.sol";

import {WOTSPlusImplementationTest} from "../WOTSPlusImplementation.t.sol";
import {WOTSPlusImplementation} from "../../../../contracts/deprecated/wots/WOTSPlusImplementation.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.2.0/contracts/WOTSPlus.sol";
import {WOTSPlusCodec as Codec} from "../../../../contracts/deprecated/wots/WOTSPlusCodec.sol";

/// @title Upgrade without Migration Scenario Test
/// @dev Full upgrade-without-migration flow: deploy → use → upgrade with
///      shouldMigrate=false → verify state preserved → resume operations.
contract WOTSPlusImplementation_upgradeWithoutMigration is WOTSPlusImplementationTest {
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

    function _doUpgradeWithoutMigration(address impl)
        internal
        returns (WOTSPlus.WinternitzAddress memory nextPq, bytes32 nextPrivKey)
    {
        (nextPq, nextPrivKey) = _generateKeyPair("upgrade-next-pq");

        // No migration: migrator slot is zero-filled (2048 bytes). The wallet
        // never decodes or delegatecalls into it when shouldMigrate=false.
        bytes memory migratorPayload = new bytes(2048);

        bytes32 digest = Codec.upgradeDigest(
            address(wallet),
            block.chainid,
            impl,
            currentPq.publicSeed,
            currentPq.publicKeyHash,
            nextPq.publicSeed,
            nextPq.publicKeyHash,
            false,
            keccak256(migratorPayload)
        );
        WOTSPlus.WinternitzElements memory pqSig = _sign(
            currentPrivKey,
            digest
        );

        (
            WOTSPlus.WinternitzAddress memory vPub,
            WOTSPlus.WinternitzElements memory vSig
        ) = _buildVerifierData(impl, "no-migrate-verifier");

        bytes memory data = Codec.encodeUpgradeToAndCall(
            currentPq,
            nextPq,
            pqSig,
            vPub,
            vSig,
            false,
            migratorPayload
        );

        vm.prank(ALICE);
        wallet.upgradeToAndCall(impl, data);
    }

    /// @dev Deploy → execute → upgrade without migration → verify state preserved → resume.
    function test_simulation_upgradeWithoutMigration() public {
        uint256 balBefore;
        (currentPq, currentPrivKey, balBefore) = _primeUpgradeScenario();

        // Step 2: Upgrade without migration
        (WOTSPlus.WinternitzAddress memory upgradedPq, bytes32 upgradedPriv) =
            _doUpgradeWithoutMigration(address(newImpl));

        // Step 3: Verify state preserved
        // pqOwner is the auth's nextPqOwner (no migration override)
        _assertUpgradePreservedBasics(address(newImpl), upgradedPq, balBefore);

        // Recovery keys unchanged (still the original set)
        for (uint256 i = 0; i < recoveryPubkeys.length; i++) {
            assertTrue(wallet.isKey(Codec.KeyType.Recovery, recoveryPubkeys[i]));
        }

        // Step 4: Resume operations with the upgraded key
        currentPq = upgradedPq;
        currentPrivKey = upgradedPriv;
        _resumeExecuteAfterUpgrade(currentPq, currentPrivKey, "post-upgrade-key");
    }
}
