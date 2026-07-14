// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {IWOTSPlusImplementation} from "../../../contracts/deprecated/wots/interfaces/IWOTSPlusImplementation.sol";

import {WOTSPlusImplementationTest} from "../WOTSPlusImplementation.t.sol";
import {WOTSPlusImplementation} from "../../../contracts/deprecated/wots/WOTSPlusImplementation.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.2.0/contracts/WOTSPlus.sol";
import {WOTSPlusCodec as Codec} from "../../../contracts/deprecated/wots/WOTSPlusCodec.sol";

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
        currentPq = alicePubkey;
        currentPrivKey = alicePrivateKey;

        // Step 1: Execute a transfer before upgrading
        {
            (WOTSPlus.WinternitzAddress memory nextPq, bytes32 nextPriv) = _generateKeyPair("pre-upgrade-key");
            uint256 fee = wallet.getExecuteFee();
            bytes32 msgHash = _buildExecuteMessageHash(address(wallet), currentPq, nextPq, BOB, 0.1 ether, "", fee);
            WOTSPlus.WinternitzElements memory sig = _sign(currentPrivKey, msgHash);

            vm.prank(ALICE);
            wallet.execute(Codec.encodeExecute(currentPq, nextPq, sig, BOB, 0.1 ether, ""));

            currentPq = nextPq;
            currentPrivKey = nextPriv;
        }

        uint256 balBefore = address(wallet).balance;

        // Step 2: Upgrade without migration
        (WOTSPlus.WinternitzAddress memory upgradedPq, bytes32 upgradedPriv) =
            _doUpgradeWithoutMigration(address(newImpl));

        // Step 3: Verify state preserved
        // 3a: Implementation changed
        assertEq(wallet.version(), factory.getVettedCodeIndex(address(newImpl).codehash));

        // 3b: pqOwner is the auth's nextPqOwner (no migration override)
        assertTrue(wallet.isKey(Codec.KeyType.Transaction, upgradedPq));

        // 3c: Recovery keys unchanged (still the original set)
        assertEq(wallet.keyCount(Codec.KeyType.Recovery), 10);
        for (uint256 i = 0; i < recoveryPubkeys.length; i++) {
            assertTrue(wallet.isKey(Codec.KeyType.Recovery, recoveryPubkeys[i]));
        }

        // 3d: Balance and owner preserved
        assertEq(address(wallet).balance, balBefore);
        assertEq(wallet.owner(), ALICE);

        // Step 4: Resume operations with the upgraded key
        currentPq = upgradedPq;
        currentPrivKey = upgradedPriv;

        (WOTSPlus.WinternitzAddress memory postPq,) = _generateKeyPair("post-upgrade-key");
        uint256 fee = wallet.getExecuteFee();
        bytes32 msgHash = _buildExecuteMessageHash(address(wallet), currentPq, postPq, BOB, 0.05 ether, "", fee);
        WOTSPlus.WinternitzElements memory postSig = _sign(currentPrivKey, msgHash);

        uint256 bobBal = BOB.balance;
        vm.prank(ALICE);
        wallet.execute(Codec.encodeExecute(currentPq, postPq, postSig, BOB, 0.05 ether, ""));
        assertEq(BOB.balance, bobBal + 0.05 ether);
    }
}
