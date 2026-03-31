// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {QuipWalletTest} from "../QuipWallet.t.sol";
import {QuipWallet} from "../../../contracts/QuipWallet.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";
import {WOTSPlusCodec as Codec} from "../../../contracts/WOTSPlusCodec.sol";
import {Ownable as SoladyOwnable} from "solady-0.1.26/src/auth/Ownable.sol";
import {IQuipWallet} from "../../../contracts/interfaces/IQuipWallet.sol";

contract QuipWallet_upgradeToAndCall is QuipWalletTest {
    QuipWallet public newImpl;

    function setUp() public override {
        super.setUp();
        // Deploy a second implementation for upgrades
        newImpl = new QuipWallet(payable(address(factory)));
        vm.prank(ADMIN);
        factory.vetImplementation(address(newImpl));
    }

    /// @dev Builds the full upgrade data payload (5121 bytes).
    ///      Layout: [0:64) nextPqOwner, [64:2208) pqSig,
    ///              [2208:2272) verifier, [2272:4416) verifySig,
    ///              [4416] shouldMigrate, [4417:5121) migratorPayload.
    function _buildUpgradeData(
        address newImplementation_,
        bytes32 signingKey,
        WOTSPlus.WinternitzAddress memory currentPqOwner,
        WOTSPlus.WinternitzAddress memory nextPqOwner,
        bytes32 verifierSeed,
        bool shouldMigrate,
        WOTSPlus.WinternitzAddress memory migratePqOwner,
        WOTSPlus.WinternitzAddress[] memory migrateRecoveryKeys
    ) internal view returns (bytes memory) {
        // Build the upgrade digest — s1,h1 = current storage owner; s2,h2 = next owner from calldata
        bytes32 digest = Codec.upgradeDigest(
            address(wallet),
            block.chainid,
            address(newImplementation_),
            currentPqOwner.publicSeed,
            currentPqOwner.publicKeyHash,
            nextPqOwner.publicSeed,
            nextPqOwner.publicKeyHash
        );

        // Sign with the current owner's private key
        WOTSPlus.WinternitzElements memory sig = _sign(signingKey, digest);

        // Pack nextPqOwner as the pqSigner field (64 bytes)
        bytes memory pqSigner = abi.encodePacked(nextPqOwner.publicSeed, nextPqOwner.publicKeyHash);

        // Pack pqSig (2144 bytes)
        bytes memory pqSig;
        for (uint256 i = 0; i < 67; i++) {
            pqSig = abi.encodePacked(pqSig, sig.elements[i]);
        }

        // Verifier data (2208 bytes): verifier address (64) + verifier sig (2144)
        bytes memory verifierData = _buildVerifierData(newImplementation_, verifierSeed);

        // shouldMigrate flag (1 byte)
        bytes memory migrateFlag = abi.encodePacked(shouldMigrate ? uint8(1) : uint8(0));

        // Migrator payload (704 bytes): pqOwner (64) + recoveryKeys[10] (640)
        bytes memory migratorPayload = abi.encodePacked(
            migratePqOwner.publicSeed,
            migratePqOwner.publicKeyHash
        );
        for (uint256 i = 0; i < 10; i++) {
            if (i < migrateRecoveryKeys.length) {
                migratorPayload = abi.encodePacked(
                    migratorPayload,
                    migrateRecoveryKeys[i].publicSeed,
                    migrateRecoveryKeys[i].publicKeyHash
                );
            } else {
                migratorPayload = abi.encodePacked(
                    migratorPayload,
                    bytes32(uint256(i + 1)),
                    bytes32(uint256(i + 100))
                );
            }
        }

        return abi.encodePacked(
            pqSigner,       // [0:64)
            pqSig,          // [64:2208)
            verifierData,   // [2208:4416)
            migrateFlag,    // [4416]
            migratorPayload // [4417:5121)
        );
    }

    function _buildVerifierData(
        address newImplementation_,
        bytes32 verifierSeed
    ) internal view returns (bytes memory) {
        (WOTSPlus.WinternitzAddress memory vPub, bytes32 vPriv) = _generateKeyPair(verifierSeed);
        bytes32 vHash = Codec.verificationDigest(
            address(wallet), block.chainid, newImplementation_,
            vPub.publicSeed, vPub.publicKeyHash
        );
        WOTSPlus.WinternitzElements memory vSig = _sign(vPriv, vHash);

        bytes memory data = abi.encodePacked(vPub.publicSeed, vPub.publicKeyHash);
        for (uint256 i = 0; i < 67; i++) {
            data = abi.encodePacked(data, vSig.elements[i]);
        }
        return data;
    }

    // ── Happy paths ──────────────────────────────────────────────────

    function test_upgradeSetUp_vetsSecondImpl() public view {
        assertEq(factory.getVettedCodeCount(), 2);
    }

    function test_upgradeToAndCall_upgradesImplementation() public {
        (WOTSPlus.WinternitzAddress memory nextPq,) = _generateKeyPair("upgrade-next-pq");
        WOTSPlus.WinternitzAddress memory dummyPq = WOTSPlus.WinternitzAddress({
            publicSeed: bytes32(uint256(1)),
            publicKeyHash: bytes32(uint256(2))
        });
        WOTSPlus.WinternitzAddress[] memory emptyKeys = new WOTSPlus.WinternitzAddress[](0);

        bytes memory data = _buildUpgradeData(
            address(newImpl),
            alicePrivateKey,
            alicePubkey,
            nextPq,
            "verifier",
            false,
            dummyPq,
            emptyKeys
        );

        vm.prank(ALICE);
        wallet.upgradeToAndCall(address(newImpl), data);

        assertEq(wallet.owner(), ALICE);
        (bytes32 publicSeed, bytes32 publicKeyHash) = wallet.pqOwner();
        assertEq(publicSeed, nextPq.publicSeed);
        assertEq(publicKeyHash, nextPq.publicKeyHash);
    }

    function test_upgradeToAndCall_migratesStateWhenFlagSet() public {
        (WOTSPlus.WinternitzAddress memory nextPq,) = _generateKeyPair("upgrade-next-pq");
        (WOTSPlus.WinternitzAddress memory newMigratePq,) = _generateKeyPair("migrate-pq");
        bytes32 migrateBase = keccak256("migrate-recovery");
        WOTSPlus.WinternitzAddress[] memory migrateKeys = _generateRecoveryKeys(migrateBase, 10);

        bytes memory data = _buildUpgradeData(
            address(newImpl),
            alicePrivateKey,
            alicePubkey,
            nextPq,
            "verifier",
            true,
            newMigratePq,
            migrateKeys
        );

        vm.prank(ALICE);
        wallet.upgradeToAndCall(address(newImpl), data);

        // pqOwner should be the migrator's pqOwner (migrate overwrites the C-1 rotation)
        (bytes32 publicSeed, bytes32 publicKeyHash) = wallet.pqOwner();
        assertEq(publicSeed, newMigratePq.publicSeed);
        assertEq(publicKeyHash, newMigratePq.publicKeyHash);

        assertEq(wallet.getRecoveryKeyCount(), 10);
    }

    function test_upgradeToAndCall_skipsMigrationWhenFlagUnset() public {
        (WOTSPlus.WinternitzAddress memory nextPq,) = _generateKeyPair("upgrade-next-pq");
        WOTSPlus.WinternitzAddress memory dummyPq = WOTSPlus.WinternitzAddress({
            publicSeed: bytes32(uint256(1)),
            publicKeyHash: bytes32(uint256(2))
        });
        WOTSPlus.WinternitzAddress[] memory emptyKeys = new WOTSPlus.WinternitzAddress[](0);

        bytes memory data = _buildUpgradeData(
            address(newImpl),
            alicePrivateKey,
            alicePubkey,
            nextPq,
            "verifier",
            false,
            dummyPq,
            emptyKeys
        );

        vm.prank(ALICE);
        wallet.upgradeToAndCall(address(newImpl), data);

        // pqOwner should be nextPq (C-1 rotation, no migration)
        (bytes32 publicSeed, bytes32 publicKeyHash) = wallet.pqOwner();
        assertEq(publicSeed, nextPq.publicSeed);
        assertEq(publicKeyHash, nextPq.publicKeyHash);

        assertEq(wallet.getRecoveryKeyCount(), 10);
    }

    function test_upgradeToAndCall_preservesBalanceAndOwner() public {
        uint256 balBefore = address(wallet).balance;
        address ownerBefore = wallet.owner();

        (WOTSPlus.WinternitzAddress memory nextPq,) = _generateKeyPair("upgrade-preserve");
        WOTSPlus.WinternitzAddress memory dummyPq = WOTSPlus.WinternitzAddress({
            publicSeed: bytes32(uint256(1)),
            publicKeyHash: bytes32(uint256(2))
        });
        WOTSPlus.WinternitzAddress[] memory emptyKeys = new WOTSPlus.WinternitzAddress[](0);

        bytes memory data = _buildUpgradeData(
            address(newImpl), alicePrivateKey, alicePubkey, nextPq,
            "verifier", false, dummyPq, emptyKeys
        );

        vm.prank(ALICE);
        wallet.upgradeToAndCall(address(newImpl), data);

        assertEq(address(wallet).balance, balBefore);
        assertEq(wallet.owner(), ownerBefore);
    }

    function test_upgradeToAndCall_migrateInvalidatesOldRecoveryKeys() public {
        (WOTSPlus.WinternitzAddress memory nextPq,) = _generateKeyPair("upgrade-migrate-keys");
        (WOTSPlus.WinternitzAddress memory newMigratePq,) = _generateKeyPair("migrate-pq-keys");
        bytes32 migrateBase = keccak256("migrate-keys-recovery");
        WOTSPlus.WinternitzAddress[] memory migrateKeys = _generateRecoveryKeys(migrateBase, 10);

        bytes memory data = _buildUpgradeData(
            address(newImpl), alicePrivateKey, alicePubkey, nextPq,
            "verifier", true, newMigratePq, migrateKeys
        );

        vm.prank(ALICE);
        wallet.upgradeToAndCall(address(newImpl), data);

        // Old recovery keys should be gone
        for (uint256 i = 0; i < recoveryPubkeys.length; i++) {
            bytes32 keyHash = keccak256(abi.encode(recoveryPubkeys[i].publicSeed, recoveryPubkeys[i].publicKeyHash));
            assertFalse(wallet.isRecoveryKey(keyHash));
        }
    }

    // ── Reverts ──────────────────────────────────────────────────────

    function test_upgradeToAndCall_revertsWhen_callerNotOwner() public {
        WOTSPlus.WinternitzAddress memory dummyPq = WOTSPlus.WinternitzAddress({
            publicSeed: bytes32(uint256(1)),
            publicKeyHash: bytes32(uint256(2))
        });
        WOTSPlus.WinternitzAddress[] memory emptyKeys = new WOTSPlus.WinternitzAddress[](0);

        (WOTSPlus.WinternitzAddress memory nextPq_,) = _generateKeyPair("revert-next-pq");
        bytes memory data = _buildUpgradeData(
            address(newImpl),
            alicePrivateKey,
            alicePubkey,
            nextPq_,
            "verifier",
            false,
            dummyPq,
            emptyKeys
        );

        vm.prank(BOB);
        vm.expectRevert(SoladyOwnable.Unauthorized.selector);
        wallet.upgradeToAndCall(address(newImpl), data);
    }

    function test_upgradeToAndCall_revertsWhen_invalidSignature() public {
        WOTSPlus.WinternitzAddress memory dummyPq = WOTSPlus.WinternitzAddress({
            publicSeed: bytes32(uint256(1)),
            publicKeyHash: bytes32(uint256(2))
        });
        WOTSPlus.WinternitzAddress[] memory emptyKeys = new WOTSPlus.WinternitzAddress[](0);

        // Use a wrong signing key
        (WOTSPlus.WinternitzAddress memory nextPq_,) = _generateKeyPair("inv-sig-next-pq");
        (, bytes32 wrongKey) = _generateKeyPair("wrong-key");
        bytes memory data = _buildUpgradeData(
            address(newImpl),
            wrongKey,
            alicePubkey,
            nextPq_,
            "verifier",
            false,
            dummyPq,
            emptyKeys
        );

        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.InvalidSignature.selector);
        wallet.upgradeToAndCall(address(newImpl), data);
    }

    function test_migrate_revertsWhen_calledDirectly() public {
        (WOTSPlus.WinternitzAddress memory newPq,) = _generateKeyPair("migrate-direct");
        WOTSPlus.WinternitzAddress[] memory rKeys = _generateRecoveryKeys(keccak256("migrate-r"), 10);
        bytes memory migratorPayload = _encodeInitPayload(newPq, rKeys);

        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.NotUpgrading.selector);
        wallet.migrate(migratorPayload);
    }

    function test_migrate_revertsWhen_newPqOwnerIsZero() public {
        WOTSPlus.WinternitzAddress memory zeroPq = WOTSPlus.WinternitzAddress({
            publicSeed: bytes32(0),
            publicKeyHash: bytes32(0)
        });
        WOTSPlus.WinternitzAddress[] memory rKeys = _generateRecoveryKeys(keccak256("migrate-r"), 10);

        (WOTSPlus.WinternitzAddress memory nextPq_,) = _generateKeyPair("zero-migrate-next-pq");
        bytes memory data = _buildUpgradeData(
            address(newImpl),
            alicePrivateKey,
            alicePubkey,
            nextPq_,
            "verifier",
            true,
            zeroPq,
            rKeys
        );

        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.ZeroValuePqOwner.selector);
        wallet.upgradeToAndCall(address(newImpl), data);
    }

    function test_upgradeToAndCall_revertsWhen_pqOwnerReuse() public {
        WOTSPlus.WinternitzAddress memory dummyPq = WOTSPlus.WinternitzAddress({
            publicSeed: bytes32(uint256(1)),
            publicKeyHash: bytes32(uint256(2))
        });
        WOTSPlus.WinternitzAddress[] memory emptyKeys = new WOTSPlus.WinternitzAddress[](0);

        // Use current alicePubkey as nextPq — should trigger PqOwnerReuse
        bytes memory data = _buildUpgradeData(
            address(newImpl),
            alicePrivateKey,
            alicePubkey,
            alicePubkey, // REUSE
            "verifier",
            false,
            dummyPq,
            emptyKeys
        );

        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.PqOwnerReuse.selector);
        wallet.upgradeToAndCall(address(newImpl), data);
    }

    function test_upgradeToAndCall_revertsWhen_nextPqOwnerSeedIsZero() public {
        WOTSPlus.WinternitzAddress memory zeroPq = WOTSPlus.WinternitzAddress({
            publicSeed: bytes32(0),
            publicKeyHash: bytes32("non-empty")
        });
        WOTSPlus.WinternitzAddress memory dummyPq = WOTSPlus.WinternitzAddress({
            publicSeed: bytes32(uint256(1)),
            publicKeyHash: bytes32(uint256(2))
        });
        WOTSPlus.WinternitzAddress[] memory emptyKeys = new WOTSPlus.WinternitzAddress[](0);

        bytes memory data = _buildUpgradeData(
            address(newImpl),
            alicePrivateKey,
            alicePubkey,
            zeroPq,
            "verifier",
            false,
            dummyPq,
            emptyKeys
        );

        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.ZeroValuePqOwner.selector);
        wallet.upgradeToAndCall(address(newImpl), data);
    }

    function test_upgradeToAndCall_revertsWhen_nextPqOwnerHashIsZero() public {
        WOTSPlus.WinternitzAddress memory zeroPq = WOTSPlus.WinternitzAddress({
            publicSeed: bytes32("non-empty"),
            publicKeyHash: bytes32(0)
        });
        WOTSPlus.WinternitzAddress memory dummyPq = WOTSPlus.WinternitzAddress({
            publicSeed: bytes32(uint256(1)),
            publicKeyHash: bytes32(uint256(2))
        });
        WOTSPlus.WinternitzAddress[] memory emptyKeys = new WOTSPlus.WinternitzAddress[](0);

        bytes memory data = _buildUpgradeData(
            address(newImpl),
            alicePrivateKey,
            alicePubkey,
            zeroPq,
            "verifier",
            false,
            dummyPq,
            emptyKeys
        );

        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.ZeroValuePqOwner.selector);
        wallet.upgradeToAndCall(address(newImpl), data);
    }

}
