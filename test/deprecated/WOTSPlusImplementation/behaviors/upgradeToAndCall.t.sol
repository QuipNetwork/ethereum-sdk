// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WOTSPlusImplementationTest} from "../WOTSPlusImplementation.t.sol";
import {WOTSPlusImplementation} from "../../../../contracts/deprecated/wots/WOTSPlusImplementation.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.2.0/contracts/WOTSPlus.sol";
import {WOTSPlusCodec as Codec} from "../../../../contracts/deprecated/wots/WOTSPlusCodec.sol";
import {Ownable as SoladyOwnable} from "solady-0.1.26/src/auth/Ownable.sol";
import {IWOTSPlusImplementation} from "../../../../contracts/deprecated/wots/interfaces/IWOTSPlusImplementation.sol";
import {EnumerableWinternitzAddressSet as Keyset} from "../../../../contracts/deprecated/wots/EnumerableWinternitzAddressSet.sol";
import {WOTSPlusStorage as Storage} from "../../../../contracts/deprecated/wots/WOTSPlusStorage.sol";

/// @dev Minimal "rogue vetted impl" used to prove the verify-delegatecall guard
///      catches SSTOREs to any guarded slot. The fallback overwrites the
///      `ownershipKey` publicSeed slot — one of the seven slots snapshotted by
///      the guard. If the guard did not fire, this SSTORE would silently
///      succeed against the wallet's storage and brick the ownership-transfer
///      path. Slot is loaded from `WOTSPlusStorage` via a local variable
///      because Yul rejects direct cross-library constant references.
contract RogueUpgradeImpl_WritesGuardedSlot {
    fallback() external payable {
        bytes32 slot = Storage._OWNERSHIP_KEY_SEED_SLOT;
        /// @solidity memory-safe-assembly
        assembly {
            sstore(slot, 0xdeadbeef)
        }
    }
}

contract WOTSPlusImplementation_upgradeToAndCall is WOTSPlusImplementationTest {
    WOTSPlusImplementation public newImpl;

    function setUp() public override {
        super.setUp();
        // Deploy a second implementation for upgrades
        newImpl = new WOTSPlusImplementation(payable(address(factory)));
        vm.prank(ADMIN);
        factory.vetImplementation(address(newImpl));
    }

    // ── Happy paths ──────────────────────────────────────────────────

    function test_upgradeSetUp_vetsSecondImpl() public view {
        assertEq(factory.getVettedCodeCount(), 2);
    }

    function test_upgradeToAndCall_upgradesImplementation() public {
        (WOTSPlus.WinternitzAddress memory nextPq,) = _generateKeyPair("upgrade-next-pq");
        WOTSPlus.WinternitzAddress memory dummyPq =
            WOTSPlus.WinternitzAddress({publicSeed: bytes32(uint256(1)), publicKeyHash: bytes32(uint256(2))});
        WOTSPlus.WinternitzAddress[] memory emptyKeys = new WOTSPlus.WinternitzAddress[](0);

        bytes memory data = _buildUpgradeData(
            address(newImpl), alicePrivateKey, alicePubkey, nextPq, "verifier", false, dummyPq, emptyKeys
        );

        vm.prank(ALICE);
        wallet.upgradeToAndCall(address(newImpl), data);

        assertEq(wallet.owner(), ALICE);
        assertTrue(wallet.isKey(Codec.KeyType.Transaction, nextPq));
    }

    function test_upgradeToAndCall_migratesStateWhenFlagSet() public {
        (WOTSPlus.WinternitzAddress memory nextPq,) = _generateKeyPair("upgrade-next-pq");
        (WOTSPlus.WinternitzAddress memory newMigratePq,) = _generateKeyPair("migrate-pq");
        bytes32 migrateBase = keccak256("migrate-recovery");
        WOTSPlus.WinternitzAddress[] memory migrateKeys = _generateRecoveryKeys(migrateBase, 10);

        bytes memory data = _buildUpgradeData(
            address(newImpl), alicePrivateKey, alicePubkey, nextPq, "verifier", true, newMigratePq, migrateKeys
        );

        vm.prank(ALICE);
        wallet.upgradeToAndCall(address(newImpl), data);

        // pqOwner should be the migrator's pqOwner (migrate overwrites the C-1 rotation)
        assertTrue(wallet.isKey(Codec.KeyType.Transaction, newMigratePq));

        assertEq(wallet.keyCount(Codec.KeyType.Recovery), 10);
    }

    function test_upgradeToAndCall_skipsMigrationWhenFlagUnset() public {
        (WOTSPlus.WinternitzAddress memory nextPq,) = _generateKeyPair("upgrade-next-pq");
        WOTSPlus.WinternitzAddress memory dummyPq =
            WOTSPlus.WinternitzAddress({publicSeed: bytes32(uint256(1)), publicKeyHash: bytes32(uint256(2))});
        WOTSPlus.WinternitzAddress[] memory emptyKeys = new WOTSPlus.WinternitzAddress[](0);

        bytes memory data = _buildUpgradeData(
            address(newImpl), alicePrivateKey, alicePubkey, nextPq, "verifier", false, dummyPq, emptyKeys
        );

        vm.prank(ALICE);
        wallet.upgradeToAndCall(address(newImpl), data);

        // pqOwner should be nextPq (C-1 rotation, no migration)
        assertTrue(wallet.isKey(Codec.KeyType.Transaction, nextPq));

        assertEq(wallet.keyCount(Codec.KeyType.Recovery), 10);
    }

    function test_upgradeToAndCall_preservesBalanceAndOwner() public {
        uint256 balBefore = address(wallet).balance;
        address ownerBefore = wallet.owner();

        (WOTSPlus.WinternitzAddress memory nextPq,) = _generateKeyPair("upgrade-preserve");
        WOTSPlus.WinternitzAddress memory dummyPq =
            WOTSPlus.WinternitzAddress({publicSeed: bytes32(uint256(1)), publicKeyHash: bytes32(uint256(2))});
        WOTSPlus.WinternitzAddress[] memory emptyKeys = new WOTSPlus.WinternitzAddress[](0);

        bytes memory data = _buildUpgradeData(
            address(newImpl), alicePrivateKey, alicePubkey, nextPq, "verifier", false, dummyPq, emptyKeys
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
            address(newImpl), alicePrivateKey, alicePubkey, nextPq, "verifier", true, newMigratePq, migrateKeys
        );

        vm.prank(ALICE);
        wallet.upgradeToAndCall(address(newImpl), data);

        // Old recovery keys should be gone
        for (uint256 i = 0; i < recoveryPubkeys.length; i++) {
            assertFalse(wallet.isKey(Codec.KeyType.Recovery, recoveryPubkeys[i]));
        }
    }

    // ── Reverts ──────────────────────────────────────────────────────

    function test_upgradeToAndCall_revertsWhen_callerNotOwner() public {
        WOTSPlus.WinternitzAddress memory dummyPq =
            WOTSPlus.WinternitzAddress({publicSeed: bytes32(uint256(1)), publicKeyHash: bytes32(uint256(2))});
        WOTSPlus.WinternitzAddress[] memory emptyKeys = new WOTSPlus.WinternitzAddress[](0);

        (WOTSPlus.WinternitzAddress memory nextPq_,) = _generateKeyPair("revert-next-pq");
        bytes memory data = _buildUpgradeData(
            address(newImpl), alicePrivateKey, alicePubkey, nextPq_, "verifier", false, dummyPq, emptyKeys
        );

        vm.prank(BOB);
        vm.expectRevert(SoladyOwnable.Unauthorized.selector);
        wallet.upgradeToAndCall(address(newImpl), data);
    }

    function test_upgradeToAndCall_revertsWhen_invalidSignature() public {
        WOTSPlus.WinternitzAddress memory dummyPq =
            WOTSPlus.WinternitzAddress({publicSeed: bytes32(uint256(1)), publicKeyHash: bytes32(uint256(2))});
        WOTSPlus.WinternitzAddress[] memory emptyKeys = new WOTSPlus.WinternitzAddress[](0);

        // Use a wrong signing key
        (WOTSPlus.WinternitzAddress memory nextPq_,) = _generateKeyPair("inv-sig-next-pq");
        (, bytes32 wrongKey) = _generateKeyPair("wrong-key");
        bytes memory data =
            _buildUpgradeData(address(newImpl), wrongKey, alicePubkey, nextPq_, "verifier", false, dummyPq, emptyKeys);

        vm.prank(ALICE);
        vm.expectRevert(IWOTSPlusImplementation.InvalidSignature.selector);
        wallet.upgradeToAndCall(address(newImpl), data);
    }

    function test_upgradeToAndCall_revertsWhen_shouldMigrateTampered() public {
        WOTSPlus.WinternitzAddress memory dummyPq = WOTSPlus.WinternitzAddress({
            publicSeed: bytes32(uint256(1)),
            publicKeyHash: bytes32(uint256(2))
        });
        WOTSPlus.WinternitzAddress[]
            memory emptyKeys = new WOTSPlus.WinternitzAddress[](0);

        (WOTSPlus.WinternitzAddress memory nextPq_, ) = _generateKeyPair(
            "tamper-migrate-next-pq"
        );
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
        data[4480] = 0x01;

        vm.prank(ALICE);
        vm.expectRevert(IWOTSPlusImplementation.InvalidSignature.selector);
        wallet.upgradeToAndCall(address(newImpl), data);
    }

    function test_upgradeToAndCall_revertsWhen_migratorPayloadTampered()
        public
    {
        WOTSPlus.WinternitzAddress memory dummyPq = WOTSPlus.WinternitzAddress({
            publicSeed: bytes32(uint256(1)),
            publicKeyHash: bytes32(uint256(2))
        });
        WOTSPlus.WinternitzAddress[]
            memory emptyKeys = new WOTSPlus.WinternitzAddress[](0);

        (WOTSPlus.WinternitzAddress memory nextPq_, ) = _generateKeyPair(
            "tamper-payload-next-pq"
        );
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
        data[4481] = bytes1(uint8(data[4481]) ^ 0xff);

        vm.prank(ALICE);
        vm.expectRevert(IWOTSPlusImplementation.InvalidSignature.selector);
        wallet.upgradeToAndCall(address(newImpl), data);
    }

    function test_migrate_revertsWhen_calledDirectly() public {
        (WOTSPlus.WinternitzAddress memory newPq, ) = _generateKeyPair(
            "migrate-direct"
        );
        WOTSPlus.WinternitzAddress[] memory rKeys = _generateRecoveryKeys(
            keccak256("migrate-r"),
            10
        );
        bytes memory migratorPayload = _encodeInitPayload(newPq, rKeys);

        vm.prank(ALICE);
        vm.expectRevert(IWOTSPlusImplementation.NotUpgrading.selector);
        wallet.migrate(migratorPayload);
    }

    function test_migrate_revertsWhen_initialKeyIsZero() public {
        WOTSPlus.WinternitzAddress memory zeroPq =
            WOTSPlus.WinternitzAddress({publicSeed: bytes32(0), publicKeyHash: bytes32(0)});
        WOTSPlus.WinternitzAddress[] memory rKeys = _generateRecoveryKeys(keccak256("migrate-r"), 10);

        (WOTSPlus.WinternitzAddress memory nextPq_,) = _generateKeyPair("zero-migrate-next-pq");
        bytes memory data =
            _buildUpgradeData(address(newImpl), alicePrivateKey, alicePubkey, nextPq_, "verifier", true, zeroPq, rKeys);

        vm.prank(ALICE);
        vm.expectRevert(Keyset.ZeroValueWinternitzAddress.selector);
        wallet.upgradeToAndCall(address(newImpl), data);
    }

    function test_upgradeToAndCall_revertsWhen_nextKeyEqualsCurrentKey() public {
        WOTSPlus.WinternitzAddress memory dummyPq =
            WOTSPlus.WinternitzAddress({publicSeed: bytes32(uint256(1)), publicKeyHash: bytes32(uint256(2))});
        WOTSPlus.WinternitzAddress[] memory emptyKeys = new WOTSPlus.WinternitzAddress[](0);

        // Use current alicePubkey as nextKey — should trigger SameKey
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
        vm.expectRevert(IWOTSPlusImplementation.SameKey.selector);
        wallet.upgradeToAndCall(address(newImpl), data);
    }

    // ── Cross-set: nextKey collides with another keyset / single ──────
    //
    // The auth rotation goes through `_verifyAndRotate(transactionKeys, ...)`,
    // which runs `_enforceUnspentKey(nextKey)` against ALL keysets and both
    // single keys. Each of these tests stages a cross-set collision and
    // asserts `KeyInUse` before WOTS+ verify.

    function _runUpgradeWithNextPq(WOTSPlus.WinternitzAddress memory nextPq, bytes32 verifierTag)
        internal
        returns (bytes memory data)
    {
        WOTSPlus.WinternitzAddress memory dummyPq =
            WOTSPlus.WinternitzAddress({publicSeed: bytes32(uint256(1)), publicKeyHash: bytes32(uint256(2))});
        WOTSPlus.WinternitzAddress[] memory emptyKeys = new WOTSPlus.WinternitzAddress[](0);
        data = _buildUpgradeData(
            address(newImpl), alicePrivateKey, alicePubkey, nextPq, verifierTag, false, dummyPq, emptyKeys
        );
    }

    function test_upgradeToAndCall_revertsWhen_nextKeyInRecoverySet() public {
        bytes memory data = _runUpgradeWithNextPq(recoveryPubkeys[2], "verifier-rec");

        vm.prank(ALICE);
        vm.expectRevert(IWOTSPlusImplementation.KeyInUse.selector);
        wallet.upgradeToAndCall(address(newImpl), data);
    }

    function test_upgradeToAndCall_revertsWhen_nextKeyEqualsOwnershipKey() public {
        bytes memory data = _runUpgradeWithNextPq(ownershipPubkey, "verifier-own");

        vm.prank(ALICE);
        vm.expectRevert(IWOTSPlusImplementation.KeyInUse.selector);
        wallet.upgradeToAndCall(address(newImpl), data);
    }

    function test_upgradeToAndCall_revertsWhen_nextKeyEqualsDisasterKey() public {
        (WOTSPlus.WinternitzAddress memory disasterPub,) = _generateDisasterRecoveryKey(VAULT_SEED);
        bytes memory data = _runUpgradeWithNextPq(disasterPub, "verifier-dis");

        vm.prank(ALICE);
        vm.expectRevert(IWOTSPlusImplementation.KeyInUse.selector);
        wallet.upgradeToAndCall(address(newImpl), data);
    }

    function test_upgradeToAndCall_revertsWhen_nextKeySeedIsZero() public {
        WOTSPlus.WinternitzAddress memory zeroPq =
            WOTSPlus.WinternitzAddress({publicSeed: bytes32(0), publicKeyHash: bytes32("non-empty")});
        WOTSPlus.WinternitzAddress memory dummyPq =
            WOTSPlus.WinternitzAddress({publicSeed: bytes32(uint256(1)), publicKeyHash: bytes32(uint256(2))});
        WOTSPlus.WinternitzAddress[] memory emptyKeys = new WOTSPlus.WinternitzAddress[](0);

        bytes memory data = _buildUpgradeData(
            address(newImpl), alicePrivateKey, alicePubkey, zeroPq, "verifier", false, dummyPq, emptyKeys
        );

        vm.prank(ALICE);
        vm.expectRevert(Keyset.ZeroValueWinternitzAddress.selector);
        wallet.upgradeToAndCall(address(newImpl), data);
    }

    function test_upgradeToAndCall_revertsWhen_nextKeyHashIsZero() public {
        WOTSPlus.WinternitzAddress memory zeroPq =
            WOTSPlus.WinternitzAddress({publicSeed: bytes32("non-empty"), publicKeyHash: bytes32(0)});
        WOTSPlus.WinternitzAddress memory dummyPq =
            WOTSPlus.WinternitzAddress({publicSeed: bytes32(uint256(1)), publicKeyHash: bytes32(uint256(2))});
        WOTSPlus.WinternitzAddress[] memory emptyKeys = new WOTSPlus.WinternitzAddress[](0);

        bytes memory data = _buildUpgradeData(
            address(newImpl), alicePrivateKey, alicePubkey, zeroPq, "verifier", false, dummyPq, emptyKeys
        );

        vm.prank(ALICE);
        vm.expectRevert(Keyset.ZeroValueWinternitzAddress.selector);
        wallet.upgradeToAndCall(address(newImpl), data);
    }

    function test_upgradeToAndCall_revertsWhen_implementationNotVetted() public {
        // Deploy but do NOT vet
        WOTSPlusImplementation unvetted = new WOTSPlusImplementation(payable(address(factory)));

        (WOTSPlus.WinternitzAddress memory nextPq,) = _generateKeyPair("unvetted-next-pq");
        WOTSPlus.WinternitzAddress memory dummyPq =
            WOTSPlus.WinternitzAddress({publicSeed: bytes32(uint256(1)), publicKeyHash: bytes32(uint256(2))});
        WOTSPlus.WinternitzAddress[] memory emptyKeys = new WOTSPlus.WinternitzAddress[](0);

        bytes memory data = _buildUpgradeData(
            address(unvetted), alicePrivateKey, alicePubkey, nextPq, "verifier", false, dummyPq, emptyKeys
        );

        vm.prank(ALICE);
        vm.expectRevert(IWOTSPlusImplementation.ImplementationNotVetted.selector);
        wallet.upgradeToAndCall(address(unvetted), data);
    }

    function test_upgradeToAndCall_revertsWhen_implementationDeprecated() public {
        // Deprecate the already-vetted newImpl
        vm.prank(ADMIN);
        factory.deprecateImplementation(address(newImpl));

        (WOTSPlus.WinternitzAddress memory nextPq,) = _generateKeyPair("deprecated-next-pq");
        WOTSPlus.WinternitzAddress memory dummyPq =
            WOTSPlus.WinternitzAddress({publicSeed: bytes32(uint256(1)), publicKeyHash: bytes32(uint256(2))});
        WOTSPlus.WinternitzAddress[] memory emptyKeys = new WOTSPlus.WinternitzAddress[](0);

        bytes memory data = _buildUpgradeData(
            address(newImpl), alicePrivateKey, alicePubkey, nextPq, "verifier", false, dummyPq, emptyKeys
        );

        vm.prank(ALICE);
        vm.expectRevert(IWOTSPlusImplementation.ImplementationDeprecated.selector);
        wallet.upgradeToAndCall(address(newImpl), data);
    }

    /// @dev Belt-and-suspenders test for the verify-delegatecall storage guard.
    ///      A rogue but factory-vetted impl whose `verifyUpgrade` delegatecall
    ///      SSTOREs to a guarded slot must be caught by the post-delegatecall
    ///      snapshot assert in `upgradeToAndCall`.
    function test_upgradeToAndCall_revertsWhen_verifyDelegateCallMutatesGuardedSlot() public {
        RogueUpgradeImpl_WritesGuardedSlot rogue = new RogueUpgradeImpl_WritesGuardedSlot();
        vm.prank(ADMIN);
        factory.vetImplementation(address(rogue));

        (WOTSPlus.WinternitzAddress memory nextPq,) = _generateKeyPair("rogue-next-pq");
        WOTSPlus.WinternitzAddress memory dummyPq =
            WOTSPlus.WinternitzAddress({publicSeed: bytes32(uint256(1)), publicKeyHash: bytes32(uint256(2))});
        WOTSPlus.WinternitzAddress[] memory emptyKeys = new WOTSPlus.WinternitzAddress[](0);

        bytes memory data = _buildUpgradeData(
            address(rogue), alicePrivateKey, alicePubkey, nextPq, "rogue-verifier", false, dummyPq, emptyKeys
        );

        // The guard reverts with empty data (plain revert), consistent with
        // Solady's parent guard style.
        vm.prank(ALICE);
        vm.expectRevert();
        wallet.upgradeToAndCall(address(rogue), data);
    }
}
