// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {QuipWalletTest} from "../QuipWallet.t.sol";
import {QuipWallet} from "../../../contracts/QuipWallet.sol";
import {QuipWalletHarness, HarnessKeyset} from "../../harness/QuipWalletHarness.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";
import {Ownable as SoladyOwnable} from "solady-0.1.26/src/auth/Ownable.sol";
import {IQuipWallet} from "../../../contracts/interfaces/IQuipWallet.sol";
import {WOTSPlusCodec as Codec} from "../../../contracts/WOTSPlusCodec.sol";
import {Vm} from "forge-std-1.14.0/Vm.sol";
import {EnumerableWinternitzAddressSet as Keyset} from "../../../contracts/libraries/EnumerableWinternitzAddressSet.sol";

/// @dev Tests for `addKeys(KeyType.Recovery, ...)`.
///
///      The wallet's recovery set is initialised at MAX_KEYS (10), and
///      `recoverWallet` is size-preserving (rotation, not consumption). Tests
///      that need an open slot use the harness `burnKey` escape hatch to
///      remove a key directly — clearer than threading a full
///      WOTS+-authenticated `refreshKeys` flow through setup.
contract QuipWallet_addKeys_Recovery is QuipWalletTest {
    QuipWalletHarness public harnessProxy;

    function setUp() public override {
        super.setUp();

        QuipWalletHarness harnessImpl = new QuipWalletHarness(
            payable(address(factory))
        );
        vm.prank(ADMIN);
        factory.vetImplementation(address(harnessImpl));

        bytes memory payload = _encodeInitPayload(alicePubkey, recoveryPubkeys);

        vm.prank(ALICE);
        address proxyAddr = factory.deployLatestWalletProxy{
            value: INITIAL_DEPOSIT
        }(keccak256("addKeys-recovery-vault"), payable(ALICE), payload);
        harnessProxy = QuipWalletHarness(payable(proxyAddr));
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                       STATE CHANGES                            */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    function test_addKeys_Recovery_installsNewKeyInRecoverySet() public {
        harnessProxy.burnKey(HarnessKeyset.Recovery, recoveryPubkeys[0]);

        WOTSPlus.WinternitzAddress[] memory newKeys = _generateRecoveryKeys(
            keccak256("install-recovery"),
            1
        );
        (WOTSPlus.WinternitzAddress memory nextPq, ) = _generateKeyPair(
            "install-recovery-next-pq"
        );

        bytes32 msgHash = _buildAddRecoveryKeysMessageHash(
            address(harnessProxy),
            alicePubkey,
            nextPq,
            newKeys
        );
        WOTSPlus.WinternitzElements memory sig = _sign(
            alicePrivateKey,
            msgHash
        );

        assertFalse(harnessProxy.isKey(Codec.KeyType.Recovery, newKeys[0]));

        vm.prank(ALICE);
        harnessProxy.addKeys(
            Codec.encodeKeyManagement(
                Codec.KeyType.Recovery,
                alicePubkey,
                nextPq,
                sig,
                newKeys
            )
        );

        assertTrue(harnessProxy.isKey(Codec.KeyType.Recovery, newKeys[0]));
    }

    function test_addKeys_Recovery_addsMultipleKeysInOneBatch() public {
        // Free 3 slots so a 3-key batch fits.
        harnessProxy.burnKey(HarnessKeyset.Recovery, recoveryPubkeys[0]);
        harnessProxy.burnKey(HarnessKeyset.Recovery, recoveryPubkeys[1]);
        harnessProxy.burnKey(HarnessKeyset.Recovery, recoveryPubkeys[2]);
        uint256 sizeBefore = harnessProxy.keyCount(Codec.KeyType.Recovery);

        WOTSPlus.WinternitzAddress[] memory newKeys = _generateRecoveryKeys(
            keccak256("multi-batch"),
            3
        );
        (WOTSPlus.WinternitzAddress memory nextPq, ) = _generateKeyPair(
            "multi-batch-next-pq"
        );

        bytes32 msgHash = _buildAddRecoveryKeysMessageHash(
            address(harnessProxy),
            alicePubkey,
            nextPq,
            newKeys
        );
        WOTSPlus.WinternitzElements memory sig = _sign(
            alicePrivateKey,
            msgHash
        );

        vm.prank(ALICE);
        harnessProxy.addKeys(
            Codec.encodeKeyManagement(
                Codec.KeyType.Recovery,
                alicePubkey,
                nextPq,
                sig,
                newKeys
            )
        );

        // All 3 new keys are in the set, count grew by exactly 3.
        for (uint256 i = 0; i < newKeys.length; i++) {
            assertTrue(harnessProxy.isKey(Codec.KeyType.Recovery, newKeys[i]));
        }
        assertEq(
            harnessProxy.keyCount(Codec.KeyType.Recovery),
            sizeBefore + newKeys.length
        );
    }

    function test_addKeys_Recovery_growsRecoveryKeysetSize() public {
        harnessProxy.burnKey(HarnessKeyset.Recovery, recoveryPubkeys[0]);
        uint256 sizeBefore = harnessProxy.keyCount(Codec.KeyType.Recovery);

        WOTSPlus.WinternitzAddress[] memory newKeys = _generateRecoveryKeys(
            keccak256("grow-recovery"),
            1
        );
        (WOTSPlus.WinternitzAddress memory nextPq, ) = _generateKeyPair(
            "grow-recovery-next-pq"
        );

        bytes32 msgHash = _buildAddRecoveryKeysMessageHash(
            address(harnessProxy),
            alicePubkey,
            nextPq,
            newKeys
        );
        WOTSPlus.WinternitzElements memory sig = _sign(
            alicePrivateKey,
            msgHash
        );

        vm.prank(ALICE);
        harnessProxy.addKeys(
            Codec.encodeKeyManagement(
                Codec.KeyType.Recovery,
                alicePubkey,
                nextPq,
                sig,
                newKeys
            )
        );

        assertEq(
            harnessProxy.keyCount(Codec.KeyType.Recovery),
            sizeBefore + newKeys.length
        );
    }

    function test_addKeys_Recovery_rotatesAuthTransactionKey() public {
        harnessProxy.burnKey(HarnessKeyset.Recovery, recoveryPubkeys[0]);

        WOTSPlus.WinternitzAddress[] memory newKeys = _generateRecoveryKeys(
            keccak256("rotate-auth"),
            1
        );
        (WOTSPlus.WinternitzAddress memory nextPq, ) = _generateKeyPair(
            "rotate-auth-next-pq"
        );

        bytes32 msgHash = _buildAddRecoveryKeysMessageHash(
            address(harnessProxy),
            alicePubkey,
            nextPq,
            newKeys
        );
        WOTSPlus.WinternitzElements memory sig = _sign(
            alicePrivateKey,
            msgHash
        );

        assertTrue(harnessProxy.isKey(Codec.KeyType.Transaction, alicePubkey));
        assertFalse(harnessProxy.isKey(Codec.KeyType.Transaction, nextPq));

        vm.prank(ALICE);
        harnessProxy.addKeys(
            Codec.encodeKeyManagement(
                Codec.KeyType.Recovery,
                alicePubkey,
                nextPq,
                sig,
                newKeys
            )
        );

        assertFalse(harnessProxy.isKey(Codec.KeyType.Transaction, alicePubkey));
        assertTrue(harnessProxy.isKey(Codec.KeyType.Transaction, nextPq));
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                          EVENTS                                */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    function test_addKeys_Recovery_emitsKeysAddedEvent() public {
        harnessProxy.burnKey(HarnessKeyset.Recovery, recoveryPubkeys[0]);

        WOTSPlus.WinternitzAddress[] memory newKeys = _generateRecoveryKeys(
            keccak256("emits-event-recovery"),
            1
        );
        (WOTSPlus.WinternitzAddress memory nextPq, ) = _generateKeyPair(
            "emits-event-next-pq"
        );

        bytes32 msgHash = _buildAddRecoveryKeysMessageHash(
            address(harnessProxy),
            alicePubkey,
            nextPq,
            newKeys
        );
        WOTSPlus.WinternitzElements memory sig = _sign(
            alicePrivateKey,
            msgHash
        );

        vm.prank(ALICE);
        vm.recordLogs();
        harnessProxy.addKeys(
            Codec.encodeKeyManagement(
                Codec.KeyType.Recovery,
                alicePubkey,
                nextPq,
                sig,
                newKeys
            )
        );

        Vm.Log[] memory logs = vm.getRecordedLogs();
        bool found = false;
        for (uint256 i = 0; i < logs.length; i++) {
            if (logs[i].topics[0] == IQuipWallet.KeysAdded.selector) {
                found = true;
                break;
            }
        }
        assertTrue(found, "KeysAdded event not emitted");
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                      ACCESS CONTROL                            */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    function test_addKeys_Recovery_revertsWhen_callerNotOwner() public {
        WOTSPlus.WinternitzAddress[] memory newKeys = _generateRecoveryKeys(
            keccak256("not-owner-recovery"),
            1
        );
        (WOTSPlus.WinternitzAddress memory nextPq, ) = _generateKeyPair(
            "not-owner-next-pq"
        );

        bytes32 msgHash = _buildAddRecoveryKeysMessageHash(
            address(harnessProxy),
            alicePubkey,
            nextPq,
            newKeys
        );
        WOTSPlus.WinternitzElements memory sig = _sign(
            alicePrivateKey,
            msgHash
        );

        vm.prank(BOB);
        vm.expectRevert(SoladyOwnable.Unauthorized.selector);
        harnessProxy.addKeys(
            Codec.encodeKeyManagement(
                Codec.KeyType.Recovery,
                alicePubkey,
                nextPq,
                sig,
                newKeys
            )
        );
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                  SIGNATURE INTEGRITY                           */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    function test_addKeys_Recovery_revertsWhen_invalidSignature() public {
        // Open a slot so the invalid-sig check fires before ExceedsCapacity.
        harnessProxy.burnKey(HarnessKeyset.Recovery, recoveryPubkeys[0]);

        WOTSPlus.WinternitzAddress[] memory newKeys = _generateRecoveryKeys(
            keccak256("invalid-sig-recovery"),
            1
        );
        (WOTSPlus.WinternitzAddress memory nextPq, ) = _generateKeyPair(
            "invalid-sig-next-pq"
        );

        (, bytes32 wrongKey) = _generateKeyPair("invalid-sig-wrong");
        WOTSPlus.WinternitzElements memory badSig = _sign(
            wrongKey,
            keccak256("not the digest")
        );

        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.InvalidSignature.selector);
        harnessProxy.addKeys(
            Codec.encodeKeyManagement(
                Codec.KeyType.Recovery,
                alicePubkey,
                nextPq,
                badSig,
                newKeys
            )
        );
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                  AUTH-KEY VALIDATION                           */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    function test_addKeys_Recovery_revertsWhen_nextTransactionKeySeedZero()
        public
    {
        WOTSPlus.WinternitzAddress memory zeroPq = WOTSPlus.WinternitzAddress({
            publicSeed: bytes32(0),
            publicKeyHash: bytes32("non-empty")
        });
        WOTSPlus.WinternitzAddress[]
            memory newKeys = new WOTSPlus.WinternitzAddress[](1);
        newKeys[0] = WOTSPlus.WinternitzAddress({
            publicSeed: bytes32("a"),
            publicKeyHash: bytes32("b")
        });

        WOTSPlus.WinternitzElements memory dummySig = _sign(
            alicePrivateKey,
            keccak256("dummy")
        );

        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.InvalidSignature.selector);
        harnessProxy.addKeys(
            Codec.encodeKeyManagement(
                Codec.KeyType.Recovery,
                alicePubkey,
                zeroPq,
                dummySig,
                newKeys
            )
        );
    }

    function test_addKeys_Recovery_revertsWhen_nextTransactionKeyHashZero()
        public
    {
        WOTSPlus.WinternitzAddress memory zeroPq = WOTSPlus.WinternitzAddress({
            publicSeed: bytes32("non-empty"),
            publicKeyHash: bytes32(0)
        });
        WOTSPlus.WinternitzAddress[]
            memory newKeys = new WOTSPlus.WinternitzAddress[](1);
        newKeys[0] = WOTSPlus.WinternitzAddress({
            publicSeed: bytes32("a"),
            publicKeyHash: bytes32("b")
        });

        WOTSPlus.WinternitzElements memory dummySig = _sign(
            alicePrivateKey,
            keccak256("dummy")
        );

        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.InvalidSignature.selector);
        harnessProxy.addKeys(
            Codec.encodeKeyManagement(
                Codec.KeyType.Recovery,
                alicePubkey,
                zeroPq,
                dummySig,
                newKeys
            )
        );
    }

    function test_addKeys_Recovery_revertsWhen_nextTransactionKeyEqualsCurrentTransactionKey()
        public
    {
        harnessProxy.burnKey(HarnessKeyset.Recovery, recoveryPubkeys[0]);

        WOTSPlus.WinternitzAddress[] memory newKeys = _generateRecoveryKeys(
            keccak256("next-equals-current"),
            1
        );

        // nextTransactionKey == currentTransactionKey: caught by
        // `_enforceDifferentKeys(currentKey, nextKey)` at the top of
        // `_verifyAndRotate` before any storage reads or WOTS+ verify.
        bytes32 msgHash = _buildAddRecoveryKeysMessageHash(
            address(harnessProxy),
            alicePubkey,
            alicePubkey,
            newKeys
        );
        WOTSPlus.WinternitzElements memory sig = _sign(
            alicePrivateKey,
            msgHash
        );

        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.SameKey.selector);
        harnessProxy.addKeys(
            Codec.encodeKeyManagement(
                Codec.KeyType.Recovery,
                alicePubkey,
                alicePubkey,
                sig,
                newKeys
            )
        );
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                    PAYLOAD VALIDATION                          */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    function test_addKeys_Recovery_revertsWhen_keysArrayEmpty() public {
        (WOTSPlus.WinternitzAddress memory nextPq, ) = _generateKeyPair(
            "empty-array-next-pq"
        );
        WOTSPlus.WinternitzAddress[]
            memory emptyKeys = new WOTSPlus.WinternitzAddress[](0);

        bytes32 msgHash = _buildAddRecoveryKeysMessageHash(
            address(harnessProxy),
            alicePubkey,
            nextPq,
            emptyKeys
        );
        WOTSPlus.WinternitzElements memory sig = _sign(
            alicePrivateKey,
            msgHash
        );

        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.EmptyKeys.selector);
        harnessProxy.addKeys(
            Codec.encodeKeyManagement(
                Codec.KeyType.Recovery,
                alicePubkey,
                nextPq,
                sig,
                emptyKeys
            )
        );
    }

    function test_addKeys_Recovery_revertsWhen_newRecoveryKeySeedZero() public {
        harnessProxy.burnKey(HarnessKeyset.Recovery, recoveryPubkeys[0]);

        WOTSPlus.WinternitzAddress[]
            memory badKeys = new WOTSPlus.WinternitzAddress[](1);
        badKeys[0] = WOTSPlus.WinternitzAddress({
            publicSeed: bytes32(0),
            publicKeyHash: bytes32("non-empty")
        });
        (WOTSPlus.WinternitzAddress memory nextPq, ) = _generateKeyPair(
            "zero-seed-next-pq"
        );

        bytes32 msgHash = _buildAddRecoveryKeysMessageHash(
            address(harnessProxy),
            alicePubkey,
            nextPq,
            badKeys
        );
        WOTSPlus.WinternitzElements memory sig = _sign(
            alicePrivateKey,
            msgHash
        );

        vm.prank(ALICE);
        vm.expectRevert(Keyset.ZeroValueWinternitzAddress.selector);
        harnessProxy.addKeys(
            Codec.encodeKeyManagement(
                Codec.KeyType.Recovery,
                alicePubkey,
                nextPq,
                sig,
                badKeys
            )
        );
    }

    function test_addKeys_Recovery_revertsWhen_newRecoveryKeyHashZero() public {
        harnessProxy.burnKey(HarnessKeyset.Recovery, recoveryPubkeys[0]);

        WOTSPlus.WinternitzAddress[]
            memory badKeys = new WOTSPlus.WinternitzAddress[](1);
        badKeys[0] = WOTSPlus.WinternitzAddress({
            publicSeed: bytes32("non-empty"),
            publicKeyHash: bytes32(0)
        });
        (WOTSPlus.WinternitzAddress memory nextPq, ) = _generateKeyPair(
            "zero-hash-next-pq"
        );

        bytes32 msgHash = _buildAddRecoveryKeysMessageHash(
            address(harnessProxy),
            alicePubkey,
            nextPq,
            badKeys
        );
        WOTSPlus.WinternitzElements memory sig = _sign(
            alicePrivateKey,
            msgHash
        );

        vm.prank(ALICE);
        vm.expectRevert(Keyset.ZeroValueWinternitzAddress.selector);
        harnessProxy.addKeys(
            Codec.encodeKeyManagement(
                Codec.KeyType.Recovery,
                alicePubkey,
                nextPq,
                sig,
                badKeys
            )
        );
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                 UNIQUENESS / CAPACITY                          */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    function test_addKeys_Recovery_revertsWhen_batchContainsDuplicateKeys()
        public
    {
        // Free 2 slots so two keys can be attempted before tripping the cap.
        harnessProxy.burnKey(HarnessKeyset.Recovery, recoveryPubkeys[0]);
        harnessProxy.burnKey(HarnessKeyset.Recovery, recoveryPubkeys[1]);

        WOTSPlus.WinternitzAddress[]
            memory dupKeys = new WOTSPlus.WinternitzAddress[](2);
        (dupKeys[0], ) = _generateKeyPair("dup-batch-key");
        dupKeys[1] = dupKeys[0]; // duplicate!

        (WOTSPlus.WinternitzAddress memory nextPq, ) = _generateKeyPair(
            "dup-batch-next-pq"
        );
        bytes32 msgHash = _buildAddRecoveryKeysMessageHash(
            address(harnessProxy),
            alicePubkey,
            nextPq,
            dupKeys
        );
        WOTSPlus.WinternitzElements memory sig = _sign(
            alicePrivateKey,
            msgHash
        );

        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.KeyInUse.selector);
        harnessProxy.addKeys(
            Codec.encodeKeyManagement(
                Codec.KeyType.Recovery,
                alicePubkey,
                nextPq,
                sig,
                dupKeys
            )
        );
    }

    function test_addKeys_Recovery_revertsWhen_newKeyAlreadyInRecoverySet()
        public
    {
        harnessProxy.burnKey(HarnessKeyset.Recovery, recoveryPubkeys[0]);

        // Try to add a key that's still in the active recovery set.
        WOTSPlus.WinternitzAddress[]
            memory existingKey = new WOTSPlus.WinternitzAddress[](1);
        existingKey[0] = recoveryPubkeys[1]; // still active

        (WOTSPlus.WinternitzAddress memory nextPq, ) = _generateKeyPair(
            "already-in-set-next-pq"
        );
        bytes32 msgHash = _buildAddRecoveryKeysMessageHash(
            address(harnessProxy),
            alicePubkey,
            nextPq,
            existingKey
        );
        WOTSPlus.WinternitzElements memory sig = _sign(
            alicePrivateKey,
            msgHash
        );

        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.KeyInUse.selector);
        harnessProxy.addKeys(
            Codec.encodeKeyManagement(
                Codec.KeyType.Recovery,
                alicePubkey,
                nextPq,
                sig,
                existingKey
            )
        );
    }

    function test_addKeys_Recovery_revertsWhen_recoveryKeysetAtCapacity()
        public
    {
        // Recovery set already at MAX_KEYS (10) — adding 1 trips ExceedsCapacity.
        WOTSPlus.WinternitzAddress[] memory extraKey = _generateRecoveryKeys(
            keccak256("at-capacity-recovery"),
            1
        );
        (WOTSPlus.WinternitzAddress memory nextPq, ) = _generateKeyPair(
            "at-capacity-next-pq"
        );

        bytes32 msgHash = _buildAddRecoveryKeysMessageHash(
            address(harnessProxy),
            alicePubkey,
            nextPq,
            extraKey
        );
        WOTSPlus.WinternitzElements memory sig = _sign(
            alicePrivateKey,
            msgHash
        );

        vm.prank(ALICE);
        vm.expectRevert(Keyset.ExceedsCapacity.selector);
        harnessProxy.addKeys(
            Codec.encodeKeyManagement(
                Codec.KeyType.Recovery,
                alicePubkey,
                nextPq,
                sig,
                extraKey
            )
        );
    }
}
