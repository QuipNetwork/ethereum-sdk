// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {QuipWalletTest} from "../QuipWallet.t.sol";
import {QuipWallet} from "../../../contracts/QuipWallet.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";
import {WOTSPlusCodec as Codec} from "../../../contracts/WOTSPlusCodec.sol";
import {Ownable as SoladyOwnable} from "solady-0.1.26/src/auth/Ownable.sol";
import {IQuipWallet} from "../../../contracts/interfaces/IQuipWallet.sol";
import {Vm} from "forge-std-1.14.0/Vm.sol";
import {EnumerableWinternitzAddressSet as Keyset} from "../../../contracts/libraries/EnumerableWinternitzAddressSet.sol";

/// @dev Tests for `refreshKeys(KeyType.Recovery, ...)`.
///
///      `refreshKeys` rotates the auth transaction key (currentKey → nextKey),
///      then clears the target keyset and replaces it with the supplied batch.
///      Atomic: signature verification happens before the clear, so a bad sig
///      leaves the original keyset untouched.
contract QuipWallet_refreshKeys_Recovery is QuipWalletTest {
    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                       STATE CHANGES                            */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    function test_refreshKeys_Recovery_clearsRecoverySet() public {
        WOTSPlus.WinternitzAddress[] memory newKeys = _generateRecoveryKeys(
            keccak256("clears-recovery"),
            5
        );
        (WOTSPlus.WinternitzAddress memory nextPq, ) = _generateKeyPair(
            "clears-recovery-next-pq"
        );

        bytes32 msgHash = _buildReplenishRecoveryKeysMessageHash(
            address(wallet),
            alicePubkey,
            nextPq,
            newKeys
        );
        WOTSPlus.WinternitzElements memory sig = _sign(
            alicePrivateKey,
            msgHash
        );

        for (uint256 i = 0; i < recoveryPubkeys.length; i++) {
            assertTrue(
                wallet.isKey(Codec.KeyType.Recovery, recoveryPubkeys[i])
            );
        }

        vm.prank(ALICE);
        wallet.refreshKeys(
            Codec.encodeKeyManagement(
                Codec.KeyType.Recovery,
                alicePubkey,
                nextPq,
                sig,
                newKeys
            )
        );

        for (uint256 i = 0; i < recoveryPubkeys.length; i++) {
            assertFalse(
                wallet.isKey(Codec.KeyType.Recovery, recoveryPubkeys[i])
            );
        }
    }

    function test_refreshKeys_Recovery_installsAllNewKeys() public {
        WOTSPlus.WinternitzAddress[] memory newKeys = _generateRecoveryKeys(
            keccak256("installs-all"),
            5
        );
        (WOTSPlus.WinternitzAddress memory nextPq, ) = _generateKeyPair(
            "installs-all-next-pq"
        );

        bytes32 msgHash = _buildReplenishRecoveryKeysMessageHash(
            address(wallet),
            alicePubkey,
            nextPq,
            newKeys
        );
        WOTSPlus.WinternitzElements memory sig = _sign(
            alicePrivateKey,
            msgHash
        );

        vm.prank(ALICE);
        wallet.refreshKeys(
            Codec.encodeKeyManagement(
                Codec.KeyType.Recovery,
                alicePubkey,
                nextPq,
                sig,
                newKeys
            )
        );

        for (uint256 i = 0; i < newKeys.length; i++) {
            assertTrue(wallet.isKey(Codec.KeyType.Recovery, newKeys[i]));
        }
    }

    function test_refreshKeys_Recovery_resizesRecoveryKeysetToBatchLength()
        public
    {
        WOTSPlus.WinternitzAddress[] memory newKeys = _generateRecoveryKeys(
            keccak256("resize-recovery"),
            5
        );
        (WOTSPlus.WinternitzAddress memory nextPq, ) = _generateKeyPair(
            "resize-recovery-next-pq"
        );

        bytes32 msgHash = _buildReplenishRecoveryKeysMessageHash(
            address(wallet),
            alicePubkey,
            nextPq,
            newKeys
        );
        WOTSPlus.WinternitzElements memory sig = _sign(
            alicePrivateKey,
            msgHash
        );

        vm.prank(ALICE);
        wallet.refreshKeys(
            Codec.encodeKeyManagement(
                Codec.KeyType.Recovery,
                alicePubkey,
                nextPq,
                sig,
                newKeys
            )
        );

        assertEq(wallet.keyCount(Codec.KeyType.Recovery), newKeys.length);
    }

    function test_refreshKeys_Recovery_rotatesAuthTransactionKey() public {
        WOTSPlus.WinternitzAddress[] memory newKeys = _generateRecoveryKeys(
            keccak256("rotate-auth"),
            5
        );
        (WOTSPlus.WinternitzAddress memory nextPq, ) = _generateKeyPair(
            "rotate-auth-next-pq"
        );

        bytes32 msgHash = _buildReplenishRecoveryKeysMessageHash(
            address(wallet),
            alicePubkey,
            nextPq,
            newKeys
        );
        WOTSPlus.WinternitzElements memory sig = _sign(
            alicePrivateKey,
            msgHash
        );

        assertTrue(wallet.isKey(Codec.KeyType.Transaction, alicePubkey));
        assertFalse(wallet.isKey(Codec.KeyType.Transaction, nextPq));

        vm.prank(ALICE);
        wallet.refreshKeys(
            Codec.encodeKeyManagement(
                Codec.KeyType.Recovery,
                alicePubkey,
                nextPq,
                sig,
                newKeys
            )
        );

        assertFalse(wallet.isKey(Codec.KeyType.Transaction, alicePubkey));
        assertTrue(wallet.isKey(Codec.KeyType.Transaction, nextPq));
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                          BOUNDARY                              */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    function test_refreshKeys_Recovery_acceptsExactlyMaxKeysBatch() public {
        WOTSPlus.WinternitzAddress[] memory maxKeys = _generateRecoveryKeys(
            keccak256("max-keys-batch"),
            10
        );
        (WOTSPlus.WinternitzAddress memory nextPq, ) = _generateKeyPair(
            "max-keys-next-pq"
        );

        bytes32 msgHash = _buildReplenishRecoveryKeysMessageHash(
            address(wallet),
            alicePubkey,
            nextPq,
            maxKeys
        );
        WOTSPlus.WinternitzElements memory sig = _sign(
            alicePrivateKey,
            msgHash
        );

        vm.prank(ALICE);
        wallet.refreshKeys(
            Codec.encodeKeyManagement(
                Codec.KeyType.Recovery,
                alicePubkey,
                nextPq,
                sig,
                maxKeys
            )
        );

        assertEq(wallet.keyCount(Codec.KeyType.Recovery), 10);
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                  POST-REFRESH OPERATIONS                       */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    function test_refreshKeys_Recovery_replenishedKeyCanRecoverWallet() public {
        bytes32 replenishBase = keccak256("post-refresh-recover");
        WOTSPlus.WinternitzAddress[] memory newKeys = _generateRecoveryKeys(
            replenishBase,
            5
        );
        (WOTSPlus.WinternitzAddress memory nextPq, ) = _generateKeyPair(
            "post-refresh-next-pq"
        );

        bytes32 msgHash = _buildReplenishRecoveryKeysMessageHash(
            address(wallet),
            alicePubkey,
            nextPq,
            newKeys
        );
        WOTSPlus.WinternitzElements memory sig = _sign(
            alicePrivateKey,
            msgHash
        );

        vm.prank(ALICE);
        wallet.refreshKeys(
            Codec.encodeKeyManagement(
                Codec.KeyType.Recovery,
                alicePubkey,
                nextPq,
                sig,
                newKeys
            )
        );

        // Use the first replenished recovery key to recover the wallet.
        (WOTSPlus.WinternitzAddress memory recoveredPq, ) = _generateKeyPair(
            "post-refresh-recovered-pq"
        );
        (WOTSPlus.WinternitzAddress memory recoveredRk, ) = _generateKeyPair(
            "post-refresh-recovered-rk"
        );

        bytes32 recoverMsg = _buildRecoverWalletMessageHash(
            address(wallet),
            newKeys[0],
            recoveredRk,
            recoveredPq
        );
        WOTSPlus.WinternitzElements memory recoverSig = _sign(
            _recoverySigningKey(replenishBase, 0),
            recoverMsg
        );

        vm.prank(ALICE);
        wallet.recoverWallet(
            Codec.encodeRecoverWallet(
                newKeys[0],
                recoveredRk,
                recoveredPq,
                recoverSig
            )
        );

        assertTrue(wallet.isKey(Codec.KeyType.Transaction, recoveredPq));
        assertFalse(wallet.isKey(Codec.KeyType.Recovery, newKeys[0]));
        assertTrue(wallet.isKey(Codec.KeyType.Recovery, recoveredRk));
    }

    function test_refreshKeys_Recovery_replacedKeysCannotRecoverWalletAfterRefresh()
        public
    {
        WOTSPlus.WinternitzAddress[] memory newKeys = _generateRecoveryKeys(
            keccak256("replaced-keys-invalid"),
            5
        );
        (WOTSPlus.WinternitzAddress memory nextPq, ) = _generateKeyPair(
            "replaced-keys-next-pq"
        );

        bytes32 msgHash = _buildReplenishRecoveryKeysMessageHash(
            address(wallet),
            alicePubkey,
            nextPq,
            newKeys
        );
        WOTSPlus.WinternitzElements memory sig = _sign(
            alicePrivateKey,
            msgHash
        );

        vm.prank(ALICE);
        wallet.refreshKeys(
            Codec.encodeKeyManagement(
                Codec.KeyType.Recovery,
                alicePubkey,
                nextPq,
                sig,
                newKeys
            )
        );

        // Try recoverWallet with one of the replaced (now-cleared) keys.
        WOTSPlus.WinternitzAddress memory replacedKey = recoveryPubkeys[0];
        (WOTSPlus.WinternitzAddress memory recoveredPq, ) = _generateKeyPair(
            "replaced-recovered-pq"
        );
        (WOTSPlus.WinternitzAddress memory recoveredRk, ) = _generateKeyPair(
            "replaced-recovered-rk"
        );
        bytes32 rPrivKey = _recoverySigningKey(alicePrivateKey, 0);
        bytes32 recoverMsg = _buildRecoverWalletMessageHash(
            address(wallet),
            replacedKey,
            recoveredRk,
            recoveredPq
        );
        WOTSPlus.WinternitzElements memory recoverSig = _sign(
            rPrivKey,
            recoverMsg
        );

        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.UnknownKey.selector);
        wallet.recoverWallet(
            Codec.encodeRecoverWallet(
                replacedKey,
                recoveredRk,
                recoveredPq,
                recoverSig
            )
        );
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                          EVENTS                                */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    function test_refreshKeys_Recovery_emitsKeysRefreshedEvent() public {
        WOTSPlus.WinternitzAddress[] memory newKeys = _generateRecoveryKeys(
            keccak256("emits-event"),
            5
        );
        (WOTSPlus.WinternitzAddress memory nextPq, ) = _generateKeyPair(
            "emits-event-next-pq"
        );

        bytes32 msgHash = _buildReplenishRecoveryKeysMessageHash(
            address(wallet),
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
        wallet.refreshKeys(
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
            if (logs[i].topics[0] == IQuipWallet.KeysRefreshed.selector) {
                found = true;
                break;
            }
        }
        assertTrue(found, "KeysRefreshed event not emitted");
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                      ACCESS CONTROL                            */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    function test_refreshKeys_Recovery_revertsWhen_callerNotOwner() public {
        WOTSPlus.WinternitzAddress[] memory newKeys = _generateRecoveryKeys(
            keccak256("not-owner-recovery"),
            3
        );
        (WOTSPlus.WinternitzAddress memory nextPq, ) = _generateKeyPair(
            "not-owner-next-pq"
        );

        bytes32 msgHash = _buildReplenishRecoveryKeysMessageHash(
            address(wallet),
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
        wallet.refreshKeys(
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

    function test_refreshKeys_Recovery_revertsWhen_invalidSignature() public {
        WOTSPlus.WinternitzAddress[] memory newKeys = _generateRecoveryKeys(
            keccak256("invalid-sig-recovery"),
            3
        );
        (WOTSPlus.WinternitzAddress memory nextPq, ) = _generateKeyPair(
            "invalid-sig-next-pq"
        );

        WOTSPlus.WinternitzElements memory badSig = _sign(
            alicePrivateKey,
            keccak256("not the digest")
        );

        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.InvalidSignature.selector);
        wallet.refreshKeys(
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

    function test_refreshKeys_Recovery_revertsWhen_nextTransactionKeySeedZero()
        public
    {
        WOTSPlus.WinternitzAddress memory zeroPq = WOTSPlus.WinternitzAddress({
            publicSeed: bytes32(0),
            publicKeyHash: bytes32("non-empty")
        });
        WOTSPlus.WinternitzAddress[] memory newKeys = _generateRecoveryKeys(
            keccak256("zero-seed-pq"),
            3
        );
        WOTSPlus.WinternitzElements memory dummySig = _sign(
            alicePrivateKey,
            keccak256("dummy")
        );

        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.InvalidSignature.selector);
        wallet.refreshKeys(
            Codec.encodeKeyManagement(
                Codec.KeyType.Recovery,
                alicePubkey,
                zeroPq,
                dummySig,
                newKeys
            )
        );
    }

    function test_refreshKeys_Recovery_revertsWhen_nextTransactionKeyHashZero()
        public
    {
        WOTSPlus.WinternitzAddress memory zeroPq = WOTSPlus.WinternitzAddress({
            publicSeed: bytes32("non-empty"),
            publicKeyHash: bytes32(0)
        });
        WOTSPlus.WinternitzAddress[] memory newKeys = _generateRecoveryKeys(
            keccak256("zero-hash-pq"),
            3
        );
        WOTSPlus.WinternitzElements memory dummySig = _sign(
            alicePrivateKey,
            keccak256("dummy")
        );

        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.InvalidSignature.selector);
        wallet.refreshKeys(
            Codec.encodeKeyManagement(
                Codec.KeyType.Recovery,
                alicePubkey,
                zeroPq,
                dummySig,
                newKeys
            )
        );
    }

    function test_refreshKeys_Recovery_revertsWhen_nextTransactionKeyEqualsCurrentTransactionKey()
        public
    {
        WOTSPlus.WinternitzAddress[] memory newKeys = _generateRecoveryKeys(
            keccak256("next-equals-current"),
            5
        );

        bytes32 msgHash = _buildReplenishRecoveryKeysMessageHash(
            address(wallet),
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
        wallet.refreshKeys(
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

    function test_refreshKeys_Recovery_revertsWhen_keysArrayEmpty() public {
        WOTSPlus.WinternitzAddress[]
            memory emptyKeys = new WOTSPlus.WinternitzAddress[](0);
        (WOTSPlus.WinternitzAddress memory nextPq, ) = _generateKeyPair(
            "empty-array-next-pq"
        );

        bytes32 msgHash = _buildReplenishRecoveryKeysMessageHash(
            address(wallet),
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
        wallet.refreshKeys(
            Codec.encodeKeyManagement(
                Codec.KeyType.Recovery,
                alicePubkey,
                nextPq,
                sig,
                emptyKeys
            )
        );
    }

    function test_refreshKeys_Recovery_revertsWhen_newRecoveryKeySeedZero()
        public
    {
        WOTSPlus.WinternitzAddress[]
            memory badKeys = new WOTSPlus.WinternitzAddress[](1);
        badKeys[0] = WOTSPlus.WinternitzAddress({
            publicSeed: bytes32(0),
            publicKeyHash: bytes32("non-empty")
        });
        (WOTSPlus.WinternitzAddress memory nextPq, ) = _generateKeyPair(
            "zero-seed-recovery-next-pq"
        );

        bytes32 msgHash = _buildReplenishRecoveryKeysMessageHash(
            address(wallet),
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
        wallet.refreshKeys(
            Codec.encodeKeyManagement(
                Codec.KeyType.Recovery,
                alicePubkey,
                nextPq,
                sig,
                badKeys
            )
        );
    }

    function test_refreshKeys_Recovery_revertsWhen_newRecoveryKeyHashZero()
        public
    {
        WOTSPlus.WinternitzAddress[]
            memory badKeys = new WOTSPlus.WinternitzAddress[](1);
        badKeys[0] = WOTSPlus.WinternitzAddress({
            publicSeed: bytes32("non-empty"),
            publicKeyHash: bytes32(0)
        });
        (WOTSPlus.WinternitzAddress memory nextPq, ) = _generateKeyPair(
            "zero-hash-recovery-next-pq"
        );

        bytes32 msgHash = _buildReplenishRecoveryKeysMessageHash(
            address(wallet),
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
        wallet.refreshKeys(
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

    function test_refreshKeys_Recovery_revertsWhen_batchContainsDuplicateKeys()
        public
    {
        WOTSPlus.WinternitzAddress[]
            memory dupKeys = new WOTSPlus.WinternitzAddress[](2);
        (dupKeys[0], ) = _generateKeyPair("dup-key");
        dupKeys[1] = dupKeys[0]; // duplicate

        (WOTSPlus.WinternitzAddress memory nextPq, ) = _generateKeyPair(
            "dup-batch-next-pq"
        );
        bytes32 msgHash = _buildReplenishRecoveryKeysMessageHash(
            address(wallet),
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
        wallet.refreshKeys(
            Codec.encodeKeyManagement(
                Codec.KeyType.Recovery,
                alicePubkey,
                nextPq,
                sig,
                dupKeys
            )
        );
    }

    function test_refreshKeys_Recovery_revertsWhen_batchExceedsRecoveryKeysetCapacity()
        public
    {
        WOTSPlus.WinternitzAddress[] memory tooMany = _generateRecoveryKeys(
            keccak256("over-capacity"),
            11
        );
        (WOTSPlus.WinternitzAddress memory nextPq, ) = _generateKeyPair(
            "over-capacity-next-pq"
        );

        bytes32 msgHash = _buildReplenishRecoveryKeysMessageHash(
            address(wallet),
            alicePubkey,
            nextPq,
            tooMany
        );
        WOTSPlus.WinternitzElements memory sig = _sign(
            alicePrivateKey,
            msgHash
        );

        vm.prank(ALICE);
        vm.expectRevert(Keyset.ExceedsCapacity.selector);
        wallet.refreshKeys(
            Codec.encodeKeyManagement(
                Codec.KeyType.Recovery,
                alicePubkey,
                nextPq,
                sig,
                tooMany
            )
        );
    }
}
