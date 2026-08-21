// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WOTSPlusImplementationTest} from "../WOTSPlusImplementation.t.sol";
import {WOTSPlusImplementation} from "../../../../contracts/deprecated/wots/WOTSPlusImplementation.sol";
import {WOTSPlusImplementationHarness, HarnessKeyset} from "../../harness/WOTSPlusImplementationHarness.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.2.0/contracts/WOTSPlus.sol";
import {Ownable as SoladyOwnable} from "solady-0.1.26/src/auth/Ownable.sol";
import {IWOTSPlusImplementation} from "../../../../contracts/deprecated/wots/interfaces/IWOTSPlusImplementation.sol";
import {WOTSPlusCodec as Codec} from "../../../../contracts/deprecated/wots/WOTSPlusCodec.sol";
import {Vm} from "forge-std-1.14.0/Vm.sol";
import {EnumerableWinternitzAddressSet as Keyset} from "../../../../contracts/deprecated/wots/EnumerableWinternitzAddressSet.sol";

/// @dev Tests for `replaceKeys` when `kind == KeyType.Recovery`.
///      The recovery keyset inits at MAX_KEYS=10 (so N=10 swaps are exercisable
///      directly). Both Transaction-signed and Recovery-signed variants are
///      covered here; cross-target reverts that don't depend on the target
///      keyset live in this file as the "central" file for the function.
contract WOTSPlusImplementation_replaceKeys_Recovery is WOTSPlusImplementationTest {
    WOTSPlusImplementationHarness public harnessProxy;

    function setUp() public override {
        super.setUp();

        WOTSPlusImplementationHarness harnessImpl = new WOTSPlusImplementationHarness(payable(address(factory)));
        vm.prank(ADMIN);
        factory.vetImplementation(address(harnessImpl));

        bytes memory payload = _encodeInitPayload(alicePubkey, recoveryPubkeys);

        vm.prank(ALICE);
        address proxyAddr = factory.deployLatestWalletProxy{value: INITIAL_DEPOSIT}(keccak256("replaceKeys-recovery-vault"), COMMITMENT, payable(ALICE), payload
        );
        harnessProxy = WOTSPlusImplementationHarness(payable(proxyAddr));
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                       HAPPY PATHS                            */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    function test_replaceKeys_Recovery_txSigned_swapsN3() public {
        // Pick 3 oldKeys from recoveryPubkeys; generate 3 fresh new keys.
        WOTSPlus.WinternitzAddress[] memory oldKeys = _slice(recoveryPubkeys, 0, 3);
        WOTSPlus.WinternitzAddress[] memory newKeys = _freshKeys(keccak256("rec-tx-N3"), 3);
        (WOTSPlus.WinternitzAddress memory nextPq,) = _generateKeyPair("rec-tx-N3-next-pq");

        bytes memory payload = _encodeReplaceKeysPayload(
            Codec.KeyType.Recovery, Codec.KeyType.Transaction, alicePubkey, alicePrivateKey, nextPq, oldKeys, newKeys
        );

        // Pre: all 3 old in target, none of new in target. Tx-signing key alive.
        for (uint256 i = 0; i < 3; i++) {
            assertTrue(harnessProxy.isKey(Codec.KeyType.Recovery, oldKeys[i]));
            assertFalse(harnessProxy.isKey(Codec.KeyType.Recovery, newKeys[i]));
        }
        assertTrue(harnessProxy.isKey(Codec.KeyType.Transaction, alicePubkey));

        vm.prank(ALICE);
        harnessProxy.replaceKeys(payload);

        // Post: all 3 old removed, all 3 new installed. Signing-set rotation
        // committed.
        for (uint256 i = 0; i < 3; i++) {
            assertFalse(harnessProxy.isKey(Codec.KeyType.Recovery, oldKeys[i]));
            assertTrue(harnessProxy.isKey(Codec.KeyType.Recovery, newKeys[i]));
        }
        assertFalse(harnessProxy.isKey(Codec.KeyType.Transaction, alicePubkey));
        assertTrue(harnessProxy.isKey(Codec.KeyType.Transaction, nextPq));
        // Both keysets preserved at their pre-call lengths.
        assertEq(harnessProxy.keyCount(Codec.KeyType.Recovery), 10);
        assertEq(harnessProxy.keyCount(Codec.KeyType.Transaction), 10);
    }

    function test_replaceKeys_Recovery_txSigned_swapsN10_fullSet() public {
        // Swap every recovery key in one batch.
        WOTSPlus.WinternitzAddress[] memory oldKeys = _slice(recoveryPubkeys, 0, 10);
        WOTSPlus.WinternitzAddress[] memory newKeys = _freshKeys(keccak256("rec-tx-N10"), 10);
        (WOTSPlus.WinternitzAddress memory nextPq,) = _generateKeyPair("rec-tx-N10-next-pq");

        bytes memory payload = _encodeReplaceKeysPayload(
            Codec.KeyType.Recovery, Codec.KeyType.Transaction, alicePubkey, alicePrivateKey, nextPq, oldKeys, newKeys
        );

        vm.prank(ALICE);
        harnessProxy.replaceKeys(payload);

        for (uint256 i = 0; i < 10; i++) {
            assertFalse(harnessProxy.isKey(Codec.KeyType.Recovery, oldKeys[i]));
            assertTrue(harnessProxy.isKey(Codec.KeyType.Recovery, newKeys[i]));
        }
        assertEq(harnessProxy.keyCount(Codec.KeyType.Recovery), 10);
    }

    function test_replaceKeys_Recovery_txSigned_N1_boundary() public {
        WOTSPlus.WinternitzAddress[] memory oldKeys = _slice(recoveryPubkeys, 0, 1);
        WOTSPlus.WinternitzAddress[] memory newKeys = _freshKeys(keccak256("rec-tx-N1"), 1);
        (WOTSPlus.WinternitzAddress memory nextPq,) = _generateKeyPair("rec-tx-N1-next-pq");

        // Build payload BEFORE prank: argument evaluation can perform an
        // external library call that silently consumes a vm.prank set ahead.
        bytes memory payload = _encodeReplaceKeysPayload(
            Codec.KeyType.Recovery, Codec.KeyType.Transaction, alicePubkey, alicePrivateKey, nextPq, oldKeys, newKeys
        );

        vm.prank(ALICE);
        harnessProxy.replaceKeys(payload);

        assertFalse(harnessProxy.isKey(Codec.KeyType.Recovery, oldKeys[0]));
        assertTrue(harnessProxy.isKey(Codec.KeyType.Recovery, newKeys[0]));
    }

    function test_replaceKeys_Recovery_recoverySigned_sameKeysetSwap() public {
        // Sign with a recovery key, swap OTHER recovery keys. currentKey must
        // not be in oldKeys (else signing rotation removes it first, then the
        // remove loop tries to remove a missing key).
        bytes32 recPriv = _recoverySigningKey(alicePrivateKey, 0);
        WOTSPlus.WinternitzAddress memory currentRec = recoveryPubkeys[0];

        WOTSPlus.WinternitzAddress[] memory oldKeys = _slice(recoveryPubkeys, 5, 8);
        WOTSPlus.WinternitzAddress[] memory newKeys = _freshKeys(keccak256("rec-rec-same"), 3);
        (WOTSPlus.WinternitzAddress memory nextRec,) = _generateKeyPair("rec-rec-same-next");

        bytes memory payload = _encodeReplaceKeysPayload(
            Codec.KeyType.Recovery, Codec.KeyType.Recovery, currentRec, recPriv, nextRec, oldKeys, newKeys
        );

        vm.prank(ALICE);
        harnessProxy.replaceKeys(payload);

        // Signing rotation: currentRec out, nextRec in. N=3 swap applies on top.
        assertFalse(harnessProxy.isKey(Codec.KeyType.Recovery, currentRec));
        assertTrue(harnessProxy.isKey(Codec.KeyType.Recovery, nextRec));
        for (uint256 i = 0; i < 3; i++) {
            assertFalse(harnessProxy.isKey(Codec.KeyType.Recovery, oldKeys[i]));
            assertTrue(harnessProxy.isKey(Codec.KeyType.Recovery, newKeys[i]));
        }
        assertEq(harnessProxy.keyCount(Codec.KeyType.Recovery), 10);
        // Transaction keyset untouched.
        assertEq(harnessProxy.keyCount(Codec.KeyType.Transaction), 10);
        assertTrue(harnessProxy.isKey(Codec.KeyType.Transaction, alicePubkey));
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                          EVENTS                              */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    function test_replaceKeys_Recovery_emitsKeysReplaced() public {
        WOTSPlus.WinternitzAddress[] memory oldKeys = _slice(recoveryPubkeys, 0, 2);
        WOTSPlus.WinternitzAddress[] memory newKeys = _freshKeys(keccak256("rec-event"), 2);
        (WOTSPlus.WinternitzAddress memory nextPq,) = _generateKeyPair("rec-event-next");

        bytes memory payload = _encodeReplaceKeysPayload(
            Codec.KeyType.Recovery, Codec.KeyType.Transaction, alicePubkey, alicePrivateKey, nextPq, oldKeys, newKeys
        );

        vm.recordLogs();
        vm.prank(ALICE);
        harnessProxy.replaceKeys(payload);

        Vm.Log[] memory logs = vm.getRecordedLogs();
        bool found = false;
        for (uint256 i = 0; i < logs.length; i++) {
            if (logs[i].topics[0] == IWOTSPlusImplementation.KeysReplaced.selector) {
                found = true;
                break;
            }
        }
        assertTrue(found, "KeysReplaced event not emitted");
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                          REVERTS                             */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    function test_replaceKeys_revertsWhen_signingKindIsVerification() public {
        WOTSPlus.WinternitzAddress[] memory oldKeys = _slice(recoveryPubkeys, 0, 1);
        WOTSPlus.WinternitzAddress[] memory newKeys = _freshKeys(keccak256("rev-verif-sign"), 1);
        (WOTSPlus.WinternitzAddress memory nextPq,) = _generateKeyPair("rev-verif-sign-next");

        bytes memory payload = _encodeReplaceKeysPayload(
            Codec.KeyType.Recovery,
            Codec.KeyType.Verification, // INVALID signingKind
            alicePubkey,
            alicePrivateKey,
            nextPq,
            oldKeys,
            newKeys
        );

        vm.prank(ALICE);
        vm.expectRevert(IWOTSPlusImplementation.InvalidSigningKeyset.selector);
        harnessProxy.replaceKeys(payload);
    }

    function test_replaceKeys_revertsWhen_nIsZero() public {
        // Codec accepts the 2368-byte n=0 payload; wallet must reject with EmptyKeys.
        WOTSPlus.WinternitzAddress[] memory empty = new WOTSPlus.WinternitzAddress[](0);
        (WOTSPlus.WinternitzAddress memory nextPq,) = _generateKeyPair("rev-empty-next");

        bytes memory payload = _encodeReplaceKeysPayload(
            Codec.KeyType.Recovery, Codec.KeyType.Transaction, alicePubkey, alicePrivateKey, nextPq, empty, empty
        );

        vm.prank(ALICE);
        vm.expectRevert(IWOTSPlusImplementation.EmptyKeys.selector);
        harnessProxy.replaceKeys(payload);
    }

    function test_replaceKeys_revertsWhen_signatureInvalid() public {
        WOTSPlus.WinternitzAddress[] memory oldKeys = _slice(recoveryPubkeys, 0, 1);
        WOTSPlus.WinternitzAddress[] memory newKeys = _freshKeys(keccak256("rev-bad-sig"), 1);
        (WOTSPlus.WinternitzAddress memory nextPq,) = _generateKeyPair("rev-bad-sig-next");

        // Build with a sig from a different (unrelated) private key.
        (, bytes32 wrongPriv) = _generateKeyPair("rev-bad-sig-wrong");
        WOTSPlus.WinternitzElements memory badSig = _sign(wrongPriv, keccak256("not the digest"));

        bytes memory payload = Codec.encodeReplaceKeys(
            Codec.KeyType.Recovery,
            Codec.KeyType.Transaction,
            oldKeys.length,
            alicePubkey,
            nextPq,
            badSig,
            oldKeys,
            newKeys
        );

        vm.prank(ALICE);
        vm.expectRevert(IWOTSPlusImplementation.InvalidSignature.selector);
        harnessProxy.replaceKeys(payload);
    }

    function test_replaceKeys_revertsWhen_currentKeyNotInSigningSet() public {
        // Pass a key that isn't in the Transaction set as currentKey, with
        // signingKind=Transaction. `_verifyAndRotate`'s `_enforceContained`
        // must reject with UnknownKey.
        WOTSPlus.WinternitzAddress[] memory oldKeys = _slice(recoveryPubkeys, 0, 1);
        WOTSPlus.WinternitzAddress[] memory newKeys = _freshKeys(keccak256("rev-unknown"), 1);
        (WOTSPlus.WinternitzAddress memory unknownPub, bytes32 unknownPriv) = _generateKeyPair("rev-unknown-currentkey");
        (WOTSPlus.WinternitzAddress memory nextPq,) = _generateKeyPair("rev-unknown-next");

        bytes memory payload = _encodeReplaceKeysPayload(
            Codec.KeyType.Recovery, Codec.KeyType.Transaction, unknownPub, unknownPriv, nextPq, oldKeys, newKeys
        );

        vm.prank(ALICE);
        vm.expectRevert(IWOTSPlusImplementation.UnknownKey.selector);
        harnessProxy.replaceKeys(payload);
    }

    function test_replaceKeys_revertsWhen_currentKeyEqualsNextKey() public {
        WOTSPlus.WinternitzAddress[] memory oldKeys = _slice(recoveryPubkeys, 0, 1);
        WOTSPlus.WinternitzAddress[] memory newKeys = _freshKeys(keccak256("rev-same-key"), 1);

        bytes memory payload = _encodeReplaceKeysPayload(
            Codec.KeyType.Recovery,
            Codec.KeyType.Transaction,
            alicePubkey,
            alicePrivateKey,
            alicePubkey, // nextKey == currentKey
            oldKeys,
            newKeys
        );

        vm.prank(ALICE);
        vm.expectRevert(IWOTSPlusImplementation.SameKey.selector);
        harnessProxy.replaceKeys(payload);
    }

    function test_replaceKeys_revertsWhen_oldKeyNotInTarget() public {
        // Old keys array references a key that isn't in the recovery set.
        WOTSPlus.WinternitzAddress[] memory oldKeys = new WOTSPlus.WinternitzAddress[](1);
        (oldKeys[0],) = _generateKeyPair("rev-missing-old"); // never installed
        WOTSPlus.WinternitzAddress[] memory newKeys = _freshKeys(keccak256("rev-missing-old-new"), 1);
        (WOTSPlus.WinternitzAddress memory nextPq,) = _generateKeyPair("rev-missing-old-next");

        bytes memory payload = _encodeReplaceKeysPayload(
            Codec.KeyType.Recovery, Codec.KeyType.Transaction, alicePubkey, alicePrivateKey, nextPq, oldKeys, newKeys
        );

        vm.prank(ALICE);
        vm.expectRevert(IWOTSPlusImplementation.KeyRemovalFailed.selector);
        harnessProxy.replaceKeys(payload);
    }

    function test_replaceKeys_revertsWhen_newKeyAlreadySpent() public {
        // Put a recoveryPubkey into newKeys — it's already in the recovery set,
        // so isKeySpent[H(it)] is true and `_safeAddKey` will revert KeyInUse.
        WOTSPlus.WinternitzAddress[] memory oldKeys = _slice(recoveryPubkeys, 0, 1);
        WOTSPlus.WinternitzAddress[] memory newKeys = new WOTSPlus.WinternitzAddress[](1);
        newKeys[0] = recoveryPubkeys[5]; // already in recovery set
        (WOTSPlus.WinternitzAddress memory nextPq,) = _generateKeyPair("rev-spent-new-next");

        bytes memory payload = _encodeReplaceKeysPayload(
            Codec.KeyType.Recovery, Codec.KeyType.Transaction, alicePubkey, alicePrivateKey, nextPq, oldKeys, newKeys
        );

        vm.prank(ALICE);
        vm.expectRevert(IWOTSPlusImplementation.KeyInUse.selector);
        harnessProxy.replaceKeys(payload);
    }

    function test_replaceKeys_revertsWhen_oldNewOverlap() public {
        // Sneak oldKeys[0] into newKeys[1]. After remove, isKeySpent flag
        // persists, so the add at iteration 1 reverts KeyInUse.
        WOTSPlus.WinternitzAddress[] memory oldKeys = _slice(recoveryPubkeys, 0, 2);
        WOTSPlus.WinternitzAddress[] memory newKeys = new WOTSPlus.WinternitzAddress[](2);
        (newKeys[0],) = _generateKeyPair("rev-overlap-fresh");
        newKeys[1] = oldKeys[0]; // overlap with one of the oldKeys

        (WOTSPlus.WinternitzAddress memory nextPq,) = _generateKeyPair("rev-overlap-next");

        bytes memory payload = _encodeReplaceKeysPayload(
            Codec.KeyType.Recovery, Codec.KeyType.Transaction, alicePubkey, alicePrivateKey, nextPq, oldKeys, newKeys
        );

        vm.prank(ALICE);
        vm.expectRevert(IWOTSPlusImplementation.KeyInUse.selector);
        harnessProxy.replaceKeys(payload);
    }

    function test_replaceKeys_sameKeyset_revertsWhen_currentKeyInOldKeys() public {
        // Same-keyset path: signing rotation removes currentRec from recovery,
        // then the oldKeys loop tries to remove it again -> KeyRemovalFailed.
        bytes32 recPriv = _recoverySigningKey(alicePrivateKey, 0);
        WOTSPlus.WinternitzAddress memory currentRec = recoveryPubkeys[0];

        WOTSPlus.WinternitzAddress[] memory oldKeys = new WOTSPlus.WinternitzAddress[](1);
        oldKeys[0] = currentRec; // ← the signing key itself
        WOTSPlus.WinternitzAddress[] memory newKeys = _freshKeys(keccak256("rev-sameset-curOld"), 1);
        (WOTSPlus.WinternitzAddress memory nextRec,) = _generateKeyPair("rev-sameset-curOld-next");

        bytes memory payload = _encodeReplaceKeysPayload(
            Codec.KeyType.Recovery, Codec.KeyType.Recovery, currentRec, recPriv, nextRec, oldKeys, newKeys
        );

        vm.prank(ALICE);
        vm.expectRevert(IWOTSPlusImplementation.KeyRemovalFailed.selector);
        harnessProxy.replaceKeys(payload);
    }

    function test_replaceKeys_sameKeyset_revertsWhen_nextKeyInNewKeys() public {
        // Same-keyset path: signing rotation installs nextRec and marks it
        // spent. Then the newKeys loop tries to add it again -> KeyInUse.
        bytes32 recPriv = _recoverySigningKey(alicePrivateKey, 0);
        WOTSPlus.WinternitzAddress memory currentRec = recoveryPubkeys[0];

        WOTSPlus.WinternitzAddress[] memory oldKeys = _slice(recoveryPubkeys, 1, 2);
        (WOTSPlus.WinternitzAddress memory nextRec,) = _generateKeyPair("rev-sameset-nxtNew-next");
        WOTSPlus.WinternitzAddress[] memory newKeys = new WOTSPlus.WinternitzAddress[](1);
        newKeys[0] = nextRec; // ← collides with the signing-rotation replacement

        bytes memory payload = _encodeReplaceKeysPayload(
            Codec.KeyType.Recovery, Codec.KeyType.Recovery, currentRec, recPriv, nextRec, oldKeys, newKeys
        );

        vm.prank(ALICE);
        vm.expectRevert(IWOTSPlusImplementation.KeyInUse.selector);
        harnessProxy.replaceKeys(payload);
    }

    function test_replaceKeys_revertsWhen_callerNotOwner() public {
        WOTSPlus.WinternitzAddress[] memory oldKeys = _slice(recoveryPubkeys, 0, 1);
        WOTSPlus.WinternitzAddress[] memory newKeys = _freshKeys(keccak256("rev-not-owner"), 1);
        (WOTSPlus.WinternitzAddress memory nextPq,) = _generateKeyPair("rev-not-owner-next");

        bytes memory payload = _encodeReplaceKeysPayload(
            Codec.KeyType.Recovery, Codec.KeyType.Transaction, alicePubkey, alicePrivateKey, nextPq, oldKeys, newKeys
        );

        vm.prank(BOB);
        vm.expectRevert(SoladyOwnable.Unauthorized.selector);
        harnessProxy.replaceKeys(payload);
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                         HELPERS                              */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    function _slice(WOTSPlus.WinternitzAddress[] storage src, uint256 start, uint256 end)
        internal
        view
        returns (WOTSPlus.WinternitzAddress[] memory out)
    {
        out = new WOTSPlus.WinternitzAddress[](end - start);
        for (uint256 i = 0; i < end - start; i++) {
            out[i] = src[start + i];
        }
    }

    function _freshKeys(bytes32 seed, uint256 n) internal pure returns (WOTSPlus.WinternitzAddress[] memory out) {
        out = new WOTSPlus.WinternitzAddress[](n);
        for (uint256 i = 0; i < n; i++) {
            (out[i],) = WOTSPlus.generateKeyPair(keccak256(abi.encode(seed, i)));
        }
    }

    function _encodeReplaceKeysPayload(
        Codec.KeyType kind,
        Codec.KeyType signingKind,
        WOTSPlus.WinternitzAddress memory currentPq,
        bytes32 currentPriv,
        WOTSPlus.WinternitzAddress memory nextPq,
        WOTSPlus.WinternitzAddress[] memory oldKeys,
        WOTSPlus.WinternitzAddress[] memory newKeys
    ) internal view returns (bytes memory) {
        bytes32 digest = _buildReplaceKeysMessageHash(
            kind, signingKind, address(harnessProxy), currentPq, nextPq, oldKeys, newKeys
        );
        WOTSPlus.WinternitzElements memory sig = _sign(currentPriv, digest);
        return Codec.encodeReplaceKeys(kind, signingKind, oldKeys.length, currentPq, nextPq, sig, oldKeys, newKeys);
    }
}
