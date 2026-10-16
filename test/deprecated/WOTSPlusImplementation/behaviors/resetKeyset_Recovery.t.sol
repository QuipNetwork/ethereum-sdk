// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WOTSPlusImplementationTest} from "../WOTSPlusImplementation.t.sol";
import {WOTSPlusImplementationHarness} from "../../harness/WOTSPlusImplementationHarness.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.2.0/contracts/WOTSPlus.sol";
import {WOTSPlusTestSigner} from "@quip.network/hashsigs-solidity-0.2.0/test/helpers/WOTSPlusTestSigner.sol";
import {Ownable as SoladyOwnable} from "solady-0.1.26/src/auth/Ownable.sol";
import {IWOTSPlusImplementation} from "../../../../contracts/deprecated/wots/interfaces/IWOTSPlusImplementation.sol";
import {WOTSPlusCodec as Codec} from "../../../../contracts/deprecated/wots/WOTSPlusCodec.sol";

/// @dev Tests for `resetKeyset` when `kind == KeyType.Recovery`. This is the
///      "central" file for the function — all cross-target reverts that don't
///      depend on the specific target keyset live here. Per-target files
///      (`resetKeyset_Transaction.t.sol`, `resetKeyset_Verification.t.sol`)
///      cover the target-specific happy paths.
contract WOTSPlusImplementation_resetKeyset_Recovery is WOTSPlusImplementationTest {
    WOTSPlusImplementationHarness public harnessProxy;

    function setUp() public override {
        super.setUp();

        WOTSPlusImplementationHarness harnessImpl = new WOTSPlusImplementationHarness(payable(address(factory)));
        vm.prank(ADMIN);
        factory.vetImplementation(address(harnessImpl));

        bytes memory payload = _encodeInitPayload(alicePubkey, recoveryPubkeys);
        vm.prank(ALICE);
        address proxyAddr = factory.deployLatestWalletProxy{value: INITIAL_DEPOSIT}(keccak256("resetKeyset-recovery-vault"), payable(ALICE), payload
        );
        harnessProxy = WOTSPlusImplementationHarness(payable(proxyAddr));
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                       HAPPY PATHS                            */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    function test_resetKeyset_Recovery_txSigned_resets() public {
        WOTSPlus.WinternitzAddress[10] memory newKeys = _freshKeys10(keccak256("rec-tx-reset"));
        (WOTSPlus.WinternitzAddress memory nextPq,) = _generateKeyPair("rec-tx-reset-next");

        bytes memory payload = _encodeResetKeysetPayload(
            Codec.KeyType.Recovery, Codec.KeyType.Transaction, alicePubkey, alicePrivateKey, nextPq, newKeys
        );

        // Pre: all 10 original recovery keys present.
        for (uint256 i = 0; i < 10; i++) {
            assertTrue(harnessProxy.isKey(Codec.KeyType.Recovery, recoveryPubkeys[i]));
        }

        vm.prank(ALICE);
        harnessProxy.resetKeyset(payload);

        // Post: all 10 original recovery keys gone, all 10 new keys in.
        for (uint256 i = 0; i < 10; i++) {
            assertFalse(harnessProxy.isKey(Codec.KeyType.Recovery, recoveryPubkeys[i]));
            assertTrue(harnessProxy.isKey(Codec.KeyType.Recovery, newKeys[i]));
        }
        assertEq(harnessProxy.keyCount(Codec.KeyType.Recovery), 10);
        // Tx signing rotation committed.
        assertFalse(harnessProxy.isKey(Codec.KeyType.Transaction, alicePubkey));
        assertTrue(harnessProxy.isKey(Codec.KeyType.Transaction, nextPq));
    }

    function test_resetKeyset_Recovery_recoverySigned_resets() public {
        // Same-keyset auth: sign with recovery[0], reset recovery to 10 fresh.
        bytes32 recPriv = _recoverySigningKey(alicePrivateKey, 0);
        WOTSPlus.WinternitzAddress memory currentRec = recoveryPubkeys[0];
        WOTSPlus.WinternitzAddress[10] memory newKeys = _freshKeys10(keccak256("rec-rec-reset"));
        (WOTSPlus.WinternitzAddress memory nextRec,) = _generateKeyPair("rec-rec-reset-next");

        bytes memory payload = _encodeResetKeysetPayload(
            Codec.KeyType.Recovery, Codec.KeyType.Recovery, currentRec, recPriv, nextRec, newKeys
        );

        vm.prank(ALICE);
        harnessProxy.resetKeyset(payload);

        // Both the originally-installed currentRec AND the transiently-installed
        // nextRec are absent post-clear; only newKeys remain.
        assertFalse(harnessProxy.isKey(Codec.KeyType.Recovery, currentRec));
        assertFalse(harnessProxy.isKey(Codec.KeyType.Recovery, nextRec));
        for (uint256 i = 0; i < 10; i++) {
            assertTrue(harnessProxy.isKey(Codec.KeyType.Recovery, newKeys[i]));
        }
        assertEq(harnessProxy.keyCount(Codec.KeyType.Recovery), 10);
    }

    function test_resetKeyset_Recovery_emitsKeysetReset() public {
        WOTSPlus.WinternitzAddress[10] memory newKeys = _freshKeys10(keccak256("rec-event"));
        (WOTSPlus.WinternitzAddress memory nextPq,) = _generateKeyPair("rec-event-next");

        bytes memory payload = _encodeResetKeysetPayload(
            Codec.KeyType.Recovery, Codec.KeyType.Transaction, alicePubkey, alicePrivateKey, nextPq, newKeys
        );

        vm.expectEmit(true, true, false, true, address(harnessProxy));
        emit IWOTSPlusImplementation.KeysetReset(
            Codec.KeyType.Recovery, Codec.KeyType.Transaction, alicePubkey, nextPq, newKeys
        );
        vm.prank(ALICE);
        harnessProxy.resetKeyset(payload);
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                          REVERTS                             */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    function test_resetKeyset_revertsWhen_signingKindIsVerification() public {
        WOTSPlus.WinternitzAddress[10] memory newKeys = _freshKeys10(keccak256("rev-sk-verif"));
        (WOTSPlus.WinternitzAddress memory nextPq,) = _generateKeyPair("rev-sk-verif-next");

        bytes memory payload = _encodeResetKeysetPayload(
            Codec.KeyType.Recovery, Codec.KeyType.Verification, alicePubkey, alicePrivateKey, nextPq, newKeys
        );

        vm.prank(ALICE);
        vm.expectRevert(IWOTSPlusImplementation.InvalidSigningKeyset.selector);
        harnessProxy.resetKeyset(payload);
    }

    function test_resetKeyset_revertsWhen_callerIsNotOwner() public {
        WOTSPlus.WinternitzAddress[10] memory newKeys = _freshKeys10(keccak256("rev-caller"));
        (WOTSPlus.WinternitzAddress memory nextPq,) = _generateKeyPair("rev-caller-next");

        bytes memory payload = _encodeResetKeysetPayload(
            Codec.KeyType.Recovery, Codec.KeyType.Transaction, alicePubkey, alicePrivateKey, nextPq, newKeys
        );

        vm.prank(BOB);
        vm.expectRevert(SoladyOwnable.Unauthorized.selector);
        harnessProxy.resetKeyset(payload);
    }

    function test_resetKeyset_revertsWhen_currentKeyNotInSigningSet() public {
        // alicePubkey is in the tx set; pick a fresh key as currentPq that has
        // never been installed. `_verifyAndRotate` -> `_enforceContained`
        // reverts `UnknownKey`.
        (WOTSPlus.WinternitzAddress memory currentPq, bytes32 currentPriv) = _generateKeyPair("rev-unknown-current");
        WOTSPlus.WinternitzAddress[10] memory newKeys = _freshKeys10(keccak256("rev-unknown"));
        (WOTSPlus.WinternitzAddress memory nextPq,) = _generateKeyPair("rev-unknown-next");

        bytes memory payload = _encodeResetKeysetPayload(
            Codec.KeyType.Recovery, Codec.KeyType.Transaction, currentPq, currentPriv, nextPq, newKeys
        );

        vm.prank(ALICE);
        vm.expectRevert(IWOTSPlusImplementation.UnknownKey.selector);
        harnessProxy.resetKeyset(payload);
    }

    function test_resetKeyset_revertsWhen_currentKeyEqualsNextKey() public {
        WOTSPlus.WinternitzAddress[10] memory newKeys = _freshKeys10(keccak256("rev-same-cur-next"));
        // Both currentPq and nextPq are alicePubkey — `_verifyAndRotate` ->
        // `_enforceDifferentKeys` reverts `SameKey`.
        bytes memory payload = _encodeResetKeysetPayload(
            Codec.KeyType.Recovery, Codec.KeyType.Transaction, alicePubkey, alicePrivateKey, alicePubkey, newKeys
        );

        vm.prank(ALICE);
        vm.expectRevert(IWOTSPlusImplementation.SameKey.selector);
        harnessProxy.resetKeyset(payload);
    }

    function test_resetKeyset_revertsWhen_signatureInvalid() public {
        WOTSPlus.WinternitzAddress[10] memory newKeys = _freshKeys10(keccak256("rev-bad-sig"));
        (WOTSPlus.WinternitzAddress memory nextPq,) = _generateKeyPair("rev-bad-sig-next");

        // Sign with the wrong private key — but the currentPq is alicePubkey,
        // so the WOTS+ verify fails.
        (, bytes32 wrongPriv) = _generateKeyPair("wrong-priv");
        bytes32 digest = _buildResetKeysetMessageHash(
            Codec.KeyType.Recovery, Codec.KeyType.Transaction, address(harnessProxy), alicePubkey, nextPq, newKeys
        );
        WOTSPlus.WinternitzElements memory sig = _sign(wrongPriv, digest);
        bytes memory payload = Codec.encodeResetKeyset(
            Codec.KeyType.Recovery, Codec.KeyType.Transaction, alicePubkey, nextPq, sig, newKeys
        );

        vm.prank(ALICE);
        vm.expectRevert(IWOTSPlusImplementation.InvalidSignature.selector);
        harnessProxy.resetKeyset(payload);
    }

    function test_resetKeyset_revertsWhen_newKeyAlreadySpent() public {
        // Include alicePubkey (already installed/spent on init) in newKeys.
        // `_safeAddKey` -> `_enforceUnspentKey` reverts `KeyInUse`.
        WOTSPlus.WinternitzAddress[10] memory newKeys = _freshKeys10(keccak256("rev-spent"));
        newKeys[7] = alicePubkey;
        (WOTSPlus.WinternitzAddress memory nextPq,) = _generateKeyPair("rev-spent-next");

        bytes memory payload = _encodeResetKeysetPayload(
            Codec.KeyType.Recovery, Codec.KeyType.Transaction, alicePubkey, alicePrivateKey, nextPq, newKeys
        );

        vm.prank(ALICE);
        vm.expectRevert(IWOTSPlusImplementation.KeyInUse.selector);
        harnessProxy.resetKeyset(payload);
    }

    function test_resetKeyset_revertsWhen_sameKeysetAuth_newKeysContainsCurrentKey() public {
        // Same-keyset auth on Recovery: include currentKey (recoveryPubkeys[0])
        // in newKeys. The rotation removes it and the burn index keeps it
        // permanently spent — `_safeAddKey` rejects with `KeyInUse`.
        bytes32 recPriv = _recoverySigningKey(alicePrivateKey, 0);
        WOTSPlus.WinternitzAddress memory currentRec = recoveryPubkeys[0];
        WOTSPlus.WinternitzAddress[10] memory newKeys = _freshKeys10(keccak256("rev-sk-cur"));
        newKeys[3] = currentRec;
        (WOTSPlus.WinternitzAddress memory nextRec,) = _generateKeyPair("rev-sk-cur-next");

        bytes memory payload = _encodeResetKeysetPayload(
            Codec.KeyType.Recovery, Codec.KeyType.Recovery, currentRec, recPriv, nextRec, newKeys
        );

        vm.prank(ALICE);
        vm.expectRevert(IWOTSPlusImplementation.KeyInUse.selector);
        harnessProxy.resetKeyset(payload);
    }

    function test_resetKeyset_revertsWhen_sameKeysetAuth_newKeysContainsNextKey() public {
        // Same-keyset auth on Recovery: include nextKey in newKeys. Rotate
        // adds and burns nextKey; clear wipes it; reinstall fails on burn
        // index.
        bytes32 recPriv = _recoverySigningKey(alicePrivateKey, 0);
        WOTSPlus.WinternitzAddress memory currentRec = recoveryPubkeys[0];
        WOTSPlus.WinternitzAddress[10] memory newKeys = _freshKeys10(keccak256("rev-sk-nxt"));
        (WOTSPlus.WinternitzAddress memory nextRec,) = _generateKeyPair("rev-sk-nxt-next");
        newKeys[5] = nextRec;

        bytes memory payload = _encodeResetKeysetPayload(
            Codec.KeyType.Recovery, Codec.KeyType.Recovery, currentRec, recPriv, nextRec, newKeys
        );

        vm.prank(ALICE);
        vm.expectRevert(IWOTSPlusImplementation.KeyInUse.selector);
        harnessProxy.resetKeyset(payload);
    }

    function test_resetKeyset_revertsWhen_newKeysHasDuplicates() public {
        // newKeys[2] == newKeys[8]. First install marks it spent; second
        // install reverts `KeyInUse`.
        WOTSPlus.WinternitzAddress[10] memory newKeys = _freshKeys10(keccak256("rev-dup"));
        newKeys[8] = newKeys[2];
        (WOTSPlus.WinternitzAddress memory nextPq,) = _generateKeyPair("rev-dup-next");

        bytes memory payload = _encodeResetKeysetPayload(
            Codec.KeyType.Recovery, Codec.KeyType.Transaction, alicePubkey, alicePrivateKey, nextPq, newKeys
        );

        vm.prank(ALICE);
        vm.expectRevert(IWOTSPlusImplementation.KeyInUse.selector);
        harnessProxy.resetKeyset(payload);
    }

    function test_resetKeyset_revertsWhen_payloadMalformed() public {
        // Truncate a valid payload by 1 byte → codec's exact-length check
        // reverts `MalformedPayload(2976, 2975)`.
        WOTSPlus.WinternitzAddress[10] memory newKeys = _freshKeys10(keccak256("rev-trunc"));
        (WOTSPlus.WinternitzAddress memory nextPq,) = _generateKeyPair("rev-trunc-next");

        bytes memory payload = _encodeResetKeysetPayload(
            Codec.KeyType.Recovery, Codec.KeyType.Transaction, alicePubkey, alicePrivateKey, nextPq, newKeys
        );
        bytes memory truncated = new bytes(payload.length - 1);
        for (uint256 i = 0; i < truncated.length; i++) {
            truncated[i] = payload[i];
        }

        vm.prank(ALICE);
        vm.expectRevert(abi.encodeWithSelector(Codec.MalformedPayload.selector, 2976, 2975));
        harnessProxy.resetKeyset(truncated);
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                         HELPERS                              */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    function _freshKeys10(bytes32 seed) internal pure returns (WOTSPlus.WinternitzAddress[10] memory out) {
        for (uint256 i = 0; i < 10; i++) {
            (out[i],) = WOTSPlusTestSigner.generateKeyPair(keccak256(abi.encode(seed, i)));
        }
    }

    function _encodeResetKeysetPayload(
        Codec.KeyType kind,
        Codec.KeyType signingKind,
        WOTSPlus.WinternitzAddress memory currentPq,
        bytes32 currentPriv,
        WOTSPlus.WinternitzAddress memory nextPq,
        WOTSPlus.WinternitzAddress[10] memory newKeys
    ) internal view returns (bytes memory) {
        bytes32 digest = _buildResetKeysetMessageHash(
            kind, signingKind, address(harnessProxy), currentPq, nextPq, newKeys
        );
        WOTSPlus.WinternitzElements memory sig = _sign(currentPriv, digest);
        return Codec.encodeResetKeyset(kind, signingKind, currentPq, nextPq, sig, newKeys);
    }
}
