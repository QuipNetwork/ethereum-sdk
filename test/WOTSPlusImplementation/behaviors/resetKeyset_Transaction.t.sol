// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WOTSPlusImplementationTest} from "../WOTSPlusImplementation.t.sol";
import {WOTSPlusImplementationHarness} from "../../harness/WOTSPlusImplementationHarness.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";
import {IWOTSPlusImplementation} from "../../../contracts/wots/interfaces/IWOTSPlusImplementation.sol";
import {WOTSPlusCodec as Codec} from "../../../contracts/wots/WOTSPlusCodec.sol";

/// @dev Tests for `resetKeyset` when `kind == KeyType.Transaction`. Covers
///      both signing modes:
///        - Same-keyset auth (signingKind = Transaction): rotate adds nextPq
///          to tx-set, clear wipes everything including nextPq, install
///          rebuilds tx-set from newKeys[10]. Caller must NOT include
///          alicePubkey/nextPq in newKeys (burn index rejects either with
///          KeyInUse — covered in `resetKeyset_Recovery.t.sol`).
///        - Cross-keyset auth (signingKind = Recovery): recovery-key
///          authorizes tx-set reset. Initial tx keyset (10 keys under
///          always-10) is wiped and replaced with 10 fresh keys.
contract WOTSPlusImplementation_resetKeyset_Transaction is WOTSPlusImplementationTest {
    WOTSPlusImplementationHarness public harnessProxy;

    function setUp() public override {
        super.setUp();

        WOTSPlusImplementationHarness harnessImpl = new WOTSPlusImplementationHarness(
            payable(address(factory))
        );
        vm.prank(ADMIN);
        factory.vetImplementation(address(harnessImpl));

        bytes memory payload = _encodeInitPayload(alicePubkey, recoveryPubkeys);
        vm.prank(ALICE);
        address proxyAddr = factory.deployLatestWalletProxy{
            value: INITIAL_DEPOSIT
        }(keccak256("resetKeyset-tx-vault"), payable(ALICE), payload);
        harnessProxy = WOTSPlusImplementationHarness(payable(proxyAddr));
    }

    function test_resetKeyset_Transaction_txSigned_sameKeysetReset() public {
        WOTSPlus.WinternitzAddress[10] memory newKeys = _freshKeys10(
            keccak256("tx-tx-reset")
        );
        (WOTSPlus.WinternitzAddress memory nextPq, ) = _generateKeyPair(
            "tx-tx-reset-next"
        );

        bytes memory payload = _encodeResetKeysetPayload(
            Codec.KeyType.Transaction,
            Codec.KeyType.Transaction,
            alicePubkey,
            alicePrivateKey,
            nextPq,
            newKeys
        );

        // Pre: tx set holds 10 init keys (alicePubkey + 9 derived fillers).
        assertEq(harnessProxy.keyCount(Codec.KeyType.Transaction), 10);
        assertTrue(harnessProxy.isKey(Codec.KeyType.Transaction, alicePubkey));

        vm.prank(ALICE);
        harnessProxy.resetKeyset(payload);

        // Post: tx set holds exactly the 10 newKeys. alicePubkey and nextPq
        // both absent (both pass through the spent index and get wiped by
        // clear).
        assertEq(harnessProxy.keyCount(Codec.KeyType.Transaction), 10);
        assertFalse(harnessProxy.isKey(Codec.KeyType.Transaction, alicePubkey));
        assertFalse(harnessProxy.isKey(Codec.KeyType.Transaction, nextPq));
        for (uint256 i = 0; i < 10; i++) {
            assertTrue(harnessProxy.isKey(Codec.KeyType.Transaction, newKeys[i]));
        }
        // Recovery untouched.
        assertEq(harnessProxy.keyCount(Codec.KeyType.Recovery), 10);
    }

    function test_resetKeyset_Transaction_recoverySigned_resets() public {
        // Cross-keyset auth: recovery key authorizes tx-set wholesale reset.
        bytes32 recPriv = _recoverySigningKey(alicePrivateKey, 0);
        WOTSPlus.WinternitzAddress memory currentRec = recoveryPubkeys[0];
        WOTSPlus.WinternitzAddress[10] memory newKeys = _freshKeys10(
            keccak256("tx-rec-reset")
        );
        (WOTSPlus.WinternitzAddress memory nextRec, ) = _generateKeyPair(
            "tx-rec-reset-next"
        );

        bytes memory payload = _encodeResetKeysetPayload(
            Codec.KeyType.Transaction,
            Codec.KeyType.Recovery,
            currentRec,
            recPriv,
            nextRec,
            newKeys
        );

        vm.prank(ALICE);
        harnessProxy.resetKeyset(payload);

        // Tx set rebuilt to 10; alicePubkey gone (wiped by clear).
        assertEq(harnessProxy.keyCount(Codec.KeyType.Transaction), 10);
        assertFalse(harnessProxy.isKey(Codec.KeyType.Transaction, alicePubkey));
        for (uint256 i = 0; i < 10; i++) {
            assertTrue(harnessProxy.isKey(Codec.KeyType.Transaction, newKeys[i]));
        }
        // Recovery rotation committed.
        assertFalse(harnessProxy.isKey(Codec.KeyType.Recovery, currentRec));
        assertTrue(harnessProxy.isKey(Codec.KeyType.Recovery, nextRec));
        assertEq(harnessProxy.keyCount(Codec.KeyType.Recovery), 10);
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                         HELPERS                              */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    function _freshKeys10(
        bytes32 seed
    ) internal pure returns (WOTSPlus.WinternitzAddress[10] memory out) {
        for (uint256 i = 0; i < 10; i++) {
            (out[i], ) = WOTSPlus.generateKeyPair(keccak256(abi.encode(seed, i)));
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
            kind,
            signingKind,
            address(harnessProxy),
            currentPq,
            nextPq,
            newKeys
        );
        WOTSPlus.WinternitzElements memory sig = _sign(currentPriv, digest);
        return
            Codec.encodeResetKeyset(
                kind,
                signingKind,
                currentPq,
                nextPq,
                sig,
                newKeys
            );
    }
}
