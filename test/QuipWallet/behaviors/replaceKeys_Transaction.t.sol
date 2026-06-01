// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {QuipWalletTest} from "../QuipWallet.t.sol";
import {QuipWalletHarness, HarnessKeyset} from "../../harness/QuipWalletHarness.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";
import {IQuipWallet} from "../../../contracts/interfaces/IQuipWallet.sol";
import {WOTSPlusCodec as Codec} from "../../../contracts/WOTSPlusCodec.sol";

/// @dev Tests for `replaceKeys` when `kind == KeyType.Transaction`.
///      Transaction set inits at 5 keys; tests size N to fit. The Recovery-
///      signed → Transaction-target path is the canonical "recoverWallet
///      replacement" — sign with a recovery key to wholesale-rotate the
///      transaction keyset.
contract QuipWallet_replaceKeys_Transaction is QuipWalletTest {
    QuipWalletHarness public harnessProxy;
    /// @dev The harness wallet's actual transaction keys. Index 0 is
    ///      `alicePubkey`; indices 1..4 are deterministically derived by
    ///      `_encodeInitPayload` from `alicePubkey`'s components and differ
    ///      from `harnessTxKeys[1..4]` (which belong to the base `wallet`).
    WOTSPlus.WinternitzAddress[5] internal harnessTxKeys;

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
        }(keccak256("replaceKeys-tx-vault"), payable(ALICE), payload);
        harnessProxy = QuipWalletHarness(payable(proxyAddr));

        // Mirror `_encodeInitPayload`'s txn-key derivation so tests can
        // reference the harness wallet's actual transaction-keyset members.
        harnessTxKeys[0] = alicePubkey;
        for (uint256 i = 1; i < 5; i++) {
            bytes32 seed = keccak256(
                abi.encodePacked(
                    alicePubkey.publicSeed,
                    alicePubkey.publicKeyHash,
                    "txn-fill",
                    i
                )
            );
            (harnessTxKeys[i], ) = WOTSPlus.generateKeyPair(seed);
        }
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                       HAPPY PATHS                            */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    function test_replaceKeys_Transaction_recoverySigned_swapsAllTxKeys()
        public
    {
        // Sign with recovery key 0, replace all 5 tx keys in one batch.
        bytes32 recPriv = _recoverySigningKey(alicePrivateKey, 0);
        WOTSPlus.WinternitzAddress memory currentRec = recoveryPubkeys[0];

        WOTSPlus.WinternitzAddress[]
            memory oldKeys = new WOTSPlus.WinternitzAddress[](5);
        for (uint256 i = 0; i < 5; i++) oldKeys[i] = harnessTxKeys[i];

        WOTSPlus.WinternitzAddress[] memory newKeys = _freshKeys(
            keccak256("tx-rec-N5"),
            5
        );
        (WOTSPlus.WinternitzAddress memory nextRec, ) = _generateKeyPair(
            "tx-rec-N5-next"
        );

        bytes memory payload = _encodeReplaceKeysPayload(
            Codec.KeyType.Transaction,
            Codec.KeyType.Recovery,
            currentRec,
            recPriv,
            nextRec,
            oldKeys,
            newKeys
        );

        // Pre: all old tx keys in set; recovery signing key alive.
        for (uint256 i = 0; i < 5; i++) {
            assertTrue(harnessProxy.isKey(Codec.KeyType.Transaction, oldKeys[i]));
        }
        assertTrue(harnessProxy.isKey(Codec.KeyType.Recovery, currentRec));

        vm.prank(ALICE);
        harnessProxy.replaceKeys(payload);

        // Post: tx keyset fully rotated; recovery rotation committed.
        for (uint256 i = 0; i < 5; i++) {
            assertFalse(harnessProxy.isKey(Codec.KeyType.Transaction, oldKeys[i]));
            assertTrue(harnessProxy.isKey(Codec.KeyType.Transaction, newKeys[i]));
        }
        assertFalse(harnessProxy.isKey(Codec.KeyType.Recovery, currentRec));
        assertTrue(harnessProxy.isKey(Codec.KeyType.Recovery, nextRec));
        assertEq(harnessProxy.keyCount(Codec.KeyType.Transaction), 5);
        assertEq(harnessProxy.keyCount(Codec.KeyType.Recovery), 10);
    }

    function test_replaceKeys_Transaction_txSigned_sameKeysetSwap() public {
        // Same-keyset: sign with tx key 0, swap tx keys 1 and 2.
        // currentKey must NOT be in oldKeys (caller obligation).
        WOTSPlus.WinternitzAddress[]
            memory oldKeys = new WOTSPlus.WinternitzAddress[](2);
        oldKeys[0] = harnessTxKeys[1];
        oldKeys[1] = harnessTxKeys[2];

        WOTSPlus.WinternitzAddress[] memory newKeys = _freshKeys(
            keccak256("tx-tx-same"),
            2
        );
        (WOTSPlus.WinternitzAddress memory nextPq, ) = _generateKeyPair(
            "tx-tx-same-next"
        );

        bytes memory payload = _encodeReplaceKeysPayload(
            Codec.KeyType.Transaction,
            Codec.KeyType.Transaction,
            alicePubkey,
            alicePrivateKey,
            nextPq,
            oldKeys,
            newKeys
        );

        vm.prank(ALICE);
        harnessProxy.replaceKeys(payload);

        // Signing rotation: alicePubkey → nextPq.
        assertFalse(harnessProxy.isKey(Codec.KeyType.Transaction, alicePubkey));
        assertTrue(harnessProxy.isKey(Codec.KeyType.Transaction, nextPq));
        // N=2 swap committed.
        for (uint256 i = 0; i < 2; i++) {
            assertFalse(harnessProxy.isKey(Codec.KeyType.Transaction, oldKeys[i]));
            assertTrue(harnessProxy.isKey(Codec.KeyType.Transaction, newKeys[i]));
        }
        assertEq(harnessProxy.keyCount(Codec.KeyType.Transaction), 5);
    }

    function test_replaceKeys_Transaction_recoverySigned_N1_boundary() public {
        bytes32 recPriv = _recoverySigningKey(alicePrivateKey, 0);
        WOTSPlus.WinternitzAddress memory currentRec = recoveryPubkeys[0];

        WOTSPlus.WinternitzAddress[]
            memory oldKeys = new WOTSPlus.WinternitzAddress[](1);
        oldKeys[0] = harnessTxKeys[3];
        WOTSPlus.WinternitzAddress[] memory newKeys = _freshKeys(
            keccak256("tx-rec-N1"),
            1
        );
        (WOTSPlus.WinternitzAddress memory nextRec, ) = _generateKeyPair(
            "tx-rec-N1-next"
        );

        bytes memory payload = _encodeReplaceKeysPayload(
            Codec.KeyType.Transaction,
            Codec.KeyType.Recovery,
            currentRec,
            recPriv,
            nextRec,
            oldKeys,
            newKeys
        );

        vm.prank(ALICE);
        harnessProxy.replaceKeys(payload);

        assertFalse(harnessProxy.isKey(Codec.KeyType.Transaction, harnessTxKeys[3]));
        assertTrue(harnessProxy.isKey(Codec.KeyType.Transaction, newKeys[0]));
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                          REVERTS                             */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    function test_replaceKeys_Transaction_revertsWhen_currentKeyInOldKeys_sameKeyset()
        public
    {
        // Same-keyset path: sig rotation removes currentKey; redundant remove
        // in the oldKeys loop reverts KeyRemovalFailed.
        WOTSPlus.WinternitzAddress[]
            memory oldKeys = new WOTSPlus.WinternitzAddress[](1);
        oldKeys[0] = alicePubkey; // ← the signing key
        WOTSPlus.WinternitzAddress[] memory newKeys = _freshKeys(
            keccak256("tx-curOld"),
            1
        );
        (WOTSPlus.WinternitzAddress memory nextPq, ) = _generateKeyPair(
            "tx-curOld-next"
        );

        bytes memory payload = _encodeReplaceKeysPayload(
            Codec.KeyType.Transaction,
            Codec.KeyType.Transaction,
            alicePubkey,
            alicePrivateKey,
            nextPq,
            oldKeys,
            newKeys
        );

        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.KeyRemovalFailed.selector);
        harnessProxy.replaceKeys(payload);
    }

    function test_replaceKeys_Transaction_revertsWhen_nextKeyInNewKeys_sameKeyset()
        public
    {
        WOTSPlus.WinternitzAddress[]
            memory oldKeys = new WOTSPlus.WinternitzAddress[](1);
        oldKeys[0] = harnessTxKeys[1];
        (WOTSPlus.WinternitzAddress memory nextPq, ) = _generateKeyPair(
            "tx-nxtNew-next"
        );
        WOTSPlus.WinternitzAddress[]
            memory newKeys = new WOTSPlus.WinternitzAddress[](1);
        newKeys[0] = nextPq; // collides with signing-rotation install

        bytes memory payload = _encodeReplaceKeysPayload(
            Codec.KeyType.Transaction,
            Codec.KeyType.Transaction,
            alicePubkey,
            alicePrivateKey,
            nextPq,
            oldKeys,
            newKeys
        );

        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.KeyInUse.selector);
        harnessProxy.replaceKeys(payload);
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                         HELPERS                              */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    function _freshKeys(
        bytes32 seed,
        uint256 n
    ) internal pure returns (WOTSPlus.WinternitzAddress[] memory out) {
        out = new WOTSPlus.WinternitzAddress[](n);
        for (uint256 i = 0; i < n; i++) {
            (out[i], ) = WOTSPlus.generateKeyPair(
                keccak256(abi.encode(seed, i))
            );
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
            kind,
            signingKind,
            address(harnessProxy),
            currentPq,
            nextPq,
            oldKeys,
            newKeys
        );
        WOTSPlus.WinternitzElements memory sig = _sign(currentPriv, digest);
        return
            Codec.encodeReplaceKeys(
                kind,
                signingKind,
                oldKeys.length,
                currentPq,
                nextPq,
                sig,
                oldKeys,
                newKeys
            );
    }
}
