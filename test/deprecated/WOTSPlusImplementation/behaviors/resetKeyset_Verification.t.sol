// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WOTSPlusImplementationTest} from "../WOTSPlusImplementation.t.sol";
import {WOTSPlusImplementationHarness} from "../../harness/WOTSPlusImplementationHarness.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.2.0/contracts/WOTSPlus.sol";
import {WOTSPlusTestSigner} from "@quip.network/hashsigs-solidity-0.2.0/test/helpers/WOTSPlusTestSigner.sol";
import {IWOTSPlusImplementation} from "../../../../contracts/deprecated/wots/interfaces/IWOTSPlusImplementation.sol";
import {WOTSPlusCodec as Codec} from "../../../../contracts/deprecated/wots/WOTSPlusCodec.sol";

/// @dev Tests for `resetKeyset` when `kind == KeyType.Verification`. The
///      verification keyset starts full (10 init-seeded keys), so resetKeyset's
///      `_clearKeys` wipes the existing 10 and the install loop reinstalls a
///      fresh 10 — exercising the always-10 invariant.
contract WOTSPlusImplementation_resetKeyset_Verification is WOTSPlusImplementationTest {
    WOTSPlusImplementationHarness public harnessProxy;

    function setUp() public override {
        super.setUp();

        WOTSPlusImplementationHarness harnessImpl = new WOTSPlusImplementationHarness(payable(address(factory)));
        vm.prank(ADMIN);
        factory.vetImplementation(address(harnessImpl));

        bytes memory payload = _encodeInitPayload(alicePubkey, recoveryPubkeys);
        vm.prank(ALICE);
        address proxyAddr = factory.deployLatestWalletProxy{value: INITIAL_DEPOSIT}(keccak256("resetKeyset-verif-vault"), payable(ALICE), payload
        );
        harnessProxy = WOTSPlusImplementationHarness(payable(proxyAddr));
    }

    function test_resetKeyset_Verification_txSigned_wholesaleReplaces() public {
        // Pre: verification keyset is full at init under the always-10 invariant.
        assertEq(harnessProxy.keyCount(Codec.KeyType.Verification), 10);

        WOTSPlus.WinternitzAddress[10] memory newKeys = _freshKeys10(keccak256("verif-tx-seed"));
        (WOTSPlus.WinternitzAddress memory nextPq,) = _generateKeyPair("verif-tx-seed-next");

        bytes memory payload = _encodeResetKeysetPayload(
            Codec.KeyType.Verification, Codec.KeyType.Transaction, alicePubkey, alicePrivateKey, nextPq, newKeys
        );

        vm.prank(ALICE);
        harnessProxy.resetKeyset(payload);

        // Post: verification holds exactly the 10 newKeys.
        assertEq(harnessProxy.keyCount(Codec.KeyType.Verification), 10);
        for (uint256 i = 0; i < 10; i++) {
            assertTrue(harnessProxy.isKey(Codec.KeyType.Verification, newKeys[i]));
        }
        // Tx signing rotation committed.
        assertFalse(harnessProxy.isKey(Codec.KeyType.Transaction, alicePubkey));
        assertTrue(harnessProxy.isKey(Codec.KeyType.Transaction, nextPq));
    }

    function test_resetKeyset_Verification_recoverySigned_wholesaleReplaces() public {
        bytes32 recPriv = _recoverySigningKey(alicePrivateKey, 0);
        WOTSPlus.WinternitzAddress memory currentRec = recoveryPubkeys[0];
        WOTSPlus.WinternitzAddress[10] memory newKeys = _freshKeys10(keccak256("verif-rec-seed"));
        (WOTSPlus.WinternitzAddress memory nextRec,) = _generateKeyPair("verif-rec-seed-next");

        bytes memory payload = _encodeResetKeysetPayload(
            Codec.KeyType.Verification, Codec.KeyType.Recovery, currentRec, recPriv, nextRec, newKeys
        );

        vm.prank(ALICE);
        harnessProxy.resetKeyset(payload);

        assertEq(harnessProxy.keyCount(Codec.KeyType.Verification), 10);
        // Recovery rotation committed.
        assertFalse(harnessProxy.isKey(Codec.KeyType.Recovery, currentRec));
        assertTrue(harnessProxy.isKey(Codec.KeyType.Recovery, nextRec));
    }

    function test_resetKeyset_Verification_canRebuildAfterFirstSeed() public {
        // First seed via tx-signed reset.
        WOTSPlus.WinternitzAddress[10] memory firstKeys = _freshKeys10(keccak256("verif-rebuild-first"));
        (WOTSPlus.WinternitzAddress memory firstNext,) = _generateKeyPair("verif-rebuild-first-next");
        bytes memory firstPayload = _encodeResetKeysetPayload(
            Codec.KeyType.Verification, Codec.KeyType.Transaction, alicePubkey, alicePrivateKey, firstNext, firstKeys
        );
        vm.prank(ALICE);
        harnessProxy.resetKeyset(firstPayload);

        // Now re-seed with second batch. Tx signing key has rotated to firstNext.
        // Re-derive private key for firstNext from the same seed used by
        // _generateKeyPair.
        (, bytes32 firstNextPriv) = _generateKeyPair("verif-rebuild-first-next");
        WOTSPlus.WinternitzAddress[10] memory secondKeys = _freshKeys10(keccak256("verif-rebuild-second"));
        (WOTSPlus.WinternitzAddress memory secondNext,) = _generateKeyPair("verif-rebuild-second-next");
        bytes memory secondPayload = _encodeResetKeysetPayload(
            Codec.KeyType.Verification, Codec.KeyType.Transaction, firstNext, firstNextPriv, secondNext, secondKeys
        );
        vm.prank(ALICE);
        harnessProxy.resetKeyset(secondPayload);

        assertEq(harnessProxy.keyCount(Codec.KeyType.Verification), 10);
        for (uint256 i = 0; i < 10; i++) {
            assertFalse(harnessProxy.isKey(Codec.KeyType.Verification, firstKeys[i]));
            assertTrue(harnessProxy.isKey(Codec.KeyType.Verification, secondKeys[i]));
        }
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
