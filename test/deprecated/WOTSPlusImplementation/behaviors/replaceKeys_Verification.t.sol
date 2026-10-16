// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WOTSPlusImplementationTest} from "../WOTSPlusImplementation.t.sol";
import {WOTSPlusImplementationHarness, HarnessKeyset} from "../../harness/WOTSPlusImplementationHarness.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.2.0/contracts/WOTSPlus.sol";
import {WOTSPlusTestSigner} from "@quip.network/hashsigs-solidity-0.2.0/test/helpers/WOTSPlusTestSigner.sol";
import {IWOTSPlusImplementation} from "../../../../contracts/deprecated/wots/interfaces/IWOTSPlusImplementation.sol";
import {WOTSPlusCodec as Codec} from "../../../../contracts/deprecated/wots/WOTSPlusCodec.sol";

/// @dev Tests for `replaceKeys` when `kind == KeyType.Verification`.
///      Under always-10, the verification set inits with 10 keys derived by
///      `_encodeInitPayload` from `alicePubkey`. `seededVerifierKeys` mirrors
///      that derivation so tests can name the in-set entries to swap.
///      Both Transaction-signed and Recovery-signed paths are covered.
contract WOTSPlusImplementation_replaceKeys_Verification is WOTSPlusImplementationTest {
    WOTSPlusImplementationHarness public harnessProxy;
    WOTSPlus.WinternitzAddress[] internal seededVerifierKeys;

    function setUp() public override {
        super.setUp();

        WOTSPlusImplementationHarness harnessImpl = new WOTSPlusImplementationHarness(payable(address(factory)));
        vm.prank(ADMIN);
        factory.vetImplementation(address(harnessImpl));

        bytes memory payload = _encodeInitPayload(alicePubkey, recoveryPubkeys);

        vm.prank(ALICE);
        address proxyAddr = factory.deployLatestWalletProxy{value: INITIAL_DEPOSIT}(keccak256("replaceKeys-verif-vault"), payable(ALICE), payload
        );
        harnessProxy = WOTSPlusImplementationHarness(payable(proxyAddr));

        // Mirror `_encodeInitPayload`'s "verify-fill" derivation so tests can
        // reference the in-set verification keys.
        for (uint256 i = 0; i < 10; i++) {
            (WOTSPlus.WinternitzAddress memory key,) = WOTSPlusTestSigner.generateKeyPair(
                keccak256(abi.encodePacked(alicePubkey.publicSeed, alicePubkey.publicKeyHash, "verify-fill", i))
            );
            seededVerifierKeys.push(key);
        }
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                       HAPPY PATHS                            */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    function test_replaceKeys_Verification_txSigned_swapsN3() public {
        WOTSPlus.WinternitzAddress[] memory oldKeys = new WOTSPlus.WinternitzAddress[](3);
        for (uint256 i = 0; i < 3; i++) {
            oldKeys[i] = seededVerifierKeys[i];
        }
        WOTSPlus.WinternitzAddress[] memory newKeys = _freshKeys(keccak256("vrf-tx-N3"), 3);
        (WOTSPlus.WinternitzAddress memory nextPq,) = _generateKeyPair("vrf-tx-N3-next");

        bytes memory payload = _encodeReplaceKeysPayload(
            Codec.KeyType.Verification,
            Codec.KeyType.Transaction,
            alicePubkey,
            alicePrivateKey,
            nextPq,
            oldKeys,
            newKeys
        );

        vm.prank(ALICE);
        harnessProxy.replaceKeys(payload);

        for (uint256 i = 0; i < 3; i++) {
            assertFalse(harnessProxy.isKey(Codec.KeyType.Verification, oldKeys[i]));
            assertTrue(harnessProxy.isKey(Codec.KeyType.Verification, newKeys[i]));
        }
        assertEq(harnessProxy.keyCount(Codec.KeyType.Verification), 10);
        // Tx signing rotation committed.
        assertFalse(harnessProxy.isKey(Codec.KeyType.Transaction, alicePubkey));
        assertTrue(harnessProxy.isKey(Codec.KeyType.Transaction, nextPq));
    }

    function test_replaceKeys_Verification_recoverySigned_swapsAll() public {
        // Recovery-signed wholesale rotation of the verification set.
        bytes32 recPriv = _recoverySigningKey(alicePrivateKey, 0);
        WOTSPlus.WinternitzAddress memory currentRec = recoveryPubkeys[0];

        WOTSPlus.WinternitzAddress[] memory oldKeys = new WOTSPlus.WinternitzAddress[](5);
        for (uint256 i = 0; i < 5; i++) {
            oldKeys[i] = seededVerifierKeys[i];
        }
        WOTSPlus.WinternitzAddress[] memory newKeys = _freshKeys(keccak256("vrf-rec-all"), 5);
        (WOTSPlus.WinternitzAddress memory nextRec,) = _generateKeyPair("vrf-rec-all-next");

        bytes memory payload = _encodeReplaceKeysPayload(
            Codec.KeyType.Verification, Codec.KeyType.Recovery, currentRec, recPriv, nextRec, oldKeys, newKeys
        );

        vm.prank(ALICE);
        harnessProxy.replaceKeys(payload);

        for (uint256 i = 0; i < 5; i++) {
            assertFalse(harnessProxy.isKey(Codec.KeyType.Verification, oldKeys[i]));
            assertTrue(harnessProxy.isKey(Codec.KeyType.Verification, newKeys[i]));
        }
        // Recovery rotation committed.
        assertFalse(harnessProxy.isKey(Codec.KeyType.Recovery, currentRec));
        assertTrue(harnessProxy.isKey(Codec.KeyType.Recovery, nextRec));
        // Tx keyset untouched.
        assertEq(harnessProxy.keyCount(Codec.KeyType.Transaction), 10);
    }

    function test_replaceKeys_Verification_txSigned_N1_boundary() public {
        WOTSPlus.WinternitzAddress[] memory oldKeys = new WOTSPlus.WinternitzAddress[](1);
        oldKeys[0] = seededVerifierKeys[0];
        WOTSPlus.WinternitzAddress[] memory newKeys = _freshKeys(keccak256("vrf-tx-N1"), 1);
        (WOTSPlus.WinternitzAddress memory nextPq,) = _generateKeyPair("vrf-tx-N1-next");

        bytes memory payload = _encodeReplaceKeysPayload(
            Codec.KeyType.Verification,
            Codec.KeyType.Transaction,
            alicePubkey,
            alicePrivateKey,
            nextPq,
            oldKeys,
            newKeys
        );

        vm.prank(ALICE);
        harnessProxy.replaceKeys(payload);

        assertFalse(harnessProxy.isKey(Codec.KeyType.Verification, seededVerifierKeys[0]));
        assertTrue(harnessProxy.isKey(Codec.KeyType.Verification, newKeys[0]));
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                          REVERTS                             */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    function test_replaceKeys_Verification_revertsWhen_oldKeyNotInVerifSet() public {
        // Pass an unrelated key as oldKey — not in the verification set.
        WOTSPlus.WinternitzAddress[] memory oldKeys = new WOTSPlus.WinternitzAddress[](1);
        (oldKeys[0],) = _generateKeyPair("vrf-rev-missing-old");
        WOTSPlus.WinternitzAddress[] memory newKeys = _freshKeys(keccak256("vrf-rev-missing-new"), 1);
        (WOTSPlus.WinternitzAddress memory nextPq,) = _generateKeyPair("vrf-rev-missing-next");

        bytes memory payload = _encodeReplaceKeysPayload(
            Codec.KeyType.Verification,
            Codec.KeyType.Transaction,
            alicePubkey,
            alicePrivateKey,
            nextPq,
            oldKeys,
            newKeys
        );

        vm.prank(ALICE);
        vm.expectRevert(IWOTSPlusImplementation.KeyRemovalFailed.selector);
        harnessProxy.replaceKeys(payload);
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                         HELPERS                              */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    function _freshKeys(bytes32 seed, uint256 n) internal pure returns (WOTSPlus.WinternitzAddress[] memory out) {
        out = new WOTSPlus.WinternitzAddress[](n);
        for (uint256 i = 0; i < n; i++) {
            (out[i],) = WOTSPlusTestSigner.generateKeyPair(keccak256(abi.encode(seed, i)));
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
