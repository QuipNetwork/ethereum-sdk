// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WOTSPlusCodec as Codec} from "../../../../contracts/deprecated/wots/WOTSPlusCodec.sol";
import {WOTSPlusImplementationTest} from "../WOTSPlusImplementation.t.sol";
import {WOTSPlusImplementationHarness, HarnessKeyset} from "../../harness/WOTSPlusImplementationHarness.sol";
import {IWOTSPlusImplementation} from "../../../../contracts/deprecated/wots/interfaces/IWOTSPlusImplementation.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.2.0/contracts/WOTSPlus.sol";

/// @dev Behaviour tests for `_verifyAndRotate(set, current, next, pqSig, digest)`.
///      Enforces (a) `current ∈ set`, (b) `next ∉ set`, (c) valid WOTS+ sig over
///      `digest`. On success, rotates `current → next` in place.
contract WOTSPlusImplementation__verifyAndRotate is WOTSPlusImplementationTest {
    WOTSPlusImplementationHarness public harnessProxy;

    // Seeded WOTS+ keypair used as the "current" key across tests.
    WOTSPlus.WinternitzAddress internal currentKey;
    bytes32 internal currentPriv;

    function setUp() public override {
        super.setUp();
        WOTSPlusImplementationHarness harnessImpl = new WOTSPlusImplementationHarness(payable(address(factory)));
        vm.prank(ADMIN);
        factory.vetImplementation(address(harnessImpl));

        (currentKey, currentPriv) = _generateKeyPair("h-vr-current");
        WOTSPlus.WinternitzAddress[] memory rKeys = _generateRecoveryKeys(currentPriv, 10);
        bytes memory payload = _encodeInitPayload(currentKey, rKeys);

        vm.prank(ALICE);
        address proxyAddr =
            factory.deployLatestWalletProxy{value: INITIAL_DEPOSIT}(keccak256("h-vr-vault"), COMMITMENT, payable(ALICE), payload);
        harnessProxy = WOTSPlusImplementationHarness(payable(proxyAddr));
    }

    function test_exposed_verifyAndRotate_happyPath() public {
        (WOTSPlus.WinternitzAddress memory nextKey,) = _generateKeyPair("h-vr-next");
        bytes32 digest = keccak256("vr-happy");
        WOTSPlus.WinternitzElements memory sig = _sign(currentPriv, digest);

        harnessProxy.exposed_verifyAndRotate(HarnessKeyset.Transaction, currentKey, nextKey, sig, digest);

        assertFalse(harnessProxy.isKey(Codec.KeyType.Transaction, currentKey));
        assertTrue(harnessProxy.isKey(Codec.KeyType.Transaction, nextKey));
    }

    function test_exposed_verifyAndRotate_revertsWhen_currentAbsent() public {
        (WOTSPlus.WinternitzAddress memory stray, bytes32 strayPriv) = _generateKeyPair("h-vr-stray");
        (WOTSPlus.WinternitzAddress memory nextKey,) = _generateKeyPair("h-vr-next-2");
        bytes32 digest = keccak256("vr-absent");
        WOTSPlus.WinternitzElements memory sig = _sign(strayPriv, digest);

        vm.expectRevert(IWOTSPlusImplementation.UnknownKey.selector);
        harnessProxy.exposed_verifyAndRotate(HarnessKeyset.Transaction, stray, nextKey, sig, digest);
    }

    function test_exposed_verifyAndRotate_revertsWhen_nextAlreadyPresent() public {
        // Pick another existing transaction key as `next`.
        WOTSPlus.WinternitzAddress memory next = harnessProxy.keyAt(Codec.KeyType.Transaction, 1);
        bytes32 digest = keccak256("vr-dup");
        WOTSPlus.WinternitzElements memory sig = _sign(currentPriv, digest);

        vm.expectRevert(IWOTSPlusImplementation.KeyInUse.selector);
        harnessProxy.exposed_verifyAndRotate(HarnessKeyset.Transaction, currentKey, next, sig, digest);
    }

    function test_exposed_verifyAndRotate_revertsWhen_signatureInvalid() public {
        (WOTSPlus.WinternitzAddress memory nextKey,) = _generateKeyPair("h-vr-next-3");
        bytes32 digest = keccak256("vr-sig-bad");
        // Sign a *different* digest so verification fails on the real one.
        WOTSPlus.WinternitzElements memory sig = _sign(currentPriv, keccak256("not-the-digest"));

        vm.expectRevert(IWOTSPlusImplementation.InvalidSignature.selector);
        harnessProxy.exposed_verifyAndRotate(HarnessKeyset.Transaction, currentKey, nextKey, sig, digest);
    }
}
