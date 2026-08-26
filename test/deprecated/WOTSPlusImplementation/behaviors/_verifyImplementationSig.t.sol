// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WOTSPlusCodec as Codec} from "../../../../contracts/deprecated/wots/WOTSPlusCodec.sol";
import {WOTSPlusImplementationTest} from "../WOTSPlusImplementation.t.sol";
import {WOTSPlusImplementationHarness} from "../../harness/WOTSPlusImplementationHarness.sol";
import {IWOTSPlusImplementation} from "../../../../contracts/deprecated/wots/interfaces/IWOTSPlusImplementation.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.2.0/contracts/WOTSPlus.sol";

/// @dev Behaviour tests for `_verifyImplementationSig(newImpl, verifier, verifySig)`.
///      Shared between `verifyUpgrade` and `verifyRecoveryUpgrade`. Computes the
///      `verificationDigest(wallet, chainId, newImpl, verifierSeed, verifierHash)`
///      and reverts `InvalidSignature` if the WOTS+ signature does not verify.
contract WOTSPlusImplementation__verifyImplementationSig is WOTSPlusImplementationTest {
    WOTSPlusImplementationHarness public harnessProxy;

    function setUp() public override {
        super.setUp();
        WOTSPlusImplementationHarness harnessImpl = new WOTSPlusImplementationHarness(payable(address(factory)));
        vm.prank(ADMIN);
        factory.vetImplementation(address(harnessImpl));

        (WOTSPlus.WinternitzAddress memory pub, bytes32 priv) = _generateKeyPair("h-vis");
        WOTSPlus.WinternitzAddress[] memory rKeys = _generateRecoveryKeys(priv, 10);
        bytes memory payload = _encodeInitPayload(pub, rKeys);

        vm.prank(ALICE);
        address proxyAddr =
            factory.deployLatestWalletProxy{value: INITIAL_DEPOSIT}(keccak256("h-vis-vault"), COMMITMENT, payable(ALICE), payload);
        harnessProxy = WOTSPlusImplementationHarness(payable(proxyAddr));
    }

    function test_exposed_verifyImplementationSig_happyPath() public view {
        address newImpl = address(0x9999);
        (WOTSPlus.WinternitzAddress memory verifier, bytes32 verifierPriv) = _generateKeyPair("h-vis-verifier");

        bytes32 digest = Codec.verificationDigest(
            address(harnessProxy), block.chainid, newImpl, verifier.publicSeed, verifier.publicKeyHash
        );
        WOTSPlus.WinternitzElements memory sig = _sign(verifierPriv, digest);

        harnessProxy.exposed_verifyImplementationSig(newImpl, verifier, sig);
    }

    function test_exposed_verifyImplementationSig_revertsWhen_signatureInvalid() public {
        address newImpl = address(0xA1A1);
        (WOTSPlus.WinternitzAddress memory verifier, bytes32 verifierPriv) = _generateKeyPair("h-vis-verifier-bad");

        // Sign the wrong digest so verification fails.
        WOTSPlus.WinternitzElements memory sig = _sign(verifierPriv, keccak256("wrong-digest"));

        vm.expectRevert(IWOTSPlusImplementation.InvalidSignature.selector);
        harnessProxy.exposed_verifyImplementationSig(newImpl, verifier, sig);
    }

    // Wrong `newImpl` in the digest → digest mismatch → verification fails.
    function test_exposed_verifyImplementationSig_revertsWhen_newImplMismatch() public {
        address realImpl = address(0xB2B2);
        address wrongImpl = address(0xC3C3);
        (WOTSPlus.WinternitzAddress memory verifier, bytes32 verifierPriv) = _generateKeyPair("h-vis-verifier-2");

        // Sign digest for realImpl…
        bytes32 signedDigest = Codec.verificationDigest(
            address(harnessProxy), block.chainid, realImpl, verifier.publicSeed, verifier.publicKeyHash
        );
        WOTSPlus.WinternitzElements memory sig = _sign(verifierPriv, signedDigest);

        // …but call with wrongImpl so the digest it reconstructs differs.
        vm.expectRevert(IWOTSPlusImplementation.InvalidSignature.selector);
        harnessProxy.exposed_verifyImplementationSig(wrongImpl, verifier, sig);
    }
}
