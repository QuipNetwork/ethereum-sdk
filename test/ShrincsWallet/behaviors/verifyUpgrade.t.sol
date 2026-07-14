// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {SHRINCS} from "@quip.network/hashsigs-solidity-0.2.0/contracts/SHRINCS.sol";
import {SPHINCSPlusC} from "@quip.network/hashsigs-solidity-0.2.0/contracts/SPHINCSPlusC.sol";
import {UXMSS} from "@quip.network/hashsigs-solidity-0.2.0/contracts/UXMSS.sol";
import {HashSuite} from "shrincs-hash/HashSuite.sol";
import {SHRINCSParams} from "shrincs-profile/SHRINCSParams.sol";
import {ShrincsWalletCodec as Codec} from "../../../contracts/shrincs/ShrincsWalletCodec.sol";
import {IShrincsWallet} from "../../../contracts/shrincs/interfaces/IShrincsWallet.sol";
import {ShrincsWalletTest} from "../ShrincsWallet.t.sol";

/// @dev Behavior tests for the `verifyUpgrade` reachability probe: the failure (InvalidSignature)
///      branch, the success probe over a live-signed UPGRADE signature, and the blob-nonce
///      property `upgradeToAndCall` depends on (the probe rebuilds the context from the blob's
///      nonce, never the live one).
contract ShrincsWallet_verifyUpgrade is ShrincsWalletTest {
    function _data(SHRINCS.Signature memory sig) internal view returns (bytes memory) {
        return abi.encode(_mainPk(), sig, false, bytes(""), wallet.actionNonce());
    }

    function test_verifyUpgrade_revertsWhen_invalidSignature() public {
        bytes memory data = _data(_wrongContextStatefulSig());
        vm.expectRevert(IShrincsWallet.InvalidSignature.selector);
        wallet.verifyUpgrade(address(0xBEEF), data);
    }

    function test_verifyUpgrade_succeeds() public view {
        // The signature binds newImplementation = 0xBEEF, shouldMigrate=false, empty migrator.
        SHRINCS.Signature memory sig = _signStatefulAction(
            Codec.ACTION_UPGRADE, Codec.upgradePayloadHash(address(0xBEEF), false, keccak256("")), 1
        );
        wallet.verifyUpgrade(address(0xBEEF), _data(sig));
    }

    /// @dev Pins the post-consumption re-verify property: a blob signed (and bound) at nonce 5
    ///      still probes successfully after the live nonce has advanced past it. If this breaks
    ///      (e.g. someone "fixes" verifyUpgrade to read the live nonce), every upgrade bricks —
    ///      `upgradeToAndCall` delegatecalls this probe AFTER consuming the signature.
    function test_verifyUpgrade_usesBlobNonce_notLiveNonce() public {
        wallet.harness_setNonce(5);
        SHRINCS.Signature memory sig = _signStatefulAction(
            Codec.ACTION_UPGRADE, Codec.upgradePayloadHash(address(0xBEEF), false, keccak256("")), 1
        );
        bytes memory data = abi.encode(_mainPk(), sig, false, bytes(""), uint256(5));

        // Simulate the post-consumption moment: live nonce has moved past the signed one.
        wallet.harness_setNonce(6);
        wallet.verifyUpgrade(address(0xBEEF), data);
    }
}
