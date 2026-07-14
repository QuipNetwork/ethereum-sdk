// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {ShrincsTypes} from "@quip.network/hashsigs-solidity-0.1.0/contracts/ShrincsTypes.sol";
import {ShrincsWalletCodec as Codec} from "../../../contracts/shrincs/ShrincsWalletCodec.sol";
import {IShrincsWallet} from "../../../contracts/shrincs/interfaces/IShrincsWallet.sol";
import {ShrincsWalletTest} from "../ShrincsWallet.t.sol";

/// @dev Behavior tests for the `verifyUpgrade` reachability probe: the failure (InvalidSignature)
///      branch and the success probe over a live-signed UPGRADE signature.
contract ShrincsWallet_verifyUpgrade is ShrincsWalletTest {
    function _data(ShrincsTypes.StatefulSignature memory sig) internal view returns (bytes memory) {
        return abi.encode(_mainPk(), sig, false, bytes(""));
    }

    function test_verifyUpgrade_revertsWhen_invalidSignature() public {
        bytes memory data = _data(_wrongContextStatefulSig());
        vm.expectRevert(IShrincsWallet.InvalidSignature.selector);
        wallet.verifyUpgrade(address(0xBEEF), data);
    }

    function test_verifyUpgrade_succeeds() public view {
        // The signature binds newImplementation = 0xBEEF, shouldMigrate=false, empty migrator.
        ShrincsTypes.StatefulSignature memory sig = _signStatefulAction(
            Codec.ACTION_UPGRADE, Codec.upgradePayloadHash(address(0xBEEF), false, keccak256("")), 1
        );
        wallet.verifyUpgrade(address(0xBEEF), _data(sig));
    }
}
