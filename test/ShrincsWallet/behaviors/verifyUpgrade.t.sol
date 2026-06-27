// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {ShrincsTypes} from "@quip.network/hashsigs-solidity-0.1.0/contracts/ShrincsTypes.sol";
import {IShrincsWallet} from "../../../contracts/shrincs/interfaces/IShrincsWallet.sol";
import {ShrincsWalletTest} from "../ShrincsWallet.t.sol";

/// @dev Behavior tests for the `verifyUpgrade` reachability probe. The failure (InvalidSignature)
///      branch is testable now; the success probe is exercised by the regenerated UPGRADE vector.
contract ShrincsWallet_verifyUpgrade is ShrincsWalletTest {
    function _data(ShrincsTypes.StatefulSignature memory sig) internal view returns (bytes memory) {
        return abi.encode(_parsePublicKey(".mainKey"), sig, false, bytes(""));
    }

    function test_verifyUpgrade_revertsWhen_invalidSignature() public {
        vm.expectRevert(IShrincsWallet.InvalidSignature.selector);
        wallet.verifyUpgrade(address(0xBEEF), _data(_wrongContextStatefulSig()));
    }

    function test_verifyUpgrade_succeeds() public view {
        // The UPGRADE vector binds newImplementation = 0xBEEF, shouldMigrate=false, empty migrator.
        ShrincsTypes.StatefulSignature memory sig = _parseStatefulSignature(".cases.upgrade.signature");
        wallet.verifyUpgrade(address(0xBEEF), _data(sig));
    }
}
