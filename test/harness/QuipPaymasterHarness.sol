// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {QuipPaymaster} from "../../contracts/QuipPaymaster.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";

contract QuipPaymasterHarness is QuipPaymaster {
    function exposed_guardInitializeOwner() external pure returns (bool) {
        return _guardInitializeOwner();
    }

    function exposed_authorizeUpgrade(address newImpl) external {
        _authorizeUpgrade(newImpl);
    }

    function exposed_verifyAndRotate(
        address sender,
        bytes32 userOpHash,
        bytes calldata paymasterData
    ) external returns (bool) {
        return _verifyAndRotate(sender, userOpHash, paymasterData);
    }
}
